#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <linux/types.h>

#include "include/vpnhide.h"
#include "parson.h"
#include "vpnhide_policy.h"

/* CONNECT and BIND are mandatory because port policy is enforced by those
 * hooks. They are not user-configurable hook switches. */
#define VPNHIDE_PORT_HOOK_MASK ((1u << 13) | (1u << 16))
#define VPNHIDE_STATS_SOCKET "vpnhide.stats.v1"

static int print_stats_history(int clear)
{
	struct sockaddr_un address;
	char buffer[4096];
	int fd, length;
	const char *command = clear ? "CLEAR_HISTORY\n" : "GET_STATS\n";
	memset(&address, 0, sizeof(address));
	address.sun_family = AF_UNIX;
	address.sun_path[0] = '\0';
	strncpy(address.sun_path + 1, VPNHIDE_STATS_SOCKET,
			sizeof(address.sun_path) - 2);
	length = (int)(offsetof(struct sockaddr_un, sun_path) + 1 +
			strlen(VPNHIDE_STATS_SOCKET));
	fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (fd < 0 || connect(fd, (struct sockaddr *)&address, length) < 0) {
		if (fd >= 0) close(fd);
		perror("stats_history socket");
		return 1;
	}
	if (write(fd, command, strlen(command)) != (ssize_t)strlen(command)) {
		perror("stats_history write");
		close(fd);
		return 1;
	}
	shutdown(fd, SHUT_WR);
	while ((length = (int)read(fd, buffer, sizeof(buffer))) > 0) {
		if (write(STDOUT_FILENO, buffer, (size_t)length) != length) {
			perror("stats_history output");
			close(fd);
			return 1;
		}
	}
	close(fd);
	return length < 0 ? 1 : 0;
}

void print_usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s <load|validate|preview|set_spoof_ip|active_hooks|java_hooks|stats|stats_history|version> [args...]\n",
		prog);
	fprintf(stderr, "  load format: <json_path> [self_uid]\n");
	fprintf(stderr, "  validate/preview format: <json_path> [self_uid]\n");
	fprintf(stderr, "  stats output: uid;ioctl;netlink;proc;sockopt;connect;getname;port\n");
	fprintf(stderr, "  proto: 0=TCP, 1=UDP, 2=BOTH\n");
	fprintf(stderr, "  set_spoof_ip format: <ipv4|none> <ipv6|none>\n");
	fprintf(stderr, "  version format: [ctl|kmod] (default: print both ctl and running kmod version)\n");
}

static void sort_uids(uid_t *arr, size_t count)
{
	for (size_t i = 0; i + 1 < count; i++) {
		for (size_t j = 0; j + 1 < count - i; j++) {
			if (arr[j] > arr[j + 1]) {
				uid_t temp = arr[j];
				arr[j] = arr[j + 1];
				arr[j + 1] = temp;
			}
		}
	}
}

struct app_hook_mask_vector {
	size_t count;
	size_t capacity;
	struct vpnhide_app_hook_mask_v3 *items;
};

static int append_app_hook_mask(struct app_hook_mask_vector *vector,
				const struct vpnhide_app_hook_mask_v3 *mask)
{
	if (vector->count == vector->capacity) {
		size_t capacity = vector->capacity ? vector->capacity * 2 : 16;
		void *grown;
		if (capacity < vector->capacity ||
		    capacity > SIZE_MAX / sizeof(*vector->items))
			return -1;
		grown = realloc(vector->items, capacity * sizeof(*vector->items));
		if (!grown)
			return -1;
		vector->items = grown;
		vector->capacity = capacity;
	}
	vector->items[vector->count++] = *mask;
	return 0;
}

static int policy_add_size(size_t *total, size_t count, size_t element_size)
{
	size_t bytes;
	if (count && element_size > SIZE_MAX / count)
		return -1;
	bytes = count * element_size;
	if (*total > SIZE_MAX - bytes)
		return -1;
	*total += bytes;
	return 0;
}

static int pack_policy_v3(const struct vpnhide_uid_vector *targets,
			  const struct vpnhide_uid_vector *lsposed,
			  const struct vpnhide_port_policy *ports,
			  const struct app_hook_mask_vector *masks,
			  const struct vpnhide_iface_ioctl_data *ifaces,
			  unsigned int active_mask, unsigned int java_mask,
			  int debug_enabled, void **out, uint32_t *out_size)
{
	struct vpnhide_policy_payload_v3 *payload;
	struct vpnhide_port_target_v3 *port_targets;
	struct vpnhide_port_rule_v3 *port_rules;
	size_t total = sizeof(*payload), total_rules = 0, cursor;
	size_t i, j;

	for (i = 0; i < ports->count; i++) {
		if (total_rules > SIZE_MAX - ports->targets[i].rule_count)
			return -1;
		total_rules += ports->targets[i].rule_count;
	}
	if (targets->count > UINT32_MAX || lsposed->count > UINT32_MAX ||
	    ports->count > UINT32_MAX || total_rules > UINT32_MAX ||
	    masks->count > UINT32_MAX)
		return -1;
	if (policy_add_size(&total, targets->count, sizeof(__u32)) ||
	    policy_add_size(&total, lsposed->count, sizeof(__u32)) ||
	    policy_add_size(&total, ports->count, sizeof(*port_targets)) ||
	    policy_add_size(&total, total_rules, sizeof(*port_rules)) ||
	    policy_add_size(&total, masks->count, sizeof(*masks->items)) ||
	    total > UINT32_MAX || total > VPNHIDE_POLICY_MAX_BYTES)
		return -1;

	payload = calloc(1, total);
	if (!payload)
		return -1;
	payload->total_size = (uint32_t)total;
	payload->active_hooks_mask = active_mask;
	payload->java_hooks_mask = java_mask;
	payload->debug_enabled = !!debug_enabled;
	payload->iface_count = (uint32_t)ifaces->count;
	memcpy(payload->iface_prefixes, ifaces->prefixes,
	       sizeof(payload->iface_prefixes));

	cursor = sizeof(*payload);
#define PACK_SECTION(section, source, count_value, element_size) do { \
	payload->section.offset = (uint32_t)cursor; \
	payload->section.count = (uint32_t)(count_value); \
	if ((count_value) != 0) \
		memcpy((unsigned char *)payload + cursor, (source), \
		       (count_value) * (element_size)); \
	cursor += (count_value) * (element_size); \
} while (0)
	PACK_SECTION(kmod_uids, targets->items, targets->count, sizeof(__u32));
	PACK_SECTION(lsposed_uids, lsposed->items, lsposed->count, sizeof(__u32));
	payload->port_targets.offset = (uint32_t)cursor;
	payload->port_targets.count = (uint32_t)ports->count;
	port_targets = (void *)((unsigned char *)payload + cursor);
	cursor += ports->count * sizeof(*port_targets);
	payload->port_rules.offset = (uint32_t)cursor;
	payload->port_rules.count = (uint32_t)total_rules;
	port_rules = (void *)((unsigned char *)payload + cursor);
	cursor += total_rules * sizeof(*port_rules);
	for (i = 0, j = 0; i < ports->count; i++) {
		port_targets[i].uid = ports->targets[i].uid;
		port_targets[i].first_rule = (uint32_t)j;
		port_targets[i].rule_count = (uint32_t)ports->targets[i].rule_count;
		port_targets[i].mode = ports->targets[i].mode;
		for (size_t r = 0; r < ports->targets[i].rule_count; r++, j++) {
			port_rules[j].start_port = ports->targets[i].rules[r].start_port;
			port_rules[j].end_port = ports->targets[i].rules[r].end_port;
			port_rules[j].protocol = ports->targets[i].rules[r].protocol;
		}
	}
	PACK_SECTION(app_hook_masks, masks->items, masks->count,
		     sizeof(*masks->items));
#undef PACK_SECTION
	*out = payload;
	*out_size = (uint32_t)total;
	return 0;
}

int main(int argc, char **argv)
{
	int fd;
	if (argc < 2) {
		print_usage(argv[0]);
		return 1;
	}
	if (strcmp(argv[1], "stats_history") == 0)
		return print_stats_history(argc > 2 && strcmp(argv[2], "clear") == 0);

	if (strcmp(argv[1], "version") == 0) {
		int kversion = -1;
		int temp_fd = open("/dev/vpnhide_ctrl", O_RDONLY);
		if (temp_fd >= 0) {
			if (ioctl(temp_fd, VH_GET_VERSION, &kversion) < 0) {
				kversion = -1;
			}
			close(temp_fd);
		}
		if (argc > 2) {
			if (strcmp(argv[2], "ctl") == 0) {
				printf("%d\n", VPNHIDE_VERSION_CODE);
			} else if (strcmp(argv[2], "kmod") == 0) {
				printf("%d\n", kversion);
			} else {
				fprintf(stderr, "Unknown version component: %s\n", argv[2]);
				return 1;
			}
		} else {
			printf("ctl: %d\n", VPNHIDE_VERSION_CODE);
			printf("kmod: %d\n", kversion);
		}
		return 0;
	}

	if (strcmp(argv[1], "validate") == 0 ||
	    strcmp(argv[1], "preview") == 0) {
		JSON_Value *root_value;
		JSON_Object *root;
		struct vpnhide_uid_vector targets = {0}, lsposed = {0};
		struct vpnhide_port_policy ports = {0};
		struct vpnhide_policy_summary summary;
		char error[256];
		uid_t self_uid = 0;
		int ret;

		if (argc < 3) {
			fprintf(stderr, "Error: %s requires <json_path> [self_uid]\n", argv[1]);
			return 1;
		}
		if (argc > 3)
			self_uid = (uid_t)atoi(argv[3]);
		root_value = json_parse_file(argv[2]);
		if (!root_value || json_value_get_type(root_value) != JSONObject) {
			fprintf(stderr, "Failed to parse JSON file: %s\n", argv[2]);
			if (root_value)
				json_value_free(root_value);
			return 1;
		}
		root = json_value_get_object(root_value);
		memset(error, 0, sizeof(error));
		ret = vpnhide_resolve_targets(root, self_uid, &targets, &lsposed,
						      &summary, error, sizeof(error));
		if (ret) {
			fprintf(stderr, "Policy rejected (%s): %s\n",
				vpnhide_list_mode_name(summary.mode),
				error[0] ? error : "unknown error");
			json_value_free(root_value);
			vpnhide_uid_vector_free(&targets);
			vpnhide_uid_vector_free(&lsposed);
			return 1;
		}
		ret = vpnhide_resolve_port_rules(root, self_uid, &ports, &summary,
						 error, sizeof(error));
		if (ret) {
			fprintf(stderr, "Port policy rejected: %s\n",
				error[0] ? error : "unknown error");
			json_value_free(root_value);
			vpnhide_uid_vector_free(&targets);
			vpnhide_uid_vector_free(&lsposed);
			vpnhide_port_policy_free(&ports);
			return 1;
		}
		printf("mode=%s\n", vpnhide_list_mode_name(summary.mode));
		printf("discovered_packages=%d\n", summary.discovered_packages);
		printf("protected_packages=%d\n", summary.protected_packages);
		printf("selected_exceptions=%d\n", summary.selected_exceptions);
		printf("ignored_selected_system_packages=%d\n",
		       summary.ignored_selected_system_packages);
		printf("kmod_targets=%d\n", summary.kmod_targets);
		printf("lsposed_targets=%d\n", summary.lsposed_targets);
		printf("port_targets=%d\n", summary.port_targets);
		if (strcmp(argv[1], "preview") == 0) {
			for (size_t i = 0; i < ports.count; i++) {
				printf("port_target[%zu].uid=%u\n", i,
				       (unsigned int)ports.targets[i].uid);
				printf("port_target[%zu].mode=%u\n", i,
				       (unsigned int)ports.targets[i].mode);
				for (size_t j = 0; j < ports.targets[i].rule_count; j++) {
					const struct vpnhide_port_rule *rule =
						&ports.targets[i].rules[j];
					printf("port_target[%zu].rule[%zu]=%u-%u/%u\n",
					       i, j, (unsigned int)rule->start_port,
					       (unsigned int)rule->end_port,
					       (unsigned int)rule->protocol);
				}
			}
		}
		json_value_free(root_value);
		vpnhide_uid_vector_free(&targets);
		vpnhide_uid_vector_free(&lsposed);
		vpnhide_port_policy_free(&ports);
		return 0;
	}

	fd = open("/dev/vpnhide_ctrl", O_RDWR);
	if (fd < 0) {
		perror("open /dev/vpnhide_ctrl");
		return 1;
	}

	if (strcmp(argv[1], "load") == 0) {
		if (argc < 3) {
			fprintf(stderr, "Error: load requires <json_path> [self_uid]\n");
			close(fd);
			return 1;
		}
		const char *json_path = argv[2];
		uid_t self_uid = 0;
		int apply_failed = 0;
		unsigned int kernel_mask = 0;
		unsigned int java_mask = 0;
		int debug_logging = 0;
		int have_global_config = 0;
		int allowlist_mode = 0;
		if (argc > 3) {
			self_uid = (uid_t)atoi(argv[3]);
		}

		JSON_Value *root_value = json_parse_file(json_path);
		if (!root_value || json_value_get_type(root_value) != JSONObject) {
			fprintf(stderr, "Failed to parse JSON file: %s\n", json_path);
			if (root_value)
				json_value_free(root_value);
			close(fd);
			return 1;
		}

		JSON_Object *root = json_value_get_object(root_value);

		// 1. Hook masks & debug level
		JSON_Object *global_config = json_object_get_object(root, "globalConfig");
		if (global_config) {
			kernel_mask = (unsigned int)json_object_get_number(global_config, "kernelHookMask");
			java_mask = (unsigned int)json_object_get_number(global_config, "javaHookMask");
			debug_logging = (int)json_object_get_number(global_config, "debugLogging");
			{
				const char *list_mode = json_object_get_string(global_config, "listMode");
				allowlist_mode = list_mode &&
					(!strcmp(list_mode, "ALLOWLIST") ||
					 !strcmp(list_mode, "allowlist"));
			}
			have_global_config = 1;
		}
		kernel_mask |= VPNHIDE_PORT_HOOK_MASK;

		// 2. Resolve declarative targets into effective UID snapshots.
		JSON_Array *apps = json_object_get_array(root, "apps");
		struct vpnhide_uid_vector targets = {0};
		struct vpnhide_uid_vector lsposed = {0};
		struct vpnhide_port_policy port_policy = {0};
		struct app_hook_mask_vector app_hook_masks = {0};
		struct vpnhide_iface_ioctl_data idata;
		void *payload = NULL;
		uint32_t payload_size = 0;
		struct vpnhide_policy_ioctl policy_request;
		struct vpnhide_policy_summary policy_summary;
		char policy_error[256];
		int policy_ret;
		memset(&idata, 0, sizeof(idata));
		memset(policy_error, 0, sizeof(policy_error));

		if (apps) {
			size_t apps_count = json_array_get_count(apps);
			for (size_t i = 0; i < apps_count; i++) {
				JSON_Object *app = json_array_get_object(apps, i);
				if (!app)
					continue;

				uid_t uid = (uid_t)json_object_get_number(app, "uid");
				if (uid != 0) {
					int has_kernel = json_object_has_value(app, "kernelHookMask");
					int has_java = json_object_has_value(app, "javaHookMask");

					if (has_kernel || has_java) {
						struct vpnhide_app_hook_mask_v3 mask;
						struct vpnhide_app_hook_mask_v3 *m = &mask;
						memset(&mask, 0, sizeof(mask));
						unsigned int raw_kernel_mask = has_kernel ?
							(unsigned int)json_object_get_number(app, "kernelHookMask") : 0;
						unsigned int raw_java_mask = has_java ?
							(unsigned int)json_object_get_number(app, "javaHookMask") : 0;
						m->uid = uid;
						m->has_kernel_override = has_kernel ? 1 : 0;
						/* In allowlist an enabled per-app hook bit is an
						 * exception, not an active hook. Store the effective
						 * active mask expected by the kernel. */
						m->kernel_mask = (allowlist_mode ?
							(have_global_config ? kernel_mask : 0xFFFFFFFFu) &
							~raw_kernel_mask : raw_kernel_mask) |
							VPNHIDE_PORT_HOOK_MASK;
						m->has_java_override = has_java ? 1 : 0;
						m->java_mask = allowlist_mode ?
							(have_global_config ? java_mask : 0xFFFFFFFFu) &
							~raw_java_mask : raw_java_mask;
						if (append_app_hook_mask(&app_hook_masks, &mask)) {
							fprintf(stderr, "Out of memory while building app hook masks\n");
							free(app_hook_masks.items);
							json_value_free(root_value);
							close(fd);
							return 1;
						}
					}
				}
			}
		}

		policy_ret = vpnhide_resolve_targets(root, self_uid, &targets,
							     &lsposed, &policy_summary,
							     policy_error, sizeof(policy_error));
		if (policy_ret) {
			fprintf(stderr, "Policy rejected (%s): %s\n",
				vpnhide_list_mode_name(policy_summary.mode),
				policy_error[0] ? policy_error : "unknown error");
			json_value_free(root_value);
			close(fd);
			return 1;
		}
		policy_ret = vpnhide_resolve_port_rules(root, self_uid, &port_policy,
								&policy_summary, policy_error,
								sizeof(policy_error));
		if (policy_ret) {
			fprintf(stderr, "Port policy rejected: %s\n",
				policy_error[0] ? policy_error : "unknown error");
			json_value_free(root_value);
			close(fd);
			return 1;
		}

		fprintf(stderr, "Applying %s policy: kmod=%d lsposed=%d protected=%d\n",
			vpnhide_list_mode_name(policy_summary.mode),
			policy_summary.kmod_targets, policy_summary.lsposed_targets,
			policy_summary.protected_packages);

		sort_uids(targets.items, targets.count);
		sort_uids(lsposed.items, lsposed.count);

		// 3. Interface prefixes
		JSON_Array *prefixes = json_object_get_array(root, "ifacePrefixes");
		if (prefixes) {
			size_t prefixes_count = json_array_get_count(prefixes);
			idata.count = prefixes_count < MAX_IFACE_PREFIXES ? prefixes_count : MAX_IFACE_PREFIXES;
			for (int i = 0; i < idata.count; i++) {
				const char *prefix_str = json_array_get_string(prefixes, i);
				if (prefix_str) {
					strncpy(idata.prefixes[i], prefix_str, MAX_IFACE_LEN - 1);
					idata.prefixes[i][MAX_IFACE_LEN - 1] = '\0';
				}
			}
		}
		if (pack_policy_v3(&targets, &lsposed, &port_policy,
				   &app_hook_masks, &idata,
				   have_global_config ? kernel_mask : 0xFFFFFFFFu,
				   have_global_config ? java_mask : 0xFFFFFFFFu,
				   have_global_config ? !!debug_logging : 0,
				   &payload, &payload_size)) {
			fprintf(stderr, "Cannot serialize variable-length policy\n");
			free(app_hook_masks.items);
			vpnhide_uid_vector_free(&targets);
			vpnhide_uid_vector_free(&lsposed);
			vpnhide_port_policy_free(&port_policy);
			json_value_free(root_value);
			close(fd);
			return 1;
		}

		memset(&policy_request, 0, sizeof(policy_request));
		policy_request.abi_version = VPNHIDE_POLICY_ABI_VERSION_V3;
		policy_request.payload_size = payload_size;
		policy_request.payload_ptr = (uintptr_t)payload;
		if (ioctl(fd, VH_SET_POLICY, &policy_request) < 0) {
			perror("VH_SET_POLICY");
			apply_failed = 1;
		}
		free(payload);
		free(app_hook_masks.items);
		vpnhide_uid_vector_free(&targets);
		vpnhide_uid_vector_free(&lsposed);
		vpnhide_port_policy_free(&port_policy);

		json_value_free(root_value);
		close(fd);
		if (apply_failed) {
			fprintf(stderr, "Configuration apply failed; previous policy was retained only if the kernel rejected before commit.\n");
			return 1;
		}
		return 0;
	} else if (strcmp(argv[1], "set_spoof_ip") == 0) {
		struct vpnhide_spoof_ip spoof;
		memset(&spoof, 0, sizeof(spoof));

		if (argc < 4) {
			fprintf(stderr,
				"Error: set_spoof_ip requires <ipv4|none> <ipv6|none>\n");
			print_usage(argv[0]);
			close(fd);
			return 1;
		}

		if (strcmp(argv[2], "none") != 0) {
			if (inet_pton(AF_INET, argv[2], &spoof.ipv4_addr) !=
			    1) {
				fprintf(stderr, "Invalid IPv4 address: %s\n",
					argv[2]);
				close(fd);
				return 1;
			}
			spoof.has_ipv4 = 1;
		}

		if (strcmp(argv[3], "none") != 0) {
			if (inet_pton(AF_INET6, argv[3], spoof.ipv6_addr) !=
			    1) {
				fprintf(stderr, "Invalid IPv6 address: %s\n",
					argv[3]);
				close(fd);
				return 1;
			}
			spoof.has_ipv6 = 1;
		}

		if (ioctl(fd, VH_SET_SPOOF_IP, &spoof) < 0) {
			perror("VH_SET_SPOOF_IP");
			close(fd);
			return 1;
		}
	} else if (strcmp(argv[1], "active_hooks") == 0) {
		if (argc < 3) {
			unsigned int mask = 0;
			if (ioctl(fd, VH_GET_ACTIVE_HOOKS, &mask) < 0) {
				perror("VH_GET_ACTIVE_HOOKS");
				close(fd);
				return 1;
			}
			printf("%u\n", mask);
		} else {
			fprintf(stderr, "active_hooks is read-only; use load with globalConfig.kernelHookMask\n");
			close(fd);
			return 1;
		}
	} else if (strcmp(argv[1], "java_hooks") == 0) {
		if (argc < 3) {
			unsigned int mask = 0;
			if (ioctl(fd, VH_GET_JAVA_HOOK_MASK, &mask) < 0) {
				perror("VH_GET_JAVA_HOOK_MASK");
				close(fd);
				return 1;
			}
			printf("%u\n", mask);
		} else {
			fprintf(stderr, "java_hooks is read-only; use load with globalConfig.javaHookMask\n");
			close(fd);
			return 1;
		}
	} else if (strcmp(argv[1], "hook_status") == 0) {
		char buf[256];
		memset(buf, 0, sizeof(buf));
		if (ioctl(fd, VH_GET_HOOK_STATUS, buf) < 0) {
			perror("VH_GET_HOOK_STATUS");
			close(fd);
			return 1;
		}
		for (int i = 0; buf[i] != '\0'; i++) {
			if (buf[i] == ';')
				putchar('\n');
			else
				putchar(buf[i]);
		}
		putchar('\n');
	} else if (strcmp(argv[1], "java_stats") == 0) {
		if (argc > 2 && strcmp(argv[2], "clear") == 0) {
			if (write(fd, "clear_stats", 11) < 0) {
				perror("write clear_stats");
				close(fd);
				return 1;
			}
		} else {
			char buf[4096];
			memset(buf, 0, sizeof(buf));
			if (ioctl(fd, VH_GET_JAVA_STATS, buf) < 0) {
				perror("VH_GET_JAVA_STATS");
				close(fd);
				return 1;
			}
			printf("%s", buf);
		}
	} else if (strcmp(argv[1], "stats") == 0) {
		if (argc > 2 && strcmp(argv[2], "clear") == 0) {
			if (ioctl(fd, VH_CLEAR_STATS) < 0) {
				perror("VH_CLEAR_STATS");
				close(fd);
				return 1;
			}
		} else {
			struct vpnhide_stats_snapshot request;
			struct vpnhide_uid_stats *stats = NULL;
			uint32_t capacity = 0;

			for (;;) {
				memset(&request, 0, sizeof(request));
				request.capacity = capacity;
				request.entries_ptr = (uint64_t)(uintptr_t)stats;
				if (ioctl(fd, VH_GET_STATS, &request) == 0)
					break;
				if (errno != ENOSPC || request.count <= capacity) {
					perror("VH_GET_STATS");
					free(stats);
					close(fd);
					return 1;
				}
				capacity = request.count;
				free(stats);
				stats = calloc(capacity, sizeof(*stats));
				if (!stats) {
					perror("calloc stats");
					close(fd);
					return 1;
				}
			}
			for (uint32_t i = 0; i < request.count; i++) {
				printf("%u;%llu;%llu;%llu;%llu;%llu;%llu;%llu\n",
				       stats[i].uid,
				       (unsigned long long)stats[i].ioctl_count,
				       (unsigned long long)stats[i].netlink_count,
				       (unsigned long long)stats[i].proc_count,
				       (unsigned long long)stats[i].sockopt_count,
				       (unsigned long long)stats[i].connect_count,
				       (unsigned long long)stats[i].getname_count,
				       (unsigned long long)stats[i].port_count);
			}
			free(stats);
		}
	} else {
		print_usage(argv[0]);
		close(fd);
		return 1;
	}

	close(fd);
	return 0;
}
