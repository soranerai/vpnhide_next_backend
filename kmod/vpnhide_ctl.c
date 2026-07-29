#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/types.h>

#include "include/vpnhide.h"
#include "parson.h"
#include "vpnhide_policy.h"

void print_usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s <load|validate|preview|targets|port_targets|lsposed_targets|port_rules|iface_prefixes|set_spoof_ip|debug|active_hooks|java_hooks|app_hooks|stats|stats_window|version> [args...]\n",
		prog);
	fprintf(stderr, "  load format: <json_path> [self_uid]\n");
	fprintf(stderr, "  validate/preview format: <json_path> [self_uid]\n");
	fprintf(stderr,
		"  stats_window format: <seconds_per_bucket> (window = 30 * seconds)\n");
	fprintf(stderr,
		"  port_rules format: <uid> <rule_count> <start> <end> <proto> ...\n");
	fprintf(stderr,
		"  app_hooks format: <uid> <has_kernel:0|1> <kernel_mask> <has_java:0|1> <java_mask> ...\n");
	fprintf(stderr, "  proto: 0=TCP, 1=UDP, 2=BOTH\n");
	fprintf(stderr, "  set_spoof_ip format: <ipv4|none> <ipv6|none>\n");
	fprintf(stderr, "  version format: [ctl|kmod] (default: print both ctl and running kmod version)\n");
}

static int add_uid_distinct(uid_t *arr, int *count, uid_t uid)
{
	if (uid == 0)
		return 0;
	for (int i = 0; i < *count; i++) {
		if (arr[i] == uid)
			return 0;
	}
	if (*count < MAX_TARGET_UIDS) {
		arr[(*count)++] = uid;
		return 1;
	}
	return 0;
}

static void sort_uids(uid_t *arr, int count)
{
	for (int i = 0; i < count - 1; i++) {
		for (int j = 0; j < count - i - 1; j++) {
			if (arr[j] > arr[j + 1]) {
				uid_t temp = arr[j];
				arr[j] = arr[j + 1];
				arr[j + 1] = temp;
			}
		}
	}
}

int main(int argc, char **argv)
{
	int fd, val;
	struct vpnhide_ioctl_data data;
	struct vpnhide_port_ioctl_data pdata;

	memset(&data, 0, sizeof(data));
	memset(&pdata, 0, sizeof(pdata));

	if (argc < 2) {
		print_usage(argv[0]);
		return 1;
	}

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
		struct vpnhide_ioctl_data targets, lsposed;
		struct vpnhide_port_ioctl_data ports;
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
		memset(&targets, 0, sizeof(targets));
		memset(&lsposed, 0, sizeof(lsposed));
		memset(&ports, 0, sizeof(ports));
		memset(error, 0, sizeof(error));
		ret = vpnhide_resolve_targets(root, self_uid, &targets, &lsposed,
						      &summary, error, sizeof(error));
		if (ret) {
			fprintf(stderr, "Policy rejected (%s): %s\n",
				vpnhide_list_mode_name(summary.mode),
				error[0] ? error : "unknown error");
			json_value_free(root_value);
			return 1;
		}
		ret = vpnhide_resolve_port_rules(root, self_uid, &ports, &summary,
						 error, sizeof(error));
		if (ret) {
			fprintf(stderr, "Port policy rejected: %s\n",
				error[0] ? error : "unknown error");
			json_value_free(root_value);
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
		json_value_free(root_value);
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
			have_global_config = 1;
		}

		// 2. Resolve declarative targets into effective UID snapshots.
		JSON_Array *apps = json_object_get_array(root, "apps");
		struct vpnhide_ioctl_data targets;
		struct vpnhide_ioctl_data lsposed;
		struct vpnhide_target_bundle target_bundle;
		struct vpnhide_port_ioctl_data pdata;
		struct vpnhide_app_hook_ioctl_data app_hook_masks;
		struct vpnhide_iface_ioctl_data idata;
		struct vpnhide_policy_payload *payload;
		struct vpnhide_policy_ioctl policy_request;
		struct vpnhide_policy_summary policy_summary;
		char policy_error[256];
		int policy_ret;
		memset(&targets, 0, sizeof(targets));
		memset(&lsposed, 0, sizeof(lsposed));
		memset(&target_bundle, 0, sizeof(target_bundle));
		memset(&pdata, 0, sizeof(pdata));
		memset(&app_hook_masks, 0, sizeof(app_hook_masks));
		memset(&idata, 0, sizeof(idata));
		memset(policy_error, 0, sizeof(policy_error));

		if (apps) {
			size_t apps_count = json_array_get_count(apps);
			for (size_t i = 0; i < apps_count; i++) {
				JSON_Object *app = json_array_get_object(apps, i);
				if (!app)
					continue;

				uid_t uid = (uid_t)json_object_get_number(app, "uid");
				int kmod = json_object_get_boolean(app, "kmod");
				int lsp = json_object_get_boolean(app, "lsposed");

				if (kmod && uid != 0) {
					add_uid_distinct(targets.uids, &targets.count, uid);
				}
				if (lsp && uid != 0) {
					add_uid_distinct(lsposed.uids, &lsposed.count, uid);
				}

				if (uid != 0 &&
				    app_hook_masks.count < MAX_TARGET_UIDS) {
					int has_kernel = json_object_has_value(app, "kernelHookMask");
					int has_java = json_object_has_value(app, "javaHookMask");

					if (has_kernel || has_java) {
						struct vpnhide_app_hook_mask *m =
							&app_hook_masks.masks[app_hook_masks.count];
						m->uid = uid;
						m->has_kernel_override = has_kernel ? 1 : 0;
						m->kernel_mask = has_kernel ?
							(unsigned int)json_object_get_number(app, "kernelHookMask") : 0;
						m->has_java_override = has_java ? 1 : 0;
						m->java_mask = has_java ?
							(unsigned int)json_object_get_number(app, "javaHookMask") : 0;
						app_hook_masks.count++;
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
		policy_ret = vpnhide_resolve_port_rules(root, self_uid, &pdata,
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

		sort_uids(targets.uids, targets.count);
		sort_uids(lsposed.uids, lsposed.count);
		target_bundle.kmod_count = targets.count;
		target_bundle.lsposed_count = lsposed.count;
		memcpy(target_bundle.kmod_uids, targets.uids,
		       targets.count * sizeof(targets.uids[0]));
		memcpy(target_bundle.lsposed_uids, lsposed.uids,
		       lsposed.count * sizeof(lsposed.uids[0]));

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
		payload = calloc(1, sizeof(*payload));
		if (!payload) {
			perror("calloc policy payload");
			json_value_free(root_value);
			close(fd);
			return 1;
		}
		payload->targets = target_bundle;
		payload->ports = pdata;
		payload->iface_prefixes = idata;
		payload->app_hook_masks = app_hook_masks;
		payload->active_hooks_mask = have_global_config ? kernel_mask : 0xFFFFFFFFu;
		payload->java_hooks_mask = have_global_config ? java_mask : 0xFFFFFFFFu;
		payload->debug_enabled = have_global_config ? !!debug_logging : 0;

		memset(&policy_request, 0, sizeof(policy_request));
		policy_request.abi_version = VPNHIDE_POLICY_ABI_VERSION;
		policy_request.payload_size = sizeof(*payload);
		policy_request.payload_ptr = (uintptr_t)payload;
		if (ioctl(fd, VH_SET_POLICY, &policy_request) < 0) {
			perror("VH_SET_POLICY");
			apply_failed = 1;
		}
		free(payload);

		json_value_free(root_value);
		close(fd);
		if (apply_failed) {
			fprintf(stderr, "Configuration apply failed; previous policy was retained only if the kernel rejected before commit.\n");
			return 1;
		}
		return 0;
	} else if (strcmp(argv[1], "targets") == 0 ||
	    strcmp(argv[1], "port_targets") == 0 ||
	    strcmp(argv[1], "lsposed_targets") == 0) {
		data.count = argc - 2;
		if (data.count > MAX_TARGET_UIDS)
			data.count = MAX_TARGET_UIDS;

		for (int i = 0; i < data.count; i++) {
			data.uids[i] = (unsigned int)atoi(argv[i + 2]);
		}

		unsigned long cmd;
		if (strcmp(argv[1], "targets") == 0)
			cmd = VH_SET_TARGETS;
		else if (strcmp(argv[1], "port_targets") == 0)
			cmd = VH_SET_PORT_TARGETS;
		else
			cmd = VH_SET_LSPOSED_TARGETS;

		if (ioctl(fd, cmd, &data) < 0) {
			perror("ioctl");
			close(fd);
			return 1;
		}
	} else if (strcmp(argv[1], "port_rules") == 0) {
		int arg_idx = 2;
		pdata.count = 0;

		while (arg_idx < argc && pdata.count < MAX_TARGET_UIDS) {
			struct vpnhide_uid_port_rules *target =
				&pdata.targets[pdata.count];
			if (arg_idx >= argc)
				break;
			target->uid = (uid_t)atoi(argv[arg_idx++]);
			if (arg_idx >= argc)
				break;
			int rules_to_parse = atoi(argv[arg_idx++]);

			if (rules_to_parse > MAX_PORT_RULES_PER_UID)
				rules_to_parse = MAX_PORT_RULES_PER_UID;

			target->rule_count = 0;
			for (int i = 0; i < rules_to_parse; i++) {
				if (arg_idx + 2 >= argc)
					break;
				target->rules[i].start_port =
					(unsigned short)atoi(argv[arg_idx++]);
				target->rules[i].end_port =
					(unsigned short)atoi(argv[arg_idx++]);
				target->rules[i].protocol =
					(unsigned char)atoi(argv[arg_idx++]);
				target->rule_count++;
			}
			pdata.count++;
		}

		if (ioctl(fd, VH_SET_PORT_RULES, &pdata) < 0) {
			perror("VH_SET_PORT_RULES");
			close(fd);
			return 1;
		}
	} else if (strcmp(argv[1], "iface_prefixes") == 0) {
		struct vpnhide_iface_ioctl_data idata;
		memset(&idata, 0, sizeof(idata));
		idata.count = argc - 2;
		if (idata.count > MAX_IFACE_PREFIXES)
			idata.count = MAX_IFACE_PREFIXES;

		for (int i = 0; i < idata.count; i++) {
			strncpy(idata.prefixes[i], argv[i + 2],
				MAX_IFACE_LEN - 1);
			idata.prefixes[i][MAX_IFACE_LEN - 1] = '\0';
		}

		if (ioctl(fd, VH_SET_IFACE_PREFIXES, &idata) < 0) {
			perror("VH_SET_IFACE_PREFIXES");
			close(fd);
			return 1;
		}
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
	} else if (strcmp(argv[1], "debug") == 0) {
		if (argc < 3) {
			print_usage(argv[0]);
			close(fd);
			return 1;
		}
		val = atoi(argv[2]);
		if (ioctl(fd, VH_SET_DEBUG, &val) < 0) {
			perror("VH_SET_DEBUG");
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
			unsigned int mask =
				(unsigned int)strtoul(argv[2], NULL, 0);
			if (ioctl(fd, VH_SET_ACTIVE_HOOKS, &mask) < 0) {
				perror("VH_SET_ACTIVE_HOOKS");
				close(fd);
				return 1;
			}
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
			unsigned int mask =
				(unsigned int)strtoul(argv[2], NULL, 0);
			if (ioctl(fd, VH_SET_JAVA_HOOK_MASK, &mask) < 0) {
				perror("VH_SET_JAVA_HOOK_MASK");
				close(fd);
				return 1;
			}
		}
	} else if (strcmp(argv[1], "app_hooks") == 0) {
		struct vpnhide_app_hook_ioctl_data adata;
		int arg_idx = 2;

		memset(&adata, 0, sizeof(adata));

		while (arg_idx + 4 < argc && adata.count < MAX_TARGET_UIDS) {
			struct vpnhide_app_hook_mask *m = &adata.masks[adata.count];

			m->uid = (uid_t)atoi(argv[arg_idx++]);
			m->has_kernel_override = (unsigned char)atoi(argv[arg_idx++]);
			m->kernel_mask = (unsigned int)strtoul(argv[arg_idx++], NULL, 0);
			m->has_java_override = (unsigned char)atoi(argv[arg_idx++]);
			m->java_mask = (unsigned int)strtoul(argv[arg_idx++], NULL, 0);
			adata.count++;
		}

		if (ioctl(fd, VH_SET_APP_HOOK_MASKS, &adata) < 0) {
			perror("VH_SET_APP_HOOK_MASKS");
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
			struct vpnhide_kmod_stats_data sdata;
			memset(&sdata, 0, sizeof(sdata));
			if (ioctl(fd, VH_GET_STATS, &sdata) < 0) {
				perror("VH_GET_STATS");
				close(fd);
				return 1;
			}
			for (int i = 0; i < sdata.count; i++) {
				printf("%u;%u;%u;%u;%u;%u;%u;%u\n", sdata.stats[i].uid,
				       sdata.stats[i].ioctl_count,
				       sdata.stats[i].netlink_count,
				       sdata.stats[i].proc_count,
				       sdata.stats[i].sockopt_count,
				       sdata.stats[i].connect_count,
				       sdata.stats[i].getname_count,
				       sdata.stats[i].port_count);
			}
		}
	} else if (strcmp(argv[1], "stats_window") == 0) {
		if (argc < 3) {
			print_usage(argv[0]);
			close(fd);
			return 1;
		}
		unsigned int secs = (unsigned int)strtoul(argv[2], NULL, 0);
		if (ioctl(fd, VH_SET_STATS_WINDOW, &secs) < 0) {
			perror("VH_SET_STATS_WINDOW");
			close(fd);
			return 1;
		}
	} else {
		print_usage(argv[0]);
		close(fd);
		return 1;
	}

	close(fd);
	return 0;
}
