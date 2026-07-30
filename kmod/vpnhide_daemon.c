#define _GNU_SOURCE

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <arpa/inet.h>
#include <linux/types.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <poll.h>
#include <sys/inotify.h>
#include <sys/wait.h>
#include <limits.h>
#include <stdint.h>

#include "include/vpnhide.h"
#include "generated/iface_lists.h"

static bool is_interface_operstate_up(const char *ifname)
{
	char path[256];
	char buf[32];
	int fd;
	ssize_t len;

	snprintf(path, sizeof(path), "/sys/class/net/%s/operstate", ifname);
	fd = open(path, O_RDONLY);
	if (fd < 0)
		return false;

	len = read(fd, buf, sizeof(buf) - 1);
	close(fd);

	if (len <= 0)
		return false;

	buf[len] = '\0';
	while (len > 0 && (buf[len - 1] == '\n' || buf[len - 1] == '\r' ||
			   buf[len - 1] == ' ')) {
		buf[--len] = '\0';
	}

	return strcmp(buf, "up") == 0 || strcmp(buf, "unknown") == 0;
}

#include <time.h>

static int test_interface_egress(const char *ifname, int af, char *out_ip, size_t max_len)
{
	int sock = socket(af, SOCK_DGRAM, 0);
	if (sock < 0)
		return 0;

	if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, ifname, strlen(ifname)) < 0) {
		close(sock);
		return 0;
	}

	if (af == AF_INET) {
		struct sockaddr_in serv;
		memset(&serv, 0, sizeof(serv));
		serv.sin_family = AF_INET;
		serv.sin_addr.s_addr = inet_addr("8.8.8.8");
		serv.sin_port = htons(53);

		if (connect(sock, (const struct sockaddr *)&serv, sizeof(serv)) < 0) {
			close(sock);
			return 0;
		}

		struct sockaddr_in name;
		socklen_t namelen = sizeof(name);
		if (getsockname(sock, (struct sockaddr *)&name, &namelen) == 0) {
			inet_ntop(AF_INET, &name.sin_addr, out_ip, max_len);
			close(sock);
			return 1;
		}
	} else if (af == AF_INET6) {
		struct sockaddr_in6 serv;
		memset(&serv, 0, sizeof(serv));
		serv.sin6_family = AF_INET6;
		if (inet_pton(AF_INET6, "2001:4860:4860::8888", &serv.sin6_addr) != 1) {
			close(sock);
			return 0;
		}
		serv.sin6_port = htons(53);

		if (connect(sock, (const struct sockaddr *)&serv, sizeof(serv)) < 0) {
			close(sock);
			return 0;
		}

		struct sockaddr_in6 name;
		socklen_t namelen = sizeof(name);
		if (getsockname(sock, (struct sockaddr *)&name, &namelen) == 0) {
			if (IN6_IS_ADDR_LINKLOCAL(&(name.sin6_addr))) {
				close(sock);
				return 0;
			}
			inet_ntop(AF_INET6, &name.sin6_addr, out_ip, max_len);
			close(sock);
			return 1;
		}
	}

	close(sock);
	return 0;
}

static bool
daemon_is_vpn_ifname(const char *name,
		     const struct vpnhide_iface_ioctl_data *prefixes)
{
	/* Use auto-generated static patterns */
	if (vpnhide_iface_is_vpn(name))
		return true;

	/* Configured prefixes */
	if (prefixes) {
		for (int i = 0; i < prefixes->count; i++) {
			int len = strlen(prefixes->prefixes[i]);
			if (len > 0 && strncasecmp(name, prefixes->prefixes[i],
						   len) == 0) {
				return true;
			}
		}
	}
	return false;
}

static void update_spoof_ip(int fd, char *last_ipv4, char *last_ipv6)
{
	struct ifaddrs *ifaddr = NULL;
	struct ifaddrs *ifa = NULL;
	char best_ifname[IFNAMSIZ];
	int best_score = -1;
	char new_ipv4[64];
	char new_ipv6[64];
	struct vpnhide_iface_ioctl_data prefixes;
	struct vpnhide_vpn_ifindexes active_vpns;

	memset(&prefixes, 0, sizeof(prefixes));
	memset(&active_vpns, 0, sizeof(active_vpns));
	ioctl(fd, VH_GET_IFACE_PREFIXES, &prefixes);

	best_ifname[0] = '\0';
	strcpy(new_ipv4, "none");
	strcpy(new_ipv6, "none");

	if (getifaddrs(&ifaddr) == -1) {
		return;
	}

	/* Helper structures to aggregate interface info */
	struct iface_info {
		char name[IFNAMSIZ];
		char ipv4[64];
		char ipv6[64];
		bool has_ipv4;
		bool has_ipv6;
		int score;
	} interfaces[32];
	int iface_count = 0;

	for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr == NULL)
			continue;

		if (!(ifa->ifa_flags & IFF_UP))
			continue;

		if (ifa->ifa_flags & IFF_LOOPBACK)
			continue;

		char *name = ifa->ifa_name;
		bool is_vpn = false;

		if (ifa->ifa_flags & IFF_POINTOPOINT) {
			is_vpn = true;
		} else {
			is_vpn = daemon_is_vpn_ifname(name, &prefixes);
		}

		if (is_vpn) {
			unsigned int vpn_idx = if_nametoindex(name);
			if (vpn_idx > 0) {
				bool dup = false;
				for (int i = 0; i < active_vpns.count; i++) {
					if (active_vpns.vpns[i].ifindex ==
					    vpn_idx) {
						dup = true;
						break;
					}
				}
				if (!dup &&
				    active_vpns.count < MAX_ACTIVE_VPNS) {
					active_vpns.vpns[active_vpns.count].ifindex = vpn_idx;
					strncpy(active_vpns.vpns[active_vpns.count].name, name, MAX_IFACE_LEN - 1);
					active_vpns.vpns[active_vpns.count].name[MAX_IFACE_LEN - 1] = '\0';
					active_vpns.count++;
				}
			}
			continue;
		}

		if (!is_interface_operstate_up(name))
			continue;

		/* Find or create interface info slot */
		int idx = -1;
		for (int i = 0; i < iface_count; i++) {
			if (strcmp(interfaces[i].name, name) == 0) {
				idx = i;
				break;
			}
		}
		if (idx == -1 && iface_count < 32) {
			idx = iface_count++;
			memset(&interfaces[idx], 0, sizeof(struct iface_info));
			strncpy(interfaces[idx].name, name, IFNAMSIZ - 1);

			// Test IPv4 egress route
			char tmp_ipv4[64] = {0};
			if (test_interface_egress(name, AF_INET, tmp_ipv4, sizeof(tmp_ipv4))) {
				interfaces[idx].has_ipv4 = true;
				strcpy(interfaces[idx].ipv4, tmp_ipv4);
			}

			// Test IPv6 egress route
			char tmp_ipv6[64] = {0};
			if (test_interface_egress(name, AF_INET6, tmp_ipv6, sizeof(tmp_ipv6))) {
				interfaces[idx].has_ipv6 = true;
				strcpy(interfaces[idx].ipv6, tmp_ipv6);
			}
		}
	}

	freeifaddrs(ifaddr);

	/* Score all aggregated interfaces that have at least one active egress route */
	for (int i = 0; i < iface_count; i++) {
		struct iface_info *info = &interfaces[i];
		if (!info->has_ipv4 && !info->has_ipv6) {
			continue; // No internet access, ignore completely
		}

		info->score = 1000;

		if (strncmp(info->name, "eth", 3) == 0) {
			info->score = 100000;
		} else if (strncmp(info->name, "wlan", 4) == 0 ||
			   strncmp(info->name, "ap", 2) == 0) {
			info->score = 50000;
		} else if (strncmp(info->name, "rmnet", 5) == 0 ||
			   strncmp(info->name, "ccmni", 5) == 0 ||
			   strncmp(info->name, "epdg", 4) == 0 ||
			   strncmp(info->name, "r_net", 5) == 0 ||
			   strncmp(info->name, "pdp", 3) == 0) {
			info->score = 10000;
		}

		/* Add priority for dual-stack or having active IPv4 / IPv6 */
		if (info->has_ipv4)
			info->score += 5000;
		if (info->has_ipv6)
			info->score += 5000;

		if (info->score > best_score) {
			best_score = info->score;
			strncpy(best_ifname, info->name, IFNAMSIZ - 1);
			best_ifname[IFNAMSIZ - 1] = '\0';
			if (info->has_ipv4) {
				strcpy(new_ipv4, info->ipv4);
			} else {
				strcpy(new_ipv4, "none");
			}
			if (info->has_ipv6) {
				strcpy(new_ipv6, info->ipv6);
			} else {
				strcpy(new_ipv6, "none");
			}
		}
	}

	if (strcmp(new_ipv4, last_ipv4) != 0 ||
	    strcmp(new_ipv6, last_ipv6) != 0) {
		struct vpnhide_spoof_ip spoof;
		memset(&spoof, 0, sizeof(spoof));

		if (strcmp(new_ipv4, "none") != 0) {
			if (inet_pton(AF_INET, new_ipv4, &spoof.ipv4_addr) ==
			    1) {
				spoof.has_ipv4 = 1;
			}
		}
		if (strcmp(new_ipv6, "none") != 0) {
			if (inet_pton(AF_INET6, new_ipv6, spoof.ipv6_addr) ==
			    1) {
				spoof.has_ipv6 = 1;
			}
		}

		if (ioctl(fd, VH_SET_SPOOF_IP, &spoof) == 0) {
			strcpy(last_ipv4, new_ipv4);
			strcpy(last_ipv6, new_ipv6);
		}
	}

	/* Always update cover ifindex so the kernel's BPF stats laundering
	 * uses the correct interface even if the spoof IP hasn't changed. */
	if (best_ifname[0] != '\0') {
		struct vpnhide_cover_iface ci;
		ci.ifindex = if_nametoindex(best_ifname);
		if (ci.ifindex > 0) {
			ioctl(fd, VH_SET_COVER_IFACE, &ci);
			char buf[64];
			int len = snprintf(buf, sizeof(buf), "cover_iface:%s\n", best_ifname);
			if (len > 0) {
				if (write(fd, buf, len) < 0) {
					/* The control fd may disappear during module removal. */
				}
			}
		}
	} else {
		if (write(fd, "cover_iface:none\n", 17) < 0) {
			/* The control fd may disappear during module removal. */
		}
	}

	/* Send the list of active VPNs to the kernel module */
	ioctl(fd, VH_SET_VPN_IFINDEXES, &active_vpns);
}

static unsigned long long get_time_ms(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (unsigned long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static void reload_policy(const char *ctl, const char *config, const char *self_uid)
{
	pid_t pid;
	int status;

	if (!ctl || !config || access(config, R_OK) != 0)
		return;
	pid = fork();
	if (pid < 0) {
		fprintf(stderr, "vpnhide-daemon: cannot fork policy reload: %s\n",
			strerror(errno));
		return;
	}
	if (pid == 0) {
		if (self_uid && self_uid[0])
			execl(ctl, ctl, "load", config, self_uid, (char *)NULL);
		else
			execl(ctl, ctl, "load", config, (char *)NULL);
		_exit(127);
	}
	if (waitpid(pid, &status, 0) < 0 || !WIFEXITED(status) || WEXITSTATUS(status) != 0)
		fprintf(stderr, "vpnhide-daemon: policy reload failed\n");
}

static void drain_config_events(int inotify_fd, const char *config,
					const char *ctl, const char *self_uid)
{
	char buffer[4096];
	ssize_t length;
	bool changed = false;
	const char *config_name = strrchr(config, '/');
	config_name = config_name ? config_name + 1 : config;

	while ((length = read(inotify_fd, buffer, sizeof(buffer))) > 0) {
		size_t offset = 0;
		while (offset < (size_t)length) {
			struct inotify_event *event = (struct inotify_event *)(buffer + offset);
			if (event->len > 0 && !strcmp(event->name, config_name) &&
			    (event->mask & (IN_CLOSE_WRITE | IN_MOVED_TO | IN_CREATE | IN_ATTRIB)))
				changed = true;
			offset += sizeof(*event) + event->len;
		}
	}
	if (changed) {
		fprintf(stderr, "vpnhide-daemon: configuration changed, reloading\n");
		reload_policy(ctl, config, self_uid);
	}
}

/* Package Manager reconciliation is deliberately filesystem-free. The
 * daemon polls the same `pm` interface used by vpnhide_ctl and keeps only a
 * fingerprint in memory; it never opens or watches Package Manager state
 * files directly. */
static int package_fingerprint(unsigned long long *out)
{
	FILE *pipe;
	char line[1024];
	unsigned long long hash = 1469598103934665603ULL;
	unsigned int lines = 0;

	pipe = popen("pm list packages -f -U --user all 2>/dev/null", "r");
	if (!pipe)
		return -1;
	while (fgets(line, sizeof(line), pipe)) {
		for (size_t i = 0; line[i] != '\0'; i++) {
			hash ^= (unsigned char)line[i];
			hash *= 1099511628211ULL;
		}
		lines++;
	}
	if (pclose(pipe) != 0 || lines == 0)
		return -1;
	*out = hash;
	return 0;
}

int main(int argc, char **argv)
{
	int fd, nl_fd, config_fd = -1;
	const char *ctl = argc > 1 ? argv[1] : NULL;
	const char *config = argc > 2 ? argv[2] : NULL;
	const char *self_uid = argc > 3 ? argv[3] : NULL;
	char config_dir[PATH_MAX];
	struct sockaddr_nl sa;
	char last_ipv4[64];
	char last_ipv6[64];

	setbuf(stdout, NULL);
	setbuf(stderr, NULL);

	strcpy(last_ipv4, "none");
	strcpy(last_ipv6, "none");

	fd = open("/dev/vpnhide_ctrl", O_RDWR);
	if (fd < 0) {
		fprintf(stderr,
			"vpnhide-daemon: failed to open /dev/vpnhide_ctrl: %d (%s)\n",
			errno, strerror(errno));
		return 1;
	}

	nl_fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (nl_fd < 0) {
		close(fd);
		return 1;
	}

	memset(&sa, 0, sizeof(sa));
	sa.nl_family = AF_NETLINK;
	sa.nl_groups = RTMGRP_LINK | RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR |
		       RTMGRP_IPV4_ROUTE | RTMGRP_IPV6_ROUTE;
	if (bind(nl_fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		close(nl_fd);
		close(fd);
		return 1;
	}

	if (config && ctl) {
		const char *slash = strrchr(config, '/');
		size_t dir_len = slash ? (size_t)(slash - config) : 0;
		if (dir_len > 0 && dir_len < sizeof(config_dir)) {
			memcpy(config_dir, config, dir_len);
			config_dir[dir_len] = '\0';
			config_fd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
			if (config_fd >= 0 && inotify_add_watch(config_fd, config_dir,
					IN_CLOSE_WRITE | IN_MOVED_TO | IN_CREATE | IN_ATTRIB) < 0) {
				close(config_fd);
				config_fd = -1;
			}
			if (config_fd < 0)
				fprintf(stderr, "vpnhide-daemon: config watch unavailable: %s\n",
					strerror(errno));
		}
	}

	// Initial update
	update_spoof_ip(fd, last_ipv4, last_ipv6);

	unsigned long long next_update_time = 0;
	bool update_pending = false;
	int retry_count = 0;
	unsigned long long pm_reload_due = 0;
	unsigned long long next_pm_poll = get_time_ms();
	unsigned long long pm_fingerprint = 0;
	bool pm_fingerprint_valid = false;

	while (1) {
		int poll_timeout = -1;
		if (update_pending) {
			unsigned long long now = get_time_ms();
			if (now >= next_update_time) {
				poll_timeout = 0;
			} else {
				poll_timeout = (int)(next_update_time - now);
			}
		}
		if (pm_reload_due) {
			unsigned long long now = get_time_ms();
			int pm_timeout = now >= pm_reload_due ? 0 :
				(int)(pm_reload_due - now);
			if (poll_timeout < 0 || pm_timeout < poll_timeout)
				poll_timeout = pm_timeout;
		}
		if (config && ctl) {
			unsigned long long now = get_time_ms();
			int pm_timeout = now >= next_pm_poll ? 0 :
				(int)(next_pm_poll - now);
			if (poll_timeout < 0 || pm_timeout < poll_timeout)
				poll_timeout = pm_timeout;
		}

		struct pollfd pfds[2];
		int nfds = 1;
		memset(pfds, 0, sizeof(pfds));
		pfds[0].fd = nl_fd;
		pfds[0].events = POLLIN;
		if (config_fd >= 0) {
			pfds[nfds].fd = config_fd;
			pfds[nfds].events = POLLIN;
			nfds++;
		}

		int ret = poll(pfds, nfds, poll_timeout);
		if (ret < 0) {
			if (errno == EINTR)
				continue;
			sleep(1);
			continue;
		}

		bool trigger_update = false;
		bool netlink_event = false;

		if (ret > 0 && (pfds[0].revents & POLLIN)) {
			char buf[4096];
			// Consume all pending data on netlink socket to clear the POLLIN state
			while (recv(nl_fd, buf, sizeof(buf), MSG_DONTWAIT) > 0)
				;
			usleep(200000); // 200ms debounce
			trigger_update = true;
			netlink_event = true;
		}
		if (config_fd >= 0 && ret > 0 && (pfds[1].revents & POLLIN)) {
			drain_config_events(config_fd, config, ctl, self_uid);
		}
		if (config && ctl && get_time_ms() >= next_pm_poll) {
			unsigned long long current_fingerprint;
			next_pm_poll = get_time_ms() + 30000;
			if (package_fingerprint(&current_fingerprint) == 0) {
				if (pm_fingerprint_valid && current_fingerprint != pm_fingerprint)
					pm_reload_due = get_time_ms() + 500;
				pm_fingerprint = current_fingerprint;
				pm_fingerprint_valid = true;
			}
		}
		if (pm_reload_due && get_time_ms() >= pm_reload_due) {
			pm_reload_due = 0;
			reload_policy(ctl, config, self_uid);
		}

		if (update_pending && get_time_ms() >= next_update_time) {
			trigger_update = true;
			update_pending = false;
		}

		if (trigger_update) {
			update_spoof_ip(fd, last_ipv4, last_ipv6);

			if (netlink_event) {
				// Netlink event occurred, schedule follow-ups
				next_update_time = get_time_ms() + 1000;
				update_pending = true;
				retry_count = 2;
			} else if (retry_count > 0) {
				retry_count--;
				if (retry_count == 1) {
					next_update_time = get_time_ms() + 2000;
					update_pending = true;
				}
			}
		}
	}

	close(nl_fd);
	if (config_fd >= 0)
		close(config_fd);
	close(fd);
	return 0;
}
