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
#include <sys/un.h>
#include <sys/types.h>

#include "include/vpnhide.h"
#include "generated/iface_lists.h"
#include "daemon_iface.h"

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

static int test_interface_egress(const char *ifname, int af, char *out_ip,
				 size_t max_len, unsigned int *out_mtu)
{
	int sock = socket(af, SOCK_DGRAM, 0);
	int mtu = 0;
	socklen_t mtu_len = sizeof(mtu);
	int mtu_level = af == AF_INET ? IPPROTO_IP : IPPROTO_IPV6;
	int mtu_opt = af == AF_INET ? IP_MTU : IPV6_MTU;

	if (out_mtu)
		*out_mtu = 0;
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
			if (out_mtu && getsockopt(sock, mtu_level, mtu_opt, &mtu,
						   &mtu_len) == 0 && mtu > 0)
				*out_mtu = (unsigned int)mtu;
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
			if (out_mtu && getsockopt(sock, mtu_level, mtu_opt, &mtu,
						   &mtu_len) == 0 && mtu > 0)
				*out_mtu = (unsigned int)mtu;
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

static void update_spoof_ip(int fd, char *last_ipv4, char *last_ipv6,
			    char *last_ipv6_linklocal,
			    unsigned int *last_ipv4_mtu,
			    unsigned int *last_ipv6_mtu)
{
	struct ifaddrs *ifaddr = NULL;
	struct ifaddrs *ifa = NULL;
	char best_ifname[IFNAMSIZ];
	int best_score = -1;
	char new_ipv4[64];
	char new_ipv6[64];
	char new_ipv6_linklocal[64];
	unsigned int new_ipv4_mtu = 0;
	unsigned int new_ipv6_mtu = 0;
	struct vpnhide_iface_ioctl_data prefixes;
	struct vpnhide_vpn_ifindexes active_vpns;

	memset(&prefixes, 0, sizeof(prefixes));
	memset(&active_vpns, 0, sizeof(active_vpns));
	ioctl(fd, VH_GET_IFACE_PREFIXES, &prefixes);

	best_ifname[0] = '\0';
	strcpy(new_ipv4, "none");
	strcpy(new_ipv6, "none");
	strcpy(new_ipv6_linklocal, "none");

	if (getifaddrs(&ifaddr) == -1) {
		return;
	}

	/* Helper structures to aggregate interface info */
	struct iface_info {
		char name[IFNAMSIZ];
		char ipv4[64];
		char ipv6[64];
		char ipv6_linklocal[64];
		unsigned int ipv4_mtu;
		unsigned int ipv6_mtu;
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

		if (!vpnhide_daemon_is_cover_candidate(name))
			continue;

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
			if (test_interface_egress(name, AF_INET, tmp_ipv4,
						  sizeof(tmp_ipv4),
						  &interfaces[idx].ipv4_mtu)) {
				interfaces[idx].has_ipv4 = true;
				strcpy(interfaces[idx].ipv4, tmp_ipv4);
			}

			// Test IPv6 egress route
			char tmp_ipv6[64] = {0};
			if (test_interface_egress(name, AF_INET6, tmp_ipv6,
						  sizeof(tmp_ipv6),
						  &interfaces[idx].ipv6_mtu)) {
				interfaces[idx].has_ipv6 = true;
				strcpy(interfaces[idx].ipv6, tmp_ipv6);
			}
		}
		if (idx >= 0 && ifa->ifa_addr->sa_family == AF_INET6) {
			struct sockaddr_in6 *sin6 =
				(struct sockaddr_in6 *)ifa->ifa_addr;

			if (IN6_IS_ADDR_LINKLOCAL(&sin6->sin6_addr))
				inet_ntop(AF_INET6, &sin6->sin6_addr,
					  interfaces[idx].ipv6_linklocal,
					  sizeof(interfaces[idx].ipv6_linklocal));
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
				new_ipv4_mtu = info->ipv4_mtu;
			} else {
				strcpy(new_ipv4, "none");
			}
			if (info->has_ipv6) {
				strcpy(new_ipv6, info->ipv6);
				new_ipv6_mtu = info->ipv6_mtu;
			} else {
				strcpy(new_ipv6, "none");
			}
			if (info->ipv6_linklocal[0])
				strcpy(new_ipv6_linklocal, info->ipv6_linklocal);
		}
	}

	if (strcmp(new_ipv4, last_ipv4) != 0 ||
	    strcmp(new_ipv6, last_ipv6) != 0 ||
	    strcmp(new_ipv6_linklocal, last_ipv6_linklocal) != 0 ||
	    new_ipv4_mtu != *last_ipv4_mtu ||
	    new_ipv6_mtu != *last_ipv6_mtu) {
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
		if (strcmp(new_ipv6_linklocal, "none") != 0 &&
		    inet_pton(AF_INET6, new_ipv6_linklocal,
			      spoof.ipv6_linklocal_addr) == 1)
			spoof.has_ipv6_linklocal = 1;
		spoof.ipv4_mtu = new_ipv4_mtu;
		spoof.ipv6_mtu = new_ipv6_mtu;

		if (ioctl(fd, VH_SET_SPOOF_IP, &spoof) == 0) {
			strcpy(last_ipv4, new_ipv4);
			strcpy(last_ipv6, new_ipv6);
			strcpy(last_ipv6_linklocal, new_ipv6_linklocal);
			*last_ipv4_mtu = new_ipv4_mtu;
			*last_ipv6_mtu = new_ipv6_mtu;
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

static unsigned long long get_wall_time_ms(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_REALTIME, &ts);
	return (unsigned long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

#define STATS_RESOLUTION_SEC 60
#define STATS_RETENTION_SEC (24 * 60 * 60)
#define STATS_RING_POINTS (STATS_RETENTION_SEC / STATS_RESOLUTION_SEC)
#define STATS_SOCKET_NAME "vpnhide.stats.v1"

struct daemon_stats_point {
	unsigned long long timestamp_ms;
	bool gap;
	uint32_t count;
	struct vpnhide_uid_stats *entries;
};

struct daemon_stats_ring {
	struct daemon_stats_point points[STATS_RING_POINTS];
	unsigned int head;
	unsigned int count;
	unsigned long long dropped_intervals;
	uint64_t latest_sequence;
	uint64_t previous_sequence;
	char session_id[128];
	struct vpnhide_uid_stats *previous;
	uint32_t previous_capacity;
	uint32_t previous_count;
	bool baseline_valid;
};

static void free_stats_point(struct daemon_stats_point *point)
{
	free(point->entries);
	memset(point, 0, sizeof(*point));
}

static void clear_stats_ring(struct daemon_stats_ring *ring)
{
	for (unsigned int i = 0; i < STATS_RING_POINTS; i++)
		free_stats_point(&ring->points[i]);
	ring->head = 0;
	ring->count = 0;
	ring->dropped_intervals = 0;
	ring->latest_sequence = 0;
	ring->previous_sequence = 0;
	ring->previous_count = 0;
	ring->previous_capacity = 0;
	ring->baseline_valid = false;
	free(ring->previous);
	ring->previous = NULL;
}

static void initialize_session_id(int fd, struct daemon_stats_ring *ring)
{
	char boot_id[80] = "unknown";
	uint64_t kernel_session = 0;
	FILE *boot = fopen("/proc/sys/kernel/random/boot_id", "r");
	if (boot) {
		if (fgets(boot_id, sizeof(boot_id), boot))
			boot_id[strcspn(boot_id, "\r\n")] = '\0';
		fclose(boot);
	}
	if (ioctl(fd, VH_GET_STATS_SESSION, &kernel_session) == 0)
		snprintf(ring->session_id, sizeof(ring->session_id), "%s-%016llx",
			boot_id, (unsigned long long)kernel_session);
	else
		snprintf(ring->session_id, sizeof(ring->session_id), "%s", boot_id);
}

static const struct vpnhide_uid_stats *find_uid_stats(
	const struct vpnhide_uid_stats *entries, uint32_t count, uid_t uid)
{
	for (uint32_t i = 0; i < count; i++)
		if (entries[i].uid == uid)
			return &entries[i];
	return NULL;
}

static uint64_t stats_delta(uint64_t current, uint64_t previous)
{
	/* A kernel clear or session change must not turn a reset into an enormous
	 * interval. The caller detects the sequence reset and marks a gap. */
	return current >= previous ? current - previous : current;
}

static int read_kernel_stats(int fd, struct vpnhide_uid_stats **entries,
				     uint32_t *count, uint64_t *sequence)
{
	struct vpnhide_stats_snapshot request;
	struct vpnhide_uid_stats *buffer = NULL;
	uint32_t capacity = 0;
	for (;;) {
		memset(&request, 0, sizeof(request));
		request.capacity = capacity;
		request.entries_ptr = (uint64_t)(uintptr_t)buffer;
		if (ioctl(fd, VH_GET_STATS, &request) == 0) {
			*entries = buffer;
			*count = request.count;
			*sequence = request.sequence;
			return 0;
		}
		if (errno != ENOSPC || request.count <= capacity) {
			free(buffer);
			return -1;
		}
		capacity = request.count;
		free(buffer);
		buffer = calloc(capacity, sizeof(*buffer));
		if (!buffer)
			return -1;
	}
}

static void append_stats_point(struct daemon_stats_ring *ring,
				       const struct vpnhide_uid_stats *current,
				       uint32_t current_count, uint64_t sequence,
				       unsigned long long timestamp_ms)
{
	struct daemon_stats_point point;
	bool gap = !ring->baseline_valid;
	uint32_t delta_count = 0;
	struct vpnhide_uid_stats *grown;

	if (current_count > ring->previous_capacity) {
		grown = realloc(ring->previous, current_count * sizeof(*grown));
		if (!grown)
			return;
		ring->previous = grown;
		ring->previous_capacity = current_count;
	}

	if (ring->baseline_valid && sequence <= ring->previous_sequence)
		gap = true;

	if (!gap) {
		for (uint32_t i = 0; i < current_count; i++) {
			const struct vpnhide_uid_stats *old = find_uid_stats(
				ring->previous, ring->previous_count, current[i].uid);
			if (!old ||
				stats_delta(current[i].ioctl_count, old->ioctl_count) ||
				stats_delta(current[i].netlink_count, old->netlink_count) ||
				stats_delta(current[i].proc_count, old->proc_count) ||
				stats_delta(current[i].sockopt_count, old->sockopt_count) ||
				stats_delta(current[i].connect_count, old->connect_count) ||
				stats_delta(current[i].getname_count, old->getname_count) ||
				stats_delta(current[i].port_count, old->port_count))
				delta_count++;
		}
	}

	memset(&point, 0, sizeof(point));
	point.timestamp_ms = timestamp_ms;
	point.gap = gap;
	if (delta_count) {
		point.entries = calloc(delta_count, sizeof(*point.entries));
		if (!point.entries)
			return;
	}
	if (!gap) {
		for (uint32_t i = 0, out = 0; i < current_count; i++) {
			const struct vpnhide_uid_stats *old = find_uid_stats(
				ring->previous, ring->previous_count, current[i].uid);
			__u64 *dst;
			if (old &&
				(!stats_delta(current[i].ioctl_count, old->ioctl_count) &&
				 !stats_delta(current[i].netlink_count, old->netlink_count) &&
				 !stats_delta(current[i].proc_count, old->proc_count) &&
				 !stats_delta(current[i].sockopt_count, old->sockopt_count) &&
				 !stats_delta(current[i].connect_count, old->connect_count) &&
				 !stats_delta(current[i].getname_count, old->getname_count) &&
				 !stats_delta(current[i].port_count, old->port_count)))
				continue;
			point.entries[out].uid = current[i].uid;
			dst = &point.entries[out].ioctl_count;
			dst[0] = stats_delta(current[i].ioctl_count, old ? old->ioctl_count : 0);
			dst[1] = stats_delta(current[i].netlink_count, old ? old->netlink_count : 0);
			dst[2] = stats_delta(current[i].proc_count, old ? old->proc_count : 0);
			dst[3] = stats_delta(current[i].sockopt_count, old ? old->sockopt_count : 0);
			dst[4] = stats_delta(current[i].connect_count, old ? old->connect_count : 0);
			dst[5] = stats_delta(current[i].getname_count, old ? old->getname_count : 0);
			dst[6] = stats_delta(current[i].port_count, old ? old->port_count : 0);
			out++;
		}
		point.count = delta_count;
	}

	if (ring->count == STATS_RING_POINTS) {
		free_stats_point(&ring->points[ring->head]);
		ring->head = (ring->head + 1) % STATS_RING_POINTS;
		ring->dropped_intervals++;
	} else {
		ring->count++;
	}
	ring->points[(ring->head + ring->count - 1) % STATS_RING_POINTS] = point;
	memcpy(ring->previous, current, current_count * sizeof(*current));
	ring->previous_count = current_count;
	ring->previous_sequence = sequence;
	ring->latest_sequence = sequence;
	ring->baseline_valid = true;
}

static void sample_stats(int fd, struct daemon_stats_ring *ring)
{
	struct vpnhide_uid_stats *current = NULL;
	uint32_t count;
	uint64_t sequence;
	if (read_kernel_stats(fd, &current, &count, &sequence) == 0)
		append_stats_point(ring, current, count, sequence, get_wall_time_ms());
	free(current);
}

static void write_stats_json(FILE *out, const struct daemon_stats_ring *ring)
{
	unsigned long long oldest = 0, newest = 0;
	if (ring->count) {
		oldest = ring->points[ring->head].timestamp_ms;
		newest = ring->points[(ring->head + ring->count - 1) % STATS_RING_POINTS].timestamp_ms;
	}
	fprintf(out, "{\"sessionId\":\"%s\"", ring->session_id[0] ? ring->session_id : "unknown");
	fprintf(out, ",\"sequence\":%llu,\"resolutionSec\":%d,\"retentionSec\":%d,\"dropped\":%s,\"droppedIntervals\":%llu,\"oldestTimestampMs\":%llu,\"newestTimestampMs\":%llu,\"points\":[",
		(unsigned long long)ring->latest_sequence, STATS_RESOLUTION_SEC, STATS_RETENTION_SEC,
		ring->dropped_intervals ? "true" : "false",
		ring->dropped_intervals, oldest, newest);
	for (unsigned int n = 0; n < ring->count; n++) {
		const struct daemon_stats_point *point = &ring->points[(ring->head + n) % STATS_RING_POINTS];
		if (n) fputc(',', out);
		fprintf(out, "{\"timestampMs\":%llu,\"gap\":%s,\"uids\":[",
			point->timestamp_ms, point->gap ? "true" : "false");
		for (uint32_t i = 0; i < point->count; i++) {
			const struct vpnhide_uid_stats *s = &point->entries[i];
			if (i) fputc(',', out);
			fprintf(out, "{\"uid\":%u,\"ioctl\":%llu,\"netlink\":%llu,\"proc\":%llu,\"sockopt\":%llu,\"connect\":%llu,\"getname\":%llu,\"port\":%llu}",
				s->uid, (unsigned long long)s->ioctl_count, (unsigned long long)s->netlink_count,
				(unsigned long long)s->proc_count, (unsigned long long)s->sockopt_count,
				(unsigned long long)s->connect_count, (unsigned long long)s->getname_count,
				(unsigned long long)s->port_count);
		}
		fputs("]}", out);
	}
	fputs("]}\n", out);
}

static int open_stats_socket(uid_t allowed_uid)
{
	struct sockaddr_un address;
	int fd, length;
	memset(&address, 0, sizeof(address));
	address.sun_family = AF_UNIX;
	address.sun_path[0] = '\0';
	strncpy(address.sun_path + 1, STATS_SOCKET_NAME, sizeof(address.sun_path) - 2);
	length = (int)(offsetof(struct sockaddr_un, sun_path) + 1 + strlen(STATS_SOCKET_NAME));
	fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (fd < 0 || bind(fd, (struct sockaddr *)&address, length) < 0 || listen(fd, 4) < 0) {
		if (fd >= 0) close(fd);
		return -1;
	}
	(void)allowed_uid;
	return fd;
}

static void serve_stats_client(int listen_fd, uid_t allowed_uid,
				       struct daemon_stats_ring *ring)
{
	struct ucred peer;
	socklen_t peer_len = sizeof(peer);
	char command[64];
	int client = accept4(listen_fd, NULL, NULL, SOCK_CLOEXEC);
	if (client < 0)
		return;
	if (getsockopt(client, SOL_SOCKET, SO_PEERCRED, &peer, &peer_len) < 0 ||
		(peer.uid != allowed_uid && peer.uid != 0)) {
		close(client);
		return;
	}
	ssize_t length = read(client, command, sizeof(command) - 1);
	if (length > 0) {
		command[length] = '\0';
		FILE *out = fdopen(client, "w");
		if (out) {
			if (!strncmp(command, "CLEAR_HISTORY", 13))
				clear_stats_ring(ring);
			write_stats_json(out, ring);
			fclose(out);
			return;
		}
	}
	close(client);
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
	int fd, nl_fd, config_fd = -1, stats_fd = -1;
	const char *ctl = argc > 1 ? argv[1] : NULL;
	const char *config = argc > 2 ? argv[2] : NULL;
	const char *self_uid = argc > 3 ? argv[3] : NULL;
	uid_t stats_allowed_uid = (uid_t)-1;
	char config_dir[PATH_MAX];
	struct sockaddr_nl sa;
	char last_ipv4[64];
	char last_ipv6[64];
	char last_ipv6_linklocal[64];
	unsigned int last_ipv4_mtu = UINT_MAX;
	unsigned int last_ipv6_mtu = UINT_MAX;

	setbuf(stdout, NULL);
	setbuf(stderr, NULL);

	strcpy(last_ipv4, "none");
	strcpy(last_ipv6, "none");
	strcpy(last_ipv6_linklocal, "none");

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
	if (self_uid && self_uid[0]) {
		char *end = NULL;
		unsigned long parsed = strtoul(self_uid, &end, 10);
		if (end && *end == '\0' && parsed <= UINT_MAX) {
			stats_allowed_uid = (uid_t)parsed;
			stats_fd = open_stats_socket(stats_allowed_uid);
		}
	}
	if (stats_fd < 0 && stats_allowed_uid != (uid_t)-1)
		fprintf(stderr, "vpnhide-daemon: statistics socket unavailable: %s\n",
			strerror(errno));

	// Initial update
	update_spoof_ip(fd, last_ipv4, last_ipv6, last_ipv6_linklocal,
			&last_ipv4_mtu, &last_ipv6_mtu);
	struct daemon_stats_ring stats_ring;
	memset(&stats_ring, 0, sizeof(stats_ring));
	initialize_session_id(fd, &stats_ring);
	sample_stats(fd, &stats_ring);

	unsigned long long next_update_time = 0;
	bool update_pending = false;
	int retry_count = 0;
	unsigned long long pm_reload_due = 0;
	unsigned long long next_pm_poll = get_time_ms();
	unsigned long long next_stats_sample = get_time_ms() + STATS_RESOLUTION_SEC * 1000ULL;
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
		{
			unsigned long long now = get_time_ms();
			int stats_timeout = now >= next_stats_sample ? 0 :
				(int)(next_stats_sample - now);
			if (poll_timeout < 0 || stats_timeout < poll_timeout)
				poll_timeout = stats_timeout;
		}

		struct pollfd pfds[3];
		int nfds = 1;
		memset(pfds, 0, sizeof(pfds));
		pfds[0].fd = nl_fd;
		pfds[0].events = POLLIN;
		if (config_fd >= 0) {
			pfds[nfds].fd = config_fd;
			pfds[nfds].events = POLLIN;
			nfds++;
		}
		if (stats_fd >= 0) {
			pfds[nfds].fd = stats_fd;
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
		if (stats_fd >= 0) {
			int stats_index = config_fd >= 0 ? 2 : 1;
			if (ret > 0 && (pfds[stats_index].revents & POLLIN))
				serve_stats_client(stats_fd, stats_allowed_uid, &stats_ring);
		}
		if (get_time_ms() >= next_stats_sample) {
			do {
				next_stats_sample += STATS_RESOLUTION_SEC * 1000ULL;
			} while (next_stats_sample <= get_time_ms());
			sample_stats(fd, &stats_ring);
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
			update_spoof_ip(fd, last_ipv4, last_ipv6,
					last_ipv6_linklocal,
					&last_ipv4_mtu, &last_ipv6_mtu);

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
	if (stats_fd >= 0)
		close(stats_fd);
	clear_stats_ring(&stats_ring);
	close(fd);
	return 0;
}
