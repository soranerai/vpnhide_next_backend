#ifndef VPNHIDE_DAEMON_H
#define VPNHIDE_DAEMON_H

#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <limits.h>
#include <linux/inet_diag.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/sock_diag.h>
#include <linux/types.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/inotify.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "../kmod/generated/iface_lists.h"
#include "../kmod/include/vpnhide.h"
#include "interface.h"

#define IFACE_RESCAN_INTERVAL_MS 10000ULL
#define STATS_RESOLUTION_SEC 60
#define STATS_RETENTION_SEC (6 * 60 * 60)
#define STATS_RING_POINTS (STATS_RETENTION_SEC / STATS_RESOLUTION_SEC)
#define STATS_SOCKET_NAME "vpnhide.stats.v1"

struct daemon_stats_point {
  unsigned long long timestamp_ms;
  bool gap;
  uint32_t count;
  struct vpnhide_uid_stats *entries;
  uint32_t port_count;
  struct vpnhide_port_stats *ports;
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
  struct vpnhide_port_stats *previous_ports;
  uint32_t previous_port_capacity;
  uint32_t previous_port_count;
  uint64_t dropped_port_entries;
  bool baseline_valid;
};

unsigned long long daemon_get_time_ms(void);
unsigned long long daemon_get_wall_time_ms(void);
void file_hiding_set_config_path(const char *config_path);
void file_hiding_sync_interfaces(const struct vpnhide_vpn_ifindexes *vpns);
bool update_spoof_ip(int fd, char *last_ipv4, char *last_ipv6,
                     char *last_ipv6_linklocal, unsigned int *last_ipv4_mtu,
                     unsigned int *last_ipv6_mtu);
void clear_stats_ring(struct daemon_stats_ring *ring);
void initialize_session_id(int fd, struct daemon_stats_ring *ring);
void sample_stats(int fd, struct daemon_stats_ring *ring);
int open_stats_socket(uid_t allowed_uid);
void serve_stats_client(int listen_fd, uid_t allowed_uid,
                        struct daemon_stats_ring *ring);
void drain_config_events(int inotify_fd, const char *config, const char *ctl);
int refresh_owned_ports(int control_fd);
int open_diag_events(void);

#endif /* VPNHIDE_DAEMON_H */
