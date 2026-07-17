#ifndef _SECURITY_VPNHIDE_H
#define _SECURITY_VPNHIDE_H

#include <linux/types.h>
#include <linux/cred.h>
#include <linux/uidgid.h>
#include <linux/netdevice.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/bpf.h>
#include <linux/fs.h>
#include <linux/tcp.h>
#include <linux/version.h>

#include "vpnhide_uapi.h"

#define MODNAME "vpnhide"
#define BUCKETS_COUNT 30

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 11, 0)
#define vh_fd_file(f) fd_file(f)
#else
#define vh_fd_file(f) ((f).file)
#endif

#ifndef BPF_FS_MAGIC
#define BPF_FS_MAGIC 0xcafe4a4b
#endif

#ifndef IP_MTU_DISCOVER
#define IP_MTU_DISCOVER 10
#endif

#ifndef IP_PMTUDISC_DONT
#define IP_PMTUDISC_DONT 0
#endif

#ifndef IP_PMTUDISC_DO
#define IP_PMTUDISC_DO 2
#endif

#ifndef IPV6_MTU_DISCOVER
#define IPV6_MTU_DISCOVER 23
#endif

#ifndef IPV6_PMTUDISC_DONT
#define IPV6_PMTUDISC_DONT 0
#endif

#ifndef IPV6_PMTUDISC_DO
#define IPV6_PMTUDISC_DO 2
#endif

#ifndef SO_TIMESTAMPING
#define SO_TIMESTAMPING 37
#endif

#ifndef SOF_TIMESTAMPING_TX_HARDWARE
#define SOF_TIMESTAMPING_TX_HARDWARE (1 << 0)
#define SOF_TIMESTAMPING_RX_HARDWARE (1 << 2)
#define SOF_TIMESTAMPING_RAW_HARDWARE (1 << 6)
#endif

/* Debug logging */
extern bool debug_enabled;
extern unsigned int active_hooks_mask;

#define vpnhide_dbg(fmt, ...)                                                  \
  do {                                                                         \
    if (READ_ONCE(debug_enabled))                                              \
      pr_info(MODNAME ": " fmt, ##__VA_ARGS__);                                \
  } while (0)

enum vpnhide_hook_idx {
  HOOK_DEV_IOCTL = 0,
  HOOK_SOCK_IOCTL = 1,
  HOOK_RTNL_FILL = 2,
  HOOK_INET6_FILL = 3,
  HOOK_INET_FILL = 4,
  HOOK_FIB_ROUTE = 5,
  HOOK_IPV6_ROUTE = 6,
  HOOK_FIB_DUMP = 7,
  HOOK_FIB_RULE_FILL = 8,
  HOOK_RT6_FILL = 9,
  HOOK_RT_FILL = 10,
  HOOK_SETSOCKOPT = 11,
  HOOK_GETSOCKOPT = 12,
  HOOK_CONNECT = 13,
  HOOK_GETNAME_INET = 14,
  HOOK_GETNAME_INET6 = 15,
  HOOK_BIND = 16,
  HOOK_BPF = 17,
  HOOK_GETDENTS64 = 18,
  HOOK_FACCESSAT = 19,
  HOOK_FACCESSAT2 = 20,
  HOOK_NEWFSTATAT = 21,
  HOOK_OPENAT = 22,
  HOOK_OPENAT2 = 23,
  HOOK_READLINKAT = 24,
  HOOK_UDP_SENDMSG = 25,
  HOOK_DEV_SEQ = 26,
  HOOK_IF6_SEQ = 27,
  HOOK_INET6_BIND_LL = 28,
  HOOK_UDPV6_SENDMSG = 29,
  HOOK_FIB_TRIE = 30,
  HOOK_TC_FILL_QDISC = 31,
};

struct vpnhide_app_hook_masks {
  int count;
  struct vpnhide_app_hook_mask masks[MAX_TARGET_UIDS];
  struct rcu_head rcu;
};

struct vpnhide_targets {
  int count;
  uid_t uids[MAX_TARGET_UIDS];
  struct rcu_head rcu;
};

struct vpnhide_port_targets {
  int count;
  struct vpnhide_uid_port_rules targets[MAX_TARGET_UIDS];
  struct rcu_head rcu;
};

struct vpnhide_iface_prefixes {
  int count;
  char prefixes[MAX_IFACE_PREFIXES][MAX_IFACE_LEN];
  struct rcu_head rcu;
};

struct vpnhide_spoof_ip_rcu {
  struct vpnhide_spoof_ip sip;
  struct rcu_head rcu;
};

struct vpnhide_active_vpns {
  int count;
  struct vpnhide_active_vpn vpns[MAX_ACTIVE_VPNS];
  struct rcu_head rcu;
};

struct vh_vpn_name_cache {
  int count;
  u32 hashes[MAX_ACTIVE_VPNS];
  char names[MAX_ACTIVE_VPNS][MAX_IFACE_LEN];
  struct rcu_head rcu;
};

struct vh_stats_key {
  u32 uid;
  u32 tag;
  u32 counterSet;
  u32 ifaceIndex;
};

struct vh_stats_value {
  u64 rxBytes;
  u64 rxPackets;
  u64 txBytes;
  u64 txPackets;
};

/* Global configurations and RCU pointers */
extern struct vpnhide_app_hook_masks __rcu *global_app_hook_masks;
extern spinlock_t app_hook_masks_update_lock;

extern struct vpnhide_targets __rcu *global_targets;
extern spinlock_t targets_update_lock;

extern struct vpnhide_targets __rcu *global_lsposed_targets;
extern spinlock_t lsposed_targets_update_lock;

extern wait_queue_head_t vpnhide_config_wait;
extern atomic_t vpnhide_config_generation;
extern atomic_t java_stats_clear_generation;
extern unsigned int java_hooks_mask;

extern struct vpnhide_port_targets __rcu *global_port_targets;
extern spinlock_t port_targets_update_lock;

extern struct vpnhide_iface_prefixes __rcu *global_iface_prefixes;
extern spinlock_t iface_prefixes_lock;

extern struct vpnhide_spoof_ip_rcu __rcu *global_spoof_ip;
extern spinlock_t spoof_ip_lock;

extern struct vpnhide_active_vpns __rcu *global_active_vpns;
extern spinlock_t active_vpns_lock;

extern struct vh_vpn_name_cache __rcu *g_vpn_name_cache;
extern spinlock_t g_vpn_name_cache_lock;

extern atomic_t global_cover_ifindex;
extern bool g_stats_pkts_first;
extern atomic_t stats_bucket_secs;

/* Common Functions */
bool lookup_app_kernel_mask(uid_t uid, unsigned int *out);
bool is_hook_active(enum vpnhide_hook_idx index, uid_t uid);
bool is_active_vpn_ifindex(u32 ifindex);
bool is_active_vpn_ifname(const char *name);
bool is_target_uid_val(uid_t uid);
bool is_target_uid(void);
void record_kmod_intercept(uid_t uid, int type);
void get_spoof_ip(struct vpnhide_spoof_ip *dst);
int update_spoof_ip(const struct vpnhide_spoof_ip *sip);
u32 fnv1a_name(const char *s, int maxlen);
void vh_rebuild_name_cache(const struct vpnhide_vpn_ifindexes *idata);
bool vh_is_vpn_name_cached(const char *name, size_t len);

/* Stats helper inline functions */
static inline u64 sv_rx_bytes(const struct vh_stats_value *sv) {
  return g_stats_pkts_first ? sv->rxPackets : sv->rxBytes;
}
static inline u64 sv_tx_bytes(const struct vh_stats_value *sv) {
  return g_stats_pkts_first ? sv->txPackets : sv->txBytes;
}
static inline u64 sv_rx_pkts(const struct vh_stats_value *sv) {
  return g_stats_pkts_first ? sv->rxBytes : sv->rxPackets;
}
static inline u64 sv_tx_pkts(const struct vh_stats_value *sv) {
  return g_stats_pkts_first ? sv->txBytes : sv->txPackets;
}
static inline void sv_add(struct vh_stats_value *dst,
                          const struct vh_stats_value *src) {
  if (g_stats_pkts_first) {
    dst->rxPackets += src->rxPackets;
    dst->rxBytes += src->rxBytes;
    dst->txPackets += src->txPackets;
    dst->txBytes += src->txBytes;
  } else {
    dst->rxBytes += src->rxBytes;
    dst->rxPackets += src->rxPackets;
    dst->txBytes += src->txBytes;
    dst->txPackets += src->txPackets;
  }
}

/* ------------------------------------------------------------- */
/* Direct Hook Prototypes (called by core kernel files)          */
/* ------------------------------------------------------------- */

/* Net / Socket Hooks */
bool vpnhide_should_hide_dev(const struct net_device *dev);

int vpnhide_setsockopt(int fd, int level, int optname, char __user *optval, int optlen, int *retval);
int vpnhide_getsockopt(struct socket *sock, int level, int optname, char __user *optval, int __user *optlen, int *retval);
int vpnhide_connect(struct socket *sock, struct sockaddr __user *uservaddr, int addrlen, int *retval);
int vpnhide_bind(struct socket *sock, struct sockaddr __user *uservaddr, int addrlen);
int vpnhide_getname(struct socket *sock, struct sockaddr *uaddr, int peer, int *retval);
int vpnhide_ioctl(struct socket *sock, unsigned int cmd, unsigned long arg, int *retval);
int vpnhide_sys_bpf(int cmd, union bpf_attr __user *uattr, unsigned int size, int *retval);
void vpnhide_bpf_lookup_elem(struct bpf_map *map, void *key, void *value);
void vpnhide_bpf_lookup_batch(struct bpf_map *map, const union bpf_attr *attr, union bpf_attr __user *uattr);
bool vpnhide_udp_sendmsg_pre(struct sock *sk, struct msghdr *msg, size_t len);

/* Filesystem / VFS Hooks */
bool vpnhide_should_hide_path(const struct path *path);
bool vpnhide_should_hide_filename(int dfd, const char *filename);
int vpnhide_filename_lookup(int dfd, struct filename *name, unsigned int flags, struct path *path, int *retval);
int vpnhide_getdents64(unsigned int fd, struct linux_dirent64 __user *dirent, unsigned int count, int *retval);

#endif /* _SECURITY_VPNHIDE_H */
