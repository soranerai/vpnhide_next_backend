#ifndef _VPNHIDE_KMOD_H
#define _VPNHIDE_KMOD_H

#include <linux/bpf.h>
#include <linux/cred.h>
#include <linux/delay.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/if.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/inetdevice.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/net.h>
#include <linux/netdevice.h>
#include <linux/proc_fs.h>
#include <linux/rtnetlink.h>
#include <linux/seq_file.h>
#include <linux/skbuff.h>
#include <linux/slab.h>
#include <linux/socket.h>
#include <linux/string.h>
#include <linux/tcp.h>
#include <linux/uaccess.h>
#include <linux/uidgid.h>
#include <linux/version.h>
#include <net/fib_rules.h>
#include <net/if_inet6.h>
#include <net/ip6_fib.h>
#include <net/ip6_route.h>
#include <net/ip_fib.h>
#include <net/ipv6.h>
#include <net/nexthop.h>
#include <net/route.h>

#include "include/vpnhide.h"

#define MODNAME "vpnhide"

#define VPNHIDE_KRETPROBE_MAXACTIVE 64
#define BUCKETS_COUNT 30

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 11, 0)
#define vh_fd_file(f) fd_file(f)
#else
#define vh_fd_file(f) ((f).file)
#endif

#ifndef BPF_FS_MAGIC
#define BPF_FS_MAGIC 0xcafe4a4b
#endif

#ifndef CONFIG_ARM64
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

/* Hook uses wrapper flags */
extern bool sys_setsockopt_uses_wrapper;
extern bool sys_getsockopt_uses_wrapper;
extern bool sys_connect_uses_wrapper;
extern bool sys_bind_uses_wrapper;
extern bool sys_getsockname_uses_wrapper;
extern bool sys_bpf_uses_wrapper;
extern bool sys_getdents64_uses_wrapper;
extern bool sys_openat_uses_wrapper;
extern bool sys_openat2_uses_wrapper;
extern bool sys_faccessat_uses_wrapper;
extern bool sys_faccessat2_uses_wrapper;
extern bool sys_newfstatat_uses_wrapper;
extern bool sys_readlinkat_uses_wrapper;

/* Common Functions */
bool lookup_app_kernel_mask(uid_t uid, unsigned int *out);
bool is_hook_active(enum vpnhide_hook_idx index, uid_t uid);
bool is_active_vpn_ifindex(u32 ifindex);
bool is_active_vpn_ifname(const char *name);
bool is_target_uid_val(uid_t uid);
bool is_target_uid(void);
bool vpnhide_udp_dst_is_vpn_bound(struct sock *sk, struct msghdr *msg);
bool udp_rate_limit_exceeded(uid_t uid);
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

/* Extern Declarations for kretprobes defined in hook files */
extern struct kretprobe dev_ioctl_krp;
extern struct kretprobe inet_ioctl_krp;
extern struct kretprobe sock_ioctl_krp;
extern struct kretprobe sys_setsockopt_krp;
extern struct kretprobe sock_getsockopt_krp;
extern struct kretprobe sys_getsockopt_krp;
extern struct kretprobe sk_getsockopt_krp;
extern struct kretprobe sock_common_getsockopt_krp;
extern struct kretprobe rtnl_fill_krp;
extern struct kretprobe inet6_fill_krp;
extern struct kretprobe inet_fill_krp;
extern struct kretprobe fib_route_krp;
extern struct kretprobe fib_dump_krp;
extern struct kretprobe fib_rule_fill_krp;
extern struct kretprobe rt6_fill_krp;
extern struct kretprobe ipv6_route_krp;
extern struct kretprobe rt_fill_krp;
extern struct kretprobe socket_connect_krp;
extern struct kretprobe socket_bind_krp;
extern struct kretprobe inet6_bind_ll_krp;
extern struct kretprobe sys_getsockname_krp;
extern struct kretprobe inet_getname_krp;
extern struct kretprobe inet6_getname_krp;
extern struct kretprobe sys_bpf_krp;
extern struct kretprobe sys_getdents64_krp;
extern struct kretprobe dev_seq_krp;
extern struct kretprobe if6_seq_krp;
extern struct kretprobe sys_openat_krp;
extern struct kretprobe sys_openat2_krp;
extern struct kretprobe sys_faccessat_krp;
extern struct kretprobe sys_faccessat2_krp;
extern struct kretprobe sys_newfstatat_krp;
extern struct kretprobe proc_sys_lookup_krp;
extern struct kretprobe sys_readlinkat_krp;
extern struct kretprobe udp_sendmsg_krp;
extern struct kretprobe udpv6_sendmsg_ll_krp;
extern struct kretprobe fib_trie_krp;
extern struct kretprobe tc_fill_qdisc_krp;



#endif /* _VPNHIDE_KMOD_H */
