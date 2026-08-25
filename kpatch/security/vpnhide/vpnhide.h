/* SPDX-License-Identifier: GPL-2.0 */
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
#include <linux/hashtable.h>
#include <linux/tcp.h>
#include <linux/version.h>
#include <linux/miscdevice.h>
#include <linux/sort.h>
#include <linux/vpnhide.h>

#include "vpnhide_uapi.h"

bool vpnhide_skip_fib_rule(struct sk_buff *skb, struct fib_rule *rule);

#define MODNAME        "vpnhide_ctrl"
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 11, 0)
#define vh_fd_file(f) fd_file(f)
#else
#define vh_fd_file(f) ((f).file)
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
#ifndef SO_BINDTOIFINDEX
#define SO_BINDTOIFINDEX 62
#endif
#ifndef SOF_TIMESTAMPING_TX_HARDWARE
#define SOF_TIMESTAMPING_TX_HARDWARE (1 << 0)
#define SOF_TIMESTAMPING_RX_HARDWARE (1 << 2)
#define SOF_TIMESTAMPING_RAW_HARDWARE (1 << 6)
#endif

#define vpnhide_dbg(fmt, ...)                                  \
	do {                                                   \
		if (vpnhide_debug_is_enabled())                \
			pr_info(MODNAME ": " fmt, ##__VA_ARGS__); \
	} while (0)

enum vpnhide_hook_idx {
	HOOK_DEV_IOCTL     = 0,
	HOOK_SOCK_IOCTL    = 1,
	HOOK_RTNL_FILL     = 2,
	HOOK_INET6_FILL    = 3,
	HOOK_INET_FILL     = 4,
	HOOK_FIB_ROUTE     = 5,
	HOOK_IPV6_ROUTE    = 6,
	HOOK_FIB_DUMP      = 7,
	HOOK_FIB_RULE_FILL = 8,
	HOOK_RT6_FILL      = 9,
	HOOK_RT_FILL       = 10,
	HOOK_SETSOCKOPT    = 11,
	HOOK_GETSOCKOPT    = 12,
	HOOK_CONNECT       = 13,
	HOOK_GETNAME_INET  = 14,
	HOOK_GETNAME_INET6 = 15,
	HOOK_BIND          = 16,
	HOOK_BPF           = 17,
	HOOK_GETDENTS64    = 18,
	HOOK_FACCESSAT     = 19,
	HOOK_FACCESSAT2    = 20,
	HOOK_NEWFSTATAT    = 21,
	HOOK_OPENAT        = 22,
	HOOK_OPENAT2       = 23,
	HOOK_READLINKAT    = 24,
	HOOK_UDP_SENDMSG   = 25,
	HOOK_DEV_SEQ       = 26,
	HOOK_IF6_SEQ       = 27,
	HOOK_INET6_BIND_LL = 28,
	HOOK_UDPV6_SENDMSG = 29,
	HOOK_FIB_TRIE      = 30,
	HOOK_TC_FILL_QDISC = 31,
	HOOK_PORT          = 32,
};

struct vpnhide_policy_snapshot {
	u32 active_hooks_mask;
	u32 java_hooks_mask;
	u32 debug_enabled;
	u32 flags;
	u32 kmod_match_mode;
	u32 lsposed_match_mode;
	u32 port_match_mode;
	struct vpnhide_iface_ioctl_data iface_prefixes;
	u32 kmod_count;
	u32 lsposed_count;
	u32 port_target_count;
	u32 port_rule_count;
	u32 app_hook_mask_count;
	uid_t *kmod_uids;
	uid_t *lsposed_uids;
	struct vpnhide_port_target_v3 *port_targets;
	struct vpnhide_port_rule_v3 *port_rules;
	struct vpnhide_app_hook_mask_v3 *app_hook_masks;
	struct rcu_head rcu;
	u8 data[];
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
	u32  hashes[MAX_ACTIVE_VPNS];
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

/* Per-UID token-bucket for UDP rate limiting */
#define VH_UDP_BUCKET_MAX  250
#define VH_UDP_REGEN_NS    2000000ULL /* 2 ms */

struct vh_udp_uid_rate {
	uid_t    uid;
	int      tokens;
	ktime_t  last_regen;
	struct hlist_node node;
};

/* ------------------------------------------------------------------ */
/* Global RCU state (defined in core.c)                                */
/* ------------------------------------------------------------------ */

extern wait_queue_head_t vpnhide_config_wait;
extern atomic_t          vpnhide_config_generation;
extern atomic_t          java_stats_clear_generation;
extern unsigned int      java_hooks_mask;

extern struct vpnhide_policy_snapshot __rcu *global_policy_snapshot;
extern spinlock_t policy_snapshot_lock;

extern struct vpnhide_spoof_ip_rcu __rcu *global_spoof_ip;
extern spinlock_t spoof_ip_lock;

extern struct vpnhide_active_vpns __rcu *global_active_vpns;
extern spinlock_t active_vpns_lock;

extern struct vh_vpn_name_cache __rcu *g_vpn_name_cache;
extern spinlock_t g_vpn_name_cache_lock;

extern atomic_t global_cover_ifindex;
extern bool     g_stats_pkts_first;

/* ------------------------------------------------------------------ */
/* Core helpers (core.c)                                               */
/* ------------------------------------------------------------------ */

bool lookup_app_kernel_mask(uid_t uid, unsigned int *out);
bool is_hook_active(enum vpnhide_hook_idx index, uid_t uid);
bool vpnhide_debug_is_enabled(void);
unsigned int vpnhide_active_hooks_mask(void);
unsigned int vpnhide_java_hooks_mask(void);
bool is_active_vpn_ifindex(u32 ifindex);
bool is_active_vpn_ifname(const char *name);
bool is_target_uid_val(uid_t uid);
bool is_target_uid(void);
bool vpnhide_uid_matches_mode(const uid_t *uids, u32 count, u32 mode,
			      uid_t uid);
bool vpnhide_uid_owns_port(uid_t uid, u16 port, u8 protocol, u8 family,
			   const u32 address[4]);
void vpnhide_record_bound_socket(uid_t uid, struct sock *sk);
void vpnhide_notify_port_change(uid_t uid);
void vpnhide_listen_post(struct socket *sock, int error);
int vpnhide_apply_policy(const struct vpnhide_policy_payload *payload,
			 u64 expected_generation);
int vpnhide_apply_policy_v3(const void *payload, size_t payload_size,
			    u64 expected_generation);
int vpnhide_apply_policy_v4(const void *payload, size_t payload_size,
			    u64 expected_generation);
const struct vpnhide_port_target_v3 *
vpnhide_find_port_target(const struct vpnhide_policy_snapshot *snapshot,
			 uid_t uid);
void record_kmod_intercept(uid_t uid, int type);
void record_port_intercept(uid_t uid, u16 port, u8 protocol);
void get_spoof_ip(struct vpnhide_spoof_ip *dst);
int  update_spoof_ip(const struct vpnhide_spoof_ip *sip);
u32  fnv1a_name(const char *s, int maxlen);
void vh_rebuild_name_cache(const struct vpnhide_vpn_ifindexes *idata);
bool vh_is_vpn_name_cached(const char *name, size_t len);
void vpnhide_udp_rates_prune(const struct vpnhide_policy_snapshot *snapshot);
void vpnhide_udp_rates_destroy(void);

/* ------------------------------------------------------------------ */
/* Stats helpers (inline)                                              */
/* ------------------------------------------------------------------ */

static inline u64 sv_rx_bytes(const struct vh_stats_value *sv)
{ return g_stats_pkts_first ? sv->rxPackets : sv->rxBytes; }

static inline u64 sv_tx_bytes(const struct vh_stats_value *sv)
{ return g_stats_pkts_first ? sv->txPackets : sv->txBytes; }

static inline u64 sv_rx_pkts(const struct vh_stats_value *sv)
{ return g_stats_pkts_first ? sv->rxBytes : sv->rxPackets; }

static inline u64 sv_tx_pkts(const struct vh_stats_value *sv)
{ return g_stats_pkts_first ? sv->txBytes : sv->txPackets; }

static inline void sv_add(struct vh_stats_value *dst,
			  const struct vh_stats_value *src)
{
	dst->rxBytes   += src->rxBytes;
	dst->rxPackets += src->rxPackets;
	dst->txBytes   += src->txBytes;
	dst->txPackets += src->txPackets;
}

/* ------------------------------------------------------------------ */
/* BPF helpers declared here, implemented in hook_fs.c                 */
/* ------------------------------------------------------------------ */

bool vh_is_stats_map(struct bpf_map *map);
bool vh_is_vpn_stats_key(struct bpf_map *map, const struct vh_stats_key *key);

/* ------------------------------------------------------------------ */
/* Socket hooks (hook_socket.c) — called from patched net/socket.c,    */
/* net/ipv4/udp.c and net/ipv6/udp.c                                   */
/* ------------------------------------------------------------------ */

int  vpnhide_bind_pre(struct socket *sock, struct sockaddr *addr, int addrlen);
void vpnhide_bind_post(struct socket *sock, int error);
void vpnhide_bind(struct socket *sock, struct sockaddr __user *umyaddr,
		  int addrlen);
int  vpnhide_connect_pre(struct socket *sock, struct sockaddr *addr, int addrlen);
bool vpnhide_connect(struct socket *sock, struct sockaddr __user *uservaddr,
		     int addrlen, int *ret);
void vpnhide_getname_post(struct socket *sock, struct sockaddr *addr, int peer);
void vpnhide_getname(struct socket *sock, struct sockaddr *addr,
		     int peer, int *err);
bool vpnhide_udp_sendmsg(struct sock *sk);
bool vpnhide_udp_sendmsg_pre(struct sock *sk, struct msghdr *msg,
			     size_t len, int *err);

#endif /* _SECURITY_VPNHIDE_H */
