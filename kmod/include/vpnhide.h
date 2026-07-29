#ifndef _VPNHIDE_H
#define _VPNHIDE_H

#include <linux/types.h>

#define VPNHIDE_VERSION_CODE 20202


#define MAX_TARGET_UIDS 512
#define MAX_PORT_RULES_PER_UID 16

/* Protocol types for port hiding */
#define VH_PROTO_TCP 0
#define VH_PROTO_UDP 1
#define VH_PROTO_BOTH 2

struct vpnhide_port_rule {
	unsigned short start_port;
	unsigned short end_port;
	unsigned char protocol; /* VH_PROTO_* */
};

struct vpnhide_uid_port_rules {
	uid_t uid;
	int rule_count;
	struct vpnhide_port_rule rules[MAX_PORT_RULES_PER_UID];
};

struct vpnhide_port_ioctl_data {
	int count; /* Number of UIDs in targets array */
	struct vpnhide_uid_port_rules targets[MAX_TARGET_UIDS];
};

struct vpnhide_ioctl_data {
	int count;
	uid_t uids[MAX_TARGET_UIDS];
};

/* Replace the two interface-hiding UID snapshots through one control call;
 * the kernel allocates both new snapshots before publishing them. */
struct vpnhide_target_bundle {
	int kmod_count;
	uid_t kmod_uids[MAX_TARGET_UIDS];
	int lsposed_count;
	uid_t lsposed_uids[MAX_TARGET_UIDS];
};

#define VH_IOCTL_MAGIC 0x56

#define MAX_IFACE_PREFIXES 32
#define MAX_IFACE_LEN 16

struct vpnhide_iface_ioctl_data {
	int count;
	char prefixes[MAX_IFACE_PREFIXES][MAX_IFACE_LEN];
};

struct vpnhide_spoof_ip {
	__be32 ipv4_addr; /* IPv4 address in network byte order */
	__u8 ipv6_addr[16]; /* IPv6 address */
	__u8 has_ipv4;
	__u8 has_ipv6;
};

#define VH_SET_TARGETS _IOW(VH_IOCTL_MAGIC, 0x01, struct vpnhide_ioctl_data)
#define VH_SET_TARGET_BUNDLE \
	_IOW(VH_IOCTL_MAGIC, 0x20, struct vpnhide_target_bundle)
#define VH_SET_POLICY \
	_IOW(VH_IOCTL_MAGIC, 0x21, struct vpnhide_policy_ioctl)
#define VH_SET_DEBUG _IOW(VH_IOCTL_MAGIC, 0x03, int)
#define VH_SET_PORT_TARGETS \
	_IOW(VH_IOCTL_MAGIC, 0x05, struct vpnhide_ioctl_data)
#define VH_SET_PORT_RULES _IO(VH_IOCTL_MAGIC, 0x06)
#define VH_SET_IFACE_PREFIXES \
	_IOW(VH_IOCTL_MAGIC, 0x07, struct vpnhide_iface_ioctl_data)
#define VH_SET_SPOOF_IP _IOW(VH_IOCTL_MAGIC, 0x08, struct vpnhide_spoof_ip)
#define VH_SET_ACTIVE_HOOKS _IOW(VH_IOCTL_MAGIC, 0x09, unsigned int)
#define VH_GET_ACTIVE_HOOKS _IOR(VH_IOCTL_MAGIC, 0x0A, unsigned int)
#define VH_GET_VERSION _IOR(VH_IOCTL_MAGIC, 0x1E, int)

struct vpnhide_uid_stats {
	uid_t uid;
	unsigned int ioctl_count;
	unsigned int netlink_count;
	unsigned int proc_count;
	unsigned int sockopt_count;
	unsigned int connect_count;
	unsigned int getname_count;
	unsigned int port_count;
};

/* Kept below MAX_TARGET_UIDS: the ioctl size field is 14 bits (max 16383
 * bytes), and MAX_TARGET_UIDS * sizeof(struct vpnhide_uid_stats) no longer
 * fits since port_count was added. */
#define MAX_STATS_UIDS 480

struct vpnhide_kmod_stats_data {
	int count;
	struct vpnhide_uid_stats stats[MAX_STATS_UIDS];
};

#define VH_GET_STATS _IOR(VH_IOCTL_MAGIC, 0x0B, struct vpnhide_kmod_stats_data)
#define VH_CLEAR_STATS _IO(VH_IOCTL_MAGIC, 0x0C)

/* Seconds represented by each of the BUCKETS_COUNT rolling stats buckets;
 * window = BUCKETS_COUNT * stats_bucket_secs. Also clears existing stats
 * since old bucket alignment becomes invalid under a new duration. */
#define VH_SET_STATS_WINDOW _IOW(VH_IOCTL_MAGIC, 0x1D, unsigned int)
#define VH_GET_TARGETS _IOR(VH_IOCTL_MAGIC, 0x0D, struct vpnhide_ioctl_data)
#define VH_SET_BPF_MAP_FOPS _IOW(VH_IOCTL_MAGIC, 0x0E, unsigned long)
#define VH_SET_STATS_MAP_A _IOW(VH_IOCTL_MAGIC, 0x0F, int)
#define VH_SET_STATS_MAP_B _IOW(VH_IOCTL_MAGIC, 0x10, int)

/* Cover interface: the visible non-VPN iface whose stats absorb VPN traffic */
struct vpnhide_cover_iface {
	__u32 ifindex; /* 0 = not set / disabled */
};

#define VH_SET_COVER_IFACE \
	_IOW(VH_IOCTL_MAGIC, 0x11, struct vpnhide_cover_iface)

#define MAX_ACTIVE_VPNS 16

struct vpnhide_active_vpn {
	__u32 ifindex;
	char name[MAX_IFACE_LEN];
};

struct vpnhide_vpn_ifindexes {
	int count;
	struct vpnhide_active_vpn vpns[MAX_ACTIVE_VPNS];
};

#define VH_GET_IFACE_PREFIXES \
	_IOR(VH_IOCTL_MAGIC, 0x13, struct vpnhide_iface_ioctl_data)

#define VH_SET_VPN_IFINDEXES \
	_IOW(VH_IOCTL_MAGIC, 0x14, struct vpnhide_vpn_ifindexes)

#define VH_SET_JAVA_HOOK_MASK _IOW(VH_IOCTL_MAGIC, 0x15, unsigned int)
#define VH_GET_JAVA_HOOK_MASK _IOR(VH_IOCTL_MAGIC, 0x16, unsigned int)

#define VH_SET_LSPOSED_TARGETS _IOW(VH_IOCTL_MAGIC, 0x17, struct vpnhide_ioctl_data)
#define VH_GET_LSPOSED_TARGETS _IOR(VH_IOCTL_MAGIC, 0x18, struct vpnhide_ioctl_data)

#define VH_GET_JAVA_STATS _IOR(VH_IOCTL_MAGIC, 0x19, char[4096])
#define VH_GET_HOOK_STATUS _IOR(VH_IOCTL_MAGIC, 0x1A, char[256])

/* Per-app hook mask overrides: when set for a uid, take priority over the
 * global active_hooks_mask / java_hooks_mask for that uid only. */
struct vpnhide_app_hook_mask {
	uid_t uid;
	unsigned int kernel_mask;
	unsigned int java_mask;
	unsigned char has_kernel_override;
	unsigned char has_java_override;
};

struct vpnhide_app_hook_ioctl_data {
	int count;
	struct vpnhide_app_hook_mask masks[MAX_TARGET_UIDS];
};

/* Versioned, self-contained policy payload.  The payload is passed through
 * an explicit userspace pointer rather than being encoded in the ioctl
 * command size; it is larger than the 14-bit size field on some kernels. */
#define VPNHIDE_POLICY_ABI_VERSION 1
struct vpnhide_policy_payload {
	struct vpnhide_target_bundle targets;
	struct vpnhide_port_ioctl_data ports;
	struct vpnhide_iface_ioctl_data iface_prefixes;
	struct vpnhide_app_hook_ioctl_data app_hook_masks;
	__u32 active_hooks_mask;
	__u32 java_hooks_mask;
	__u32 debug_enabled;
	__u32 flags;
};

struct vpnhide_policy_ioctl {
	__u32 abi_version;
	__u32 payload_size;
	__u64 payload_ptr;
	__u64 expected_generation;
};

#define VH_SET_APP_HOOK_MASKS \
	_IOW(VH_IOCTL_MAGIC, 0x1B, struct vpnhide_app_hook_ioctl_data)
#define VH_GET_APP_HOOK_MASKS \
	_IOR(VH_IOCTL_MAGIC, 0x1C, struct vpnhide_app_hook_ioctl_data)

#endif /* _VPNHIDE_H */
