#ifndef _VPNHIDE_UAPI_H
#define _VPNHIDE_UAPI_H

#include <linux/types.h>

#define VPNHIDE_VERSION_CODE 20503

#define VPNHIDE_LEGACY_TARGET_UIDS 512
#define VPNHIDE_LEGACY_PORT_RULES_PER_UID 16

/* Protocol types for port hiding */
#define VH_PROTO_TCP 0
#define VH_PROTO_UDP 1
#define VH_PROTO_BOTH 2

/* Port policy is block-only at the kernel boundary. */
#define VH_PORT_POLICY_RULES        0
#define VH_PORT_POLICY_UNRESTRICTED 1
#define VH_PORT_POLICY_DENY_ALL     2

struct vpnhide_port_rule {
	unsigned short start_port;
	unsigned short end_port;
	unsigned char protocol; /* VH_PROTO_* */
};

struct vpnhide_uid_port_rules {
	uid_t uid;
	int rule_count;
	unsigned char mode; /* VH_PORT_POLICY_* */
	struct vpnhide_port_rule rules[VPNHIDE_LEGACY_PORT_RULES_PER_UID];
};

struct vpnhide_port_ioctl_data {
	int count; /* Number of UIDs in targets array */
	struct vpnhide_uid_port_rules targets[VPNHIDE_LEGACY_TARGET_UIDS];
};

struct vpnhide_ioctl_data {
	int count;
	uid_t uids[VPNHIDE_LEGACY_TARGET_UIDS];
};

/* Replace the two interface-hiding UID snapshots through one control call;
 * the kernel allocates both new snapshots before publishing them. */
struct vpnhide_target_bundle {
	int kmod_count;
	uid_t kmod_uids[VPNHIDE_LEGACY_TARGET_UIDS];
	int lsposed_count;
	uid_t lsposed_uids[VPNHIDE_LEGACY_TARGET_UIDS];
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
	__u8 ipv6_linklocal_addr[16]; /* cover-interface link-local IPv6 */
	__u8 has_ipv4;
	__u8 has_ipv6;
	__u8 has_ipv6_linklocal;
	__u8 reserved;
	__u32 ipv4_mtu; /* route MTU of the cover interface, 0 = unknown */
	__u32 ipv6_mtu; /* route MTU of the cover interface, 0 = unknown */
};

#define VH_SET_POLICY \
	_IOW(VH_IOCTL_MAGIC, 0x21, struct vpnhide_policy_ioctl)
#define VH_SET_SPOOF_IP _IOW(VH_IOCTL_MAGIC, 0x08, struct vpnhide_spoof_ip)
#define VH_GET_ACTIVE_HOOKS _IOR(VH_IOCTL_MAGIC, 0x0A, unsigned int)
#define VH_GET_VERSION _IOR(VH_IOCTL_MAGIC, 0x1E, int)

/* Current-session cumulative intercept counters. */
struct vpnhide_uid_stats {
	uid_t uid;
	__u64 ioctl_count;
	__u64 netlink_count;
	__u64 proc_count;
	__u64 sockopt_count;
	__u64 connect_count;
	__u64 getname_count;
	__u64 port_count;
	__u64 java_pm_count;
	__u64 java_um_count;
	__u64 java_nc_count;
	__u64 java_ni_count;
	__u64 java_net_count;
	__u64 java_lp_count;
	__u64 java_cs_count;
};

struct vpnhide_stats_snapshot {
	__u32 capacity;
	__u32 count;
	__u64 sequence;
	__u64 monotonic_ns;
	__u64 entries_ptr;
};

#define VH_GET_STATS _IOWR(VH_IOCTL_MAGIC, 0x0B, struct vpnhide_stats_snapshot)
#define VH_CLEAR_STATS _IO(VH_IOCTL_MAGIC, 0x0C)
#define VH_GET_STATS_SESSION _IOR(VH_IOCTL_MAGIC, 0x22, __u64)

struct vpnhide_port_stats {
	uid_t uid;
	__u16 port;
	__u8 protocol;
	__u8 reserved;
	__u64 count;
};

struct vpnhide_stats_snapshot_v2 {
	__u32 uid_capacity;
	__u32 uid_count;
	__u32 port_capacity;
	__u32 port_count;
	__u64 sequence;
	__u64 monotonic_ns;
	__u64 uid_entries_ptr;
	__u64 port_entries_ptr;
	__u64 dropped_port_entries;
};

#define VH_GET_STATS_V2 \
	_IOWR(VH_IOCTL_MAGIC, 0x25, struct vpnhide_stats_snapshot_v2)

struct vpnhide_owned_port {
	__u32 uid;
	__u16 port;
	__u8 protocol;
	__u8 family;
	__u32 address[4]; /* network byte order; unused words are zero */
};

struct vpnhide_owned_ports_update {
	__u32 count;
	__u32 reserved;
	__u64 entries_ptr;
};

#define VPNHIDE_OWNED_PORTS_MAX 65536U
#define VH_SET_PORT_EVENTFD _IOW(VH_IOCTL_MAGIC, 0x23, int)
#define VH_SET_OWNED_PORTS \
	_IOW(VH_IOCTL_MAGIC, 0x24, struct vpnhide_owned_ports_update)
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

#define VH_GET_JAVA_HOOK_MASK _IOR(VH_IOCTL_MAGIC, 0x16, unsigned int)
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
	struct vpnhide_app_hook_mask masks[VPNHIDE_LEGACY_TARGET_UIDS];
};

/* Incremented when the in-memory payload layout changes.  kmod and kpatch
 * must be rebuilt and released together; the ctl rejects an older kernel
 * through the payload-size/ABI check instead of silently applying garbage. */
#define VPNHIDE_POLICY_ABI_VERSION_V2 2
#define VPNHIDE_POLICY_ABI_VERSION_V3 3
#define VPNHIDE_POLICY_ABI_VERSION_V4 4
#define VPNHIDE_POLICY_ABI_VERSION VPNHIDE_POLICY_ABI_VERSION_V4

#define VPNHIDE_MATCH_INCLUDE 0
#define VPNHIDE_MATCH_EXCLUDE 1
#define VPNHIDE_POLICY_MAX_BYTES (16U * 1024U * 1024U)
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

struct vpnhide_policy_section_v3 {
	__u32 offset;
	__u32 count;
};

struct vpnhide_port_rule_v3 {
	__u16 start_port;
	__u16 end_port;
	__u8 protocol;
	__u8 reserved[3];
};

struct vpnhide_port_target_v3 {
	__u32 uid;
	__u32 first_rule;
	__u32 rule_count;
	__u8 mode;
	__u8 reserved[3];
};

struct vpnhide_app_hook_mask_v3 {
	__u32 uid;
	__u32 kernel_mask;
	__u32 java_mask;
	__u8 has_kernel_override;
	__u8 has_java_override;
	__u8 reserved[2];
};

struct vpnhide_policy_payload_v3 {
	__u32 total_size;
	__u32 flags;
	__u32 active_hooks_mask;
	__u32 java_hooks_mask;
	__u32 debug_enabled;
	__u32 iface_count;
	char iface_prefixes[MAX_IFACE_PREFIXES][MAX_IFACE_LEN];
	struct vpnhide_policy_section_v3 kmod_uids;
	struct vpnhide_policy_section_v3 lsposed_uids;
	struct vpnhide_policy_section_v3 port_targets;
	struct vpnhide_policy_section_v3 port_rules;
	struct vpnhide_policy_section_v3 app_hook_masks;
};

struct vpnhide_policy_payload_v4 {
	__u32 total_size;
	__u32 flags;
	__u32 active_hooks_mask;
	__u32 java_hooks_mask;
	__u32 debug_enabled;
	__u32 iface_count;
	__u32 kmod_match_mode;
	__u32 lsposed_match_mode;
	__u32 port_match_mode;
	__u32 reserved;
	char iface_prefixes[MAX_IFACE_PREFIXES][MAX_IFACE_LEN];
	struct vpnhide_policy_section_v3 kmod_uids;
	struct vpnhide_policy_section_v3 lsposed_uids;
	struct vpnhide_policy_section_v3 port_targets;
	struct vpnhide_policy_section_v3 port_rules;
	struct vpnhide_policy_section_v3 app_hook_masks;
};

struct vpnhide_policy_ioctl {
	__u32 abi_version;
	__u32 payload_size;
	__u64 payload_ptr;
	__u64 expected_generation;
};

#define VH_GET_APP_HOOK_MASKS \
	_IOR(VH_IOCTL_MAGIC, 0x1C, struct vpnhide_app_hook_ioctl_data)

#endif /* _VPNHIDE_UAPI_H */
