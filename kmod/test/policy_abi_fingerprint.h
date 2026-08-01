#ifndef VPNHIDE_POLICY_ABI_FINGERPRINT_H
#define VPNHIDE_POLICY_ABI_FINGERPRINT_H

#include <stddef.h>
#include <stdio.h>

_Static_assert(sizeof(struct vpnhide_policy_ioctl) == 24,
	       "policy ioctl header must remain pointer ABI stable");
_Static_assert(sizeof(struct vpnhide_policy_payload) > 16383,
	       "legacy payload must use the explicit pointer ABI");
_Static_assert(sizeof(struct vpnhide_uid_stats) == 64,
	       "stats entry ABI must remain fixed-width");
_Static_assert(sizeof(struct vpnhide_stats_snapshot) == 32,
	       "stats snapshot ABI must remain pointer-based");
_Static_assert(sizeof(struct vpnhide_policy_section_v3) == 8,
	       "v3 section descriptor must be fixed-width");
_Static_assert(sizeof(struct vpnhide_port_rule_v3) == 8,
	       "v3 port rule must be fixed-width");
_Static_assert(sizeof(struct vpnhide_port_target_v3) == 16,
	       "v3 port target must be fixed-width");
_Static_assert(sizeof(struct vpnhide_app_hook_mask_v3) == 16,
	       "v3 app mask must be fixed-width");
_Static_assert(sizeof(struct vpnhide_policy_payload_v3) == 576,
	       "v3 policy header must be fixed-width");
_Static_assert(offsetof(struct vpnhide_policy_payload_v3, kmod_uids) == 536,
	       "v3 section directory offset must remain stable");
_Static_assert(offsetof(struct vpnhide_policy_payload_v3, lsposed_uids) == 544,
	       "v3 lsposed section offset must remain stable");
_Static_assert(offsetof(struct vpnhide_policy_payload_v3, port_targets) == 552,
	       "v3 port target section offset must remain stable");
_Static_assert(offsetof(struct vpnhide_policy_payload_v3, port_rules) == 560,
	       "v3 port rule section offset must remain stable");
_Static_assert(offsetof(struct vpnhide_policy_payload_v3, app_hook_masks) == 568,
	       "v3 app mask section offset must remain stable");

static void print_policy_abi_fingerprint(void)
{
	printf("version=%u v2=%u v3=%u max=%u legacy=%u/%u "
	       "sizes=%zu/%zu/%zu/%zu/%zu/%zu/%zu/%zu/%zu "
	       "offsets=%zu/%zu/%zu/%zu/%zu/%zu/%zu/%zu/%zu "
	       "ioctls=%lu/%lu/%lu\n",
	       VPNHIDE_POLICY_ABI_VERSION,
	       VPNHIDE_POLICY_ABI_VERSION_V2,
	       VPNHIDE_POLICY_ABI_VERSION_V3,
	       VPNHIDE_POLICY_MAX_BYTES,
	       VPNHIDE_LEGACY_TARGET_UIDS,
	       VPNHIDE_LEGACY_PORT_RULES_PER_UID,
	       sizeof(struct vpnhide_policy_payload),
	       sizeof(struct vpnhide_uid_stats),
	       sizeof(struct vpnhide_stats_snapshot),
	       sizeof(struct vpnhide_policy_section_v3),
	       sizeof(struct vpnhide_port_rule_v3),
	       sizeof(struct vpnhide_port_target_v3),
	       sizeof(struct vpnhide_app_hook_mask_v3),
	       sizeof(struct vpnhide_policy_payload_v3),
	       sizeof(struct vpnhide_policy_ioctl),
	       offsetof(struct vpnhide_policy_ioctl, abi_version),
	       offsetof(struct vpnhide_policy_ioctl, payload_size),
	       offsetof(struct vpnhide_policy_ioctl, payload_ptr),
	       offsetof(struct vpnhide_policy_ioctl, expected_generation),
	       offsetof(struct vpnhide_policy_payload_v3, kmod_uids),
	       offsetof(struct vpnhide_policy_payload_v3, lsposed_uids),
	       offsetof(struct vpnhide_policy_payload_v3, port_targets),
	       offsetof(struct vpnhide_policy_payload_v3, port_rules),
	       offsetof(struct vpnhide_policy_payload_v3, app_hook_masks),
	       (unsigned long)VH_SET_POLICY,
	       (unsigned long)VH_GET_STATS,
	       (unsigned long)VH_GET_STATS_SESSION);
}

#endif
