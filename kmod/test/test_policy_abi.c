#include <stdio.h>
#include <stddef.h>
#include <sys/ioctl.h>
#include <sys/types.h>

#include "../include/vpnhide.h"

_Static_assert(sizeof(struct vpnhide_policy_ioctl) == 24,
               "policy ioctl header must remain pointer ABI stable");
_Static_assert(sizeof(struct vpnhide_policy_payload) > 16383,
               "payload must use explicit pointer ABI, not ioctl size");
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

int main(void)
{
	printf("policy_abi payload=%zu request=%zu command=0x%lx\n",
	       sizeof(struct vpnhide_policy_payload),
	       sizeof(struct vpnhide_policy_ioctl),
	       (unsigned long)VH_SET_POLICY);
	return 0;
}
