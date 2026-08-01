#include <stddef.h>
#include <sys/ioctl.h>
#include <sys/types.h>

#include "../security/vpnhide/vpnhide_uapi.h"

_Static_assert(sizeof(struct vpnhide_policy_ioctl) == 24,
	       "policy ioctl header must remain pointer ABI stable");
_Static_assert(sizeof(struct vpnhide_port_rule_v3) == 8,
	       "v3 port rule must be fixed-width");
_Static_assert(sizeof(struct vpnhide_port_target_v3) == 16,
	       "v3 port target must be fixed-width");
_Static_assert(sizeof(struct vpnhide_app_hook_mask_v3) == 16,
	       "v3 app mask must be fixed-width");
_Static_assert(sizeof(struct vpnhide_policy_payload_v3) == 576,
	       "v3 policy header must match the kmod layout");
_Static_assert(offsetof(struct vpnhide_policy_payload_v3, kmod_uids) == 536,
	       "v3 section directory offset must remain stable");

int main(void)
{
	return VPNHIDE_POLICY_ABI_VERSION == VPNHIDE_POLICY_ABI_VERSION_V3 ? 0 : 1;
}
