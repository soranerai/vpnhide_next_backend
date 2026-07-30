#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/types.h>

#include "../include/vpnhide.h"

_Static_assert(sizeof(struct vpnhide_policy_ioctl) == 24,
               "policy ioctl header must remain pointer ABI stable");
_Static_assert(sizeof(struct vpnhide_policy_payload) > 16383,
               "payload must use explicit pointer ABI, not ioctl size");

int main(void)
{
	printf("policy_abi payload=%zu request=%zu command=0x%lx\n",
	       sizeof(struct vpnhide_policy_payload),
	       sizeof(struct vpnhide_policy_ioctl),
	       (unsigned long)VH_SET_POLICY);
	return 0;
}
