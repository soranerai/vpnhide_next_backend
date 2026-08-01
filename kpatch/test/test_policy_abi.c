#include <sys/ioctl.h>
#include <sys/types.h>

#include "../security/vpnhide/vpnhide_uapi.h"
#include "../../kmod/test/policy_abi_fingerprint.h"

int main(void)
{
	print_policy_abi_fingerprint();
	return 0;
}
