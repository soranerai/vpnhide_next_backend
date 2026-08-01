#include <sys/ioctl.h>
#include <sys/types.h>

#include "../include/vpnhide.h"
#include "policy_abi_fingerprint.h"

int main(void)
{
	print_policy_abi_fingerprint();
	return 0;
}
