// SPDX-License-Identifier: GPL-2.0
#include <linux/netdevice.h>
#include "vpnhide.h"

bool vpnhide_should_hide_dev(const struct net_device *dev)
{
	uid_t uid = from_kuid(&init_user_ns, current_uid());

	if (!is_hook_active(HOOK_RTNL_FILL, uid))
		return false;
	if (!is_active_vpn_ifindex(dev->ifindex))
		return false;

	record_kmod_intercept(uid, HOOK_RTNL_FILL);
	return true;
}
EXPORT_SYMBOL_GPL(vpnhide_should_hide_dev);
