// SPDX-License-Identifier: GPL-2.0
#include <linux/netdevice.h>
#include <net/fib_rules.h>
#include "vpnhide.h"

bool vpnhide_should_hide_dev(const struct net_device *dev)
{
	uid_t uid;

	if (!(vpnhide_active_hooks_mask() & BIT(HOOK_RTNL_FILL)))
		return false;
	uid = from_kuid(&init_user_ns, current_uid());
	if (!is_hook_active(HOOK_RTNL_FILL, uid))
		return false;
	if (!is_target_uid_val(uid))
		return false;
	if (!is_active_vpn_ifindex(dev->ifindex))
		return false;

	record_kmod_intercept(uid, HOOK_RTNL_FILL);
	return true;
}
EXPORT_SYMBOL_GPL(vpnhide_should_hide_dev);

bool vpnhide_skip_fib_rule(struct sk_buff *skb, struct fib_rule *rule)
{
	uid_t uid;

	if (!(vpnhide_active_hooks_mask() & BIT(HOOK_FIB_RULE_FILL)))
		return false;
	uid = from_kuid(&init_user_ns, current_uid());
	if (!is_hook_active(HOOK_FIB_RULE_FILL, uid))
		return false;
	if (!is_target_uid_val(uid))
		return false;

	rcu_read_lock();

	/* Hide rules that reference a VPN interface by name */
	if ((rule->iifname[0] != '\0' && is_active_vpn_ifname(rule->iifname)) ||
	    (rule->oifname[0] != '\0' && is_active_vpn_ifname(rule->oifname))) {
		rcu_read_unlock();
		record_kmod_intercept(uid, HOOK_FIB_RULE_FILL);
		return true;
	}

	/* Hide UID split-routing rules — covers "RTM_GETRULE UID route leak":
	 * any rule with a uid_range that includes the target or any app UID
	 * (>= 10000) pointing to a non-main/default/local table. */
	{
		uid_t start = from_kuid(&init_user_ns, rule->uid_range.start);
		uid_t end   = from_kuid(&init_user_ns, rule->uid_range.end);

		if (end != (uid_t)~0 &&
		    (start >= 10000 || end >= 10000 ||
		     is_target_uid_val(start) || is_target_uid_val(end)) &&
		    rule->table != 253 && rule->table != 254 &&
		    rule->table != 255 && rule->table > 100) {
			rcu_read_unlock();
			record_kmod_intercept(uid, HOOK_FIB_RULE_FILL);
			return true;
		}
	}

	rcu_read_unlock();
	return false;
}
EXPORT_SYMBOL_GPL(vpnhide_skip_fib_rule);
