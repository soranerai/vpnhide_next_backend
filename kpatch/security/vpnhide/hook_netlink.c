// SPDX-License-Identifier: GPL-2.0
/*
 * vpnhide — netlink / routing hooks (early-return optimisation)
 *
 * Called at the TOP of each fill/seq_show function so no netlink message
 * is built at all for hidden interfaces. This is a fundamental improvement
 * over the kmod kretprobe approach which had to trim an already-built skb.
 */

#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/seq_file.h>
#include <linux/if_addr.h>
#include <linux/inetdevice.h>
#include <net/addrconf.h>
#include <net/fib_rules.h>
#include <net/ip_fib.h>
#include <net/ip6_fib.h>
#include <net/route.h>
#include <net/sch_generic.h>

#include "vpnhide.h"

/* ------------------------------------------------------------------ */
/* vpnhide_should_hide_dev — generic per-device hide check             */
/* Used by rtnetlink, devinet, addrconf, fib_trie, fib_semantics,      */
/* ip6_fib iterators that walk a net_device list.                      */
/* ------------------------------------------------------------------ */

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

/* ------------------------------------------------------------------ */
/* rtnl_fill_ifinfo — hide interface from RTM_GETLINK / NEWLINK        */
/* ------------------------------------------------------------------ */

bool vpnhide_skip_iflink(struct sk_buff *skb, const struct net_device *dev)
{
	uid_t uid = from_kuid(&init_user_ns, current_uid());

	if (!is_hook_active(HOOK_RTNL_FILL, uid))
		return false;
	if (!is_active_vpn_ifindex(dev->ifindex))
		return false;

	record_kmod_intercept(uid, HOOK_RTNL_FILL);
	return true;
}
EXPORT_SYMBOL_GPL(vpnhide_skip_iflink);

/* ------------------------------------------------------------------ */
/* inet6_fill_ifaddr — hide IPv6 address from RTM_GETADDR              */
/* ------------------------------------------------------------------ */

bool vpnhide_skip_inet6_ifaddr(struct sk_buff *skb, struct inet6_ifaddr *ifa)
{
	uid_t uid = from_kuid(&init_user_ns, current_uid());

	if (!is_hook_active(HOOK_INET6_FILL, uid))
		return false;
	if (!ifa || !ifa->idev || !ifa->idev->dev)
		return false;
	if (!is_active_vpn_ifindex(ifa->idev->dev->ifindex))
		return false;

	record_kmod_intercept(uid, HOOK_INET6_FILL);
	return true;
}
EXPORT_SYMBOL_GPL(vpnhide_skip_inet6_ifaddr);

/* ------------------------------------------------------------------ */
/* inet_fill_ifaddr — hide IPv4 address from RTM_GETADDR               */
/* ------------------------------------------------------------------ */

bool vpnhide_skip_inet_ifaddr(struct sk_buff *skb, struct in_ifaddr *ifa)
{
	uid_t uid = from_kuid(&init_user_ns, current_uid());

	if (!is_hook_active(HOOK_INET_FILL, uid))
		return false;
	if (!ifa || !ifa->ifa_dev || !ifa->ifa_dev->dev)
		return false;
	if (!is_active_vpn_ifindex(ifa->ifa_dev->dev->ifindex))
		return false;

	record_kmod_intercept(uid, HOOK_INET_FILL);
	return true;
}
EXPORT_SYMBOL_GPL(vpnhide_skip_inet_ifaddr);

/* ------------------------------------------------------------------ */
/* fib_dump_info — hide IPv4 route from RTM_GETROUTE                   */
/* ------------------------------------------------------------------ */

bool vpnhide_skip_fib_dump(struct sk_buff *skb, struct fib_info *fi, int nhsel)
{
	const struct net_device *dev = NULL;
	uid_t uid;

	if (!fi)
		return false;

	uid = from_kuid(&init_user_ns, current_uid());
	if (!is_hook_active(HOOK_FIB_DUMP, uid))
		return false;

#if IS_ENABLED(CONFIG_IP_ROUTE_MULTIPATH)
	if (fi->fib_nhs > nhsel) {
		dev = fi->fib_nh[nhsel].fib_nh_dev;
	}
#else
	if (fi->fib_nhs > 0)
		dev = fi->fib_nh[0].fib_nh_dev;
#endif
	if (!dev)
		return false;
	if (!is_active_vpn_ifindex(dev->ifindex))
		return false;

	record_kmod_intercept(uid, HOOK_FIB_DUMP);
	return true;
}
EXPORT_SYMBOL_GPL(vpnhide_skip_fib_dump);

/* ------------------------------------------------------------------ */
/* fib_nl_fill_rule — hide UID split-routing rules                     */
/* ------------------------------------------------------------------ */

bool vpnhide_skip_fib_rule(struct sk_buff *skb, struct fib_rule *rule)
{
	struct vpnhide_port_targets *pt;
	uid_t uid = from_kuid(&init_user_ns, current_uid());
	int i;

	if (!is_hook_active(HOOK_FIB_RULE_FILL, uid))
		return false;

	/* Hide rules that belong to app-uid routing tables (table > 100)
	 * whose UID range covers any of our target UIDs. */
	if (rule->table <= 100)
		return false;

	rcu_read_lock();
	pt = rcu_dereference(global_port_targets);
	if (pt) {
		for (i = 0; i < pt->count; i++) {
			uid_t tuid = pt->targets[i].uid;
			if (rule->uid_range.start.val <= tuid &&
			    tuid <= rule->uid_range.end.val) {
				rcu_read_unlock();
				record_kmod_intercept(uid, HOOK_FIB_RULE_FILL);
				return true;
			}
		}
	}
	rcu_read_unlock();

	/* Also check global target list */
	if (is_target_uid_val(rule->uid_range.start.val)) {
		record_kmod_intercept(uid, HOOK_FIB_RULE_FILL);
		return true;
	}
	return false;
}
EXPORT_SYMBOL_GPL(vpnhide_skip_fib_rule);

/* ------------------------------------------------------------------ */
/* rt6_fill_node — hide IPv6 route from RTM_GETROUTE                   */
/* ------------------------------------------------------------------ */

bool vpnhide_skip_rt6(struct sk_buff *skb, struct fib6_info *rt)
{
	const struct net_device *dev = NULL;
	uid_t uid;

	if (!rt)
		return false;

	uid = from_kuid(&init_user_ns, current_uid());
	if (!is_hook_active(HOOK_RT6_FILL, uid))
		return false;

	dev = rt->fib6_nh->fib_nh_dev;

	if (!dev)
		return false;
	if (!is_active_vpn_ifindex(dev->ifindex))
		return false;

	record_kmod_intercept(uid, HOOK_RT6_FILL);
	return true;
}
EXPORT_SYMBOL_GPL(vpnhide_skip_rt6);

/* ------------------------------------------------------------------ */
/* rt_fill_info — hide IPv4 RTM_GETROUTE reply (connected route)       */
/* ------------------------------------------------------------------ */

bool vpnhide_skip_rt4(struct sk_buff *skb, struct rtable *rt)
{
	const struct net_device *dev;
	uid_t uid;

	if (!rt)
		return false;

	uid = from_kuid(&init_user_ns, current_uid());
	if (!is_hook_active(HOOK_RT_FILL, uid))
		return false;

	dev = rt->dst.dev;
	if (!dev)
		return false;
	if (!is_active_vpn_ifindex(dev->ifindex))
		return false;

	record_kmod_intercept(uid, HOOK_RT_FILL);
	return true;
}
EXPORT_SYMBOL_GPL(vpnhide_skip_rt4);

/* ------------------------------------------------------------------ */
/* dev_seq_show — hide interface from /proc/net/dev                    */
/* ------------------------------------------------------------------ */

bool vpnhide_skip_dev_seq(struct seq_file *seq, const struct net_device *dev)
{
	uid_t uid = from_kuid(&init_user_ns, current_uid());

	if (!is_hook_active(HOOK_DEV_SEQ, uid))
		return false;
	if (!is_active_vpn_ifindex(dev->ifindex))
		return false;

	record_kmod_intercept(uid, HOOK_DEV_SEQ);
	return true;
}
EXPORT_SYMBOL_GPL(vpnhide_skip_dev_seq);

/* ------------------------------------------------------------------ */
/* if6_seq_show — hide interface from /proc/net/if_inet6               */
/* ------------------------------------------------------------------ */

bool vpnhide_skip_if6_seq(struct seq_file *seq, struct inet6_ifaddr *ifa)
{
	uid_t uid = from_kuid(&init_user_ns, current_uid());

	if (!is_hook_active(HOOK_IF6_SEQ, uid))
		return false;
	if (!ifa || !ifa->idev || !ifa->idev->dev)
		return false;
	if (!is_active_vpn_ifindex(ifa->idev->dev->ifindex))
		return false;

	record_kmod_intercept(uid, HOOK_IF6_SEQ);
	return true;
}
EXPORT_SYMBOL_GPL(vpnhide_skip_if6_seq);

/* ------------------------------------------------------------------ */
/* tc_fill_qdisc — hide qdisc from RTM_GETQDISC                        */
/* ------------------------------------------------------------------ */

bool vpnhide_skip_tc_qdisc(struct sk_buff *skb, const struct Qdisc *q)
{
	uid_t uid = from_kuid(&init_user_ns, current_uid());

	if (!is_hook_active(HOOK_TC_FILL_QDISC, uid))
		return false;
	if (!q || !q->dev_queue || !q->dev_queue->dev)
		return false;
	if (!is_active_vpn_ifindex(q->dev_queue->dev->ifindex))
		return false;

	record_kmod_intercept(uid, HOOK_TC_FILL_QDISC);
	return true;
}
EXPORT_SYMBOL_GPL(vpnhide_skip_tc_qdisc);

/* ------------------------------------------------------------------ */
/* vpnhide_filter_seq_line                                             */
/*                                                                     */
/* Called AFTER a seq_show that cannot do early return (fib_route,    */
/* fib_trie). The caller saves seq->count before the show call and     */
/* passes it here. If the written text names a VPN interface, we       */
/* roll the seq buffer back to saved_count, discarding the line.       */
/* ------------------------------------------------------------------ */

void vpnhide_filter_seq_line(struct seq_file *seq, int saved_count)
{
	char *buf;
	int written;
	uid_t uid = from_kuid(&init_user_ns, current_uid());

	if (!is_target_uid_val(uid))
		return;

	written = (int)seq->count - saved_count;
	if (written <= 0)
		return;

	buf = seq->buf + saved_count;

	/* Scan the written text for any active VPN interface name */
	if (vh_is_vpn_name_cached(buf, written))
		seq->count = saved_count;
}
EXPORT_SYMBOL_GPL(vpnhide_filter_seq_line);

/* ------------------------------------------------------------------ */
/* ioctl hooks — SIOCG* per-interface and SIOCGIFCONF                  */
/* ------------------------------------------------------------------ */

/*
 * vpnhide_ioctl_ifname_block — called before dev_ioctl dispatches a
 * per-interface command.  Returns true (→ caller should return -ENODEV)
 * when the named interface is an active VPN.
 */
bool vpnhide_ioctl_ifname_block(const char *ifname)
{
	uid_t uid = from_kuid(&init_user_ns, current_uid());

	if (!is_hook_active(HOOK_DEV_IOCTL, uid))
		return false;
	if (!ifname || !ifname[0])
		return false;
	if (!is_active_vpn_ifname(ifname))
		return false;

	record_kmod_intercept(uid, HOOK_DEV_IOCTL);
	return true;
}
EXPORT_SYMBOL_GPL(vpnhide_ioctl_ifname_block);

/*
 * vpnhide_filter_ifconf — post-filter for SIOCGIFCONF.
 * data is the void __user * passed to dev_ifconf (points to struct ifconf).
 * Compacts the ifreq array in-place, removing VPN entries, and updates
 * ifc_len so the caller sees a shorter list.
 */
void vpnhide_filter_ifconf(void __user *data)
{
	struct ifconf __user *uifc = data;
	struct ifconf ifc;
	struct ifreq tmp;
	int n, i, dst;
	uid_t uid = from_kuid(&init_user_ns, current_uid());

	if (!is_hook_active(HOOK_SOCK_IOCTL, uid))
		return;
	if (!is_target_uid_val(uid))
		return;

	if (copy_from_user(&ifc, uifc, sizeof(ifc)))
		return;
	if (!ifc.ifc_req || ifc.ifc_len <= 0)
		return;

	n = ifc.ifc_len / (int)sizeof(struct ifreq);
	dst = 0;

	for (i = 0; i < n; i++) {
		if (copy_from_user(&tmp, &ifc.ifc_req[i], sizeof(tmp)))
			return;
		tmp.ifr_name[IFNAMSIZ - 1] = '\0';
		if (is_active_vpn_ifname(tmp.ifr_name))
			continue;
		if (dst != i) {
			if (copy_to_user(&ifc.ifc_req[dst], &tmp, sizeof(tmp)))
				return;
		}
		dst++;
	}

	if (dst < n) {
		int new_len = dst * (int)sizeof(struct ifreq);
		put_user(new_len, &uifc->ifc_len);
		record_kmod_intercept(uid, HOOK_SOCK_IOCTL);
	}
}
EXPORT_SYMBOL_GPL(vpnhide_filter_ifconf);
