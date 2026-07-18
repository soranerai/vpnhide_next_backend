// SPDX-License-Identifier: GPL-2.0
/*
 * vpnhide — core state, IOCTL handler, helpers
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/rcupdate.h>
#include <linux/spinlock.h>
#include <linux/wait.h>
#include <linux/atomic.h>
#include <linux/sort.h>
#include <linux/netdevice.h>

#include "vpnhide.h"

/* ------------------------------------------------------------------ */
/* Global state                                                        */
/* ------------------------------------------------------------------ */

bool          debug_enabled;
unsigned int  active_hooks_mask = 0xFFFFFFFF;

struct vpnhide_app_hook_masks __rcu *global_app_hook_masks;
spinlock_t app_hook_masks_update_lock;

struct vpnhide_targets __rcu *global_targets;
spinlock_t targets_update_lock;

struct vpnhide_targets __rcu *global_lsposed_targets;
spinlock_t lsposed_targets_update_lock;

wait_queue_head_t vpnhide_config_wait;
atomic_t          vpnhide_config_generation = ATOMIC_INIT(0);
atomic_t          java_stats_clear_generation = ATOMIC_INIT(0);
unsigned int      java_hooks_mask;

struct vpnhide_port_targets __rcu *global_port_targets;
spinlock_t port_targets_update_lock;

struct vpnhide_iface_prefixes __rcu *global_iface_prefixes;
spinlock_t iface_prefixes_lock;

struct vpnhide_spoof_ip_rcu __rcu *global_spoof_ip;
spinlock_t spoof_ip_lock;

struct vpnhide_active_vpns __rcu *global_active_vpns;
spinlock_t active_vpns_lock;

struct vh_vpn_name_cache __rcu *g_vpn_name_cache;
spinlock_t g_vpn_name_cache_lock;

atomic_t global_cover_ifindex = ATOMIC_INIT(0);
bool     g_stats_pkts_first;
atomic_t stats_bucket_secs = ATOMIC_INIT(3);

/* Rolling intercept stats: BUCKETS_COUNT circular buckets */
static struct {
	spinlock_t lock;
	u32 uid[BUCKETS_COUNT];
	int type[BUCKETS_COUNT];
	ktime_t ts[BUCKETS_COUNT];
	int head;
} intercept_ring;

/* ------------------------------------------------------------------ */
/* FNV-1a hash                                                         */
/* ------------------------------------------------------------------ */

u32 fnv1a_name(const char *s, int maxlen)
{
	u32 h = 2166136261u;
	int i;

	for (i = 0; i < maxlen && s[i]; i++) {
		h ^= (u8)s[i];
		h *= 16777619u;
	}
	return h;
}

/* ------------------------------------------------------------------ */
/* Name cache                                                          */
/* ------------------------------------------------------------------ */

void vh_rebuild_name_cache(const struct vpnhide_vpn_ifindexes *idata)
{
	struct vh_vpn_name_cache *nc, *old;
	int i;

	nc = kzalloc(sizeof(*nc), GFP_KERNEL);
	if (!nc)
		return;

	nc->count = min(idata->count, MAX_ACTIVE_VPNS);
	for (i = 0; i < nc->count; i++) {
		strlcpy(nc->names[i], idata->vpns[i].name, MAX_IFACE_LEN);
		nc->hashes[i] = fnv1a_name(idata->vpns[i].name, MAX_IFACE_LEN);
	}

	spin_lock(&g_vpn_name_cache_lock);
	old = rcu_dereference_protected(g_vpn_name_cache,
					lockdep_is_held(&g_vpn_name_cache_lock));
	rcu_assign_pointer(g_vpn_name_cache, nc);
	spin_unlock(&g_vpn_name_cache_lock);

	if (old) {
		synchronize_rcu();
		kfree(old);
	}
}

bool vh_is_vpn_name_cached(const char *name, size_t len)
{
	struct vh_vpn_name_cache *nc;
	u32 h = fnv1a_name(name, len);
	bool found = false;
	int i;

	rcu_read_lock();
	nc = rcu_dereference(g_vpn_name_cache);
	if (nc) {
		for (i = 0; i < nc->count; i++) {
			if (nc->hashes[i] == h &&
			    !strncmp(nc->names[i], name, MAX_IFACE_LEN)) {
				found = true;
				break;
			}
		}
	}
	rcu_read_unlock();
	return found;
}

/* ------------------------------------------------------------------ */
/* Target UID lookup — binary search O(log n)                         */
/* ------------------------------------------------------------------ */

static int uid_cmp(const void *a, const void *b)
{
	uid_t ua = *(const uid_t *)a;
	uid_t ub = *(const uid_t *)b;
	return (ua > ub) - (ua < ub);
}

bool is_target_uid_val(uid_t uid)
{
	struct vpnhide_targets *t;
	bool found = false;
	int lo, hi, mid;

	if (uid == 0 || uid == 1000)
		return false;

	rcu_read_lock();
	t = rcu_dereference(global_targets);
	if (t && t->count > 0) {
		lo = 0;
		hi = t->count - 1;
		while (lo <= hi) {
			mid = (lo + hi) >> 1;
			if (t->uids[mid] == uid) {
				found = true;
				break;
			}
			if (t->uids[mid] < uid)
				lo = mid + 1;
			else
				hi = mid - 1;
		}
	}
	rcu_read_unlock();
	return found;
}

bool is_target_uid(void)
{
	return is_target_uid_val(
		from_kuid(&init_user_ns, current_uid()));
}

/* ------------------------------------------------------------------ */
/* App-specific hook mask                                              */
/* ------------------------------------------------------------------ */

bool lookup_app_kernel_mask(uid_t uid, unsigned int *out)
{
	struct vpnhide_app_hook_masks *ahm;
	bool found = false;
	int i;

	rcu_read_lock();
	ahm = rcu_dereference(global_app_hook_masks);
	if (ahm) {
		for (i = 0; i < ahm->count; i++) {
			if (ahm->masks[i].uid == uid) {
				*out = ahm->masks[i].kernel_mask;
				found = true;
				break;
			}
		}
	}
	rcu_read_unlock();
	return found;
}

bool is_hook_active(enum vpnhide_hook_idx index, uid_t uid)
{
	unsigned int app_mask;
	unsigned int bit = BIT(index);

	if (!(READ_ONCE(active_hooks_mask) & bit))
		return false;
	if (lookup_app_kernel_mask(uid, &app_mask))
		return !!(app_mask & bit);
	return is_target_uid_val(uid);
}

/* ------------------------------------------------------------------ */
/* Active VPN interface checks                                         */
/* ------------------------------------------------------------------ */

bool is_active_vpn_ifindex(u32 ifindex)
{
	struct vpnhide_active_vpns *vpns;
	bool found = false;
	int i;

	rcu_read_lock();
	vpns = rcu_dereference(global_active_vpns);
	if (vpns) {
		for (i = 0; i < vpns->count; i++) {
			if ((u32)vpns->vpns[i].ifindex == ifindex) {
				found = true;
				break;
			}
		}
	}
	rcu_read_unlock();
	return found;
}

bool is_active_vpn_ifname(const char *name)
{
	struct vpnhide_active_vpns *vpns;
	bool found = false;
	int i;

	rcu_read_lock();
	vpns = rcu_dereference(global_active_vpns);
	if (vpns) {
		for (i = 0; i < vpns->count; i++) {
			if (!strncmp(vpns->vpns[i].name, name, MAX_IFACE_LEN)) {
				found = true;
				break;
			}
		}
	}
	rcu_read_unlock();
	return found;
}

/* ------------------------------------------------------------------ */
/* Intercept stats                                                     */
/* ------------------------------------------------------------------ */

void record_kmod_intercept(uid_t uid, int type)
{
	spin_lock(&intercept_ring.lock);
	intercept_ring.uid[intercept_ring.head]  = uid;
	intercept_ring.type[intercept_ring.head] = type;
	intercept_ring.ts[intercept_ring.head]   = ktime_get();
	intercept_ring.head = (intercept_ring.head + 1) % BUCKETS_COUNT;
	spin_unlock(&intercept_ring.lock);
}

/* ------------------------------------------------------------------ */
/* Spoof IP                                                            */
/* ------------------------------------------------------------------ */

void get_spoof_ip(struct vpnhide_spoof_ip *dst)
{
	struct vpnhide_spoof_ip_rcu *s;

	rcu_read_lock();
	s = rcu_dereference(global_spoof_ip);
	if (s)
		*dst = s->sip;
	else
		memset(dst, 0, sizeof(*dst));
	rcu_read_unlock();
}

int update_spoof_ip(const struct vpnhide_spoof_ip *sip)
{
	struct vpnhide_spoof_ip_rcu *n, *old;

	n = kmalloc(sizeof(*n), GFP_KERNEL);
	if (!n)
		return -ENOMEM;
	n->sip = *sip;

	spin_lock(&spoof_ip_lock);
	old = rcu_dereference_protected(global_spoof_ip,
					lockdep_is_held(&spoof_ip_lock));
	rcu_assign_pointer(global_spoof_ip, n);
	spin_unlock(&spoof_ip_lock);

	if (old) {
		synchronize_rcu();
		kfree(old);
	}
	return 0;
}

/* ------------------------------------------------------------------ */
/* IOCTL dispatch                                                      */
/* ------------------------------------------------------------------ */

static long handle_vpnhide_ioctl(struct file *f, unsigned int cmd,
				 unsigned long arg)
{
	void __user *uarg = (void __user *)arg;
	int ret = 0;

	switch (cmd) {

	case VH_SET_TARGETS: {
		struct vpnhide_ioctl_data td;
		struct vpnhide_targets *nt, *old;
		int i;

		if (copy_from_user(&td, uarg, sizeof(td)))
			return -EFAULT;
		if (td.count < 0 || td.count > MAX_TARGET_UIDS)
			return -EINVAL;
		nt = kzalloc(sizeof(*nt), GFP_KERNEL);
		if (!nt)
			return -ENOMEM;
		nt->count = td.count;
		for (i = 0; i < td.count; i++)
			nt->uids[i] = td.uids[i];
		sort(nt->uids, nt->count, sizeof(uid_t), uid_cmp, NULL);

		spin_lock(&targets_update_lock);
		old = rcu_dereference_protected(global_targets,
				lockdep_is_held(&targets_update_lock));
		rcu_assign_pointer(global_targets, nt);
		spin_unlock(&targets_update_lock);
		if (old) { synchronize_rcu(); kfree(old); }
		atomic_inc(&vpnhide_config_generation);
		wake_up_all(&vpnhide_config_wait);
		break;
	}

	case VH_GET_TARGETS: {
		struct vpnhide_ioctl_data td = {};
		struct vpnhide_targets *t;
		int i;

		rcu_read_lock();
		t = rcu_dereference(global_targets);
		if (t) {
			td.count = t->count;
			for (i = 0; i < t->count; i++)
				td.uids[i] = t->uids[i];
		}
		rcu_read_unlock();
		if (copy_to_user(uarg, &td, sizeof(td)))
			return -EFAULT;
		break;
	}

	case VH_SET_LSPOSED_TARGETS: {
		struct vpnhide_ioctl_data td;
		struct vpnhide_targets *nt, *old;
		int i;

		if (copy_from_user(&td, uarg, sizeof(td)))
			return -EFAULT;
		if (td.count < 0 || td.count > MAX_TARGET_UIDS)
			return -EINVAL;
		nt = kzalloc(sizeof(*nt), GFP_KERNEL);
		if (!nt)
			return -ENOMEM;
		nt->count = td.count;
		for (i = 0; i < td.count; i++)
			nt->uids[i] = td.uids[i];
		sort(nt->uids, nt->count, sizeof(uid_t), uid_cmp, NULL);

		spin_lock(&lsposed_targets_update_lock);
		old = rcu_dereference_protected(global_lsposed_targets,
				lockdep_is_held(&lsposed_targets_update_lock));
		rcu_assign_pointer(global_lsposed_targets, nt);
		spin_unlock(&lsposed_targets_update_lock);
		if (old) { synchronize_rcu(); kfree(old); }
		break;
	}

	case VH_SET_PORT_TARGETS: {
		struct vpnhide_port_ioctl_data pd;
		struct vpnhide_port_targets *np, *old;

		if (copy_from_user(&pd, uarg, sizeof(pd)))
			return -EFAULT;
		if (pd.count < 0 || pd.count > MAX_TARGET_UIDS)
			return -EINVAL;
		np = kzalloc(sizeof(*np), GFP_KERNEL);
		if (!np)
			return -ENOMEM;
		np->count = pd.count;
		memcpy(np->targets, pd.targets,
		       pd.count * sizeof(np->targets[0]));

		spin_lock(&port_targets_update_lock);
		old = rcu_dereference_protected(global_port_targets,
				lockdep_is_held(&port_targets_update_lock));
		rcu_assign_pointer(global_port_targets, np);
		spin_unlock(&port_targets_update_lock);
		if (old) { synchronize_rcu(); kfree(old); }
		break;
	}

	case VH_SET_VPN_IFINDEXES: {
		struct vpnhide_vpn_ifindexes idata;
		struct vpnhide_active_vpns *nav, *old;
		int i;

		if (copy_from_user(&idata, uarg, sizeof(idata)))
			return -EFAULT;
		if (idata.count < 0 || idata.count > MAX_ACTIVE_VPNS)
			return -EINVAL;
		nav = kzalloc(sizeof(*nav), GFP_KERNEL);
		if (!nav)
			return -ENOMEM;
		nav->count = min(idata.count, MAX_ACTIVE_VPNS);
		for (i = 0; i < nav->count; i++) {
			nav->vpns[i].ifindex = idata.vpns[i].ifindex;
			strlcpy(nav->vpns[i].name,
				idata.vpns[i].name, MAX_IFACE_LEN);
		}
		spin_lock(&active_vpns_lock);
		old = rcu_dereference_protected(global_active_vpns,
				lockdep_is_held(&active_vpns_lock));
		rcu_assign_pointer(global_active_vpns, nav);
		spin_unlock(&active_vpns_lock);
		if (old) { synchronize_rcu(); kfree(old); }

		vh_rebuild_name_cache(&idata);
		atomic_inc(&vpnhide_config_generation);
		wake_up_all(&vpnhide_config_wait);
		break;
	}

	case VH_SET_DEBUG: {
		u32 val;

		if (copy_from_user(&val, uarg, sizeof(val)))
			return -EFAULT;
		WRITE_ONCE(debug_enabled, !!val);
		break;
	}

	case VH_SET_ACTIVE_HOOKS: {
		u32 mask;

		if (copy_from_user(&mask, uarg, sizeof(mask)))
			return -EFAULT;
		WRITE_ONCE(active_hooks_mask, mask);
		atomic_inc(&vpnhide_config_generation);
		wake_up_all(&vpnhide_config_wait);
		break;
	}

	case VH_SET_SPOOF_IP: {
		struct vpnhide_spoof_ip sip;

		if (copy_from_user(&sip, uarg, sizeof(sip)))
			return -EFAULT;
		ret = update_spoof_ip(&sip);
		break;
	}

	case VH_SET_IFACE_PREFIXES: {
		struct vpnhide_iface_ioctl_data pd;
		struct vpnhide_iface_prefixes *np, *old;

		if (copy_from_user(&pd, uarg, sizeof(pd)))
			return -EFAULT;
		if (pd.count < 0 || pd.count > MAX_IFACE_PREFIXES)
			return -EINVAL;
		np = kzalloc(sizeof(*np), GFP_KERNEL);
		if (!np)
			return -ENOMEM;
		np->count = pd.count;
		memcpy(np->prefixes, pd.prefixes,
		       pd.count * MAX_IFACE_LEN);

		spin_lock(&iface_prefixes_lock);
		old = rcu_dereference_protected(global_iface_prefixes,
				lockdep_is_held(&iface_prefixes_lock));
		rcu_assign_pointer(global_iface_prefixes, np);
		spin_unlock(&iface_prefixes_lock);
		if (old) { synchronize_rcu(); kfree(old); }
		break;
	}

	case VH_SET_COVER_IFACE: {
		struct vpnhide_cover_iface ci;

		if (copy_from_user(&ci, uarg, sizeof(ci)))
			return -EFAULT;
		atomic_set(&global_cover_ifindex, (int)ci.ifindex);
		break;
	}

	case VH_SET_JAVA_HOOK_MASK: {
		u32 mask;

		if (copy_from_user(&mask, uarg, sizeof(mask)))
			return -EFAULT;
		WRITE_ONCE(java_hooks_mask, mask);
		atomic_inc(&vpnhide_config_generation);
		wake_up_all(&vpnhide_config_wait);
		break;
	}

	case VH_GET_JAVA_HOOK_MASK: {
		u32 mask = READ_ONCE(java_hooks_mask);

		if (copy_to_user(uarg, &mask, sizeof(mask)))
			return -EFAULT;
		break;
	}

	case VH_SET_APP_HOOK_MASKS: {
		struct vpnhide_app_hook_ioctl_data amd;
		struct vpnhide_app_hook_masks *nm, *old;

		if (copy_from_user(&amd, uarg, sizeof(amd)))
			return -EFAULT;
		if (amd.count < 0 || amd.count > MAX_TARGET_UIDS)
			return -EINVAL;
		nm = kzalloc(sizeof(*nm), GFP_KERNEL);
		if (!nm)
			return -ENOMEM;
		nm->count = amd.count;
		memcpy(nm->masks, amd.masks,
		       amd.count * sizeof(nm->masks[0]));

		spin_lock(&app_hook_masks_update_lock);
		old = rcu_dereference_protected(global_app_hook_masks,
				lockdep_is_held(&app_hook_masks_update_lock));
		rcu_assign_pointer(global_app_hook_masks, nm);
		spin_unlock(&app_hook_masks_update_lock);
		if (old) { synchronize_rcu(); kfree(old); }
		break;
	}

	case VH_GET_APP_HOOK_MASKS: {
		struct vpnhide_app_hook_ioctl_data amd = {};
		struct vpnhide_app_hook_masks *am;

		rcu_read_lock();
		am = rcu_dereference(global_app_hook_masks);
		if (am) {
			amd.count = am->count;
			memcpy(amd.masks, am->masks,
			       am->count * sizeof(amd.masks[0]));
		}
		rcu_read_unlock();
		if (copy_to_user(uarg, &amd, sizeof(amd)))
			return -EFAULT;
		break;
	}

	case VH_GET_STATS: {
		/* Aggregate intercept ring into per-UID stats */
		struct vpnhide_kmod_stats_data sd = {};
		int i, j;

		spin_lock(&intercept_ring.lock);
		for (i = 0; i < BUCKETS_COUNT; i++) {
			uid_t r_uid = intercept_ring.uid[i];

			if (!r_uid)
				continue;
			for (j = 0; j < sd.count; j++) {
				if (sd.stats[j].uid == r_uid)
					goto found;
			}
			if (sd.count < MAX_STATS_UIDS) {
				sd.stats[sd.count].uid = r_uid;
				j = sd.count++;
			} else {
				continue;
			}
found:
			switch (intercept_ring.type[i]) {
			case HOOK_SETSOCKOPT:
			case HOOK_GETSOCKOPT:
				sd.stats[j].sockopt_count++;
				break;
			case HOOK_RTNL_FILL:
			case HOOK_INET6_FILL:
			case HOOK_INET_FILL:
			case HOOK_FIB_DUMP:
			case HOOK_RT6_FILL:
			case HOOK_RT_FILL:
				sd.stats[j].netlink_count++;
				break;
			case HOOK_GETDENTS64:
			case HOOK_OPENAT ... HOOK_READLINKAT:
				sd.stats[j].proc_count++;
				break;
			case HOOK_CONNECT:
			case HOOK_BIND:
				sd.stats[j].connect_count++;
				break;
			case HOOK_GETNAME_INET:
			case HOOK_GETNAME_INET6:
				sd.stats[j].getname_count++;
				break;
			default:
				sd.stats[j].ioctl_count++;
				break;
			}
		}
		spin_unlock(&intercept_ring.lock);

		if (copy_to_user(uarg, &sd, sizeof(sd)))
			return -EFAULT;
		break;
	}

	case VH_CLEAR_STATS:
		spin_lock(&intercept_ring.lock);
		memset(intercept_ring.uid,  0, sizeof(intercept_ring.uid));
		memset(intercept_ring.type, 0, sizeof(intercept_ring.type));
		memset(intercept_ring.ts,   0, sizeof(intercept_ring.ts));
		intercept_ring.head = 0;
		spin_unlock(&intercept_ring.lock);
		break;

	case VH_SET_STATS_WINDOW: {
		u32 secs;

		if (copy_from_user(&secs, uarg, sizeof(secs)))
			return -EFAULT;
		atomic_set(&stats_bucket_secs, secs);
		break;
	}

	case VH_GET_ACTIVE_HOOKS: {
		u32 mask = READ_ONCE(active_hooks_mask);

		if (copy_to_user(uarg, &mask, sizeof(mask)))
			return -EFAULT;
		break;
	}

	default:
		ret = -ENOTTY;
		break;
	}
	return ret;
}

static const struct file_operations vpnhide_fops = {
	.unlocked_ioctl = handle_vpnhide_ioctl,
	.compat_ioctl   = handle_vpnhide_ioctl,
	.owner          = THIS_MODULE,
};

static struct miscdevice vpnhide_misc = {
	.minor = MISC_DYNAMIC_MINOR,
	.name  = MODNAME,
	.fops  = &vpnhide_fops,
	.mode  = 0666,
};

/* ------------------------------------------------------------------ */
/* Module init / exit                                                  */
/* ------------------------------------------------------------------ */

static int __init vpnhide_init(void)
{
	int ret;

	spin_lock_init(&targets_update_lock);
	spin_lock_init(&lsposed_targets_update_lock);
	spin_lock_init(&port_targets_update_lock);
	spin_lock_init(&iface_prefixes_lock);
	spin_lock_init(&spoof_ip_lock);
	spin_lock_init(&active_vpns_lock);
	spin_lock_init(&g_vpn_name_cache_lock);
	spin_lock_init(&app_hook_masks_update_lock);
	spin_lock_init(&intercept_ring.lock);
	init_waitqueue_head(&vpnhide_config_wait);

	ret = misc_register(&vpnhide_misc);
	if (ret) {
		pr_err(MODNAME ": misc_register failed: %d\n", ret);
		return ret;
	}

	pr_info(MODNAME ": loaded (in-tree build)\n");
	return 0;
}

static void __exit vpnhide_exit(void)
{
	struct vpnhide_targets          *t;
	struct vpnhide_port_targets     *pt;
	struct vpnhide_active_vpns      *av;
	struct vh_vpn_name_cache        *nc;
	struct vpnhide_spoof_ip_rcu     *si;
	struct vpnhide_iface_prefixes   *ip;
	struct vpnhide_app_hook_masks   *am;

	misc_deregister(&vpnhide_misc);

#define VH_FREE_RCU(ptr, lock) do {                             \
	spin_lock(&(lock));                                     \
	ptr = rcu_dereference_protected(ptr,                    \
		lockdep_is_held(&(lock)));                      \
	rcu_assign_pointer(ptr, NULL);                          \
	spin_unlock(&(lock));                                   \
	synchronize_rcu();                                      \
	kfree(ptr);                                             \
} while (0)

	t  = rcu_dereference_protected(global_targets, 1);
	rcu_assign_pointer(global_targets, NULL);

	pt = rcu_dereference_protected(global_port_targets, 1);
	rcu_assign_pointer(global_port_targets, NULL);

	av = rcu_dereference_protected(global_active_vpns, 1);
	rcu_assign_pointer(global_active_vpns, NULL);

	nc = rcu_dereference_protected(g_vpn_name_cache, 1);
	rcu_assign_pointer(g_vpn_name_cache, NULL);

	si = rcu_dereference_protected(global_spoof_ip, 1);
	rcu_assign_pointer(global_spoof_ip, NULL);

	ip = rcu_dereference_protected(global_iface_prefixes, 1);
	rcu_assign_pointer(global_iface_prefixes, NULL);

	am = rcu_dereference_protected(global_app_hook_masks, 1);
	rcu_assign_pointer(global_app_hook_masks, NULL);

	synchronize_rcu();
	kfree(t);
	kfree(pt);
	kfree(av);
	kfree(nc);
	kfree(si);
	kfree(ip);
	kfree(am);

	pr_info(MODNAME ": unloaded\n");
}

late_initcall(vpnhide_init);
module_exit(vpnhide_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("VPNHide Next — in-tree kernel VPN hiding subsystem");
MODULE_AUTHOR("soranerai");
