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
#include <linux/mutex.h>
#include <linux/wait.h>
#include <linux/atomic.h>
#include <linux/vmalloc.h>
#include <linux/sort.h>
#include <linux/netdevice.h>

#include "vpnhide.h"

/* ------------------------------------------------------------------ */
/* Global state                                                        */
/* ------------------------------------------------------------------ */

/* Fast-path flags — checked before any RCU section.  Written under their
 * respective update locks; read with READ_ONCE on the hot path. */
wait_queue_head_t vpnhide_config_wait;
atomic_t          vpnhide_config_generation = ATOMIC_INIT(0);
atomic_t          java_stats_clear_generation = ATOMIC_INIT(0);

struct vpnhide_policy_snapshot __rcu *global_policy_snapshot;
spinlock_t policy_snapshot_lock;

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

/* Java-side stats/status written via device write() */
static char java_stats_buf[4096];
static DEFINE_MUTEX(java_stats_lock);
static char java_status_buf[256];
static DEFINE_MUTEX(java_status_lock);

/* Cover iface name written via device write() */
static char global_cover_ifname[IFNAMSIZ];
static DEFINE_SPINLOCK(cover_ifname_lock);

/* Per-open reader state for blocking read() */
struct vpnhide_dev_reader {
	unsigned long generation;
	char *buf;
	size_t buf_len;
	size_t read_pos;
};

/* ------------------------------------------------------------------ */
/* FNV-1a hash                                                         */
/* ------------------------------------------------------------------ */

bool vpnhide_debug_is_enabled(void)
{
	struct vpnhide_policy_snapshot *snapshot;
	bool enabled;

	rcu_read_lock();
	snapshot = rcu_dereference(global_policy_snapshot);
	enabled = snapshot && !!snapshot->payload.debug_enabled;
	rcu_read_unlock();
	return enabled;
}

unsigned int vpnhide_active_hooks_mask(void)
{
	struct vpnhide_policy_snapshot *snapshot;
	unsigned int mask;

	rcu_read_lock();
	snapshot = rcu_dereference(global_policy_snapshot);
	mask = snapshot ? snapshot->payload.active_hooks_mask : 0;
	rcu_read_unlock();
	return mask;
}

unsigned int vpnhide_java_hooks_mask(void)
{
	struct vpnhide_policy_snapshot *snapshot;
	unsigned int mask;

	rcu_read_lock();
	snapshot = rcu_dereference(global_policy_snapshot);
	mask = snapshot ? snapshot->payload.java_hooks_mask : 0;
	rcu_read_unlock();
	return mask;
}

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
		strscpy(nc->names[i], idata->vpns[i].name, MAX_IFACE_LEN);
		nc->hashes[i] = fnv1a_name(idata->vpns[i].name, MAX_IFACE_LEN);
	}

	spin_lock(&g_vpn_name_cache_lock);
	old = rcu_dereference_protected(g_vpn_name_cache,
					lockdep_is_held(&g_vpn_name_cache_lock));
	rcu_assign_pointer(g_vpn_name_cache, nc);
	spin_unlock(&g_vpn_name_cache_lock);

	if (old)
		kfree_rcu(old, rcu);
}

bool vpnhide_should_hide_ifname(const char *ifname)
{
	if (!ifname || !ifname[0])
		return false;
	if (!is_target_uid())
		return false;
	return is_active_vpn_ifname(ifname);
}
EXPORT_SYMBOL_GPL(vpnhide_should_hide_ifname);

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
	struct vpnhide_policy_snapshot *snapshot;
	bool found = false;
	int lo, hi, mid;

	if (uid == 0 || uid == 1000)
		return false;
	rcu_read_lock();
	snapshot = rcu_dereference(global_policy_snapshot);
	if (snapshot && snapshot->payload.targets.kmod_count > 0) {
		lo = 0;
		hi = snapshot->payload.targets.kmod_count - 1;
		while (lo <= hi) {
			mid = (lo + hi) >> 1;
			if (snapshot->payload.targets.kmod_uids[mid] == uid) {
				found = true;
				break;
			}
			if (snapshot->payload.targets.kmod_uids[mid] < uid)
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
	struct vpnhide_policy_snapshot *snapshot;
	bool found = false;
	int i;

	rcu_read_lock();
	snapshot = rcu_dereference(global_policy_snapshot);
	if (snapshot) {
		for (i = 0; i < snapshot->payload.app_hook_masks.count; i++) {
			if (snapshot->payload.app_hook_masks.masks[i].uid == uid &&
			    snapshot->payload.app_hook_masks.masks[i].has_kernel_override) {
				*out = snapshot->payload.app_hook_masks.masks[i].kernel_mask;
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
	unsigned int bit = BIT(index);
	unsigned int mask;

	/* Per-app mask fully overrides the global for that uid. */
	if (lookup_app_kernel_mask(uid, &mask))
		return !!(mask & bit);

	return !!(vpnhide_active_hooks_mask() & bit);
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

	if (old)
		kfree_rcu(old, rcu);
	return 0;
}

/* ------------------------------------------------------------------ */
/* Device open / release / read / write                               */
/* ------------------------------------------------------------------ */

static int vpnhide_dev_open(struct inode *inode, struct file *file)
{
	struct vpnhide_dev_reader *reader;

	reader = kzalloc(sizeof(*reader), GFP_KERNEL);
	if (!reader)
		return -ENOMEM;
	file->private_data = reader;
	return 0;
}

static int vpnhide_dev_release(struct inode *inode, struct file *file)
{
	struct vpnhide_dev_reader *reader = file->private_data;

	if (reader) {
		kvfree(reader->buf);
		kfree(reader);
	}
	return 0;
}

static ssize_t vpnhide_dev_read(struct file *file, char __user *buf,
				size_t count, loff_t *ppos)
{
	struct vpnhide_dev_reader *reader = file->private_data;
	size_t to_copy;

	if (!reader)
		return -EINVAL;

	if (reader->read_pos >= reader->buf_len) {
		unsigned long gen = (unsigned long)atomic_read(&vpnhide_config_generation);
		struct vpnhide_policy_snapshot *snapshot;
		int offset = 0, i;

		if (reader->generation >= gen) {
			if (from_kuid(&init_user_ns, current_uid()) != 1000)
				return 0;
			if (file->f_flags & O_NONBLOCK)
				return -EAGAIN;
			if (wait_event_interruptible(vpnhide_config_wait,
				reader->generation <
				(unsigned long)atomic_read(&vpnhide_config_generation)))
				return -ERESTARTSYS;
		}

		kvfree(reader->buf);
		reader->buf = kvmalloc(65536, GFP_KERNEL);
		if (!reader->buf)
			return -ENOMEM;

		offset += scnprintf(reader->buf + offset, 65536 - offset,
				    "version_code: %d\n", VPNHIDE_VERSION_CODE);

		offset += scnprintf(reader->buf + offset, 65536 - offset,
				    "java_hook_mask: %u\n", vpnhide_java_hooks_mask());
		offset += scnprintf(reader->buf + offset, 65536 - offset,
				    "java_stats_clear_gen: %d\n",
				    atomic_read(&java_stats_clear_generation));
		offset += scnprintf(reader->buf + offset, 65536 - offset,
				    "stats_bucket_secs: %d\n",
				    atomic_read(&stats_bucket_secs));
		offset += scnprintf(reader->buf + offset, 65536 - offset,
				    "debug_enabled: %d\n", vpnhide_debug_is_enabled());

		rcu_read_lock();
		snapshot = rcu_dereference(global_policy_snapshot);
		offset += scnprintf(reader->buf + offset, 65536 - offset,
				    "lsposed_targets:");
		if (snapshot) {
			for (i = 0; i < snapshot->payload.targets.lsposed_count; i++)
				offset += scnprintf(reader->buf + offset,
							65536 - offset, " %u",
							snapshot->payload.targets.lsposed_uids[i]);
		}
		offset += scnprintf(reader->buf + offset, 65536 - offset, "\n");

		offset += scnprintf(reader->buf + offset, 65536 - offset,
				    "iface_prefixes:");
		if (snapshot) {
			for (i = 0; i < snapshot->payload.iface_prefixes.count; i++)
				offset += scnprintf(reader->buf + offset,
							65536 - offset,
							" %s", snapshot->payload.iface_prefixes.prefixes[i]);
		}
		offset += scnprintf(reader->buf + offset, 65536 - offset, "\n");

		offset += scnprintf(reader->buf + offset, 65536 - offset,
				    "app_java_hook_mask:");
		if (snapshot) {
			for (i = 0; i < snapshot->payload.app_hook_masks.count; i++) {
				if (!snapshot->payload.app_hook_masks.masks[i].has_java_override)
					continue;
				offset += scnprintf(reader->buf + offset,
						    65536 - offset, " %u:%u",
							snapshot->payload.app_hook_masks.masks[i].uid,
							snapshot->payload.app_hook_masks.masks[i].java_mask);
			}
		}
		offset += scnprintf(reader->buf + offset, 65536 - offset, "\n");
		rcu_read_unlock();

		spin_lock(&cover_ifname_lock);
		offset += scnprintf(reader->buf + offset, 65536 - offset,
				    "cover_iface: %s\n",
				    global_cover_ifname[0] ? global_cover_ifname : "none");
		spin_unlock(&cover_ifname_lock);

		offset += scnprintf(reader->buf + offset, 65536 - offset, "\n");

		reader->buf_len = offset;
		reader->generation = (unsigned long)atomic_read(&vpnhide_config_generation);
		reader->read_pos = 0;
	}

	to_copy = min(count, reader->buf_len - reader->read_pos);
	if (copy_to_user(buf, reader->buf + reader->read_pos, to_copy))
		return -EFAULT;
	reader->read_pos += to_copy;
	return to_copy;
}

static ssize_t vpnhide_dev_write(struct file *file, const char __user *buf,
				 size_t count, loff_t *ppos)
{
	char *kbuf;

	if (count > 4096)
		return -EINVAL;
	kbuf = kmalloc(count + 1, GFP_KERNEL);
	if (!kbuf)
		return -ENOMEM;
	if (copy_from_user(kbuf, buf, count)) {
		kfree(kbuf);
		return -EFAULT;
	}
	kbuf[count] = '\0';

	if (strncmp(kbuf, "stats:", 6) == 0) {
		mutex_lock(&java_stats_lock);
		strncpy(java_stats_buf, kbuf + 6, sizeof(java_stats_buf) - 1);
		java_stats_buf[sizeof(java_stats_buf) - 1] = '\0';
		mutex_unlock(&java_stats_lock);
	} else if (strncmp(kbuf, "status:", 7) == 0) {
		mutex_lock(&java_status_lock);
		strncpy(java_status_buf, kbuf + 7, sizeof(java_status_buf) - 1);
		java_status_buf[sizeof(java_status_buf) - 1] = '\0';
		mutex_unlock(&java_status_lock);
	} else if (strcmp(kbuf, "clear_stats") == 0) {
		mutex_lock(&java_stats_lock);
		java_stats_buf[0] = '\0';
		mutex_unlock(&java_stats_lock);
		atomic_inc(&java_stats_clear_generation);
		atomic_inc(&vpnhide_config_generation);
		wake_up_all(&vpnhide_config_wait);
	} else if (strncmp(kbuf, "cover_iface:", 12) == 0) {
		char *val = kbuf + 12;
		size_t len = strlen(val);

		if (len > 0 && val[len - 1] == '\n') { val[--len] = '\0'; }
		spin_lock(&cover_ifname_lock);
		if (len == 0 || strcmp(val, "none") == 0)
			global_cover_ifname[0] = '\0';
		else
			strscpy(global_cover_ifname, val, IFNAMSIZ);
		spin_unlock(&cover_ifname_lock);
		atomic_inc(&vpnhide_config_generation);
		wake_up_all(&vpnhide_config_wait);
	}

	kfree(kbuf);
	return count;
}

/* ------------------------------------------------------------------ */
/* IOCTL dispatch                                                      */
/* ------------------------------------------------------------------ */

static void vh_free_policy_snapshot_rcu(struct rcu_head *head)
{
	struct vpnhide_policy_snapshot *snapshot =
		container_of(head, struct vpnhide_policy_snapshot, rcu);
	kvfree(snapshot);
}

int vpnhide_apply_policy(const struct vpnhide_policy_payload *payload,
			 u64 expected_generation)
{
	struct vpnhide_policy_snapshot *snapshot, *old_snapshot;
	int i, j;

	if (!payload || payload->targets.kmod_count < 0 ||
	    payload->targets.kmod_count > MAX_TARGET_UIDS ||
	    payload->targets.lsposed_count < 0 ||
	    payload->targets.lsposed_count > MAX_TARGET_UIDS ||
	    payload->ports.count < 0 || payload->ports.count > MAX_TARGET_UIDS ||
	    payload->iface_prefixes.count < 0 ||
	    payload->iface_prefixes.count > MAX_IFACE_PREFIXES ||
	    payload->app_hook_masks.count < 0 ||
	    payload->app_hook_masks.count > MAX_TARGET_UIDS)
		return -EINVAL;
	if (expected_generation && expected_generation !=
	    (u64)atomic_read(&vpnhide_config_generation))
		return -EAGAIN;

	for (i = 0; i < payload->ports.count; i++) {
		const struct vpnhide_uid_port_rules *target = &payload->ports.targets[i];
		if (target->rule_count < 0 || target->rule_count > MAX_PORT_RULES_PER_UID)
			return -EINVAL;
		for (j = 0; j < target->rule_count; j++) {
			const struct vpnhide_port_rule *rule = &target->rules[j];
			if (rule->start_port > rule->end_port ||
			    rule->protocol > VH_PROTO_BOTH)
				return -EINVAL;
		}
	}

	snapshot = kvzalloc(sizeof(*snapshot), GFP_KERNEL);
	if (!snapshot)
		return -ENOMEM;

	snapshot->payload = *payload;
	sort(snapshot->payload.targets.kmod_uids,
	     snapshot->payload.targets.kmod_count, sizeof(uid_t), uid_cmp, NULL);
	sort(snapshot->payload.targets.lsposed_uids,
	     snapshot->payload.targets.lsposed_count, sizeof(uid_t), uid_cmp, NULL);

	spin_lock(&policy_snapshot_lock);
	old_snapshot = rcu_dereference_protected(global_policy_snapshot,
			lockdep_is_held(&policy_snapshot_lock));
	rcu_assign_pointer(global_policy_snapshot, snapshot);
	spin_unlock(&policy_snapshot_lock);
	if (old_snapshot)
		call_rcu(&old_snapshot->rcu, vh_free_policy_snapshot_rcu);
	atomic_inc(&vpnhide_config_generation);
	wake_up_all(&vpnhide_config_wait);
	return 0;
}

static long handle_vpnhide_ioctl(struct file *f, unsigned int cmd,
				 unsigned long arg)
{
	void __user *uarg = (void __user *)arg;
	int ret = 0;

	if (!capable(CAP_NET_ADMIN))
		return -EPERM;

	switch (cmd) {
	case VH_SET_POLICY: {
		struct vpnhide_policy_ioctl request;
		struct vpnhide_policy_payload *payload;
		int policy_ret;

		if (copy_from_user(&request, uarg, sizeof(request)))
			return -EFAULT;
		if (request.abi_version != VPNHIDE_POLICY_ABI_VERSION ||
		    request.payload_size != sizeof(*payload) ||
		    !request.payload_ptr)
			return -EINVAL;
		payload = kvzalloc(sizeof(*payload), GFP_KERNEL);
		if (!payload)
			return -ENOMEM;
		if (copy_from_user(payload, u64_to_user_ptr(request.payload_ptr),
				   sizeof(*payload))) {
			kvfree(payload);
			return -EFAULT;
		}
		policy_ret = vpnhide_apply_policy(payload, request.expected_generation);
		kvfree(payload);
		return policy_ret;
	}

	case VH_GET_TARGETS: {
		struct vpnhide_ioctl_data *td;
		struct vpnhide_policy_snapshot *snapshot;
		int i;

		td = kzalloc(sizeof(*td), GFP_KERNEL);
		if (!td)
			return -ENOMEM;
		rcu_read_lock();
		snapshot = rcu_dereference(global_policy_snapshot);
		if (snapshot) {
			td->count = snapshot->payload.targets.kmod_count;
			for (i = 0; i < td->count; i++)
				td->uids[i] = snapshot->payload.targets.kmod_uids[i];
		}
		rcu_read_unlock();
		if (copy_to_user(uarg, td, sizeof(*td))) {
			kfree(td);
			return -EFAULT;
		}
		kfree(td);
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
			strscpy(nav->vpns[i].name,
				idata.vpns[i].name, MAX_IFACE_LEN);
		}
		spin_lock(&active_vpns_lock);
		old = rcu_dereference_protected(global_active_vpns,
				lockdep_is_held(&active_vpns_lock));
		rcu_assign_pointer(global_active_vpns, nav);
		spin_unlock(&active_vpns_lock);
		if (old) kfree_rcu(old, rcu);

		vh_rebuild_name_cache(&idata);
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

	case VH_SET_COVER_IFACE: {
		struct vpnhide_cover_iface ci;

		if (copy_from_user(&ci, uarg, sizeof(ci)))
			return -EFAULT;
		atomic_set(&global_cover_ifindex, (int)ci.ifindex);
		break;
	}

	case VH_GET_JAVA_HOOK_MASK: {
		u32 mask = vpnhide_java_hooks_mask();

		if (copy_to_user(uarg, &mask, sizeof(mask)))
			return -EFAULT;
		break;
	}

	case VH_GET_APP_HOOK_MASKS: {
		struct vpnhide_app_hook_ioctl_data *amd;
		struct vpnhide_policy_snapshot *snapshot;

		amd = kzalloc(sizeof(*amd), GFP_KERNEL);
		if (!amd)
			return -ENOMEM;
		rcu_read_lock();
		snapshot = rcu_dereference(global_policy_snapshot);
		if (snapshot) {
			*amd = snapshot->payload.app_hook_masks;
		}
		rcu_read_unlock();
		if (copy_to_user(uarg, amd, sizeof(*amd))) {
			kfree(amd);
			return -EFAULT;
		}
		kfree(amd);
		break;
	}

	case VH_GET_STATS: {
		struct vpnhide_kmod_stats_data *sd;
		int i, j;

		sd = kzalloc(sizeof(*sd), GFP_KERNEL);
		if (!sd)
			return -ENOMEM;

		spin_lock(&intercept_ring.lock);
		for (i = 0; i < BUCKETS_COUNT; i++) {
			uid_t r_uid = intercept_ring.uid[i];

			if (!r_uid)
				continue;
			for (j = 0; j < sd->count; j++) {
				if (sd->stats[j].uid == r_uid)
					goto found;
			}
			if (sd->count < MAX_STATS_UIDS) {
				sd->stats[sd->count].uid = r_uid;
				j = sd->count++;
			} else {
				continue;
			}
found:
			switch (intercept_ring.type[i]) {
			case HOOK_SETSOCKOPT:
			case HOOK_GETSOCKOPT:
				sd->stats[j].sockopt_count++;
				break;
			case HOOK_RTNL_FILL:
			case HOOK_INET6_FILL:
			case HOOK_INET_FILL:
			case HOOK_FIB_DUMP:
			case HOOK_RT6_FILL:
			case HOOK_RT_FILL:
				sd->stats[j].netlink_count++;
				break;
			case HOOK_GETDENTS64:
			case HOOK_OPENAT ... HOOK_READLINKAT:
				sd->stats[j].proc_count++;
				break;
			case HOOK_CONNECT:
			case HOOK_BIND:
				sd->stats[j].connect_count++;
				break;
			case HOOK_GETNAME_INET:
			case HOOK_GETNAME_INET6:
				sd->stats[j].getname_count++;
				break;
			default:
				sd->stats[j].ioctl_count++;
				break;
			}
		}
		spin_unlock(&intercept_ring.lock);

		if (copy_to_user(uarg, sd, sizeof(*sd))) {
			kfree(sd);
			return -EFAULT;
		}
		kfree(sd);
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
		u32 mask = vpnhide_active_hooks_mask();

		if (copy_to_user(uarg, &mask, sizeof(mask)))
			return -EFAULT;
		break;
	}

	case VH_GET_LSPOSED_TARGETS: {
		struct vpnhide_ioctl_data *td;
		struct vpnhide_policy_snapshot *snapshot;
		int i;

		td = kzalloc(sizeof(*td), GFP_KERNEL);
		if (!td)
			return -ENOMEM;
		rcu_read_lock();
		snapshot = rcu_dereference(global_policy_snapshot);
		if (snapshot) {
			td->count = snapshot->payload.targets.lsposed_count;
			for (i = 0; i < td->count; i++)
				td->uids[i] = snapshot->payload.targets.lsposed_uids[i];
		}
		rcu_read_unlock();
		if (copy_to_user(uarg, td, sizeof(*td))) {
			kfree(td);
			return -EFAULT;
		}
		kfree(td);
		break;
	}

	case VH_GET_IFACE_PREFIXES: {
		struct vpnhide_iface_ioctl_data pd;
		struct vpnhide_policy_snapshot *snapshot;

		memset(&pd, 0, sizeof(pd));
		rcu_read_lock();
		snapshot = rcu_dereference(global_policy_snapshot);
		if (snapshot) {
			pd = snapshot->payload.iface_prefixes;
		}
		rcu_read_unlock();
		if (copy_to_user(uarg, &pd, sizeof(pd)))
			return -EFAULT;
		break;
	}

	case VH_GET_JAVA_STATS: {
		mutex_lock(&java_stats_lock);
		if (copy_to_user(uarg, java_stats_buf, sizeof(java_stats_buf))) {
			mutex_unlock(&java_stats_lock);
			return -EFAULT;
		}
		mutex_unlock(&java_stats_lock);
		break;
	}

	case VH_GET_HOOK_STATUS: {
		mutex_lock(&java_status_lock);
		if (copy_to_user(uarg, java_status_buf, sizeof(java_status_buf))) {
			mutex_unlock(&java_status_lock);
			return -EFAULT;
		}
		mutex_unlock(&java_status_lock);
		break;
	}

	case VH_GET_VERSION: {
		int version = VPNHIDE_VERSION_CODE;
		if (copy_to_user(uarg, &version, sizeof(version)))
			return -EFAULT;
		ret = 0;
		break;
	}

	default:
		ret = -ENOTTY;
		break;
	}
	return ret;
}

static const struct file_operations vpnhide_fops = {
	.owner          = THIS_MODULE,
	.open           = vpnhide_dev_open,
	.release        = vpnhide_dev_release,
	.read           = vpnhide_dev_read,
	.write          = vpnhide_dev_write,
	.unlocked_ioctl = handle_vpnhide_ioctl,
	.compat_ioctl   = handle_vpnhide_ioctl,
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

	spin_lock_init(&policy_snapshot_lock);
	spin_lock_init(&spoof_ip_lock);
	spin_lock_init(&active_vpns_lock);
	spin_lock_init(&g_vpn_name_cache_lock);
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
	struct vpnhide_active_vpns      *av;
	struct vh_vpn_name_cache        *nc;
	struct vpnhide_spoof_ip_rcu     *si;
	struct vpnhide_policy_snapshot  *snapshot;

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

	av = rcu_dereference_protected(global_active_vpns, 1);
	rcu_assign_pointer(global_active_vpns, NULL);

	nc = rcu_dereference_protected(g_vpn_name_cache, 1);
	rcu_assign_pointer(g_vpn_name_cache, NULL);

	si = rcu_dereference_protected(global_spoof_ip, 1);
	rcu_assign_pointer(global_spoof_ip, NULL);

	snapshot = rcu_dereference_protected(global_policy_snapshot, 1);
	rcu_assign_pointer(global_policy_snapshot, NULL);

	synchronize_rcu();
	kfree(av);
	kfree(nc);
	kfree(si);
	kvfree(snapshot);

	pr_info(MODNAME ": unloaded\n");
}

late_initcall(vpnhide_init);
module_exit(vpnhide_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("VPNHide Next — in-tree kernel VPN hiding subsystem");
MODULE_AUTHOR("soranerai");
