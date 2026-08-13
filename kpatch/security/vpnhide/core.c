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
#include <linux/timekeeping.h>
#include <linux/eventfd.h>
#include <linux/version.h>
#include <net/ipv6.h>

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
/* Current-session cumulative intercept statistics. */
struct vh_uid_stats_total {
	uid_t uid;
	u64 ioctl_count;
	u64 netlink_count;
	u64 proc_count;
	u64 sockopt_count;
	u64 connect_count;
	u64 getname_count;
	u64 port_count;
	u64 java_pm_count;
	u64 java_um_count;
	u64 java_nc_count;
	u64 java_ni_count;
	u64 java_net_count;
	u64 java_lp_count;
	u64 java_cs_count;
};

static struct {
	spinlock_t lock;
	struct vh_uid_stats_total *stats;
	u32 count;
} intercept_stats;
static DEFINE_MUTEX(policy_apply_lock);
static atomic64_t intercept_stats_sequence = ATOMIC64_INIT(0);

#define VPNHIDE_PORT_STATS_CAPACITY 65536U
#define VPNHIDE_PORT_STATS_MASK (VPNHIDE_PORT_STATS_CAPACITY - 1)
#define VPNHIDE_PORT_STATS_TTL (6UL * 60 * 60 * HZ)
#define VPNHIDE_PORT_STAT_EMPTY 0
#define VPNHIDE_PORT_STAT_USED 1
#define VPNHIDE_PORT_STAT_TOMBSTONE 2

struct vh_port_stats_total {
	uid_t uid;
	u16 port;
	u8 protocol;
	u8 state;
	u64 count;
	unsigned long last_seen;
};

static struct vh_port_stats_total *port_stats;
static u64 port_stats_dropped;
static DEFINE_SPINLOCK(port_stats_lock);

static u32 port_stats_hash(uid_t uid, u16 port, u8 protocol)
{
	u32 value = (u32)uid * 0x9e3779b1U;
	value ^= (u32)port * 0x85ebca6bU;
	value ^= (u32)protocol * 0xc2b2ae35U;
	value ^= value >> 16;
	return value;
}

void record_port_intercept(uid_t uid, u16 port, u8 protocol)
{
	u32 hash, probe, first_tombstone = VPNHIDE_PORT_STATS_CAPACITY;

	record_kmod_intercept(uid, HOOK_PORT);
	if (!port_stats || !port || protocol > VH_PROTO_UDP)
		return;

	hash = port_stats_hash(uid, port, protocol);
	spin_lock(&port_stats_lock);
	for (probe = 0; probe < VPNHIDE_PORT_STATS_CAPACITY; probe++) {
		u32 index = (hash + probe) & VPNHIDE_PORT_STATS_MASK;
		struct vh_port_stats_total *entry = &port_stats[index];

		if (entry->state == VPNHIDE_PORT_STAT_USED && entry->uid == uid &&
		    entry->port == port && entry->protocol == protocol) {
			entry->count++;
			entry->last_seen = jiffies;
			spin_unlock(&port_stats_lock);
			return;
		}
		if (entry->state == VPNHIDE_PORT_STAT_TOMBSTONE &&
		    first_tombstone == VPNHIDE_PORT_STATS_CAPACITY)
			first_tombstone = index;
		if (entry->state == VPNHIDE_PORT_STAT_EMPTY) {
			if (first_tombstone != VPNHIDE_PORT_STATS_CAPACITY)
				entry = &port_stats[first_tombstone];
			entry->uid = uid;
			entry->port = port;
			entry->protocol = protocol;
			entry->count = 1;
			entry->last_seen = jiffies;
			entry->state = VPNHIDE_PORT_STAT_USED;
			spin_unlock(&port_stats_lock);
			return;
		}
	}
	if (first_tombstone != VPNHIDE_PORT_STATS_CAPACITY) {
		struct vh_port_stats_total *entry = &port_stats[first_tombstone];
		entry->uid = uid;
		entry->port = port;
		entry->protocol = protocol;
		entry->count = 1;
		entry->last_seen = jiffies;
		entry->state = VPNHIDE_PORT_STAT_USED;
		spin_unlock(&port_stats_lock);
		return;
	}
	port_stats_dropped++;
	spin_unlock(&port_stats_lock);
}

static u32 count_live_port_stats_locked(void)
{
	u32 i, count = 0;

	if (!port_stats)
		return 0;
	for (i = 0; i < VPNHIDE_PORT_STATS_CAPACITY; i++) {
		struct vh_port_stats_total *entry = &port_stats[i];
		if (entry->state != VPNHIDE_PORT_STAT_USED)
			continue;
		if (time_after(jiffies, entry->last_seen + VPNHIDE_PORT_STATS_TTL)) {
			entry->state = VPNHIDE_PORT_STAT_TOMBSTONE;
			continue;
		}
		count++;
	}
	return count;
}

struct vpnhide_owned_ports_snapshot {
	u32 bucket_count;
	u32 entry_count;
	unsigned long expires;
	struct rcu_head rcu;
	struct vpnhide_owned_port buckets[];
};

static struct vpnhide_owned_ports_snapshot __rcu *owned_ports_snapshot;
static DEFINE_SPINLOCK(owned_ports_lock);
static struct eventfd_ctx *port_event_ctx;
static DEFINE_SPINLOCK(port_event_lock);

#define VPNHIDE_PENDING_PORT_SETS 256U
#define VPNHIDE_PENDING_PORT_WAYS 4U
#define VPNHIDE_PENDING_PORT_TTL (2 * HZ)

struct vpnhide_pending_port {
	u32 sequence;
	struct vpnhide_owned_port owner;
	unsigned long expires;
};

static struct vpnhide_pending_port
	pending_ports[VPNHIDE_PENDING_PORT_SETS][VPNHIDE_PENDING_PORT_WAYS];
static DEFINE_SPINLOCK(pending_ports_lock);

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

static u32 owned_port_hash(const struct vpnhide_owned_port *owner)
{
	u32 value = owner->uid * 0x9e3779b1U;
	unsigned int i;

	value ^= (u32)owner->port * 0x85ebca6bU;
	value ^= (u32)owner->protocol * 0xc2b2ae35U;
	value ^= (u32)owner->family * 0x27d4eb2fU;
	for (i = 0; i < ARRAY_SIZE(owner->address); i++) {
		value ^= owner->address[i] * 0x165667b1U;
		value = rol32(value, 13);
	}
	value ^= value >> 16;
	return value;
}

static bool owned_port_equal(const struct vpnhide_owned_port *left,
			     const struct vpnhide_owned_port *right)
{
	return left->uid == right->uid && left->port == right->port &&
	       left->protocol == right->protocol && left->family == right->family &&
	       !memcmp(left->address, right->address, sizeof(left->address));
}

static bool owned_port_is_local(const struct vpnhide_owned_port *owner)
{
	if (owner->family == AF_INET) {
		__be32 address = (__force __be32)owner->address[0];

		return !owner->address[1] && !owner->address[2] && !owner->address[3] &&
		       (address == htonl(INADDR_ANY) || ipv4_is_loopback(address));
	}
	if (owner->family == AF_INET6) {
		struct in6_addr address;

		memcpy(&address, owner->address, sizeof(address));
		return ipv6_addr_any(&address) || ipv6_addr_loopback(&address);
	}
	return false;
}

static bool owned_port_from_sock(struct vpnhide_owned_port *owner, uid_t uid,
				 struct sock *sk)
{
	memset(owner, 0, sizeof(*owner));
	if (!sk || (sk->sk_type != SOCK_STREAM && sk->sk_type != SOCK_DGRAM))
		return false;
	owner->uid = uid;
	owner->port = inet_sk(sk)->inet_num;
	owner->protocol = sk->sk_type == SOCK_STREAM ? VH_PROTO_TCP : VH_PROTO_UDP;
	if (!owner->port)
		return false;
	if (sk->sk_family == AF_INET) {
		owner->family = AF_INET;
		owner->address[0] = (__force u32)inet_sk(sk)->inet_rcv_saddr;
	} else if (sk->sk_family == AF_INET6) {
		struct in6_addr address = sk->sk_v6_rcv_saddr;

		if (ipv6_addr_v4mapped(&address)) {
			owner->family = AF_INET;
			owner->address[0] = (__force u32)address.s6_addr32[3];
		} else {
			owner->family = AF_INET6;
			memcpy(owner->address, &address, sizeof(address));
		}
	} else {
		return false;
	}
	return owned_port_is_local(owner);
}

static bool pending_port_lookup_one(const struct vpnhide_owned_port *wanted)
{
	u32 set = owned_port_hash(wanted) & (VPNHIDE_PENDING_PORT_SETS - 1);
	unsigned int way;

	for (way = 0; way < VPNHIDE_PENDING_PORT_WAYS; way++) {
		struct vpnhide_pending_port *entry = &pending_ports[set][way];
		struct vpnhide_owned_port owner;
		unsigned long expires;
		u32 before, after;

		before = READ_ONCE(entry->sequence);
		if (before & 1)
			continue;
		smp_rmb();
		owner.uid = READ_ONCE(entry->owner.uid);
		owner.port = READ_ONCE(entry->owner.port);
		owner.protocol = READ_ONCE(entry->owner.protocol);
		owner.family = READ_ONCE(entry->owner.family);
		owner.address[0] = READ_ONCE(entry->owner.address[0]);
		owner.address[1] = READ_ONCE(entry->owner.address[1]);
		owner.address[2] = READ_ONCE(entry->owner.address[2]);
		owner.address[3] = READ_ONCE(entry->owner.address[3]);
		expires = READ_ONCE(entry->expires);
		smp_rmb();
		after = READ_ONCE(entry->sequence);
		if (before == after && !(after & 1) &&
		    owned_port_equal(&owner, wanted) && time_before(jiffies, expires))
			return true;
	}
	return false;
}

static bool owned_snapshot_contains(
	const struct vpnhide_owned_ports_snapshot *snapshot,
	const struct vpnhide_owned_port *wanted)
{
	u32 slot = owned_port_hash(wanted) & (snapshot->bucket_count - 1);
	u32 probes;

	for (probes = 0; probes < snapshot->bucket_count; probes++) {
		const struct vpnhide_owned_port *entry = &snapshot->buckets[slot];

		if (!entry->uid)
			return false;
		if (owned_port_equal(entry, wanted))
			return true;
		slot = (slot + 1) & (snapshot->bucket_count - 1);
	}
	return false;
}

bool vpnhide_uid_owns_port(uid_t uid, u16 port, u8 protocol, u8 family,
			   const u32 address[4])
{
	struct vpnhide_owned_ports_snapshot *snapshot;
	struct vpnhide_owned_port wanted = {
		.uid = uid, .port = port, .protocol = protocol, .family = family };
	struct vpnhide_owned_port wildcard;
	bool found = false;

	memcpy(wanted.address, address, sizeof(wanted.address));
	if (!owned_port_is_local(&wanted))
		return false;
	wildcard = wanted;
	memset(wildcard.address, 0, sizeof(wildcard.address));

	rcu_read_lock();
	snapshot = rcu_dereference(owned_ports_snapshot);
	if (!snapshot || !snapshot->bucket_count ||
	    time_after_eq(jiffies, snapshot->expires))
		goto out;
	found = owned_snapshot_contains(snapshot, &wanted) ||
		(memcmp(wanted.address, wildcard.address, sizeof(wanted.address)) &&
		 owned_snapshot_contains(snapshot, &wildcard));
out:
	rcu_read_unlock();
	return found || pending_port_lookup_one(&wanted) ||
	       (memcmp(wanted.address, wildcard.address, sizeof(wanted.address)) &&
		pending_port_lookup_one(&wildcard));
}

void vpnhide_record_bound_socket(uid_t uid, struct sock *sk)
{
	struct vpnhide_policy_snapshot *policy;
	struct vpnhide_pending_port *selected;
	struct vpnhide_owned_port owner;
	unsigned long now = jiffies;
	unsigned long oldest;
	u32 set;
	unsigned int way;
	bool targeted, changed;

	if (!uid || !owned_port_from_sock(&owner, uid, sk))
		return;
	rcu_read_lock();
	policy = rcu_dereference(global_policy_snapshot);
	targeted = vpnhide_find_port_target(policy, uid) != NULL;
	rcu_read_unlock();
	if (!targeted)
		return;

	set = owned_port_hash(&owner) & (VPNHIDE_PENDING_PORT_SETS - 1);
	spin_lock(&pending_ports_lock);
	selected = &pending_ports[set][0];
	oldest = READ_ONCE(selected->expires);
	for (way = 0; way < VPNHIDE_PENDING_PORT_WAYS; way++) {
		struct vpnhide_pending_port *entry = &pending_ports[set][way];
		unsigned long expires = READ_ONCE(entry->expires);

		if (owned_port_equal(&entry->owner, &owner) || !entry->owner.uid ||
		    time_after_eq(now, expires)) {
			selected = entry;
			break;
		}
		if (time_before(expires, oldest)) {
			selected = entry;
			oldest = expires;
		}
	}
	changed = !owned_port_equal(&selected->owner, &owner) ||
		  time_after_eq(now, selected->expires);
	WRITE_ONCE(selected->sequence, selected->sequence + 1);
	smp_wmb();
	selected->owner = owner;
	selected->expires = now + VPNHIDE_PENDING_PORT_TTL;
	smp_wmb();
	WRITE_ONCE(selected->sequence, selected->sequence + 1);
	spin_unlock(&pending_ports_lock);
	if (changed)
		vpnhide_notify_port_change(uid);
}

void vpnhide_notify_port_change(uid_t uid)
{
	struct vpnhide_policy_snapshot *policy;

	rcu_read_lock();
	policy = rcu_dereference(global_policy_snapshot);
	if (vpnhide_find_port_target(policy, uid)) {
		spin_lock(&port_event_lock);
		if (port_event_ctx) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 8, 0)
			eventfd_signal(port_event_ctx);
#else
			eventfd_signal(port_event_ctx, 1);
#endif
		}
		spin_unlock(&port_event_lock);
	}
	rcu_read_unlock();
}

static int replace_owned_ports(const struct vpnhide_owned_ports_update *update)
{
	struct vpnhide_owned_ports_snapshot *snapshot, *old;
	struct vpnhide_owned_port *entries = NULL;
	size_t size;
	u32 buckets = 8, i;

	if (update->reserved || update->count > VPNHIDE_OWNED_PORTS_MAX ||
	    (update->count && !update->entries_ptr))
		return -EINVAL;
	while (buckets < max_t(u32, 8, update->count * 2))
		buckets <<= 1;
	if (update->count) {
		entries = kvmalloc_array(update->count, sizeof(*entries), GFP_KERNEL);
		if (!entries)
			return -ENOMEM;
		if (copy_from_user(entries, u64_to_user_ptr(update->entries_ptr),
				   update->count * sizeof(*entries))) {
			kvfree(entries);
			return -EFAULT;
		}
	}
	size = struct_size(snapshot, buckets, buckets);
	snapshot = kvzalloc(size, GFP_KERNEL);
	if (!snapshot) {
		kvfree(entries);
		return -ENOMEM;
	}
	snapshot->bucket_count = buckets;
	snapshot->expires = jiffies + 120 * HZ;
	for (i = 0; i < update->count; i++) {
		u32 slot, probes;
		if (!entries[i].uid || !entries[i].port ||
		    entries[i].protocol > VH_PROTO_UDP ||
		    !owned_port_is_local(&entries[i])) {
			kvfree(entries);
			kvfree(snapshot);
			return -EINVAL;
		}
		slot = owned_port_hash(&entries[i]) & (buckets - 1);
		for (probes = 0; probes < buckets; probes++) {
			struct vpnhide_owned_port *dst = &snapshot->buckets[slot];
			if (!dst->uid) {
				*dst = entries[i];
				snapshot->entry_count++;
				break;
			}
			if (owned_port_equal(dst, &entries[i]))
				break;
			slot = (slot + 1) & (buckets - 1);
		}
	}
	kvfree(entries);
	spin_lock(&owned_ports_lock);
	old = rcu_dereference_protected(owned_ports_snapshot,
					lockdep_is_held(&owned_ports_lock));
	rcu_assign_pointer(owned_ports_snapshot, snapshot);
	spin_unlock(&owned_ports_lock);
	if (old)
		kvfree_rcu(old, rcu);
	return 0;
}

bool vpnhide_debug_is_enabled(void)
{
	struct vpnhide_policy_snapshot *snapshot;
	bool enabled;

	rcu_read_lock();
	snapshot = rcu_dereference(global_policy_snapshot);
	enabled = snapshot && !!snapshot->debug_enabled;
	rcu_read_unlock();
	return enabled;
}

unsigned int vpnhide_active_hooks_mask(void)
{
	struct vpnhide_policy_snapshot *snapshot;
	unsigned int mask;

	rcu_read_lock();
	snapshot = rcu_dereference(global_policy_snapshot);
	mask = snapshot ? snapshot->active_hooks_mask : 0;
	rcu_read_unlock();
	return mask;
}

unsigned int vpnhide_java_hooks_mask(void)
{
	struct vpnhide_policy_snapshot *snapshot;
	unsigned int mask;

	rcu_read_lock();
	snapshot = rcu_dereference(global_policy_snapshot);
	mask = snapshot ? snapshot->java_hooks_mask : 0;
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
	if (snapshot && snapshot->kmod_count > 0) {
		lo = 0;
		hi = snapshot->kmod_count - 1;
		while (lo <= hi) {
			mid = (lo + hi) >> 1;
			if (snapshot->kmod_uids[mid] == uid) {
				found = true;
				break;
			}
			if (snapshot->kmod_uids[mid] < uid)
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
	int lo, hi, mid;

	rcu_read_lock();
	snapshot = rcu_dereference(global_policy_snapshot);
	if (snapshot && snapshot->app_hook_mask_count) {
		lo = 0;
		hi = snapshot->app_hook_mask_count - 1;
		while (lo <= hi) {
			const struct vpnhide_app_hook_mask_v3 *mask;
			mid = lo + ((hi - lo) >> 1);
			mask = &snapshot->app_hook_masks[mid];
			if (mask->uid == uid) {
				if (mask->has_kernel_override) {
					*out = mask->kernel_mask;
					found = true;
				}
				break;
			}
			if (mask->uid < uid)
				lo = mid + 1;
			else
				hi = mid - 1;
		}
	}
	rcu_read_unlock();
	return found;
}

bool is_hook_active(enum vpnhide_hook_idx index, uid_t uid)
{
	struct vpnhide_policy_snapshot *snapshot;
	unsigned int bit = BIT(index);
	unsigned int mask = 0;
	int lo, hi;
	bool active = false;

	/* Read the global mask and the optional per-app override from the same
	 * immutable snapshot. The old implementation performed two separate RCU
	 * lookups for the common no-override case. */
	rcu_read_lock();
	snapshot = rcu_dereference(global_policy_snapshot);
	if (snapshot) {
		mask = snapshot->active_hooks_mask;
		lo = 0;
		hi = (int)snapshot->app_hook_mask_count - 1;
		while (lo <= hi) {
			int mid = lo + ((hi - lo) >> 1);
			const struct vpnhide_app_hook_mask_v3 *override =
				&snapshot->app_hook_masks[mid];

			if (override->uid == uid) {
				if (override->has_kernel_override)
					mask = override->kernel_mask;
				break;
			}
			if (override->uid < uid)
				lo = mid + 1;
			else
				hi = mid - 1;
		}
		active = !!(mask & bit);
	}
	rcu_read_unlock();
	return active;
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
	int lo, hi, i;

	if (uid == 0 || uid == 1000)
		return;

	spin_lock(&intercept_stats.lock);
	lo = 0;
	hi = intercept_stats.count - 1;
	while (lo <= hi) {
		i = lo + ((hi - lo) >> 1);
		if (intercept_stats.stats[i].uid == uid)
			goto increment;
		if (intercept_stats.stats[i].uid < uid)
			lo = i + 1;
		else
			hi = i - 1;
	}
	spin_unlock(&intercept_stats.lock);
	return;

increment:
	switch (type) {
	case HOOK_SETSOCKOPT:
	case HOOK_GETSOCKOPT:
		intercept_stats.stats[i].sockopt_count++;
		break;
	case HOOK_RTNL_FILL:
	case HOOK_INET6_FILL:
	case HOOK_INET_FILL:
	case HOOK_FIB_DUMP:
	case HOOK_RT6_FILL:
	case HOOK_RT_FILL:
		intercept_stats.stats[i].netlink_count++;
		break;
	case HOOK_GETDENTS64:
	case HOOK_OPENAT ... HOOK_READLINKAT:
		intercept_stats.stats[i].proc_count++;
		break;
	case HOOK_CONNECT:
	case HOOK_BIND:
		intercept_stats.stats[i].connect_count++;
		break;
	case HOOK_PORT:
	case 6:
		intercept_stats.stats[i].port_count++;
		break;
	case HOOK_GETNAME_INET:
	case HOOK_GETNAME_INET6:
		intercept_stats.stats[i].getname_count++;
		break;
	default:
		intercept_stats.stats[i].ioctl_count++;
		break;
	}
	spin_unlock(&intercept_stats.lock);
}

void vpnhide_record_java_stat(uid_t uid, const char *hook, u64 count)
{
	int i, lo = 0, hi;
	spin_lock(&intercept_stats.lock);
	hi = (int)intercept_stats.count - 1;
	while (lo <= hi) {
		i = lo + ((hi - lo) >> 1);
		if (intercept_stats.stats[i].uid == uid) {
			if (strcmp(hook, "PackageManager") == 0) intercept_stats.stats[i].java_pm_count += count;
			else if (strcmp(hook, "UserManager") == 0) intercept_stats.stats[i].java_um_count += count;
			else if (strcmp(hook, "NetworkCapabilities") == 0) intercept_stats.stats[i].java_nc_count += count;
			else if (strcmp(hook, "NetworkInfo") == 0) intercept_stats.stats[i].java_ni_count += count;
			else if (strcmp(hook, "Network") == 0) intercept_stats.stats[i].java_net_count += count;
			else if (strcmp(hook, "LinkProperties") == 0) intercept_stats.stats[i].java_lp_count += count;
			else if (strcmp(hook, "ConnectivityService") == 0) intercept_stats.stats[i].java_cs_count += count;
			spin_unlock(&intercept_stats.lock);
			return;
		}
		if (intercept_stats.stats[i].uid < uid)
			lo = i + 1;
		else
			hi = i - 1;
	}
	spin_unlock(&intercept_stats.lock);
}

static int intercept_stats_reconcile(const struct vpnhide_policy_snapshot *snapshot)
{
	struct vh_uid_stats_total *replacement = NULL, *old;
	u32 i, j = 0;
	if (snapshot->kmod_count) {
		replacement = kvmalloc_array(snapshot->kmod_count,
					     sizeof(*replacement), GFP_KERNEL | __GFP_ZERO);
		if (!replacement)
			return -ENOMEM;
		for (i = 0; i < snapshot->kmod_count; i++)
			replacement[i].uid = snapshot->kmod_uids[i];
	}

	spin_lock(&intercept_stats.lock);
	/* Both arrays are sorted by UID. Preserve counters with a merge instead
	 * of turning every policy reload into O(new_count * old_count). */
	for (i = 0; i < snapshot->kmod_count && j < intercept_stats.count; i++) {
		while (j < intercept_stats.count &&
		       intercept_stats.stats[j].uid < replacement[i].uid)
			j++;
		if (j < intercept_stats.count &&
		    intercept_stats.stats[j].uid == replacement[i].uid)
			replacement[i] = intercept_stats.stats[j++];
	}
	old = intercept_stats.stats;
	intercept_stats.stats = replacement;
	intercept_stats.count = snapshot->kmod_count;
	spin_unlock(&intercept_stats.lock);
	kvfree(old);
	return 0;
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
	n->sip.has_ipv4 = !!n->sip.has_ipv4;
	n->sip.has_ipv6 = !!n->sip.has_ipv6;
	n->sip.has_ipv6_linklocal = !!n->sip.has_ipv6_linklocal;
	n->sip.reserved = 0;
	if (!n->sip.has_ipv4 || n->sip.ipv4_mtu < 68 ||
	    n->sip.ipv4_mtu > 65535)
		n->sip.ipv4_mtu = 0;
	if (!n->sip.has_ipv6 || n->sip.ipv6_mtu < 1280 ||
	    n->sip.ipv6_mtu > 65535)
		n->sip.ipv6_mtu = 0;
	if (!n->sip.has_ipv6_linklocal ||
	    n->sip.ipv6_linklocal_addr[0] != 0xfe ||
	    (n->sip.ipv6_linklocal_addr[1] & 0xc0) != 0x80) {
		n->sip.has_ipv6_linklocal = 0;
		memset(n->sip.ipv6_linklocal_addr, 0,
		       sizeof(n->sip.ipv6_linklocal_addr));
	}

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
		size_t reader_capacity = 1024;
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
		mutex_lock(&policy_apply_lock);
		snapshot = rcu_dereference_protected(global_policy_snapshot,
					     lockdep_is_held(&policy_apply_lock));
		if (snapshot) {
			reader_capacity += (size_t)snapshot->lsposed_count * 16;
			reader_capacity += (size_t)snapshot->app_hook_mask_count * 32;
			reader_capacity += (size_t)snapshot->iface_prefixes.count *
				(MAX_IFACE_LEN + 1);
			reader_capacity += (size_t)MAX_ACTIVE_VPNS * (MAX_IFACE_LEN + 1);
		}
		reader->buf = kvmalloc(reader_capacity, GFP_KERNEL);
		if (!reader->buf)
		{
			mutex_unlock(&policy_apply_lock);
			return -ENOMEM;
		}

		offset += scnprintf(reader->buf + offset, reader_capacity - offset,
				    "version_code: %d\n", VPNHIDE_VERSION_CODE);

		offset += scnprintf(reader->buf + offset, reader_capacity - offset,
				    "java_hook_mask: %u\n", vpnhide_java_hooks_mask());
		offset += scnprintf(reader->buf + offset, reader_capacity - offset,
				    "java_stats_clear_gen: %d\n",
				    atomic_read(&java_stats_clear_generation));
		offset += scnprintf(reader->buf + offset, reader_capacity - offset,
				    "stats_mode: cumulative_session\n");
		offset += scnprintf(reader->buf + offset, reader_capacity - offset,
				    "debug_enabled: %d\n", vpnhide_debug_is_enabled());

		offset += scnprintf(reader->buf + offset, reader_capacity - offset,
				    "lsposed_targets:");
		if (snapshot) {
			for (i = 0; i < snapshot->lsposed_count; i++)
				offset += scnprintf(reader->buf + offset,
							reader_capacity - offset, " %u",
							snapshot->lsposed_uids[i]);
		}
		offset += scnprintf(reader->buf + offset, reader_capacity - offset, "\n");

		offset += scnprintf(reader->buf + offset, reader_capacity - offset,
				    "iface_prefixes:");
		if (snapshot) {
			for (i = 0; i < snapshot->iface_prefixes.count; i++)
				offset += scnprintf(reader->buf + offset,
							reader_capacity - offset,
							" %s", snapshot->iface_prefixes.prefixes[i]);
		}
		offset += scnprintf(reader->buf + offset, reader_capacity - offset, "\n");

		offset += scnprintf(reader->buf + offset, reader_capacity - offset,
				    "active_vpn_ifaces:");
		{
			struct vpnhide_active_vpns *vpns;
			rcu_read_lock();
			vpns = rcu_dereference(global_active_vpns);
			if (vpns) {
				for (i = 0; i < vpns->count; i++)
					offset += scnprintf(reader->buf + offset,
							reader_capacity - offset, " %s",
							vpns->vpns[i].name);
			}
			rcu_read_unlock();
		}
		offset += scnprintf(reader->buf + offset, reader_capacity - offset, "\n");

		offset += scnprintf(reader->buf + offset, reader_capacity - offset,
				    "app_java_hook_mask:");
		if (snapshot) {
			for (i = 0; i < snapshot->app_hook_mask_count; i++) {
				if (!snapshot->app_hook_masks[i].has_java_override)
					continue;
				offset += scnprintf(reader->buf + offset,
						    reader_capacity - offset, " %u:%u",
							snapshot->app_hook_masks[i].uid,
							snapshot->app_hook_masks[i].java_mask);
			}
		}
		offset += scnprintf(reader->buf + offset, reader_capacity - offset, "\n");

		spin_lock(&cover_ifname_lock);
		offset += scnprintf(reader->buf + offset, reader_capacity - offset,
				    "cover_iface: %s\n",
				    global_cover_ifname[0] ? global_cover_ifname : "none");
		spin_unlock(&cover_ifname_lock);

		offset += scnprintf(reader->buf + offset, reader_capacity - offset, "\n");

		reader->buf_len = offset;
		mutex_unlock(&policy_apply_lock);
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

		{
			char *ptr = java_stats_buf;
			while (*ptr) {
				char *line_end = strchr(ptr, '\n');
				if (line_end) *line_end = '\0';
				if (*ptr) {
					unsigned int uid = 0, count = 0;
					char hook_buf[128] = {0};
					if (sscanf(ptr, "%u;%127[^;];%u", &uid, hook_buf, &count) == 3 && count > 0) {
						vpnhide_record_java_stat((uid_t)uid, hook_buf, (u64)count);
					} else if (sscanf(ptr, "%u;%u", &uid, &count) == 2 && count > 0) {
						vpnhide_record_java_stat((uid_t)uid, "", (u64)count);
					}
				}
				if (!line_end) break;
				ptr = line_end + 1;
			}
		}
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

static int policy_port_target_cmp(const void *a, const void *b)
{
	const struct vpnhide_port_target_v3 *pa = a, *pb = b;
	return (pa->uid > pb->uid) - (pa->uid < pb->uid);
}

static int policy_port_rule_cmp(const void *a, const void *b)
{
	const struct vpnhide_port_rule_v3 *ra = a, *rb = b;
	if (ra->start_port != rb->start_port)
		return (int)ra->start_port - (int)rb->start_port;
	if (ra->end_port != rb->end_port)
		return (int)ra->end_port - (int)rb->end_port;
	return (int)ra->protocol - (int)rb->protocol;
}

static int policy_app_mask_cmp(const void *a, const void *b)
{
	const struct vpnhide_app_hook_mask_v3 *ma = a, *mb = b;
	return (ma->uid > mb->uid) - (ma->uid < mb->uid);
}

static int policy_section_validate(const struct vpnhide_policy_section_v3 *section,
				   size_t element_size, size_t *cursor,
				   size_t total_size)
{
	size_t bytes;
	if (section->offset != *cursor ||
	    check_mul_overflow((size_t)section->count, element_size, &bytes) ||
	    check_add_overflow(*cursor, bytes, cursor) || *cursor > total_size)
		return -EINVAL;
	return 0;
}

static struct vpnhide_policy_snapshot *
policy_snapshot_from_v3(const struct vpnhide_policy_payload_v3 *payload,
			size_t payload_size)
{
	struct vpnhide_policy_snapshot *snapshot;
	size_t cursor = sizeof(*payload), data_size, allocation_size;
	u8 *data;
	u32 i, next_rule = 0;

	if (!payload || payload_size < sizeof(*payload) ||
	    payload_size > VPNHIDE_POLICY_MAX_BYTES ||
	    payload->total_size != payload_size ||
	    payload->iface_count > MAX_IFACE_PREFIXES)
		return ERR_PTR(-EINVAL);
	if (policy_section_validate(&payload->kmod_uids, sizeof(__u32),
				    &cursor, payload_size) ||
	    policy_section_validate(&payload->lsposed_uids, sizeof(__u32),
				    &cursor, payload_size) ||
	    policy_section_validate(&payload->port_targets,
				    sizeof(struct vpnhide_port_target_v3),
				    &cursor, payload_size) ||
	    policy_section_validate(&payload->port_rules,
				    sizeof(struct vpnhide_port_rule_v3),
				    &cursor, payload_size) ||
	    policy_section_validate(&payload->app_hook_masks,
				    sizeof(struct vpnhide_app_hook_mask_v3),
				    &cursor, payload_size) || cursor != payload_size)
		return ERR_PTR(-EINVAL);

	data_size = payload_size - sizeof(*payload);
	if (check_add_overflow(sizeof(*snapshot), data_size, &allocation_size))
		return ERR_PTR(-EOVERFLOW);
	snapshot = kvzalloc(allocation_size, GFP_KERNEL);
	if (!snapshot)
		return ERR_PTR(-ENOMEM);
	snapshot->active_hooks_mask = payload->active_hooks_mask |
		BIT(HOOK_CONNECT) | BIT(HOOK_BIND);
	snapshot->java_hooks_mask = payload->java_hooks_mask;
	snapshot->debug_enabled = !!payload->debug_enabled;
	snapshot->flags = payload->flags;
	snapshot->iface_prefixes.count = payload->iface_count;
	memcpy(snapshot->iface_prefixes.prefixes, payload->iface_prefixes,
	       sizeof(snapshot->iface_prefixes.prefixes));
	snapshot->kmod_count = payload->kmod_uids.count;
	snapshot->lsposed_count = payload->lsposed_uids.count;
	snapshot->port_target_count = payload->port_targets.count;
	snapshot->port_rule_count = payload->port_rules.count;
	snapshot->app_hook_mask_count = payload->app_hook_masks.count;

	data = snapshot->data;
	snapshot->kmod_uids = (uid_t *)data;
	memcpy(data, (const u8 *)payload + payload->kmod_uids.offset,
	       snapshot->kmod_count * sizeof(*snapshot->kmod_uids));
	data += snapshot->kmod_count * sizeof(*snapshot->kmod_uids);
	snapshot->lsposed_uids = (uid_t *)data;
	memcpy(data, (const u8 *)payload + payload->lsposed_uids.offset,
	       snapshot->lsposed_count * sizeof(*snapshot->lsposed_uids));
	data += snapshot->lsposed_count * sizeof(*snapshot->lsposed_uids);
	snapshot->port_targets = (struct vpnhide_port_target_v3 *)data;
	memcpy(data, (const u8 *)payload + payload->port_targets.offset,
	       snapshot->port_target_count * sizeof(*snapshot->port_targets));
	data += snapshot->port_target_count * sizeof(*snapshot->port_targets);
	snapshot->port_rules = (struct vpnhide_port_rule_v3 *)data;
	memcpy(data, (const u8 *)payload + payload->port_rules.offset,
	       snapshot->port_rule_count * sizeof(*snapshot->port_rules));
	data += snapshot->port_rule_count * sizeof(*snapshot->port_rules);
	snapshot->app_hook_masks = (struct vpnhide_app_hook_mask_v3 *)data;
	memcpy(data, (const u8 *)payload + payload->app_hook_masks.offset,
	       snapshot->app_hook_mask_count * sizeof(*snapshot->app_hook_masks));

	for (i = 0; i < snapshot->port_target_count; i++) {
		struct vpnhide_port_target_v3 *target = &snapshot->port_targets[i];
		if (!target->uid || target->mode > VH_PORT_POLICY_DENY_ALL ||
		    target->reserved[0] || target->reserved[1] || target->reserved[2] ||
		    target->first_rule != next_rule ||
		    target->rule_count > snapshot->port_rule_count - next_rule)
			goto invalid;
		if (target->rule_count > 1)
			sort(snapshot->port_rules + target->first_rule,
			     target->rule_count, sizeof(*snapshot->port_rules),
			     policy_port_rule_cmp, NULL);
		next_rule += target->rule_count;
	}
	if (next_rule != snapshot->port_rule_count)
		goto invalid;
	for (i = 0; i < snapshot->port_rule_count; i++) {
		const struct vpnhide_port_rule_v3 *rule = &snapshot->port_rules[i];
		if (rule->start_port > rule->end_port || rule->protocol > VH_PROTO_BOTH ||
		    rule->reserved[0] || rule->reserved[1] || rule->reserved[2])
			goto invalid;
	}
	for (i = 0; i < snapshot->app_hook_mask_count; i++) {
		struct vpnhide_app_hook_mask_v3 *mask = &snapshot->app_hook_masks[i];
		if (!mask->uid || mask->has_kernel_override > 1 ||
		    mask->has_java_override > 1 || mask->reserved[0] ||
		    mask->reserved[1])
			goto invalid;
		if (mask->has_kernel_override)
			mask->kernel_mask |= BIT(HOOK_CONNECT) | BIT(HOOK_BIND);
	}
	sort(snapshot->kmod_uids, snapshot->kmod_count, sizeof(uid_t), uid_cmp, NULL);
	sort(snapshot->lsposed_uids, snapshot->lsposed_count, sizeof(uid_t), uid_cmp, NULL);
	sort(snapshot->port_targets, snapshot->port_target_count,
	     sizeof(*snapshot->port_targets), policy_port_target_cmp, NULL);
	sort(snapshot->app_hook_masks, snapshot->app_hook_mask_count,
	     sizeof(*snapshot->app_hook_masks), policy_app_mask_cmp, NULL);
	if ((snapshot->kmod_count && !snapshot->kmod_uids[0]) ||
	    (snapshot->lsposed_count && !snapshot->lsposed_uids[0]))
		goto invalid;
	for (i = 1; i < snapshot->kmod_count; i++)
		if (snapshot->kmod_uids[i - 1] == snapshot->kmod_uids[i]) goto invalid;
	for (i = 1; i < snapshot->lsposed_count; i++)
		if (snapshot->lsposed_uids[i - 1] == snapshot->lsposed_uids[i]) goto invalid;
	for (i = 1; i < snapshot->port_target_count; i++)
		if (snapshot->port_targets[i - 1].uid == snapshot->port_targets[i].uid)
			goto invalid;
	for (i = 1; i < snapshot->app_hook_mask_count; i++)
		if (snapshot->app_hook_masks[i - 1].uid == snapshot->app_hook_masks[i].uid)
			goto invalid;
	return snapshot;
invalid:
	kvfree(snapshot);
	return ERR_PTR(-EINVAL);
}

static int publish_policy_snapshot(struct vpnhide_policy_snapshot *snapshot,
				   u64 expected_generation)
{
	struct vpnhide_policy_snapshot *old = NULL;
	int ret = 0;
	mutex_lock(&policy_apply_lock);
	if (expected_generation && expected_generation !=
	    (u64)atomic_read(&vpnhide_config_generation)) {
		mutex_unlock(&policy_apply_lock);
		kvfree(snapshot);
		return -EAGAIN;
	}
	ret = intercept_stats_reconcile(snapshot);
	if (ret) {
		mutex_unlock(&policy_apply_lock);
		kvfree(snapshot);
		return ret;
	}
	spin_lock(&policy_snapshot_lock);
	old = rcu_dereference_protected(global_policy_snapshot,
		lockdep_is_held(&policy_snapshot_lock));
	rcu_assign_pointer(global_policy_snapshot, snapshot);
	spin_unlock(&policy_snapshot_lock);
	vpnhide_udp_rates_prune(snapshot);
	mutex_unlock(&policy_apply_lock);
	if (old)
		call_rcu(&old->rcu, vh_free_policy_snapshot_rcu);
	atomic_inc(&vpnhide_config_generation);
	wake_up_all(&vpnhide_config_wait);
	return 0;
}

int vpnhide_apply_policy_v3(const void *payload, size_t payload_size,
			    u64 expected_generation)
{
	struct vpnhide_policy_snapshot *snapshot =
		policy_snapshot_from_v3(payload, payload_size);
	if (IS_ERR(snapshot))
		return PTR_ERR(snapshot);
	return publish_policy_snapshot(snapshot, expected_generation);
}

const struct vpnhide_port_target_v3 *
vpnhide_find_port_target(const struct vpnhide_policy_snapshot *snapshot,
			 uid_t uid)
{
	int lo = 0, hi, mid;
	if (!snapshot || !snapshot->port_target_count)
		return NULL;
	hi = snapshot->port_target_count - 1;
	while (lo <= hi) {
		const struct vpnhide_port_target_v3 *target;
		mid = lo + ((hi - lo) >> 1);
		target = &snapshot->port_targets[mid];
		if (target->uid == uid)
			return target;
		if (target->uid < uid)
			lo = mid + 1;
		else
			hi = mid - 1;
	}
	return NULL;
}

int vpnhide_apply_policy(const struct vpnhide_policy_payload *payload,
			 u64 expected_generation)
{
	struct vpnhide_policy_payload_v3 *v3;
	struct vpnhide_port_target_v3 *targets;
	struct vpnhide_port_rule_v3 *rules;
	struct vpnhide_app_hook_mask_v3 *masks;
	size_t size, cursor;
	u32 rule_count = 0, rule_index = 0;
	int i, j, ret;

	if (!payload || payload->targets.kmod_count < 0 ||
	    payload->targets.kmod_count > VPNHIDE_LEGACY_TARGET_UIDS ||
	    payload->targets.lsposed_count < 0 ||
	    payload->targets.lsposed_count > VPNHIDE_LEGACY_TARGET_UIDS ||
	    payload->ports.count < 0 ||
	    payload->ports.count > VPNHIDE_LEGACY_TARGET_UIDS ||
	    payload->iface_prefixes.count < 0 ||
	    payload->iface_prefixes.count > MAX_IFACE_PREFIXES ||
	    payload->app_hook_masks.count < 0 ||
	    payload->app_hook_masks.count > VPNHIDE_LEGACY_TARGET_UIDS)
		return -EINVAL;
	for (i = 0; i < payload->ports.count; i++) {
		const struct vpnhide_uid_port_rules *target = &payload->ports.targets[i];
		if (target->rule_count < 0 ||
		    target->rule_count > VPNHIDE_LEGACY_PORT_RULES_PER_UID)
			return -EINVAL;
		for (j = 0; j < target->rule_count; j++) {
			const struct vpnhide_port_rule *rule = &target->rules[j];
			if (rule->start_port > rule->end_port ||
			    rule->protocol > VH_PROTO_BOTH)
				return -EINVAL;
		}
		rule_count += target->rule_count;
	}
	size = sizeof(*v3) + payload->targets.kmod_count * sizeof(__u32) +
		payload->targets.lsposed_count * sizeof(__u32) +
		payload->ports.count * sizeof(*targets) +
		rule_count * sizeof(*rules) +
		payload->app_hook_masks.count * sizeof(*masks);
	v3 = kvzalloc(size, GFP_KERNEL);
	if (!v3)
		return -ENOMEM;
	v3->total_size = size;
	v3->flags = payload->flags;
	v3->active_hooks_mask = payload->active_hooks_mask;
	v3->java_hooks_mask = payload->java_hooks_mask;
	v3->debug_enabled = payload->debug_enabled;
	v3->iface_count = payload->iface_prefixes.count;
	memcpy(v3->iface_prefixes, payload->iface_prefixes.prefixes,
	       sizeof(v3->iface_prefixes));
	cursor = sizeof(*v3);
	v3->kmod_uids.offset = cursor;
	v3->kmod_uids.count = payload->targets.kmod_count;
	memcpy((u8 *)v3 + cursor, payload->targets.kmod_uids,
	       v3->kmod_uids.count * sizeof(__u32));
	cursor += v3->kmod_uids.count * sizeof(__u32);
	v3->lsposed_uids.offset = cursor;
	v3->lsposed_uids.count = payload->targets.lsposed_count;
	memcpy((u8 *)v3 + cursor, payload->targets.lsposed_uids,
	       v3->lsposed_uids.count * sizeof(__u32));
	cursor += v3->lsposed_uids.count * sizeof(__u32);
	v3->port_targets.offset = cursor;
	v3->port_targets.count = payload->ports.count;
	targets = (void *)((u8 *)v3 + cursor);
	cursor += v3->port_targets.count * sizeof(*targets);
	v3->port_rules.offset = cursor;
	v3->port_rules.count = rule_count;
	rules = (void *)((u8 *)v3 + cursor);
	cursor += rule_count * sizeof(*rules);
	for (i = 0; i < payload->ports.count; i++) {
		const struct vpnhide_uid_port_rules *source = &payload->ports.targets[i];
		targets[i].uid = source->uid;
		targets[i].first_rule = rule_index;
		targets[i].rule_count = source->rule_count;
		targets[i].mode = source->mode;
		for (j = 0; j < source->rule_count; j++, rule_index++) {
			rules[rule_index].start_port = source->rules[j].start_port;
			rules[rule_index].end_port = source->rules[j].end_port;
			rules[rule_index].protocol = source->rules[j].protocol;
		}
	}
	v3->app_hook_masks.offset = cursor;
	v3->app_hook_masks.count = payload->app_hook_masks.count;
	masks = (void *)((u8 *)v3 + cursor);
	for (i = 0; i < payload->app_hook_masks.count; i++) {
		masks[i].uid = payload->app_hook_masks.masks[i].uid;
		masks[i].kernel_mask = payload->app_hook_masks.masks[i].kernel_mask;
		masks[i].java_mask = payload->app_hook_masks.masks[i].java_mask;
		masks[i].has_kernel_override =
			payload->app_hook_masks.masks[i].has_kernel_override;
		masks[i].has_java_override =
			payload->app_hook_masks.masks[i].has_java_override;
	}
	ret = vpnhide_apply_policy_v3(v3, size, expected_generation);
	kvfree(v3);
	return ret;
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
		void *payload;
		int policy_ret;

		if (copy_from_user(&request, uarg, sizeof(request)))
			return -EFAULT;
		if (!request.payload_ptr)
			return -EINVAL;
		if (request.abi_version == VPNHIDE_POLICY_ABI_VERSION_V2) {
			if (request.payload_size != sizeof(struct vpnhide_policy_payload))
				return -EINVAL;
		} else if (request.abi_version == VPNHIDE_POLICY_ABI_VERSION_V3) {
			if (request.payload_size < sizeof(struct vpnhide_policy_payload_v3) ||
			    request.payload_size > VPNHIDE_POLICY_MAX_BYTES)
				return -EINVAL;
		} else {
			return -EPROTONOSUPPORT;
		}
		payload = kvmalloc(request.payload_size, GFP_KERNEL);
		if (!payload)
			return -ENOMEM;
		if (copy_from_user(payload, u64_to_user_ptr(request.payload_ptr),
				   request.payload_size)) {
			kvfree(payload);
			return -EFAULT;
		}
		if (request.abi_version == VPNHIDE_POLICY_ABI_VERSION_V3)
			policy_ret = vpnhide_apply_policy_v3(payload, request.payload_size,
							   request.expected_generation);
		else
			policy_ret = vpnhide_apply_policy(payload,
						  request.expected_generation);
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
			if (snapshot->kmod_count > VPNHIDE_LEGACY_TARGET_UIDS) {
				rcu_read_unlock();
				kfree(td);
				return -ENOSPC;
			}
			td->count = snapshot->kmod_count;
			for (i = 0; i < td->count; i++)
				td->uids[i] = snapshot->kmod_uids[i];
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
		int i;

		amd = kzalloc(sizeof(*amd), GFP_KERNEL);
		if (!amd)
			return -ENOMEM;
		rcu_read_lock();
		snapshot = rcu_dereference(global_policy_snapshot);
		if (snapshot) {
			if (snapshot->app_hook_mask_count > VPNHIDE_LEGACY_TARGET_UIDS) {
				rcu_read_unlock();
				kfree(amd);
				return -ENOSPC;
			}
			amd->count = snapshot->app_hook_mask_count;
			for (i = 0; i < amd->count; i++) {
				amd->masks[i].uid = snapshot->app_hook_masks[i].uid;
				amd->masks[i].kernel_mask = snapshot->app_hook_masks[i].kernel_mask;
				amd->masks[i].java_mask = snapshot->app_hook_masks[i].java_mask;
				amd->masks[i].has_kernel_override =
					snapshot->app_hook_masks[i].has_kernel_override;
				amd->masks[i].has_java_override =
					snapshot->app_hook_masks[i].has_java_override;
			}
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
		struct vpnhide_stats_snapshot request;
		struct vpnhide_uid_stats *out;
		u32 count, allocated;
		int i;

		if (copy_from_user(&request, uarg, sizeof(request)))
			return -EFAULT;
		if (request.capacity && !request.entries_ptr)
			return -EINVAL;
		spin_lock(&intercept_stats.lock);
		count = intercept_stats.count;
		spin_unlock(&intercept_stats.lock);
		allocated = min(request.capacity, count);
		out = allocated ? kvmalloc_array(allocated,
						 sizeof(*out), GFP_KERNEL) : NULL;
		if (allocated && !out)
			return -ENOMEM;

		spin_lock(&intercept_stats.lock);
		count = intercept_stats.count;
		request.sequence = atomic64_inc_return(&intercept_stats_sequence);
		request.monotonic_ns = ktime_get_ns();
		request.count = count;
		if (out && request.capacity >= count && allocated >= count) {
			for (i = 0; i < count; i++) {
				out[i].uid = intercept_stats.stats[i].uid;
				out[i].ioctl_count = intercept_stats.stats[i].ioctl_count;
				out[i].netlink_count = intercept_stats.stats[i].netlink_count;
				out[i].proc_count = intercept_stats.stats[i].proc_count;
				out[i].sockopt_count = intercept_stats.stats[i].sockopt_count;
				out[i].connect_count = intercept_stats.stats[i].connect_count;
				out[i].getname_count = intercept_stats.stats[i].getname_count;
				out[i].port_count = intercept_stats.stats[i].port_count;
				out[i].java_pm_count = intercept_stats.stats[i].java_pm_count;
				out[i].java_um_count = intercept_stats.stats[i].java_um_count;
				out[i].java_nc_count = intercept_stats.stats[i].java_nc_count;
				out[i].java_ni_count = intercept_stats.stats[i].java_ni_count;
				out[i].java_net_count = intercept_stats.stats[i].java_net_count;
				out[i].java_lp_count = intercept_stats.stats[i].java_lp_count;
				out[i].java_cs_count = intercept_stats.stats[i].java_cs_count;
			}
		}
		spin_unlock(&intercept_stats.lock);

		if (request.capacity < count) {
			kvfree(out);
			if (copy_to_user(uarg, &request, sizeof(request)))
				return -EFAULT;
			return -ENOSPC;
		}
		if (out && copy_to_user((void __user *)(unsigned long)request.entries_ptr,
					out, count * sizeof(*out))) {
			kvfree(out);
			return -EFAULT;
		}
		kvfree(out);
		if (copy_to_user(uarg, &request, sizeof(request)))
			return -EFAULT;
		break;
	}

	case VH_GET_STATS_V2: {
		struct vpnhide_stats_snapshot_v2 request;
		struct vpnhide_uid_stats *uid_out = NULL;
		struct vpnhide_port_stats *port_out = NULL;
		u32 uid_count, port_count, uid_allocated = 0, port_allocated = 0;
		u32 i, out_index;

		if (copy_from_user(&request, uarg, sizeof(request)))
			return -EFAULT;
		if ((request.uid_capacity && !request.uid_entries_ptr) ||
		    (request.port_capacity && !request.port_entries_ptr))
			return -EINVAL;

		spin_lock(&intercept_stats.lock);
		uid_count = intercept_stats.count;
		spin_unlock(&intercept_stats.lock);
		spin_lock(&port_stats_lock);
		port_count = count_live_port_stats_locked();
		spin_unlock(&port_stats_lock);
		if (request.uid_capacity >= uid_count && uid_count) {
			uid_out = kvmalloc_array(uid_count, sizeof(*uid_out), GFP_KERNEL);
			if (!uid_out)
				return -ENOMEM;
			uid_allocated = uid_count;
		}
		if (request.port_capacity >= port_count && port_count) {
			port_out = kvmalloc_array(port_count, sizeof(*port_out), GFP_KERNEL);
			if (!port_out) {
				kvfree(uid_out);
				return -ENOMEM;
			}
			port_allocated = port_count;
		}

		spin_lock(&intercept_stats.lock);
		uid_count = intercept_stats.count;
		request.uid_count = uid_count;
		request.sequence = atomic64_inc_return(&intercept_stats_sequence);
		request.monotonic_ns = ktime_get_ns();
		if (uid_out && request.uid_capacity >= uid_count &&
		    uid_allocated >= uid_count) {
			for (i = 0; i < uid_count; i++) {
				uid_out[i].uid = intercept_stats.stats[i].uid;
				uid_out[i].ioctl_count = intercept_stats.stats[i].ioctl_count;
				uid_out[i].netlink_count = intercept_stats.stats[i].netlink_count;
				uid_out[i].proc_count = intercept_stats.stats[i].proc_count;
				uid_out[i].sockopt_count = intercept_stats.stats[i].sockopt_count;
				uid_out[i].connect_count = intercept_stats.stats[i].connect_count;
				uid_out[i].getname_count = intercept_stats.stats[i].getname_count;
				uid_out[i].port_count = intercept_stats.stats[i].port_count;
				uid_out[i].java_pm_count = intercept_stats.stats[i].java_pm_count;
				uid_out[i].java_um_count = intercept_stats.stats[i].java_um_count;
				uid_out[i].java_nc_count = intercept_stats.stats[i].java_nc_count;
				uid_out[i].java_ni_count = intercept_stats.stats[i].java_ni_count;
				uid_out[i].java_net_count = intercept_stats.stats[i].java_net_count;
				uid_out[i].java_lp_count = intercept_stats.stats[i].java_lp_count;
				uid_out[i].java_cs_count = intercept_stats.stats[i].java_cs_count;
			}
		}
		spin_unlock(&intercept_stats.lock);
		spin_lock(&port_stats_lock);
		port_count = count_live_port_stats_locked();
		request.port_count = port_count;
		request.dropped_port_entries = port_stats_dropped;
		if (port_out && request.port_capacity >= port_count &&
		    port_allocated >= port_count) {
			for (i = 0, out_index = 0; i < VPNHIDE_PORT_STATS_CAPACITY; i++) {
				struct vh_port_stats_total *entry = &port_stats[i];
				if (entry->state != VPNHIDE_PORT_STAT_USED)
					continue;
				port_out[out_index].uid = entry->uid;
				port_out[out_index].port = entry->port;
				port_out[out_index].protocol = entry->protocol;
				port_out[out_index].reserved = 0;
				port_out[out_index].count = entry->count;
				out_index++;
			}
		}
		spin_unlock(&port_stats_lock);

		if (request.uid_capacity < uid_count || request.port_capacity < port_count ||
		    uid_allocated < uid_count || port_allocated < port_count) {
			kvfree(uid_out);
			kvfree(port_out);
			if (copy_to_user(uarg, &request, sizeof(request)))
				return -EFAULT;
			return -ENOSPC;
		}
		if (uid_out && copy_to_user((void __user *)(unsigned long)request.uid_entries_ptr,
					    uid_out, uid_count * sizeof(*uid_out))) {
			kvfree(uid_out);
			kvfree(port_out);
			return -EFAULT;
		}
		if (port_out && copy_to_user((void __user *)(unsigned long)request.port_entries_ptr,
					     port_out, port_count * sizeof(*port_out))) {
			kvfree(uid_out);
			kvfree(port_out);
			return -EFAULT;
		}
		kvfree(uid_out);
		kvfree(port_out);
		if (copy_to_user(uarg, &request, sizeof(request)))
			return -EFAULT;
		break;
	}

	case VH_CLEAR_STATS: {
		u32 i;
		struct vh_port_stats_total *old_port_stats;
		struct vh_port_stats_total *replacement_port_stats;

		replacement_port_stats = kvcalloc(VPNHIDE_PORT_STATS_CAPACITY,
						  sizeof(*replacement_port_stats),
						  GFP_KERNEL);
		if (!replacement_port_stats)
			return -ENOMEM;
		spin_lock(&intercept_stats.lock);
		for (i = 0; i < intercept_stats.count; i++) {
			uid_t uid = intercept_stats.stats[i].uid;
			memset(&intercept_stats.stats[i], 0,
			       sizeof(intercept_stats.stats[i]));
			intercept_stats.stats[i].uid = uid;
		}
		atomic64_set(&intercept_stats_sequence, 0);
		spin_unlock(&intercept_stats.lock);
		spin_lock(&port_stats_lock);
		old_port_stats = port_stats;
		port_stats = replacement_port_stats;
		port_stats_dropped = 0;
		spin_unlock(&port_stats_lock);
		kvfree(old_port_stats);
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
			if (snapshot->lsposed_count > VPNHIDE_LEGACY_TARGET_UIDS) {
				rcu_read_unlock();
				kfree(td);
				return -ENOSPC;
			}
			td->count = snapshot->lsposed_count;
			for (i = 0; i < td->count; i++)
				td->uids[i] = snapshot->lsposed_uids[i];
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
		if (snapshot)
			pd = snapshot->iface_prefixes;
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

	case VH_SET_PORT_EVENTFD: {
		struct eventfd_ctx *new_ctx, *old_ctx;
		int event_fd;
		if (copy_from_user(&event_fd, uarg, sizeof(event_fd)))
			return -EFAULT;
		new_ctx = eventfd_ctx_fdget(event_fd);
		if (IS_ERR(new_ctx))
			return PTR_ERR(new_ctx);
		spin_lock(&port_event_lock);
		old_ctx = port_event_ctx;
		port_event_ctx = new_ctx;
		spin_unlock(&port_event_lock);
		if (old_ctx)
			eventfd_ctx_put(old_ctx);
		ret = 0;
		break;
	}

	case VH_SET_OWNED_PORTS: {
		struct vpnhide_owned_ports_update update;
		if (copy_from_user(&update, uarg, sizeof(update)))
			return -EFAULT;
		return replace_owned_ports(&update);
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
	spin_lock_init(&intercept_stats.lock);
	init_waitqueue_head(&vpnhide_config_wait);
	port_stats = kvcalloc(VPNHIDE_PORT_STATS_CAPACITY,
			      sizeof(*port_stats), GFP_KERNEL);
	if (!port_stats)
		return -ENOMEM;

	ret = misc_register(&vpnhide_misc);
	if (ret) {
		pr_err(MODNAME ": misc_register failed: %d\n", ret);
		kvfree(port_stats);
		port_stats = NULL;
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
	struct vpnhide_owned_ports_snapshot *owned;
	struct eventfd_ctx *event_ctx;

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
	owned = rcu_dereference_protected(owned_ports_snapshot, 1);
	rcu_assign_pointer(owned_ports_snapshot, NULL);
	spin_lock(&port_event_lock);
	event_ctx = port_event_ctx;
	port_event_ctx = NULL;
	spin_unlock(&port_event_lock);

	synchronize_rcu();
	kfree(av);
	kfree(nc);
	kfree(si);
	kvfree(snapshot);
	kvfree(owned);
	if (event_ctx)
		eventfd_ctx_put(event_ctx);
	kvfree(intercept_stats.stats);
	intercept_stats.stats = NULL;
	intercept_stats.count = 0;
	kvfree(port_stats);
	port_stats = NULL;
	vpnhide_udp_rates_destroy();

	pr_info(MODNAME ": unloaded\n");
}

late_initcall(vpnhide_init);
module_exit(vpnhide_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("VPNHide Next — in-tree kernel VPN hiding subsystem");
MODULE_AUTHOR("soranerai");
