// SPDX-License-Identifier: GPL-2.0
/*
 * vpnhide — BPF map hooks
 */

#include <linux/fs.h>
#include <linux/file.h>
#include <linux/dirent.h>
#include <linux/uaccess.h>
#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/namei.h>
#include <net/sock.h>

#include "vpnhide.h"

/* ------------------------------------------------------------------ */
/* BPF helpers                                                         */
/* ------------------------------------------------------------------ */

/* "stats_map_*" / "map_netd_stats*" maps key by the wide struct
 * (uid+tag+counterSet+ifaceIndex); "iface_stats*" / "tether_stats*" /
 * "map_netd_iface_*" key by a bare u32 ifindex. */
static bool vh_is_wide_stats_map(struct bpf_map *map)
{
	return !strncmp(map->name, "stats_map_", 10) ||
	       !strncmp(map->name, "map_netd_stats", 14);
}

static bool vh_is_iface_stats_map(struct bpf_map *map)
{
	return !strncmp(map->name, "iface_stats", 11) ||
	       !strncmp(map->name, "map_netd_iface_", 15) ||
	       !strncmp(map->name, "tether_stats", 12);
}

bool vh_is_stats_map(struct bpf_map *map)
{
	if (!map || !map->name[0])
		return false;
	return vh_is_wide_stats_map(map) || vh_is_iface_stats_map(map) ||
	       !strncmp(map->name, "uid_stats", 9) ||
	       !strncmp(map->name, "app_uid_stats", 13);
}

bool vh_is_vpn_stats_key(struct bpf_map *map, const struct vh_stats_key *key)
{
	return is_active_vpn_ifindex(key->ifaceIndex) ||
	       is_target_uid_val(key->uid);
}

/* Sum current byte/packet counters for every active VPN ifindex in `map`. */
static void vh_collect_vpn_traffic_sum(struct bpf_map *map,
				       struct vh_stats_value *vpn_sum)
{
	struct vpnhide_active_vpns *vpns;
	int idx;

	rcu_read_lock();
	vpns = rcu_dereference(global_active_vpns);
	if (vpns) {
		for (idx = 0; idx < vpns->count; idx++) {
			u32 vpn_idx = vpns->vpns[idx].ifindex;
			void *map_val = map->ops->map_lookup_elem(map, &vpn_idx);

			if (map_val)
				sv_add(vpn_sum, (struct vh_stats_value *)map_val);
		}
	}
	rcu_read_unlock();
}

/* Zero a single BPF map entry for a VPN/target UID key, or — for the
 * configured cover interface — add the summed VPN traffic on top of its
 * real counters so the laundered total looks organic. */
void vpnhide_bpf_lookup_elem(struct bpf_map *map, void *key, void *value)
{
	struct vh_stats_value *sv = value;
	uid_t uid;

	if (!map || !key || !value)
		return;
	if (!(vpnhide_active_hooks_mask() & BIT(HOOK_BPF)))
		return;
	uid = from_kuid(&init_user_ns, current_uid());
	/* The target process itself must see its own real traffic — only
	 * OTHER processes (e.g. netd, settings) get the laundered view. */
	if (is_target_uid_val(uid))
		return;
	if (!is_hook_active(HOOK_BPF, uid))
		return;

	if (vh_is_wide_stats_map(map)) {
		const struct vh_stats_key *sk = key;

		if (vh_is_vpn_stats_key(map, sk)) {
			memset(sv, 0, sizeof(*sv));
			vpnhide_dbg("zeroed bpf elem uid=%u ifidx=%u\n",
				    sk->uid, sk->ifaceIndex);
		}
		return;
	}

	if (vh_is_iface_stats_map(map)) {
		u32 ifindex = *(u32 *)key;
		u32 cover_idx;

		if (is_active_vpn_ifindex(ifindex)) {
			memset(sv, 0, sizeof(*sv));
			vpnhide_dbg("zeroed bpf iface elem ifidx=%u\n", ifindex);
			return;
		}

		cover_idx = (u32)atomic_read(&global_cover_ifindex);
		if (cover_idx && ifindex == cover_idx) {
			struct vh_stats_value vpn_sum;

			memset(&vpn_sum, 0, sizeof(vpn_sum));
			vh_collect_vpn_traffic_sum(map, &vpn_sum);
			if (sv_rx_bytes(&vpn_sum) || sv_tx_bytes(&vpn_sum)) {
				sv_add(sv, &vpn_sum);
				vpnhide_dbg("laundered cover elem ifidx=%u\n",
					    ifindex);
			}
		}
	}
}
EXPORT_SYMBOL_GPL(vpnhide_bpf_lookup_elem);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
/* Zero all VPN entries in a batch lookup result. Keys/values are laid out
 * back-to-back using the map's own key_size/value_size — NOT
 * sizeof(struct vh_stats_key/value) which only applies to "wide" maps and
 * would both misparse "iface_stats" (u32-keyed) maps and over-read the
 * user buffer. */
void vpnhide_bpf_lookup_batch(struct bpf_map *map,
			      const union bpf_attr *attr,
			      union bpf_attr __user *uattr)
{
	void *keys_buf  = NULL;
	void *vals_buf  = NULL;
	u32 key_size, value_size;
	u32 count = 0;
	u32 i;
	bool wide, iface;
	uid_t uid;

	if (!map || !attr || !uattr)
		return;
	if (!(vpnhide_active_hooks_mask() & BIT(HOOK_BPF)))
		return;
	uid = from_kuid(&init_user_ns, current_uid());
	/* The target process itself must see its own real traffic. */
	if (is_target_uid_val(uid))
		return;
	if (!is_hook_active(HOOK_BPF, uid))
		return;
	wide  = vh_is_wide_stats_map(map);
	iface = vh_is_iface_stats_map(map);
	if (!wide && !iface)
		return;

	key_size   = map->key_size;
	value_size = map->value_size;

	if (get_user(count, &uattr->batch.count))
		return;
	if (!count || count > 4096)
		return;

	keys_buf = kvmalloc_array(count, key_size, GFP_KERNEL);
	vals_buf = kvmalloc_array(count, value_size, GFP_KERNEL);
	if (!keys_buf || !vals_buf)
		goto out;

	if (copy_from_user(keys_buf,
			   u64_to_user_ptr(attr->batch.keys),
			   (size_t)count * key_size))
		goto out;
	if (copy_from_user(vals_buf,
			   u64_to_user_ptr(attr->batch.values),
			   (size_t)count * value_size))
		goto out;

	for (i = 0; i < count; i++) {
		void *k = (char *)keys_buf + (size_t)i * key_size;
		void *v = (char *)vals_buf + (size_t)i * value_size;
		bool hide = wide ? vh_is_vpn_stats_key(map, k)
				 : is_active_vpn_ifindex(*(u32 *)k);

		if (hide)
			memset(v, 0, value_size);
	}

	/* Interface maps expose one row per ifindex.  Keep the aggregate traffic
	 * visible by moving every hidden VPN row onto the configured cover row,
	 * exactly as the single-element lookup path does.  The sum is obtained
	 * from the map itself rather than from the batch, because a batch can be a
	 * partial page of a larger map. */
	if (iface && value_size >= sizeof(struct vh_stats_value)) {
		struct vh_stats_value vpn_sum = {0};
		u32 cover_idx = (u32)atomic_read(&global_cover_ifindex);
		int cover_pos = -1;

		vh_collect_vpn_traffic_sum(map, &vpn_sum);
		if (cover_idx &&
		    (sv_rx_bytes(&vpn_sum) || sv_tx_bytes(&vpn_sum))) {
			for (i = 0; i < count; i++) {
				void *k = (char *)keys_buf + (size_t)i * key_size;
				if (*(u32 *)k == cover_idx) {
					cover_pos = (int)i;
					break;
				}
			}
		}
		if (cover_pos >= 0)
			sv_add((struct vh_stats_value *)((char *)vals_buf +
					(size_t)cover_pos * value_size), &vpn_sum);
	}

	if (copy_to_user(u64_to_user_ptr(attr->batch.values),
			 vals_buf, (size_t)count * value_size)) {
		/* ignore copy error as we are in void post-hook and memory is already updated */
	}
out:
	kvfree(keys_buf);
	kvfree(vals_buf);
}
EXPORT_SYMBOL_GPL(vpnhide_bpf_lookup_batch);
#endif
