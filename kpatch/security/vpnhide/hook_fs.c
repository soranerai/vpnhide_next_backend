// SPDX-License-Identifier: GPL-2.0
/*
 * vpnhide — filesystem, BPF, and UDP hooks
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

#define VH_STATS_MAP_PREFIX  "iface_stat_"
#define VH_UID_MAP_PREFIX    "uid_stats"

bool vh_is_stats_map(struct bpf_map *map)
{
	if (!map || !map->name[0])
		return false;
	return !strncmp(map->name, VH_STATS_MAP_PREFIX,
			strlen(VH_STATS_MAP_PREFIX)) ||
	       !strncmp(map->name, VH_UID_MAP_PREFIX,
			strlen(VH_UID_MAP_PREFIX));
}

bool vh_is_vpn_stats_key(struct bpf_map *map, const struct vh_stats_key *key)
{
	return is_active_vpn_ifindex(key->ifaceIndex) ||
	       is_target_uid_val(key->uid);
}

/* Zero a single BPF map entry for a VPN/target UID key */
void vpnhide_bpf_lookup_elem(struct bpf_map *map, void *key, void *value)
{
	const struct vh_stats_key *sk = key;
	struct vh_stats_value *sv = value;

	if (!map || !key || !value)
		return;
	if (!vh_is_stats_map(map))
		return;
	if (!vh_is_vpn_stats_key(map, sk))
		return;

	memset(sv, 0, sizeof(*sv));
	vpnhide_dbg("zeroed bpf elem uid=%u ifidx=%u\n",
		    sk->uid, sk->ifaceIndex);
}
EXPORT_SYMBOL_GPL(vpnhide_bpf_lookup_elem);

/* Zero all VPN entries in a batch lookup result */
void vpnhide_bpf_lookup_batch(struct bpf_map *map,
			      const union bpf_attr *attr,
			      union bpf_attr __user *uattr)
{
	struct vh_stats_key  *keys_buf  = NULL;
	struct vh_stats_value *vals_buf = NULL;
	u32 count = 0;
	u32 i;

	if (!map || !attr || !uattr)
		return;
	if (!vh_is_stats_map(map))
		return;

	if (get_user(count, &uattr->batch.count))
		return;
	if (!count || count > 4096)
		return;

	keys_buf = kvmalloc_array(count, sizeof(*keys_buf), GFP_KERNEL);
	vals_buf = kvmalloc_array(count, sizeof(*vals_buf), GFP_KERNEL);
	if (!keys_buf || !vals_buf)
		goto out;

	if (copy_from_user(keys_buf,
			   u64_to_user_ptr(attr->batch.keys_out),
			   count * sizeof(*keys_buf)))
		goto out;
	if (copy_from_user(vals_buf,
			   u64_to_user_ptr(attr->batch.values),
			   count * sizeof(*vals_buf)))
		goto out;

	for (i = 0; i < count; i++) {
		if (vh_is_vpn_stats_key(map, &keys_buf[i]))
			memset(&vals_buf[i], 0, sizeof(vals_buf[i]));
	}

	copy_to_user(u64_to_user_ptr(attr->batch.values),
		     vals_buf, count * sizeof(*vals_buf));
out:
	kvfree(keys_buf);
	kvfree(vals_buf);
}
EXPORT_SYMBOL_GPL(vpnhide_bpf_lookup_batch);

/* ------------------------------------------------------------------ */
/* getdents64 — filter VPN interface names from directory listings     */
/* ------------------------------------------------------------------ */

int vpnhide_getdents64(unsigned int fd,
		       struct linux_dirent64 __user *dirent,
		       unsigned int count, long retval)
{
	struct linux_dirent64 __user *pos, *end;
	struct linux_dirent64 *kbuf, *cur, *prev;
	uid_t uid = from_kuid(&init_user_ns, current_uid());
	long bytes_left;

	if (retval <= 0)
		return (int)retval;
	if (!is_hook_active(HOOK_GETDENTS64, uid))
		return (int)retval;

	kbuf = kvmalloc(retval, GFP_KERNEL);
	if (!kbuf)
		return (int)retval;

	if (copy_from_user(kbuf, dirent, retval)) {
		kvfree(kbuf);
		return (int)retval;
	}

	bytes_left = retval;
	prev = NULL;
	cur  = kbuf;

	while ((char *)cur < (char *)kbuf + retval) {
		struct linux_dirent64 *next =
			(struct linux_dirent64 *)((char *)cur + cur->d_reclen);

		if (vh_is_vpn_name_cached(cur->d_name,
					  strnlen(cur->d_name, NAME_MAX))) {
			/* Compact: memmove everything after cur back */
			long tail = (char *)kbuf + retval -
				    (char *)next;
			if (tail > 0)
				memmove(cur, next, tail);
			retval    -= cur->d_reclen;
			bytes_left = retval - ((char *)cur - (char *)kbuf);
			/* don't advance cur — it now points to next entry */
			record_kmod_intercept(uid, HOOK_GETDENTS64);
		} else {
			prev = cur;
			cur  = next;
		}
	}

	copy_to_user(dirent, kbuf, retval);
	kvfree(kbuf);
	return (int)retval;
}
EXPORT_SYMBOL_GPL(vpnhide_getdents64);

/* ------------------------------------------------------------------ */
/* Path hiding — openat / faccessat / newfstatat / readlinkat          */
/* ------------------------------------------------------------------ */

#define VH_PROC_SYS_NET   "/proc/sys/net/"
#define VH_SYS_CLASS_NET  "/sys/class/net/"

static bool path_in_guarded_dir(const char *path)
{
	return !strncmp(path, VH_PROC_SYS_NET, strlen(VH_PROC_SYS_NET)) ||
	       !strncmp(path, VH_SYS_CLASS_NET, strlen(VH_SYS_CLASS_NET));
}

bool vpnhide_should_hide_path(const struct path *path)
{
	struct dentry *dentry = path->dentry;
	uid_t uid = from_kuid(&init_user_ns, current_uid());

	if (!is_target_uid_val(uid))
		return false;

	/* Check if path is /proc/sys/net/<vpn_iface>/...
	 * or /sys/class/net/<vpn_iface>/... */
	if (dentry && dentry->d_parent) {
		const char *name = dentry->d_name.name;

		if (name && vh_is_vpn_name_cached(name, strlen(name)))
			return true;
	}
	return false;
}
EXPORT_SYMBOL_GPL(vpnhide_should_hide_path);

/* ------------------------------------------------------------------ */
/* proc_sys_lookup — mangle VPN dentry name during sysctl lookup       */
/*                                                                     */
/* Called in fs/proc/proc_sysctl.c after the table lookup succeeds.   */
/* If the found entry's parent is a VPN interface name node, we make   */
/* the lookup return -ENOENT instead.                                  */
/* ------------------------------------------------------------------ */

static const char vh_ghost_name[] = "__vpnhide_nonexistent_void";

bool vpnhide_filter_sysctl(struct inode *dir,
			   const char *name, size_t namelen)
{
	uid_t uid = from_kuid(&init_user_ns, current_uid());

	if (!is_target_uid_val(uid))
		return false;

	/* dir inode lives under /proc/sys/net/ — check if name
	 * matches an active VPN interface */
	if (namelen > 0 && namelen < MAX_IFACE_LEN) {
		if (vh_is_vpn_name_cached(name, namelen)) {
			record_kmod_intercept(uid, HOOK_OPENAT);
			return true;
		}
	}
	return false;
}
EXPORT_SYMBOL_GPL(vpnhide_filter_sysctl);
