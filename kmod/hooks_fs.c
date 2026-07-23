#include "vpnhide_kmod.h"

/* --- eBPF Map Hijacking / Stats Hiding --- */

static inline bool is_stats_or_uid_map(const char *name) {
  if (!name || name[0] == '\0')
    return false;

  switch (name[0]) {
  case 'a':
    return strncmp(name, "app_uid_stats", 13) == 0;
  case 's':
    return strncmp(name, "stats_map_", 10) == 0;
  case 'i':
    return strncmp(name, "iface_stats", 11) == 0;
  case 'u':
    return strncmp(name, "uid_stats", 9) == 0;
  case 't':
    return strncmp(name, "tether_stats", 12) == 0;
  case 'm':
    return (strncmp(name, "map_netd_app_ui", 15) == 0 ||
            strncmp(name, "map_netd_stats", 14) == 0 ||
            strncmp(name, "map_netd_iface_", 15) == 0 ||
            strncmp(name, "map_netd_uid_st", 15) == 0);
  default:
    return false;
  }
}

static bool is_key_vpn_or_target_uid(struct bpf_map *map, void *key) {
  if (!map || !key)
    return false;

  if (strncmp(map->name, "stats_map_", 10) == 0 ||
      strncmp(map->name, "map_netd_stats", 14) == 0) {
    struct vh_stats_key *sk = (struct vh_stats_key *)key;

    vpnhide_dbg("key_check stats_map '%s': uid=%u index=%u\n", map->name,
                sk->uid, sk->ifaceIndex);

    if (is_active_vpn_ifindex(sk->ifaceIndex) || is_target_uid_val(sk->uid)) {
      vpnhide_dbg("BPF Match stats_map '%s': uid=%u index=%u -> SPOOFING ZERO STATS\n",
                  map->name, sk->uid, sk->ifaceIndex);
      return true;
    }
  } else if (strncmp(map->name, "iface_stats", 11) == 0 ||
             strncmp(map->name, "map_netd_iface_", 15) == 0 ||
             strncmp(map->name, "tether_stats", 12) == 0) {
    u32 ifaceIndex = *(u32 *)key;

    vpnhide_dbg("key_check iface/tether '%s': index=%u\n", map->name,
                ifaceIndex);

    if (is_active_vpn_ifindex(ifaceIndex)) {
      vpnhide_dbg("BPF Match iface/tether stats '%s': index=%u -> SPOOFING ZERO STATS\n",
                  map->name, ifaceIndex);
      return true;
    }
  }
  return false;
}

struct sys_bpf_data {
  int cmd;
  union bpf_attr __user *uattr;
  unsigned int size;
  union bpf_attr attr;
  u32 map_fd;
};


static int sys_bpf_entry(struct kretprobe_instance *ri, struct pt_regs *regs) {
  struct sys_bpf_data *data = (struct sys_bpf_data *)ri->data;
  int cmd;
  union bpf_attr __user *uattr;
  unsigned int size;

  if (!is_hook_active(HOOK_BPF, from_kuid(&init_user_ns, current_uid())) ||
      is_target_uid()) {
    data->uattr = NULL;
    return 1;
  }

  if (sys_bpf_uses_wrapper) {
    struct pt_regs *user_regs = (struct pt_regs *)regs->regs[0];
    if (user_regs && (unsigned long)user_regs >= 0xFFFF000000000000ULL) {
      cmd = (int)user_regs->regs[0];
      uattr = (union bpf_attr __user *)user_regs->regs[1];
      size = (unsigned int)user_regs->regs[2];
    } else {
      return 1;
    }
  } else {
    cmd = (int)regs->regs[0];
    uattr = (union bpf_attr __user *)regs->regs[1];
    size = (unsigned int)regs->regs[2];
  }

  data->cmd = cmd;
  data->uattr = uattr;
  data->size = size;
  data->map_fd = 0;

  if (uattr &&
      (cmd == BPF_MAP_LOOKUP_ELEM || cmd == BPF_MAP_UPDATE_ELEM ||
       cmd == BPF_MAP_DELETE_ELEM || cmd == BPF_MAP_GET_NEXT_KEY ||
       cmd == BPF_MAP_LOOKUP_AND_DELETE_ELEM || cmd == BPF_MAP_LOOKUP_BATCH ||
       cmd == BPF_MAP_LOOKUP_AND_DELETE_BATCH)) {
    unsigned int copy_sz = min_t(unsigned int, size, sizeof(data->attr));
    memset(&data->attr, 0, sizeof(data->attr));
    if (copy_from_user(&data->attr, uattr, copy_sz)) {
      data->uattr = NULL;
    } else {
      if (cmd == BPF_MAP_LOOKUP_BATCH ||
          cmd == BPF_MAP_LOOKUP_AND_DELETE_BATCH) {
        data->map_fd = data->attr.batch.map_fd;
      } else {
        data->map_fd = data->attr.map_fd;
      }
    }
  }
  return 0;
}

static struct bpf_map *bpf_map_from_fd(u32 map_fd, struct fd *out_f) {
  struct file *file_ptr;
  unsigned long magic = 0;
  const char *dname = "unknown";

  *out_f = fdget(map_fd);
  file_ptr = vh_fd_file(*out_f);
  if (!file_ptr)
    goto fail;

  if (file_ptr->f_path.dentry) {
    dname = file_ptr->f_path.dentry->d_name.name;
    if (file_ptr->f_path.dentry->d_sb) {
      magic = file_ptr->f_path.dentry->d_sb->s_magic;
    }
  }

  if (file_ptr->private_data) {
    bool is_bpf_file = false;

    if (magic == BPF_FS_MAGIC) {
      is_bpf_file = true;
    } else if ((magic == 0x09041934 || magic == 0x09041957) && dname &&
               strcmp(dname, "bpf-map") == 0) {
      is_bpf_file = true;
    }

    if (is_bpf_file) {
      struct bpf_map *map = file_ptr->private_data;

      if (map && !IS_ERR(map)) {
        return map;
      }
    }
  }

fail:
  fdput(*out_f);
  return NULL;
}

static void collect_vpn_traffic_sum(struct bpf_map *map,
                                    struct vh_stats_value *vpn_sum) {
  struct vpnhide_active_vpns *vpns;
  rcu_read_lock();
  vpns = rcu_dereference(global_active_vpns);
  if (vpns) {
    int idx;
    for (idx = 0; idx < vpns->count; idx++) {
      u32 vpn_idx = vpns->vpns[idx].ifindex;
      void *map_val = map->ops->map_lookup_elem(map, &vpn_idx);
      if (map_val) {
        struct vh_stats_value *sv = (struct vh_stats_value *)map_val;
        sv_add(vpn_sum, sv);
      }
    }
  }
  rcu_read_unlock();
}

static void bpf_single_cover_update(struct bpf_map *map, void __user *usr_val,
                                    u32 value_size, void *vbuf,
                                    struct vh_stats_value *vpn_sum) {
  struct vh_stats_value *sv;

  if (!sv_rx_bytes(vpn_sum) && !sv_tx_bytes(vpn_sum))
    return;

  if (copy_from_user(vbuf, usr_val, value_size) != 0)
    return;

  sv = (struct vh_stats_value *)vbuf;
  sv_add(sv, vpn_sum);

  if (copy_to_user(usr_val, vbuf, value_size) != 0) {
    vpnhide_dbg("sys_bpf_ret: single cover update copy_to_user failed\n");
  } else {
    vpnhide_dbg("sys_bpf_ret: single cover update for map '%s' success (rx=%llu, tx=%llu)\n",
                map->name, sv_rx_bytes(vpn_sum), sv_tx_bytes(vpn_sum));
  }
}

static void bpf_single_lookup_zero(struct bpf_map *map,
                                   const union bpf_attr *attr, u32 key_size,
                                   u32 value_size) {
  u8 kbuf_stack[64];
  u8 vbuf_stack[256];
  void *kbuf = NULL;
  void *vbuf = NULL;
  void __user *usr_key;
  void __user *usr_val;
  u32 ifaceIndex;
  u32 cover_idx;
  struct vh_stats_value vpn_sum;

  if (key_size <= sizeof(kbuf_stack)) {
    kbuf = kbuf_stack;
  } else {
    kbuf = kmalloc(key_size, GFP_KERNEL);
  }

  if (value_size <= sizeof(vbuf_stack)) {
    vbuf = vbuf_stack;
    memset(vbuf, 0, value_size);
  } else {
    vbuf = kzalloc(value_size, GFP_KERNEL);
  }

  if (!kbuf || !vbuf)
    goto out;

  usr_key = (void __user *)(unsigned long)attr->key;
  usr_val = (void __user *)(unsigned long)attr->value;

  if (copy_from_user(kbuf, usr_key, key_size) != 0)
    goto out;

  if (is_key_vpn_or_target_uid(map, kbuf)) {
    vpnhide_dbg("sys_bpf_ret: single zeroing for map '%s'\n", map->name);
    if (copy_to_user(usr_val, vbuf, value_size)) {
      vpnhide_dbg("sys_bpf_ret: single zeroing copy_to_user failed\n");
    }
  } else if (strncmp(map->name, "iface_stats", 11) == 0 ||
             strncmp(map->name, "map_netd_iface_", 15) == 0 ||
             strncmp(map->name, "tether_stats", 12) == 0) {
    ifaceIndex = *(u32 *)kbuf;
    cover_idx = (u32)atomic_read(&global_cover_ifindex);
    if (cover_idx && ifaceIndex == cover_idx) {
      memset(&vpn_sum, 0, sizeof(vpn_sum));
      collect_vpn_traffic_sum(map, &vpn_sum);
      bpf_single_cover_update(map, usr_val, value_size, vbuf, &vpn_sum);
    }
  }

out:
  if (kbuf && kbuf != kbuf_stack)
    kfree(kbuf);
  if (vbuf && vbuf != vbuf_stack)
    kfree(vbuf);
}

static void bpf_batch_zero_iface(struct bpf_map *map, void __user *usr_keys,
                                 void __user *usr_vals, u32 count, u32 key_size,
                                 u32 value_size, void *kbuf, void *vbuf) {
  struct vh_stats_value vpn_sum = {0};
  u32 cover_idx = (u32)atomic_read(&global_cover_ifindex);
  u32 cover_pos = UINT_MAX;
  u32 i;

  for (i = 0; i < count; i++) {
    u32 ifindex;

    if (copy_from_user(kbuf, (char __user *)usr_keys + i * key_size, key_size))
      continue;
    ifindex = *(u32 *)kbuf;

    if (is_active_vpn_ifindex(ifindex)) {
      if (copy_from_user(vbuf, (char __user *)usr_vals + i * value_size,
                         value_size) == 0) {
        struct vh_stats_value *sv = (struct vh_stats_value *)vbuf;
        sv_add(&vpn_sum, sv);
      }
      memset(vbuf, 0, value_size);
      if (copy_to_user((char __user *)usr_vals + i * value_size, vbuf,
                       value_size)) {
        vpnhide_dbg("sys_bpf_ret: batch zeroing copy_to_user failed\n");
      }
    } else if (cover_idx && ifindex == cover_idx) {
      cover_pos = i;
    }
  }

  if (cover_pos != UINT_MAX &&
      (sv_rx_bytes(&vpn_sum) || sv_tx_bytes(&vpn_sum))) {
    if (copy_from_user(vbuf, (char __user *)usr_vals + cover_pos * value_size,
                       value_size) == 0) {
      struct vh_stats_value *sv = (struct vh_stats_value *)vbuf;
      sv_add(sv, &vpn_sum);
      if (copy_to_user((char __user *)usr_vals + cover_pos * value_size, vbuf,
                       value_size)) {
        vpnhide_dbg("sys_bpf_ret: batch cover update copy_to_user failed\n");
      }
    }
  }
}

static void bpf_batch_zero_generic(struct bpf_map *map, void __user *usr_keys,
                                   void __user *usr_vals, u32 count,
                                   u32 key_size, u32 value_size, void *kbuf,
                                   void *vbuf) {
  u32 i;

  for (i = 0; i < count; i++) {
    if (copy_from_user(kbuf, (char __user *)usr_keys + i * key_size,
                       key_size) == 0) {
      if (is_key_vpn_or_target_uid(map, kbuf)) {
        memset(vbuf, 0, value_size);
        if (copy_to_user((char __user *)usr_vals + i * value_size, vbuf,
                         value_size)) {
          vpnhide_dbg("sys_bpf_ret: batch zeroing copy_to_user failed\n");
        }
      }
    }
  }
}

static void bpf_batch_lookup_zero(struct bpf_map *map,
                                  const struct sys_bpf_data *data, u32 key_size,
                                  u32 value_size) {
  u32 count = 0;

  if (get_user(count, &data->uattr->batch.count) == 0 && count > 0) {
    void __user *usr_keys = (void __user *)(unsigned long)data->attr.batch.keys;
    void __user *usr_vals =
        (void __user *)(unsigned long)data->attr.batch.values;

    if (usr_keys && usr_vals) {
      u8 kbuf_stack[64];
      u8 vbuf_stack[256];
      void *kbuf = NULL;
      void *vbuf = NULL;

      if (key_size <= sizeof(kbuf_stack)) {
        kbuf = kbuf_stack;
      } else {
        kbuf = kmalloc(key_size, GFP_KERNEL);
      }

      if (value_size <= sizeof(vbuf_stack)) {
        vbuf = vbuf_stack;
      } else {
        vbuf = kmalloc(value_size, GFP_KERNEL);
      }

      if (kbuf && vbuf) {
        if (strncmp(map->name, "iface_stats", 11) == 0 ||
            strncmp(map->name, "map_netd_iface_stats", 20) == 0) {
          bpf_batch_zero_iface(map, usr_keys, usr_vals, count, key_size,
                               value_size, kbuf, vbuf);
        } else {
          bpf_batch_zero_generic(map, usr_keys, usr_vals, count, key_size,
                                 value_size, kbuf, vbuf);
        }
      }
      if (kbuf && kbuf != kbuf_stack)
        kfree(kbuf);
      if (vbuf && vbuf != vbuf_stack)
        kfree(vbuf);
    }
  }
}

static int sys_bpf_ret(struct kretprobe_instance *ri, struct pt_regs *regs) {
  struct sys_bpf_data *data = (struct sys_bpf_data *)ri->data;
  int ret_val = regs_return_value(regs);
  struct bpf_map *map;
  struct fd f;

  if (!data || !data->uattr)
    return 0;

  if (ret_val < 0 && ret_val != -ENOENT)
    return 0;

  if (data->cmd != BPF_MAP_LOOKUP_ELEM &&
      data->cmd != BPF_MAP_LOOKUP_AND_DELETE_ELEM &&
      data->cmd != BPF_MAP_LOOKUP_BATCH &&
      data->cmd != BPF_MAP_LOOKUP_AND_DELETE_BATCH) {
    return 0;
  }

  map = bpf_map_from_fd(data->map_fd, &f);
  if (!map)
    return 0;

  if (is_stats_or_uid_map(map->name)) {
    u32 key_size = map->key_size;
    u32 value_size = map->value_size;

    vpnhide_dbg("sys_bpf_ret: matched map '%s', cmd=%d\n", map->name,
                data->cmd);

    if ((data->cmd == BPF_MAP_LOOKUP_ELEM ||
         data->cmd == BPF_MAP_LOOKUP_AND_DELETE_ELEM) &&
        ret_val == 0) {
      bpf_single_lookup_zero(map, &data->attr, key_size, value_size);
    }
    else if (data->cmd == BPF_MAP_LOOKUP_BATCH ||
             data->cmd == BPF_MAP_LOOKUP_AND_DELETE_BATCH) {
      bpf_batch_lookup_zero(map, data, key_size, value_size);
    }
  }

  fdput(f);
  return 0;
}

struct kretprobe sys_bpf_krp = {
    .entry_handler = sys_bpf_entry,
    .handler = sys_bpf_ret,
    .data_size = sizeof(struct sys_bpf_data),
    .maxactive = VPNHIDE_KRETPROBE_MAXACTIVE,
    .kp.symbol_name = "__arm64_sys_bpf",
};

/* --- Filesystem/procfs hooks --- */

static const char *const vh_guarded_dir_prefixes[] = {
    "/proc/sys/net/ipv4/conf",  "/proc/sys/net/ipv6/conf",
    "/proc/sys/net/ipv4/neigh", "/proc/sys/net/ipv6/neigh",
    "/proc/net/dev_snmp6",      "/sys/class/net",
};

static bool vh_is_path_guarded(struct file *file, char *buf, int buflen) {
  char *path_ptr;
  int i;

  if (!file)
    return false;

  path_ptr = d_path(&file->f_path, buf, buflen);
  if (IS_ERR(path_ptr))
    return false;

  for (i = 0; i < ARRAY_SIZE(vh_guarded_dir_prefixes); i++) {
    size_t len = strlen(vh_guarded_dir_prefixes[i]);
    if (strncmp(path_ptr, vh_guarded_dir_prefixes[i], len) == 0) {
      if (path_ptr[len] == '\0' || path_ptr[len] == '/')
        return true;
    }
  }

  return false;
}

struct vh_linux_dirent64 {
  u64 d_ino;
  s64 d_off;
  unsigned short d_reclen;
  unsigned char d_type;
  char d_name[];
};

struct getdents64_data {
  void __user *dirp;
  unsigned int count;
  bool should_filter;
};


static int sys_getdents64_entry(struct kretprobe_instance *ri,
                                struct pt_regs *regs) {
  struct getdents64_data *data;
  int fd;
  void __user *dirp;
  unsigned int count;
  struct fd f;
  struct file *file_ptr;
  char path_buf[256];
  bool is_guarded = false;

  if (!is_hook_active(HOOK_GETDENTS64, from_kuid(&init_user_ns, current_uid())))
    return 1;

  if (!is_target_uid())
    return 1;

  data = (void *)ri->data;
  data->should_filter = false;

  if (sys_getdents64_uses_wrapper) {
    struct pt_regs *user_regs = (struct pt_regs *)regs->regs[0];
    if (user_regs && (unsigned long)user_regs >= 0xFFFF000000000000ULL) {
      fd = (int)user_regs->regs[0];
      dirp = (void __user *)user_regs->regs[1];
      count = (unsigned int)user_regs->regs[2];
    } else {
      return 1;
    }
  } else {
    fd = (int)regs->regs[0];
    dirp = (void __user *)regs->regs[1];
    count = (unsigned int)regs->regs[2];
  }

  data->dirp = dirp;
  data->count = count;

  f = fdget(fd);
  file_ptr = vh_fd_file(f);
  if (file_ptr) {
    is_guarded = vh_is_path_guarded(file_ptr, path_buf, sizeof(path_buf));
  }
  fdput(f);

  if (is_guarded) {
    data->should_filter = true;
    vpnhide_dbg("getdents64_entry: guarding fd=%d\n", fd);
    return 0;
  }

  return 1;
}

static int sys_getdents64_ret(struct kretprobe_instance *ri,
                              struct pt_regs *regs) {
  struct getdents64_data *data = (void *)ri->data;
  int retval = (int)regs_return_value(regs);
  u8 *buf = NULL;

  if (!data->should_filter || retval <= 0)
    return 0;

  buf = kvmalloc(retval, GFP_ATOMIC);
  if (!buf)
    return 0;

  if (copy_from_user(buf, data->dirp, retval) == 0) {
    u8 *p = buf;
    u8 *end = buf + retval;
    u8 *dst = buf;
    int modified = 0;

    while (p < end) {
      struct vh_linux_dirent64 *de = (struct vh_linux_dirent64 *)p;
      if (de->d_reclen < sizeof(struct vh_linux_dirent64) ||
          p + de->d_reclen > end)
        break;

      if (vh_is_vpn_name_cached(de->d_name, strlen(de->d_name))) {
        vpnhide_dbg("sys_getdents64_ret: filtering out entry '%s'\n",
                    de->d_name);
        record_kmod_intercept(from_kuid(&init_user_ns, current_uid()), 2);
        modified = 1;
      } else {
        if (dst != p) {
          memmove(dst, p, de->d_reclen);
        }
        dst += de->d_reclen;
      }
      p += de->d_reclen;
    }

    if (modified) {
      int new_len = dst - buf;
      if (copy_to_user(data->dirp, buf, new_len) == 0) {
        regs_set_return_value(regs, new_len);
      }
    }
  }

  kvfree(buf);
  return 0;
}

struct kretprobe sys_getdents64_krp = {
    .entry_handler = sys_getdents64_entry,
    .handler = sys_getdents64_ret,
    .data_size = sizeof(struct getdents64_data),
    .maxactive = VPNHIDE_KRETPROBE_MAXACTIVE,
    .kp.symbol_name = "__arm64_sys_getdents64",
};

static int get_path_from_dfd_and_name(int dfd, const char __user *filename,
                                      char *buf, int buflen) {
  char name[256];
  struct fd f;
  struct file *file_ptr;
  char path_buf[256];
  char *path_ptr;
  int len;
  int name_len;

  if (!filename)
    return -EINVAL;

  name_len = strncpy_from_user(name, filename, sizeof(name) - 1);
  if (name_len < 0)
    return name_len;
  name[name_len] = '\0';

  if (name[0] == '/') {
    len = snprintf(buf, buflen, "%s", name);
    return (len >= buflen) ? -ENAMETOOLONG : 0;
  }

  if (dfd == AT_FDCWD) {
    len = snprintf(buf, buflen, "%s", name);
    return (len >= buflen) ? -ENAMETOOLONG : 0;
  }

  f = fdget(dfd);
  file_ptr = vh_fd_file(f);
  if (!file_ptr) {
    fdput(f);
    return -EBADF;
  }

  path_ptr = d_path(&file_ptr->f_path, path_buf, sizeof(path_buf));
  if (IS_ERR(path_ptr)) {
    fdput(f);
    return PTR_ERR(path_ptr);
  }

  len = snprintf(buf, buflen, "%s/%s", path_ptr, name);
  fdput(f);

  return (len >= buflen) ? -ENAMETOOLONG : 0;
}

static bool vh_is_resolved_path_guarded_vpn(const char *path) {
  int i;
  const char *last_slash;
  const char *iface_name;
  size_t iface_len;

  if (!path)
    return false;

  for (i = 0; i < ARRAY_SIZE(vh_guarded_dir_prefixes); i++) {
    size_t prefix_len = strlen(vh_guarded_dir_prefixes[i]);
    if (strncmp(path, vh_guarded_dir_prefixes[i], prefix_len) == 0) {
      if (path[prefix_len] == '/') {
        last_slash = strrchr(path, '/');
        if (last_slash) {
          iface_name = last_slash + 1;
          iface_len = strlen(iface_name);
          if (vh_is_vpn_name_cached(iface_name, iface_len)) {
            return true;
          }
        }
      }
    }
  }
  return false;
}

struct path_oracle_data {
  bool should_deny;
};

static int path_oracle_entry(struct kretprobe_instance *ri,
                             struct pt_regs *regs, int dfd_idx,
                             int filename_idx, enum vpnhide_hook_idx hook_idx) {
  struct path_oracle_data *data;
  int dfd;
  const char __user *filename;
  char path_buf[512];
  bool uses_wrapper = false;

  if (!is_hook_active(hook_idx, from_kuid(&init_user_ns, current_uid())))
    return 1;

  if (!is_target_uid())
    return 1;

  data = (void *)ri->data;
  data->should_deny = false;

  switch (hook_idx) {
  case HOOK_OPENAT:
    uses_wrapper = sys_openat_uses_wrapper;
    break;
  case HOOK_OPENAT2:
    uses_wrapper = sys_openat2_uses_wrapper;
    break;
  case HOOK_FACCESSAT:
    uses_wrapper = sys_faccessat_uses_wrapper;
    break;
  case HOOK_FACCESSAT2:
    uses_wrapper = sys_faccessat2_uses_wrapper;
    break;
  case HOOK_NEWFSTATAT:
    uses_wrapper = sys_newfstatat_uses_wrapper;
    break;
  case HOOK_READLINKAT:
    uses_wrapper = sys_readlinkat_uses_wrapper;
    break;
  default:
    break;
  }

  if (uses_wrapper) {
    struct pt_regs *user_regs = (struct pt_regs *)regs->regs[0];
    if (user_regs && (unsigned long)user_regs >= 0xFFFF000000000000ULL) {
      dfd = (int)user_regs->regs[dfd_idx];
      filename = (const char __user *)user_regs->regs[filename_idx];
    } else {
      return 1;
    }
  } else {
    dfd = (int)regs->regs[dfd_idx];
    filename = (const char __user *)regs->regs[filename_idx];
  }

  if (hook_idx == HOOK_NEWFSTATAT) {
    char head[11];
    long n = strncpy_from_user(head, filename, 10);
    if (n <= 0)
      return 1;
    head[n < 10 ? (size_t)n : 10] = '\0';
    if (!((n >= 5 && memcmp(head, "/sys/", 5) == 0) ||
          (n >= 10 && memcmp(head, "/proc/net/", 10) == 0)))
      return 1;
  }

  if (get_path_from_dfd_and_name(dfd, filename, path_buf, sizeof(path_buf)) ==
      0) {
    if (vh_is_resolved_path_guarded_vpn(path_buf)) {
      data->should_deny = true;
      vpnhide_dbg("path_oracle_entry: matched guarded vpn path '%s', denying\n",
                  path_buf);
      return 0;
    }
  }

  return 1;
}

static int path_oracle_ret(struct kretprobe_instance *ri,
                           struct pt_regs *regs) {
  struct path_oracle_data *data = (void *)ri->data;
  if (data->should_deny) {
    regs_set_return_value(regs, -ENOENT);
    record_kmod_intercept(from_kuid(&init_user_ns, current_uid()), 2);
  }
  return 0;
}

static int sys_openat_entry(struct kretprobe_instance *ri,
                            struct pt_regs *regs) {
  return path_oracle_entry(ri, regs, 0, 1, HOOK_OPENAT);
}
static int sys_openat_ret(struct kretprobe_instance *ri, struct pt_regs *regs) {
  return path_oracle_ret(ri, regs);
}
struct kretprobe sys_openat_krp = {
    .entry_handler = sys_openat_entry,
    .handler = sys_openat_ret,
    .data_size = sizeof(struct path_oracle_data),
    .maxactive = VPNHIDE_KRETPROBE_MAXACTIVE,
    .kp.symbol_name = "__arm64_sys_openat",
};

static int sys_openat2_entry(struct kretprobe_instance *ri,
                             struct pt_regs *regs) {
  return path_oracle_entry(ri, regs, 0, 1, HOOK_OPENAT2);
}
static int sys_openat2_ret(struct kretprobe_instance *ri,
                           struct pt_regs *regs) {
  return path_oracle_ret(ri, regs);
}
struct kretprobe sys_openat2_krp = {
    .entry_handler = sys_openat2_entry,
    .handler = sys_openat2_ret,
    .data_size = sizeof(struct path_oracle_data),
    .maxactive = VPNHIDE_KRETPROBE_MAXACTIVE,
    .kp.symbol_name = "__arm64_sys_openat2",
};

static int sys_faccessat_entry(struct kretprobe_instance *ri,
                               struct pt_regs *regs) {
  return path_oracle_entry(ri, regs, 0, 1, HOOK_FACCESSAT);
}
static int sys_faccessat_ret(struct kretprobe_instance *ri,
                             struct pt_regs *regs) {
  return path_oracle_ret(ri, regs);
}
struct kretprobe sys_faccessat_krp = {
    .entry_handler = sys_faccessat_entry,
    .handler = sys_faccessat_ret,
    .data_size = sizeof(struct path_oracle_data),
    .maxactive = VPNHIDE_KRETPROBE_MAXACTIVE,
    .kp.symbol_name = "__arm64_sys_faccessat",
};

static int sys_faccessat2_entry(struct kretprobe_instance *ri,
                                struct pt_regs *regs) {
  return path_oracle_entry(ri, regs, 0, 1, HOOK_FACCESSAT2);
}
static int sys_faccessat2_ret(struct kretprobe_instance *ri,
                              struct pt_regs *regs) {
  return path_oracle_ret(ri, regs);
}
struct kretprobe sys_faccessat2_krp = {
    .entry_handler = sys_faccessat2_entry,
    .handler = sys_faccessat2_ret,
    .data_size = sizeof(struct path_oracle_data),
    .maxactive = VPNHIDE_KRETPROBE_MAXACTIVE,
    .kp.symbol_name = "__arm64_sys_faccessat2",
};

static int sys_newfstatat_entry(struct kretprobe_instance *ri,
                                struct pt_regs *regs) {
  return path_oracle_entry(ri, regs, 0, 1, HOOK_NEWFSTATAT);
}
static int sys_newfstatat_ret(struct kretprobe_instance *ri,
                              struct pt_regs *regs) {
  return path_oracle_ret(ri, regs);
}
struct kretprobe sys_newfstatat_krp = {
    .entry_handler = sys_newfstatat_entry,
    .handler = sys_newfstatat_ret,
    .data_size = sizeof(struct path_oracle_data),
    .maxactive = VPNHIDE_KRETPROBE_MAXACTIVE,
    .kp.symbol_name = "__arm64_sys_newfstatat",
};

struct proc_sys_lookup_data {
  struct dentry *dentry;
  const unsigned char *orig_name;
  unsigned int orig_len;
  bool modified;
};

static int proc_sys_lookup_entry(struct kretprobe_instance *ri,
                                 struct pt_regs *regs) {
  struct proc_sys_lookup_data *data = (void *)ri->data;
  struct dentry *dentry;
  const unsigned char *name;
  unsigned int name_len;

  data->modified = false;
  data->dentry = NULL;

  if (!is_hook_active(HOOK_NEWFSTATAT, from_kuid(&init_user_ns, current_uid())))
    return 1;
  if (!is_target_uid())
    return 1;

  dentry = (struct dentry *)(uintptr_t)regs->regs[1];
  if (!dentry)
    return 1;

  name = dentry->d_name.name;
  name_len = dentry->d_name.len;
  if (!name || name_len == 0 || name_len >= IFNAMSIZ)
    return 1;

  if (vh_is_vpn_name_cached((const char *)name, (size_t)name_len)) {
    data->dentry = dentry;
    data->orig_name = dentry->d_name.name;
    data->orig_len = dentry->d_name.len;
    data->modified = true;

    dentry->d_name.name =
        (const unsigned char *)"__vpnhide_nonexistent_sysctl_void";
    dentry->d_name.len = 33;

    vpnhide_dbg("proc_sys_lookup: mangled VPN iface '%.*s' to void\n",
                (int)name_len, name);
    return 0;
  }

  return 1;
}

static int proc_sys_lookup_ret(struct kretprobe_instance *ri,
                               struct pt_regs *regs) {
  struct proc_sys_lookup_data *data = (void *)ri->data;
  if (data->modified && data->dentry) {
    data->dentry->d_name.name = data->orig_name;
    data->dentry->d_name.len = data->orig_len;
    record_kmod_intercept(from_kuid(&init_user_ns, current_uid()), 2);
  }
  return 0;
}

struct kretprobe proc_sys_lookup_krp = {
    .entry_handler = proc_sys_lookup_entry,
    .handler = proc_sys_lookup_ret,
    .data_size = sizeof(struct proc_sys_lookup_data),
    .maxactive = VPNHIDE_KRETPROBE_MAXACTIVE,
    .kp.symbol_name = "proc_sys_lookup",
};

static int sys_readlinkat_entry(struct kretprobe_instance *ri,
                                struct pt_regs *regs) {
  return path_oracle_entry(ri, regs, 0, 1, HOOK_READLINKAT);
}
static int sys_readlinkat_ret(struct kretprobe_instance *ri,
                              struct pt_regs *regs) {
  return path_oracle_ret(ri, regs);
}
struct kretprobe sys_readlinkat_krp = {
    .entry_handler = sys_readlinkat_entry,
    .handler = sys_readlinkat_ret,
    .data_size = sizeof(struct path_oracle_data),
    .maxactive = VPNHIDE_KRETPROBE_MAXACTIVE,
    .kp.symbol_name = "__arm64_sys_readlinkat",
};

/* --- UDP IPv4 queue emulator hook --- */

struct udp_sendmsg_data {
  struct sock *sk;
  int orig_sndbuf;
  bool spoofed;
};

#define BUCKET_CAPACITY 250
#define TOKEN_REGEN_NS 2000000ULL

struct udp_uid_rate {
  uid_t uid;
  u64 last_time_ns;
  u32 tokens;
};

static struct udp_uid_rate udp_rates[MAX_TARGET_UIDS];
static DEFINE_SPINLOCK(udp_rates_lock);

bool udp_rate_limit_exceeded(uid_t uid) {
  u64 now = ktime_get_ns();
  int i;
  bool limit_exceeded = false;
  unsigned long flags;

  spin_lock_irqsave(&udp_rates_lock, flags);
  for (i = 0; i < MAX_TARGET_UIDS; i++) {
    if (udp_rates[i].uid == uid) {
      if (now > udp_rates[i].last_time_ns) {
        u64 elapsed = now - udp_rates[i].last_time_ns;
        u64 reg_tokens = (elapsed * 1000ULL) / TOKEN_REGEN_NS;
        if (reg_tokens > 0) {
          udp_rates[i].tokens += (u32)reg_tokens;
          if (udp_rates[i].tokens >= BUCKET_CAPACITY * 1000) {
            udp_rates[i].tokens = BUCKET_CAPACITY * 1000;
            udp_rates[i].last_time_ns = now;
          } else {
            udp_rates[i].last_time_ns +=
                (reg_tokens * TOKEN_REGEN_NS) / 1000ULL;
          }
        }
      }

      if (udp_rates[i].tokens >= 1000) {
        udp_rates[i].tokens -= 1000;
        limit_exceeded = false;
      } else {
        limit_exceeded = true;
      }
      break;
    }
  }
  if (i == MAX_TARGET_UIDS) {
    for (i = 0; i < MAX_TARGET_UIDS; i++) {
      if (udp_rates[i].uid == 0) {
        udp_rates[i].uid = uid;
        udp_rates[i].last_time_ns = now;
        udp_rates[i].tokens = (BUCKET_CAPACITY - 1) * 1000;
        limit_exceeded = false;
        break;
      }
    }
  }
  spin_unlock_irqrestore(&udp_rates_lock, flags);
  return limit_exceeded;
}

/*
 * Only rate-limit sends that actually egress through a currently-hidden
 * VPN interface. Real physical interfaces produce genuine EAGAIN under
 * sustained flood (BQL/netif_stop_queue hold sk_wmem_alloc up); loopback
 * and other local traffic never experiences this, so throttling it
 * unconditionally is itself a distinguishing artifact, not a faithful
 * emulation.
 *
 * Unconnected sendto() resolves its route inside udp_sendmsg itself,
 * after this hook already ran — there is no cheap way to learn the
 * egress device yet, so we fail open (don't throttle) rather than
 * duplicate the kernel's own route lookup from kretprobe context.
 */
bool vpnhide_udp_dst_is_vpn_bound(struct sock *sk, struct msghdr *msg) {
  struct dst_entry *dst;
  bool vpn;

  if (msg && msg->msg_name)
    return false;

  if (sk->sk_family == AF_INET6) {
    if (ipv6_addr_loopback(&sk->sk_v6_daddr))
      return false;
  } else {
    if (ipv4_is_loopback(inet_sk(sk)->inet_daddr))
      return false;
  }

  dst = sk_dst_get(sk);
  if (!dst)
    return false;
  vpn = dst->dev && is_active_vpn_ifindex(dst->dev->ifindex);
  dst_release(dst);
  return vpn;
}

static int udp_sendmsg_entry(struct kretprobe_instance *ri,
                             struct pt_regs *regs) {
  struct udp_sendmsg_data *data;
  struct sock *sk;
  struct msghdr *msg;
  uid_t uid;

  if (!is_hook_active(HOOK_UDP_SENDMSG,
                      from_kuid(&init_user_ns, current_uid())))
    return 1;

  uid = from_kuid(&init_user_ns, current_uid());
  if (!is_target_uid_val(uid))
    return 1;

  sk = (struct sock *)regs->regs[0];
  msg = (struct msghdr *)regs->regs[1];

  if (!sk || !msg)
    return 1;

  data = (void *)ri->data;
  data->sk = sk;
  data->orig_sndbuf = sk->sk_sndbuf;
  data->spoofed = false;

  if ((msg->msg_flags & MSG_DONTWAIT) &&
      vpnhide_udp_dst_is_vpn_bound(sk, msg)) {
    if (udp_rate_limit_exceeded(uid)) {
      sk->sk_sndbuf = 0;
      data->spoofed = true;
      udelay(50);
    }
  }

  return 0;
}

static int udp_sendmsg_ret(struct kretprobe_instance *ri,
                           struct pt_regs *regs) {
  struct udp_sendmsg_data *data = (void *)ri->data;

  if (data->spoofed && data->sk)
    data->sk->sk_sndbuf = data->orig_sndbuf;

  return 0;
}

struct kretprobe udp_sendmsg_krp = {
    .entry_handler = udp_sendmsg_entry,
    .handler = udp_sendmsg_ret,
    .data_size = sizeof(struct udp_sendmsg_data),
    .maxactive = VPNHIDE_KRETPROBE_MAXACTIVE,
    .kp.symbol_name = "udp_sendmsg",
};
