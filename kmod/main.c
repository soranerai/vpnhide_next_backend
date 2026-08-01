#include "vpnhide_kmod.h"

bool g_stats_pkts_first = false;

DECLARE_WAIT_QUEUE_HEAD(vpnhide_config_wait);
atomic_t vpnhide_config_generation = ATOMIC_INIT(1);
atomic_t java_stats_clear_generation = ATOMIC_INIT(1);

struct vpnhide_policy_snapshot __rcu *global_policy_snapshot = NULL;
DEFINE_SPINLOCK(policy_snapshot_lock);

struct vpnhide_spoof_ip_rcu __rcu *global_spoof_ip = NULL;
DEFINE_SPINLOCK(spoof_ip_lock);

struct vpnhide_active_vpns __rcu *global_active_vpns = NULL;
DEFINE_SPINLOCK(active_vpns_lock);

struct vh_vpn_name_cache __rcu *g_vpn_name_cache = NULL;
DEFINE_SPINLOCK(g_vpn_name_cache_lock);

atomic_t global_cover_ifindex = ATOMIC_INIT(0);

/* Hook wrapper flags */
bool sys_setsockopt_uses_wrapper = false;
bool sys_getsockopt_uses_wrapper = false;
bool sys_connect_uses_wrapper = false;
bool sys_bind_uses_wrapper = false;
bool sys_getsockname_uses_wrapper = false;
bool sys_bpf_uses_wrapper = false;
bool sys_getdents64_uses_wrapper = false;
bool sys_openat_uses_wrapper = false;
bool sys_openat2_uses_wrapper = false;
bool sys_faccessat_uses_wrapper = false;
bool sys_faccessat2_uses_wrapper = false;
bool sys_newfstatat_uses_wrapper = false;
bool sys_readlinkat_uses_wrapper = false;

/* --- Core Configuration & Helper Functions --- */

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

bool lookup_app_kernel_mask(uid_t uid, unsigned int *out) {
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

bool is_hook_active(enum vpnhide_hook_idx index, uid_t uid) {
  unsigned int mask;

  if (lookup_app_kernel_mask(uid, &mask))
    return (mask & (1u << index)) != 0;

  return (vpnhide_active_hooks_mask() & (1u << index)) != 0;
}

void free_spoof_ip_rcu(struct rcu_head *head) {
  struct vpnhide_spoof_ip_rcu *p =
      container_of(head, struct vpnhide_spoof_ip_rcu, rcu);
  kfree(p);
}

int update_spoof_ip(const struct vpnhide_spoof_ip *sip) {
  struct vpnhide_spoof_ip_rcu *new_rcu, *old_rcu;

  new_rcu = kmalloc(sizeof(*new_rcu), GFP_ATOMIC);
  if (!new_rcu)
    return -ENOMEM;

  new_rcu->sip = *sip;

  spin_lock(&spoof_ip_lock);
  old_rcu = rcu_dereference_protected(global_spoof_ip,
                                      lockdep_is_held(&spoof_ip_lock));
  rcu_assign_pointer(global_spoof_ip, new_rcu);
  spin_unlock(&spoof_ip_lock);

  if (old_rcu)
    call_rcu(&old_rcu->rcu, free_spoof_ip_rcu);

  return 0;
}

void get_spoof_ip(struct vpnhide_spoof_ip *dst) {
  struct vpnhide_spoof_ip_rcu *p;

  rcu_read_lock();
  p = rcu_dereference(global_spoof_ip);
  if (p) {
    *dst = p->sip;
  } else {
    memset(dst, 0, sizeof(*dst));
  }
  rcu_read_unlock();
}

u32 fnv1a_name(const char *s, int maxlen) {
  u32 hash = 2166136261u;
  int i;
  for (i = 0; i < maxlen && s[i] != '\0'; i++) {
    hash ^= (u8)s[i];
    hash *= 16777619u;
  }
  return hash;
}

void free_vpn_name_cache_rcu(struct rcu_head *head) {
  struct vh_vpn_name_cache *p =
      container_of(head, struct vh_vpn_name_cache, rcu);
  kfree(p);
}

void vh_rebuild_name_cache(const struct vpnhide_vpn_ifindexes *idata) {
  struct vh_vpn_name_cache *new_c, *old_c;
  int i;

  new_c = kzalloc(sizeof(*new_c), GFP_KERNEL);
  if (!new_c)
    return;

  new_c->count =
      (idata->count < MAX_ACTIVE_VPNS) ? idata->count : MAX_ACTIVE_VPNS;
  for (i = 0; i < new_c->count; i++) {
    strncpy(new_c->names[i], idata->vpns[i].name, MAX_IFACE_LEN - 1);
    new_c->names[i][MAX_IFACE_LEN - 1] = '\0';
    new_c->hashes[i] = fnv1a_name(new_c->names[i], MAX_IFACE_LEN);
  }

  spin_lock(&g_vpn_name_cache_lock);
  old_c = rcu_dereference_protected(g_vpn_name_cache,
                                    lockdep_is_held(&g_vpn_name_cache_lock));
  rcu_assign_pointer(g_vpn_name_cache, new_c);
  spin_unlock(&g_vpn_name_cache_lock);

  if (old_c)
    call_rcu(&old_c->rcu, free_vpn_name_cache_rcu);
}

bool vh_is_vpn_name_cached(const char *name, size_t len) {
  struct vh_vpn_name_cache *c;
  u32 h;
  int i;
  bool found = false;

  if (unlikely(!name || len == 0))
    return false;

  h = fnv1a_name(name, len);

  rcu_read_lock();
  c = rcu_dereference(g_vpn_name_cache);
  if (likely(c)) {
    for (i = 0; i < c->count; i++) {
      if (c->hashes[i] == h && strncmp(c->names[i], name, MAX_IFACE_LEN) == 0) {
        found = true;
        break;
      }
    }
  }
  rcu_read_unlock();
  return found;
}

bool is_active_vpn_ifindex(u32 ifindex) {
  struct vpnhide_active_vpns *vpns;
  bool found = false;
  int i;

  rcu_read_lock();
  vpns = rcu_dereference(global_active_vpns);
  if (vpns) {
    for (i = 0; i < vpns->count; i++) {
      if (vpns->vpns[i].ifindex == ifindex) {
        found = true;
        break;
      }
    }
  }
  rcu_read_unlock();
  return found;
}

bool is_active_vpn_ifname(const char *name) {
  struct vpnhide_active_vpns *vpns;
  bool found = false;
  int i;

  if (!name || name[0] == '\0')
    return false;

  rcu_read_lock();
  vpns = rcu_dereference(global_active_vpns);
  if (vpns) {
    for (i = 0; i < vpns->count; i++) {
      if (strncmp(vpns->vpns[i].name, name, MAX_IFACE_LEN) == 0) {
        found = true;
        break;
      }
    }
  }
  rcu_read_unlock();
  return found;
}

bool is_target_uid_val(uid_t uid) {
  struct vpnhide_policy_snapshot *snapshot;
  bool found = false;
  int i;

  if (uid == 0 || uid == 1000)
    return false;

  rcu_read_lock();
  snapshot = rcu_dereference(global_policy_snapshot);
  if (snapshot) {
    for (i = 0; i < snapshot->payload.targets.kmod_count; i++) {
      if (snapshot->payload.targets.kmod_uids[i] == uid) {
        found = true;
        break;
      }
    }
  }
  rcu_read_unlock();
  return found;
}

bool is_target_uid(void) {
  return is_target_uid_val(from_kuid(&init_user_ns, current_uid()));
}

/* --- Current-session cumulative intercept statistics --- */

struct kmod_uid_stats_total {
  uid_t uid;
  u64 ioctl_count;
  u64 netlink_count;
  u64 proc_count;
  u64 sockopt_count;
  u64 connect_count;
  u64 getname_count;
  u64 port_count;
};

static struct kmod_uid_stats_total kmod_stats[MAX_TARGET_UIDS];
static int kmod_stats_count = 0;
DEFINE_SPINLOCK(kmod_stats_lock);
static atomic64_t kmod_stats_sequence = ATOMIC64_INIT(0);
static u64 kmod_stats_session_id;

void record_kmod_intercept(uid_t uid, int type) {
  int i;
  unsigned long flags;

  if (uid == 0 || uid == 1000)
    return;

  spin_lock_irqsave(&kmod_stats_lock, flags);
  for (i = 0; i < kmod_stats_count; i++) {
    if (kmod_stats[i].uid == uid) {
      if (type == 0)
        kmod_stats[i].ioctl_count++;
      else if (type == 1)
        kmod_stats[i].netlink_count++;
      else if (type == 2)
        kmod_stats[i].proc_count++;
      else if (type == 3)
        kmod_stats[i].sockopt_count++;
      else if (type == 4)
        kmod_stats[i].connect_count++;
      else if (type == 5)
        kmod_stats[i].getname_count++;
      else if (type == 6)
        kmod_stats[i].port_count++;
      spin_unlock_irqrestore(&kmod_stats_lock, flags);
      return;
    }
  }

  if (kmod_stats_count < MAX_TARGET_UIDS) {
    i = kmod_stats_count++;
    memset(&kmod_stats[i], 0, sizeof(kmod_stats[i]));
    kmod_stats[i].uid = uid;
    if (type == 0)
      kmod_stats[i].ioctl_count++;
    else if (type == 1)
      kmod_stats[i].netlink_count++;
    else if (type == 2)
      kmod_stats[i].proc_count++;
    else if (type == 3)
      kmod_stats[i].sockopt_count++;
    else if (type == 4)
      kmod_stats[i].connect_count++;
    else if (type == 5)
      kmod_stats[i].getname_count++;
    else if (type == 6)
      kmod_stats[i].port_count++;
  }
  spin_unlock_irqrestore(&kmod_stats_lock, flags);
}

static void kmod_stats_prune(const struct vpnhide_policy_payload *payload) {
  unsigned long flags;
  int i, j;

  spin_lock_irqsave(&kmod_stats_lock, flags);
  for (i = 0; i < kmod_stats_count;) {
    bool keep = false;
    for (j = 0; j < payload->targets.kmod_count; j++) {
      if (payload->targets.kmod_uids[j] == kmod_stats[i].uid) {
        keep = true;
        break;
      }
    }
    if (keep) {
      i++;
      continue;
    }
    kmod_stats[i] = kmod_stats[--kmod_stats_count];
    memset(&kmod_stats[kmod_stats_count], 0, sizeof(kmod_stats[0]));
  }
  spin_unlock_irqrestore(&kmod_stats_lock, flags);
}

static void free_policy_snapshot_rcu(struct rcu_head *head)
{
  struct vpnhide_policy_snapshot *snapshot =
      container_of(head, struct vpnhide_policy_snapshot, rcu);
  kvfree(snapshot);
}

static int policy_uid_cmp(const void *a, const void *b)
{
  uid_t ua = *(const uid_t *)a;
  uid_t ub = *(const uid_t *)b;
  return (ua > ub) - (ua < ub);
}

/* Common transaction entry point.  The payload is copied and validated before
 * the immutable snapshot is published. */
int vpnhide_apply_policy(const struct vpnhide_policy_payload *payload,
                         u64 expected_generation)
{
  struct vpnhide_policy_snapshot *snapshot, *old;
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

  if (expected_generation &&
      expected_generation != (u64)atomic_read(&vpnhide_config_generation))
    return -EAGAIN;

  for (i = 0; i < payload->ports.count; i++) {
    const struct vpnhide_uid_port_rules *target = &payload->ports.targets[i];
    if (target->rule_count < 0 || target->rule_count > MAX_PORT_RULES_PER_UID)
      return -EINVAL;
    for (j = 0; j < target->rule_count; j++) {
      const struct vpnhide_port_rule *rule = &target->rules[j];
      if (rule->start_port > rule->end_port || rule->protocol > VH_PROTO_BOTH)
        return -EINVAL;
    }
  }

  snapshot = kvzalloc(sizeof(*snapshot), GFP_KERNEL);
  if (!snapshot)
    return -ENOMEM;
  snapshot->payload = *payload;
  /* Port policy is authoritative and must not be disabled by a global or
   * per-app hook mask. CONNECT/BIND are required for port enforcement. */
  snapshot->payload.active_hooks_mask |=
      BIT(HOOK_CONNECT) | BIT(HOOK_BIND);
  for (i = 0; i < snapshot->payload.app_hook_masks.count; i++) {
    if (snapshot->payload.app_hook_masks.masks[i].has_kernel_override)
      snapshot->payload.app_hook_masks.masks[i].kernel_mask |=
          BIT(HOOK_CONNECT) | BIT(HOOK_BIND);
  }
  kmod_stats_prune(&snapshot->payload);
  sort(snapshot->payload.targets.kmod_uids,
       snapshot->payload.targets.kmod_count, sizeof(uid_t),
       policy_uid_cmp, NULL);
  sort(snapshot->payload.targets.lsposed_uids,
       snapshot->payload.targets.lsposed_count, sizeof(uid_t),
       policy_uid_cmp, NULL);

  spin_lock(&policy_snapshot_lock);
  old = rcu_dereference_protected(global_policy_snapshot,
                                  lockdep_is_held(&policy_snapshot_lock));
  rcu_assign_pointer(global_policy_snapshot, snapshot);
  spin_unlock(&policy_snapshot_lock);
  if (old)
    call_rcu(&old->rcu, free_policy_snapshot_rcu);

  atomic_inc(&vpnhide_config_generation);
  wake_up_interruptible(&vpnhide_config_wait);
  return 0;
}

/* --- Control Device file operations --- */

static char java_stats_buf[4096];
static DEFINE_MUTEX(java_stats_lock);
static char java_status_buf[256];
static DEFINE_MUTEX(java_status_lock);

static char global_cover_ifname[IFNAMSIZ];
static DEFINE_SPINLOCK(cover_ifname_lock);

struct vpnhide_dev_reader {
  unsigned long generation;
  char *buf;
  size_t buf_len;
  size_t read_pos;
};

static int vpnhide_dev_open(struct inode *inode, struct file *file) {
  struct vpnhide_dev_reader *reader;

  reader = kzalloc(sizeof(*reader), GFP_KERNEL);
  if (!reader)
    return -ENOMEM;

  file->private_data = reader;
  return 0;
}

static int vpnhide_dev_release(struct inode *inode, struct file *file) {
  struct vpnhide_dev_reader *reader = file->private_data;

  if (reader) {
    kvfree(reader->buf);
    kfree(reader);
  }
  return 0;
}

static ssize_t vpnhide_dev_read(struct file *file, char __user *buf,
                                size_t count, loff_t *ppos) {
  struct vpnhide_dev_reader *reader = file->private_data;

  if (!reader)
    return -EINVAL;

  if (reader->read_pos >= reader->buf_len) {
    unsigned long gen = (unsigned long)atomic_read(&vpnhide_config_generation);
    if (reader->generation >= gen) {
      if (from_kuid(&init_user_ns, current_uid()) != 1000)
        return 0;
      if (file->f_flags & O_NONBLOCK)
        return -EAGAIN;
      if (wait_event_interruptible(
              vpnhide_config_wait,
              reader->generation <
                  (unsigned long)atomic_read(&vpnhide_config_generation)))
        return -ERESTARTSYS;
    }

    kvfree(reader->buf);
    reader->buf = kvmalloc(65536, GFP_KERNEL);
    if (!reader->buf)
      return -ENOMEM;

    {
      int offset = 0;
      struct vpnhide_policy_snapshot *snapshot;
      int i;

      offset += scnprintf(reader->buf + offset, 65536 - offset,
                          "version_code: %d\n", VPNHIDE_VERSION_CODE);

      offset += scnprintf(reader->buf + offset, 65536 - offset,
                          "java_hook_mask: %u\n", vpnhide_java_hooks_mask());

      offset += scnprintf(reader->buf + offset, 65536 - offset,
                          "java_stats_clear_gen: %d\n",
                          atomic_read(&java_stats_clear_generation));

      offset +=
          scnprintf(reader->buf + offset, 65536 - offset,
                    "stats_mode: cumulative_session\n");

      offset += scnprintf(reader->buf + offset, 65536 - offset,
                          "debug_enabled: %d\n", vpnhide_debug_is_enabled());

      rcu_read_lock();
      snapshot = rcu_dereference(global_policy_snapshot);
      offset +=
          scnprintf(reader->buf + offset, 65536 - offset, "lsposed_targets:");
      if (snapshot) {
        for (i = 0; i < snapshot->payload.targets.lsposed_count; i++) {
          offset += scnprintf(reader->buf + offset, 65536 - offset, " %u",
                              snapshot->payload.targets.lsposed_uids[i]);
        }
      }
      offset += scnprintf(reader->buf + offset, 65536 - offset, "\n");

      offset +=
          scnprintf(reader->buf + offset, 65536 - offset, "iface_prefixes:");
      if (snapshot) {
        for (i = 0; i < snapshot->payload.iface_prefixes.count; i++) {
          offset += scnprintf(reader->buf + offset, 65536 - offset, " %s",
                              snapshot->payload.iface_prefixes.prefixes[i]);
        }
      }
      offset += scnprintf(reader->buf + offset, 65536 - offset, "\n");

      offset += scnprintf(reader->buf + offset, 65536 - offset,
                          "app_java_hook_mask:");
      if (snapshot) {
        for (i = 0; i < snapshot->payload.app_hook_masks.count; i++) {
          if (!snapshot->payload.app_hook_masks.masks[i].has_java_override)
            continue;
          offset += scnprintf(reader->buf + offset, 65536 - offset, " %u:%u",
                              snapshot->payload.app_hook_masks.masks[i].uid,
                              snapshot->payload.app_hook_masks.masks[i].java_mask);
        }
      }
      offset += scnprintf(reader->buf + offset, 65536 - offset, "\n");
      rcu_read_unlock();

      spin_lock(&cover_ifname_lock);
      offset +=
          scnprintf(reader->buf + offset, 65536 - offset, "cover_iface: %s\n",
                    global_cover_ifname[0] ? global_cover_ifname : "none");
      spin_unlock(&cover_ifname_lock);

      offset += scnprintf(reader->buf + offset, 65536 - offset, "\n");

      reader->buf_len = offset;
    }

    reader->generation = (unsigned long)atomic_read(&vpnhide_config_generation);
    reader->read_pos = 0;
  }

  {
    size_t to_copy = min(count, reader->buf_len - reader->read_pos);
    if (copy_to_user(buf, reader->buf + reader->read_pos, to_copy))
      return -EFAULT;
    reader->read_pos += to_copy;
    return to_copy;
  }
}

static ssize_t vpnhide_dev_write(struct file *file, const char __user *buf,
                                 size_t count, loff_t *ppos) {
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
    wake_up_interruptible(&vpnhide_config_wait);
  } else if (strncmp(kbuf, "cover_iface:", 12) == 0) {
    char *val = kbuf + 12;
    size_t len = strlen(val);
    if (len > 0 && val[len - 1] == '\n') {
      val[len - 1] = '\0';
      len--;
    }
    spin_lock(&cover_ifname_lock);
    if (len == 0 || strcmp(val, "none") == 0) {
      global_cover_ifname[0] = '\0';
    } else {
      strncpy(global_cover_ifname, val, IFNAMSIZ - 1);
      global_cover_ifname[IFNAMSIZ - 1] = '\0';
    }
    spin_unlock(&cover_ifname_lock);
    atomic_inc(&vpnhide_config_generation);
    wake_up_interruptible(&vpnhide_config_wait);
  }

  kfree(kbuf);
  return count;
}

static int handle_vpnhide_ioctl(unsigned int cmd, unsigned long arg) {
  int val, ret = 0;

  if (!capable(CAP_NET_ADMIN))
    return -EPERM;

  switch (cmd) {
  case VH_SET_POLICY: {
    struct vpnhide_policy_ioctl request;
    struct vpnhide_policy_payload *payload;
    int policy_ret;

    if (copy_from_user(&request, (void __user *)arg, sizeof(request)))
      return -EFAULT;
    if (request.abi_version != VPNHIDE_POLICY_ABI_VERSION ||
        request.payload_size != sizeof(*payload) || !request.payload_ptr)
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

  case VH_GET_TARGETS:
  case VH_GET_LSPOSED_TARGETS: {
    struct vpnhide_policy_snapshot *snapshot;
    struct vpnhide_ioctl_data *kdata;

    kdata = kzalloc(sizeof(*kdata), GFP_KERNEL);
    if (!kdata)
      return -ENOMEM;

    rcu_read_lock();
    snapshot = rcu_dereference(global_policy_snapshot);
    if (snapshot) {
      if (cmd == VH_GET_TARGETS) {
        kdata->count = snapshot->payload.targets.kmod_count;
        memcpy(kdata->uids, snapshot->payload.targets.kmod_uids,
               kdata->count * sizeof(kdata->uids[0]));
      } else {
        kdata->count = snapshot->payload.targets.lsposed_count;
        memcpy(kdata->uids, snapshot->payload.targets.lsposed_uids,
               kdata->count * sizeof(kdata->uids[0]));
      }
    }
    rcu_read_unlock();

    if (copy_to_user((void __user *)arg, kdata, sizeof(*kdata))) {
      kfree(kdata);
      return -EFAULT;
    }

    kfree(kdata);
    break;
  }

  case VH_GET_JAVA_HOOK_MASK:
    val = vpnhide_java_hooks_mask();
    if (put_user(val, (unsigned int __user *)arg))
      return -EFAULT;
    ret = 0;
    break;

  case VH_SET_SPOOF_IP: {
    struct vpnhide_spoof_ip sip;
    if (copy_from_user(&sip, (void __user *)arg, sizeof(sip)))
      return -EFAULT;
    ret = update_spoof_ip(&sip);
    if (ret == 0) {
      vpnhide_dbg("ioctl: updated spoof IP: IPv4=%pI4 (%d), IPv6=%pI6c (%d)\n",
                  &sip.ipv4_addr, sip.has_ipv4, sip.ipv6_addr, sip.has_ipv6);
    }
    break;
  }

  case VH_SET_COVER_IFACE: {
    struct vpnhide_cover_iface ci;
    if (copy_from_user(&ci, (void __user *)arg, sizeof(ci)))
      return -EFAULT;
    atomic_set(&global_cover_ifindex, (int)ci.ifindex);
    vpnhide_dbg("ioctl: cover ifindex set to %u\n", ci.ifindex);
    ret = 0;
    break;
  }

  case VH_GET_IFACE_PREFIXES: {
    struct vpnhide_iface_ioctl_data *idata;
    struct vpnhide_policy_snapshot *snapshot;

    idata = kzalloc(sizeof(*idata), GFP_KERNEL);
    if (!idata)
      return -ENOMEM;

    rcu_read_lock();
    snapshot = rcu_dereference(global_policy_snapshot);
    if (snapshot) {
      *idata = snapshot->payload.iface_prefixes;
    }
    rcu_read_unlock();

    if (copy_to_user((void __user *)arg, idata, sizeof(*idata))) {
      kfree(idata);
      return -EFAULT;
    }

    kfree(idata);
    ret = 0;
    break;
  }

  case VH_SET_VPN_IFINDEXES: {
    struct vpnhide_vpn_ifindexes *idata;
    struct vpnhide_active_vpns *new_vpns, *old_vpns;

    idata = kmalloc(sizeof(*idata), GFP_KERNEL);
    if (!idata)
      return -ENOMEM;

    if (copy_from_user(idata, (void __user *)arg, sizeof(*idata))) {
      kfree(idata);
      return -EFAULT;
    }

    if (idata->count < 0 || idata->count > MAX_ACTIVE_VPNS) {
      kfree(idata);
      return -EINVAL;
    }

    new_vpns = kzalloc(sizeof(*new_vpns), GFP_KERNEL);
    if (!new_vpns) {
      kfree(idata);
      return -ENOMEM;
    }

    new_vpns->count = idata->count;
    memcpy(new_vpns->vpns, idata->vpns, sizeof(new_vpns->vpns));

    spin_lock(&active_vpns_lock);
    old_vpns = rcu_dereference_protected(global_active_vpns,
                                         lockdep_is_held(&active_vpns_lock));
    rcu_assign_pointer(global_active_vpns, new_vpns);
    spin_unlock(&active_vpns_lock);

    vh_rebuild_name_cache(idata);

    if (old_vpns) {
      synchronize_rcu();
      kfree(old_vpns);
    }

    kfree(idata);
    ret = 0;
    break;
  }

  case VH_GET_ACTIVE_HOOKS:
    val = vpnhide_active_hooks_mask();
    if (put_user(val, (unsigned int __user *)arg))
      return -EFAULT;
    ret = 0;
    break;

  case VH_GET_APP_HOOK_MASKS: {
    struct vpnhide_app_hook_ioctl_data *adata;
    struct vpnhide_policy_snapshot *snapshot;

    adata = kvzalloc(sizeof(*adata), GFP_KERNEL);
    if (!adata)
      return -ENOMEM;

    rcu_read_lock();
    snapshot = rcu_dereference(global_policy_snapshot);
    if (snapshot) {
      *adata = snapshot->payload.app_hook_masks;
    }
    rcu_read_unlock();

    if (copy_to_user((void __user *)arg, adata, sizeof(*adata))) {
      kvfree(adata);
      return -EFAULT;
    }

    kvfree(adata);
    ret = 0;
    break;
  }

  case VH_GET_STATS: {
    struct vpnhide_stats_snapshot request;
    struct vpnhide_uid_stats *out;
    unsigned long flags;
    u32 count;
    int i;

    if (copy_from_user(&request, (void __user *)arg, sizeof(request)))
      return -EFAULT;
    if (request.capacity > MAX_TARGET_UIDS)
      return -EINVAL;
    if (request.capacity && !request.entries_ptr)
      return -EINVAL;

    out = request.capacity ? kvmalloc_array(request.capacity, sizeof(*out), GFP_KERNEL) : NULL;
    if (request.capacity && !out)
      return -ENOMEM;

    spin_lock_irqsave(&kmod_stats_lock, flags);
    count = kmod_stats_count;
    request.sequence = atomic64_inc_return(&kmod_stats_sequence);
    request.monotonic_ns = ktime_get_ns();
    request.count = count;
    if (out && request.capacity >= count) {
      for (i = 0; i < count; i++) {
        out[i].uid = kmod_stats[i].uid;
        out[i].ioctl_count = kmod_stats[i].ioctl_count;
        out[i].netlink_count = kmod_stats[i].netlink_count;
        out[i].proc_count = kmod_stats[i].proc_count;
        out[i].sockopt_count = kmod_stats[i].sockopt_count;
        out[i].connect_count = kmod_stats[i].connect_count;
        out[i].getname_count = kmod_stats[i].getname_count;
        out[i].port_count = kmod_stats[i].port_count;
      }
    }
    spin_unlock_irqrestore(&kmod_stats_lock, flags);

    if (request.capacity < count) {
      if (out)
        kvfree(out);
      if (copy_to_user((void __user *)arg, &request, sizeof(request)))
        return -EFAULT;
      return -ENOSPC;
    }
    if (out && copy_to_user((void __user *)(unsigned long)request.entries_ptr,
                            out, count * sizeof(*out))) {
      kvfree(out);
      return -EFAULT;
    }
    kvfree(out);
    if (copy_to_user((void __user *)arg, &request, sizeof(request)))
      return -EFAULT;
    ret = 0;
    break;
  }
  case VH_GET_STATS_SESSION: {
    if (copy_to_user((void __user *)arg, &kmod_stats_session_id,
                     sizeof(kmod_stats_session_id)))
      return -EFAULT;
    ret = 0;
    break;
  }
  case VH_CLEAR_STATS: {
    unsigned long flags;
    spin_lock_irqsave(&kmod_stats_lock, flags);
    kmod_stats_count = 0;
    memset(kmod_stats, 0, sizeof(kmod_stats));
    atomic64_set(&kmod_stats_sequence, 0);
    spin_unlock_irqrestore(&kmod_stats_lock, flags);
    ret = 0;
    break;
  }
  case VH_GET_JAVA_STATS: {
    mutex_lock(&java_stats_lock);
    if (copy_to_user((void __user *)arg, java_stats_buf,
                     sizeof(java_stats_buf))) {
      mutex_unlock(&java_stats_lock);
      return -EFAULT;
    }
    mutex_unlock(&java_stats_lock);
    ret = 0;
    break;
  }

  case VH_GET_HOOK_STATUS: {
    mutex_lock(&java_status_lock);
    if (copy_to_user((void __user *)arg, java_status_buf,
                     sizeof(java_status_buf))) {
      mutex_unlock(&java_status_lock);
      return -EFAULT;
    }
    mutex_unlock(&java_status_lock);
    ret = 0;
    break;
  }

  case VH_GET_VERSION: {
    int version = VPNHIDE_VERSION_CODE;
    if (copy_to_user((void __user *)arg, &version, sizeof(version)))
      return -EFAULT;
    ret = 0;
    break;
  }

  default:
    return -ENOIOCTLCMD;
  }

  return ret;
}

static long vpnhide_dev_ioctl(struct file *file, unsigned int cmd,
                              unsigned long arg) {
  return handle_vpnhide_ioctl(cmd, arg);
}

static const struct file_operations vpnhide_fops = {
    .owner = THIS_MODULE,
    .open = vpnhide_dev_open,
    .release = vpnhide_dev_release,
    .read = vpnhide_dev_read,
    .write = vpnhide_dev_write,
    .unlocked_ioctl = vpnhide_dev_ioctl,
#ifdef CONFIG_COMPAT
    .compat_ioctl = vpnhide_dev_ioctl,
#endif
};

static struct miscdevice vpnhide_misc = {
    .minor = MISC_DYNAMIC_MINOR,
    .name = "vpnhide_ctrl",
    .fops = &vpnhide_fops,
    .mode = 0660,
};

/* --- kretprobe_reg array --- */

struct kretprobe_reg {
  struct kretprobe *krp;
  const char *name;
  const char *fallback;
  bool registered;
  int primary_idx;
};

static struct kretprobe_reg probes[] = {
    {&dev_ioctl_krp, "dev_ioctl", NULL, false, -1},
    {&inet_ioctl_krp, "inet_ioctl", NULL, false, -1},
    {&sock_ioctl_krp, "sock_ioctl", NULL, false, -1},
    {&rtnl_fill_krp, "rtnl_fill_ifinfo", NULL, false, -1},
    {&inet6_fill_krp, "inet6_fill_ifaddr", NULL, false, -1},
    {&inet_fill_krp, "inet_fill_ifaddr", NULL, false, -1},
    {&fib_route_krp, "fib_route_seq_show", NULL, false, -1},
    {&fib_dump_krp, "fib_dump_info", NULL, false, -1},
    {&fib_rule_fill_krp, "fib_nl_fill_rule", NULL, false, -1},
    {&rt6_fill_krp, "rt6_fill_node", NULL, false, -1},
    {&rt_fill_krp, "rt_fill_info", NULL, false, -1},
    {&sys_setsockopt_krp, "__arm64_sys_setsockopt", NULL, false, -1},
    {&sys_getsockopt_krp, "__arm64_sys_getsockopt", NULL, false, -1},
    {&sk_getsockopt_krp, "sk_getsockopt", NULL, false, 13},
    {&sock_getsockopt_krp, "sock_getsockopt", NULL, false, 13},
    {&sock_common_getsockopt_krp, "sock_common_getsockopt", NULL, false, 13},
    {&socket_connect_krp, "__arm64_sys_connect", NULL, false, -1},
    {&socket_bind_krp, "__arm64_sys_bind", NULL, false, -1},
    {&socket_connect_krp, "security_socket_connect", NULL, false, 17},
    {&socket_bind_krp, "security_socket_bind", NULL, false, 18},
    {&inet6_bind_ll_krp, "inet6_bind", NULL, false, -1},
    {&sys_getsockname_krp, "__arm64_sys_getsockname", NULL, false, -1},
    {&inet_getname_krp, "inet_getname", NULL, false, 22},
    {&inet6_getname_krp, "inet6_getname", NULL, false, 22},
    {&sys_bpf_krp, "__arm64_sys_bpf", NULL, false, -1},
    {&sys_getdents64_krp, "__arm64_sys_getdents64", NULL, false, -1},
    {&dev_seq_krp, "dev_seq_show", NULL, false, -1},
    {&if6_seq_krp, "if6_seq_show", NULL, false, -1},
    {&sys_openat_krp, "__arm64_sys_openat", NULL, false, -1},
    {&sys_openat2_krp, "__arm64_sys_openat2", NULL, false, -1},
    {&sys_faccessat_krp, "__arm64_sys_faccessat", NULL, false, -1},
    {&sys_faccessat2_krp, "__arm64_sys_faccessat2", NULL, false, -1},
    {&proc_sys_lookup_krp, "proc_sys_lookup", NULL, false, -1},
    {&sys_readlinkat_krp, "__arm64_sys_readlinkat", NULL, false, -1},
    {&udp_sendmsg_krp, "udp_sendmsg", NULL, false, -1},
    {&udpv6_sendmsg_ll_krp, "udpv6_sendmsg", NULL, false, -1},
    {&fib_trie_krp, "fib_trie_seq_show", NULL, false, -1},
    {&tc_fill_qdisc_krp, "tc_fill_qdisc", NULL, false, -1},
};

static int __init vpnhide_init(void) {
  int i, ret, ok = 0;

  kmod_stats_session_id = get_random_u64();
  if (!kmod_stats_session_id)
    kmod_stats_session_id = 1;

  if (sys_setsockopt_krp.kp.symbol_name &&
      strcmp(sys_setsockopt_krp.kp.symbol_name, "__arm64_sys_setsockopt") ==
          0) {
    sys_setsockopt_uses_wrapper = true;
  }
  if (sys_getsockopt_krp.kp.symbol_name &&
      strcmp(sys_getsockopt_krp.kp.symbol_name, "__arm64_sys_getsockopt") ==
          0) {
    sys_getsockopt_uses_wrapper = true;
  }
  if (sys_bpf_krp.kp.symbol_name &&
      strcmp(sys_bpf_krp.kp.symbol_name, "__arm64_sys_bpf") == 0) {
    sys_bpf_uses_wrapper = true;
  }
  if (socket_connect_krp.kp.symbol_name &&
      strcmp(socket_connect_krp.kp.symbol_name, "__arm64_sys_connect") == 0) {
    sys_connect_uses_wrapper = true;
  }
  if (socket_bind_krp.kp.symbol_name &&
      strcmp(socket_bind_krp.kp.symbol_name, "__arm64_sys_bind") == 0) {
    sys_bind_uses_wrapper = true;
  }
  if (sys_getsockname_krp.kp.symbol_name &&
      strcmp(sys_getsockname_krp.kp.symbol_name, "__arm64_sys_getsockname") ==
          0) {
    sys_getsockname_uses_wrapper = true;
  }
  if (sys_getdents64_krp.kp.symbol_name &&
      strcmp(sys_getdents64_krp.kp.symbol_name, "__arm64_sys_getdents64") ==
          0) {
    sys_getdents64_uses_wrapper = true;
  }
  if (sys_openat_krp.kp.symbol_name &&
      strcmp(sys_openat_krp.kp.symbol_name, "__arm64_sys_openat") == 0) {
    sys_openat_uses_wrapper = true;
  }
  if (sys_openat2_krp.kp.symbol_name &&
      strcmp(sys_openat2_krp.kp.symbol_name, "__arm64_sys_openat2") == 0) {
    sys_openat2_uses_wrapper = true;
  }
  if (sys_faccessat_krp.kp.symbol_name &&
      strcmp(sys_faccessat_krp.kp.symbol_name, "__arm64_sys_faccessat") == 0) {
    sys_faccessat_uses_wrapper = true;
  }
  if (sys_faccessat2_krp.kp.symbol_name &&
      strcmp(sys_faccessat2_krp.kp.symbol_name, "__arm64_sys_faccessat2") ==
          0) {
    sys_faccessat2_uses_wrapper = true;
  }
  if (sys_newfstatat_krp.kp.symbol_name &&
      strcmp(sys_newfstatat_krp.kp.symbol_name, "__arm64_sys_newfstatat") ==
          0) {
    sys_newfstatat_uses_wrapper = true;
  }
  if (sys_readlinkat_krp.kp.symbol_name &&
      strcmp(sys_readlinkat_krp.kp.symbol_name, "__arm64_sys_readlinkat") ==
          0) {
    sys_readlinkat_uses_wrapper = true;
  }

  for (i = 0; i < ARRAY_SIZE(probes); i++) {
    if (strcmp(probes[i].name, "sock_getsockopt") == 0) {
      int j;
      bool skip = false;
      for (j = 0; j < ARRAY_SIZE(probes); j++) {
        if (strcmp(probes[j].name, "sk_getsockopt") == 0) {
          if (probes[j].registered) {
            skip = true;
          }
          break;
        }
      }
      if (skip) {
        pr_warn("kretprobe(%s) skipped because sk_getsockopt is registered\n",
                probes[i].name);
        continue;
      }
    }

    if (probes[i].primary_idx >= 0) {
      int p_idx = probes[i].primary_idx;
      if (probes[p_idx].registered) {
        pr_warn("kretprobe(%s) skipped because primary kretprobe(%s) is registered\n",
                probes[i].name, probes[p_idx].name);
        continue;
      }
    }
    ret = register_kretprobe(probes[i].krp);
    if (ret < 0) {
      pr_warn(MODNAME ": kretprobe(%s) failed: %d\n", probes[i].name, ret);
    } else {
      probes[i].registered = true;
      ok++;
      vpnhide_dbg("kretprobe(%s) registered\n", probes[i].name);
    }
  }

  ret = misc_register(&vpnhide_misc);
  if (ret) {
    pr_err(MODNAME ": failed to register misc device\n");
  }

  vpnhide_dbg("loaded\n");
  return 0;
}

static void __exit vpnhide_exit(void) {
  struct vpnhide_active_vpns *vpns;
  struct vpnhide_spoof_ip_rcu *old_sip;
  struct vpnhide_policy_snapshot *snapshot;
  int i;

  for (i = 0; i < ARRAY_SIZE(probes); i++) {
    if (probes[i].registered) {
      unregister_kretprobe(probes[i].krp);
      vpnhide_dbg("kretprobe(%s) unregistered (missed %d)\n", probes[i].name,
                  probes[i].krp->nmissed);
    }
  }

  spin_lock(&policy_snapshot_lock);
  snapshot = rcu_dereference_protected(
      global_policy_snapshot, lockdep_is_held(&policy_snapshot_lock));
  rcu_assign_pointer(global_policy_snapshot, NULL);
  spin_unlock(&policy_snapshot_lock);
  if (snapshot) {
    synchronize_rcu();
    kvfree(snapshot);
  }

  spin_lock(&active_vpns_lock);
  vpns = rcu_dereference_protected(global_active_vpns,
                                   lockdep_is_held(&active_vpns_lock));
  rcu_assign_pointer(global_active_vpns, NULL);
  spin_unlock(&active_vpns_lock);

  if (vpns) {
    synchronize_rcu();
    kfree(vpns);
  }

  {
    struct vh_vpn_name_cache *old_c;
    spin_lock(&g_vpn_name_cache_lock);
    old_c = rcu_dereference_protected(g_vpn_name_cache,
                                      lockdep_is_held(&g_vpn_name_cache_lock));
    rcu_assign_pointer(g_vpn_name_cache, NULL);
    spin_unlock(&g_vpn_name_cache_lock);

    if (old_c) {
      synchronize_rcu();
      kfree(old_c);
    }
  }

  spin_lock(&spoof_ip_lock);
  old_sip = rcu_dereference_protected(global_spoof_ip,
                                      lockdep_is_held(&spoof_ip_lock));
  rcu_assign_pointer(global_spoof_ip, NULL);
  spin_unlock(&spoof_ip_lock);

  if (old_sip) {
    synchronize_rcu();
    kfree(old_sip);
  }

  misc_deregister(&vpnhide_misc);

  vpnhide_dbg("unloaded\n");
}

module_init(vpnhide_init);
module_exit(vpnhide_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("soranerai");
MODULE_DESCRIPTION("Hide VPN interfaces from selected apps at kernel level");
