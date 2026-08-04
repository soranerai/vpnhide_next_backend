#include "vpnhide_kmod.h"

bool g_stats_pkts_first = false;

DECLARE_WAIT_QUEUE_HEAD(vpnhide_config_wait);
atomic_t vpnhide_config_generation = ATOMIC_INIT(1);
atomic_t java_stats_clear_generation = ATOMIC_INIT(1);

struct vpnhide_policy_snapshot __rcu *global_policy_snapshot = NULL;
DEFINE_SPINLOCK(policy_snapshot_lock);
static DEFINE_MUTEX(policy_apply_lock);

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
  u64 key;
  unsigned long expires;
};

static struct vpnhide_pending_port
    pending_ports[VPNHIDE_PENDING_PORT_SETS][VPNHIDE_PENDING_PORT_WAYS];
static DEFINE_SPINLOCK(pending_ports_lock);

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

static u32 owned_port_hash(uid_t uid, u16 port, u8 protocol) {
  u32 value = (u32)uid * 0x9e3779b1U;
  value ^= (u32)port * 0x85ebca6bU;
  value ^= (u32)protocol * 0xc2b2ae35U;
  value ^= value >> 16;
  return value;
}

static u64 pending_port_key(uid_t uid, u16 port, u8 protocol) {
  return ((u64)(u32)uid << 24) | ((u64)port << 8) | (u64)(protocol + 1);
}

static bool pending_port_lookup(uid_t uid, u16 port, u8 protocol) {
  u64 wanted = pending_port_key(uid, port, protocol);
  u32 set = owned_port_hash(uid, port, protocol) &
            (VPNHIDE_PENDING_PORT_SETS - 1);
  unsigned int way;

  for (way = 0; way < VPNHIDE_PENDING_PORT_WAYS; way++) {
    struct vpnhide_pending_port *entry = &pending_ports[set][way];
    unsigned long expires = READ_ONCE(entry->expires);

    /* Writers publish the expiry before the key.  Reading in the opposite
     * order prevents a replaced key from borrowing the new entry's TTL. */
    smp_rmb();
    if (READ_ONCE(entry->key) == wanted && time_before(jiffies, expires))
      return true;
  }
  return false;
}

bool vpnhide_uid_owns_port(uid_t uid, u16 port, u8 protocol) {
  struct vpnhide_owned_ports_snapshot *snapshot;
  bool found = false;
  u32 slot, probes;

  rcu_read_lock();
  snapshot = rcu_dereference(owned_ports_snapshot);
  if (!snapshot || !snapshot->bucket_count ||
      time_after_eq(jiffies, snapshot->expires))
    goto out;
  slot = owned_port_hash(uid, port, protocol) & (snapshot->bucket_count - 1);
  for (probes = 0; probes < snapshot->bucket_count; probes++) {
    const struct vpnhide_owned_port *entry = &snapshot->buckets[slot];
    if (!entry->uid)
      break;
    if (entry->uid == uid && entry->port == port &&
        entry->protocol == protocol) {
      found = true;
      break;
    }
    slot = (slot + 1) & (snapshot->bucket_count - 1);
  }
out:
  rcu_read_unlock();
  return found || pending_port_lookup(uid, port, protocol);
}

void vpnhide_record_bound_port(uid_t uid, u16 port, u8 protocol) {
  struct vpnhide_policy_snapshot *policy;
  struct vpnhide_pending_port *selected;
  unsigned long now = jiffies;
  unsigned long oldest;
  u64 key;
  u32 set;
  unsigned int way;
  bool targeted;

  if (!uid || !port || protocol > VH_PROTO_UDP)
    return;

  rcu_read_lock();
  policy = rcu_dereference(global_policy_snapshot);
  targeted = vpnhide_find_port_target(policy, uid) != NULL;
  rcu_read_unlock();
  if (!targeted)
    return;

  key = pending_port_key(uid, port, protocol);
  set = owned_port_hash(uid, port, protocol) &
        (VPNHIDE_PENDING_PORT_SETS - 1);

  spin_lock(&pending_ports_lock);
  selected = &pending_ports[set][0];
  oldest = READ_ONCE(selected->expires);
  for (way = 0; way < VPNHIDE_PENDING_PORT_WAYS; way++) {
    struct vpnhide_pending_port *entry = &pending_ports[set][way];
    u64 entry_key = READ_ONCE(entry->key);
    unsigned long expires = READ_ONCE(entry->expires);

    if (entry_key == key || !entry_key || time_after_eq(now, expires)) {
      selected = entry;
      break;
    }
    if (time_before(expires, oldest)) {
      selected = entry;
      oldest = expires;
    }
  }

  WRITE_ONCE(selected->key, 0);
  smp_wmb();
  WRITE_ONCE(selected->expires, now + VPNHIDE_PENDING_PORT_TTL);
  smp_wmb();
  WRITE_ONCE(selected->key, key);
  spin_unlock(&pending_ports_lock);
  vpnhide_notify_port_change(uid);
}

void vpnhide_notify_port_change(uid_t uid) {
  struct vpnhide_policy_snapshot *policy;
  struct eventfd_ctx *ctx = NULL;

  rcu_read_lock();
  policy = rcu_dereference(global_policy_snapshot);
  if (vpnhide_find_port_target(policy, uid)) {
    spin_lock(&port_event_lock);
    ctx = port_event_ctx;
    if (ctx) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 8, 0)
      eventfd_signal(ctx);
#else
      eventfd_signal(ctx, 1);
#endif
    }
    spin_unlock(&port_event_lock);
  }
  rcu_read_unlock();
}

static int replace_owned_ports(const struct vpnhide_owned_ports_update *update) {
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
    if (!entries[i].uid || !entries[i].port || entries[i].reserved ||
        entries[i].protocol > VH_PROTO_UDP) {
      kvfree(entries);
      kvfree(snapshot);
      return -EINVAL;
    }
    slot = owned_port_hash(entries[i].uid, entries[i].port,
                           entries[i].protocol) & (buckets - 1);
    for (probes = 0; probes < buckets; probes++) {
      struct vpnhide_owned_port *dst = &snapshot->buckets[slot];
      if (!dst->uid) {
        *dst = entries[i];
        snapshot->entry_count++;
        break;
      }
      if (dst->uid == entries[i].uid && dst->port == entries[i].port &&
          dst->protocol == entries[i].protocol)
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

bool lookup_app_kernel_mask(uid_t uid, unsigned int *out) {
  struct vpnhide_policy_snapshot *snapshot;
  bool found = false;

  rcu_read_lock();
  snapshot = rcu_dereference(global_policy_snapshot);
  if (snapshot) {
    int lo = 0, hi = (int)snapshot->app_hook_mask_count - 1;
    while (lo <= hi) {
      int mid = lo + ((hi - lo) >> 1);
      const struct vpnhide_app_hook_mask_v3 *mask =
          &snapshot->app_hook_masks[mid];
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
  new_rcu->sip.has_ipv4 = !!new_rcu->sip.has_ipv4;
  new_rcu->sip.has_ipv6 = !!new_rcu->sip.has_ipv6;
  new_rcu->sip.has_ipv6_linklocal = !!new_rcu->sip.has_ipv6_linklocal;
  new_rcu->sip.reserved = 0;
  if (!new_rcu->sip.has_ipv4 || new_rcu->sip.ipv4_mtu < 68 ||
      new_rcu->sip.ipv4_mtu > 65535)
    new_rcu->sip.ipv4_mtu = 0;
  if (!new_rcu->sip.has_ipv6 || new_rcu->sip.ipv6_mtu < 1280 ||
      new_rcu->sip.ipv6_mtu > 65535)
    new_rcu->sip.ipv6_mtu = 0;
  if (!new_rcu->sip.has_ipv6_linklocal ||
      !(ipv6_addr_type((struct in6_addr *)new_rcu->sip.ipv6_linklocal_addr) &
        IPV6_ADDR_LINKLOCAL)) {
    new_rcu->sip.has_ipv6_linklocal = 0;
    memset(new_rcu->sip.ipv6_linklocal_addr, 0,
           sizeof(new_rcu->sip.ipv6_linklocal_addr));
  }

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
  int lo, hi;

  if (uid == 0 || uid == 1000)
    return false;

  rcu_read_lock();
  snapshot = rcu_dereference(global_policy_snapshot);
  if (snapshot && snapshot->kmod_count) {
    lo = 0;
    hi = (int)snapshot->kmod_count - 1;
    while (lo <= hi) {
      int mid = lo + ((hi - lo) >> 1);
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

static struct kmod_uid_stats_total *kmod_stats;
static u32 kmod_stats_count;
DEFINE_SPINLOCK(kmod_stats_lock);
static atomic64_t kmod_stats_sequence = ATOMIC64_INIT(0);
static u64 kmod_stats_session_id;

void record_kmod_intercept(uid_t uid, int type) {
  int lo, hi;
  unsigned long flags;

  if (uid == 0 || uid == 1000)
    return;

  spin_lock_irqsave(&kmod_stats_lock, flags);
  lo = 0;
  hi = (int)kmod_stats_count - 1;
  while (lo <= hi) {
    int i = lo + ((hi - lo) >> 1);
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
    if (kmod_stats[i].uid < uid)
      lo = i + 1;
    else
      hi = i - 1;
  }
  spin_unlock_irqrestore(&kmod_stats_lock, flags);
}

static int kmod_stats_reconcile(const struct vpnhide_policy_snapshot *snapshot) {
  struct kmod_uid_stats_total *replacement = NULL, *old;
  unsigned long flags;
  u32 i, j;

  if (snapshot->kmod_count) {
    replacement = kvmalloc_array(snapshot->kmod_count,
                                 sizeof(*replacement), GFP_KERNEL | __GFP_ZERO);
    if (!replacement)
      return -ENOMEM;
    for (i = 0; i < snapshot->kmod_count; i++)
      replacement[i].uid = snapshot->kmod_uids[i];
  }

  spin_lock_irqsave(&kmod_stats_lock, flags);
  for (i = 0; i < snapshot->kmod_count; i++) {
    for (j = 0; j < kmod_stats_count; j++) {
      if (replacement[i].uid == kmod_stats[j].uid) {
        replacement[i] = kmod_stats[j];
        break;
      }
    }
  }
  old = kmod_stats;
  kmod_stats = replacement;
  kmod_stats_count = snapshot->kmod_count;
  spin_unlock_irqrestore(&kmod_stats_lock, flags);
  kvfree(old);
  return 0;
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

static int policy_port_target_cmp(const void *a, const void *b)
{
  const struct vpnhide_port_target_v3 *pa = a, *pb = b;
  return (pa->uid > pb->uid) - (pa->uid < pb->uid);
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
    if (target->uid == 0 || target->mode > VH_PORT_POLICY_DENY_ALL ||
        target->reserved[0] || target->reserved[1] || target->reserved[2] ||
        target->first_rule != next_rule ||
        target->rule_count > snapshot->port_rule_count - next_rule) {
      kvfree(snapshot);
      return ERR_PTR(-EINVAL);
    }
    next_rule += target->rule_count;
  }
  if (next_rule != snapshot->port_rule_count) {
    kvfree(snapshot);
    return ERR_PTR(-EINVAL);
  }
  for (i = 0; i < snapshot->port_rule_count; i++) {
    const struct vpnhide_port_rule_v3 *rule = &snapshot->port_rules[i];
    if (rule->start_port > rule->end_port || rule->protocol > VH_PROTO_BOTH ||
        rule->reserved[0] || rule->reserved[1] || rule->reserved[2]) {
      kvfree(snapshot);
      return ERR_PTR(-EINVAL);
    }
  }
  for (i = 0; i < snapshot->app_hook_mask_count; i++) {
    struct vpnhide_app_hook_mask_v3 *mask = &snapshot->app_hook_masks[i];
    if (!mask->uid || mask->has_kernel_override > 1 ||
        mask->has_java_override > 1 || mask->reserved[0] ||
        mask->reserved[1]) {
      kvfree(snapshot);
      return ERR_PTR(-EINVAL);
    }
    if (mask->has_kernel_override)
      mask->kernel_mask |= BIT(HOOK_CONNECT) | BIT(HOOK_BIND);
  }

  sort(snapshot->kmod_uids, snapshot->kmod_count, sizeof(uid_t),
       policy_uid_cmp, NULL);
  sort(snapshot->lsposed_uids, snapshot->lsposed_count, sizeof(uid_t),
       policy_uid_cmp, NULL);
  sort(snapshot->port_targets, snapshot->port_target_count,
       sizeof(*snapshot->port_targets), policy_port_target_cmp, NULL);
  sort(snapshot->app_hook_masks, snapshot->app_hook_mask_count,
       sizeof(*snapshot->app_hook_masks), policy_app_mask_cmp, NULL);
  if ((snapshot->kmod_count && !snapshot->kmod_uids[0]) ||
      (snapshot->lsposed_count && !snapshot->lsposed_uids[0]))
    goto duplicate;
  for (i = 1; i < snapshot->kmod_count; i++)
    if (snapshot->kmod_uids[i - 1] == snapshot->kmod_uids[i])
      goto duplicate;
  for (i = 1; i < snapshot->lsposed_count; i++)
    if (snapshot->lsposed_uids[i - 1] == snapshot->lsposed_uids[i])
      goto duplicate;
  for (i = 1; i < snapshot->port_target_count; i++)
    if (snapshot->port_targets[i - 1].uid == snapshot->port_targets[i].uid)
      goto duplicate;
  for (i = 1; i < snapshot->app_hook_mask_count; i++)
    if (snapshot->app_hook_masks[i - 1].uid == snapshot->app_hook_masks[i].uid)
      goto duplicate;
  return snapshot;

duplicate:
  kvfree(snapshot);
  return ERR_PTR(-EINVAL);
}

static int publish_policy_snapshot(struct vpnhide_policy_snapshot *snapshot,
                                   u64 expected_generation)
{
  struct vpnhide_policy_snapshot *old;
  int ret = 0;

  mutex_lock(&policy_apply_lock);
  if (expected_generation && expected_generation !=
      (u64)atomic_read(&vpnhide_config_generation)) {
    mutex_unlock(&policy_apply_lock);
    kvfree(snapshot);
    return -EAGAIN;
  }
  ret = kmod_stats_reconcile(snapshot);
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
    call_rcu(&old->rcu, free_policy_snapshot_rcu);
  atomic_inc(&vpnhide_config_generation);
  wake_up_interruptible(&vpnhide_config_wait);
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
  int lo = 0, hi;
  if (!snapshot || !snapshot->port_target_count)
    return NULL;
  hi = (int)snapshot->port_target_count - 1;
  while (lo <= hi) {
    int mid = lo + ((hi - lo) >> 1);
    const struct vpnhide_port_target_v3 *target =
        &snapshot->port_targets[mid];
    if (target->uid == uid)
      return target;
    if (target->uid < uid)
      lo = mid + 1;
    else
      hi = mid - 1;
  }
  return NULL;
}

/* Common transaction entry point.  The payload is copied and validated before
 * the immutable snapshot is published. */
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
      if (rule->start_port > rule->end_port || rule->protocol > VH_PROTO_BOTH)
        return -EINVAL;
    }
    rule_count += target->rule_count;
  }
  size = sizeof(*v3) +
      payload->targets.kmod_count * sizeof(__u32) +
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
    size_t reader_capacity = 1024;
    struct vpnhide_policy_snapshot *size_snapshot;
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
    mutex_lock(&policy_apply_lock);
    size_snapshot = rcu_dereference_protected(global_policy_snapshot,
                                               lockdep_is_held(&policy_apply_lock));
    if (size_snapshot) {
      reader_capacity += (size_t)size_snapshot->lsposed_count * 16;
      reader_capacity += (size_t)size_snapshot->app_hook_mask_count * 32;
      reader_capacity += (size_t)size_snapshot->iface_prefixes.count *
                         (MAX_IFACE_LEN + 1);
    }
    reader->buf = kvmalloc(reader_capacity, GFP_KERNEL);
    if (!reader->buf)
    {
      mutex_unlock(&policy_apply_lock);
      return -ENOMEM;
    }

    {
      int offset = 0;
      struct vpnhide_policy_snapshot *snapshot;
      int i;

      offset += scnprintf(reader->buf + offset, reader_capacity - offset,
                          "version_code: %d\n", VPNHIDE_VERSION_CODE);

      offset += scnprintf(reader->buf + offset, reader_capacity - offset,
                          "java_hook_mask: %u\n", vpnhide_java_hooks_mask());

      offset += scnprintf(reader->buf + offset, reader_capacity - offset,
                          "java_stats_clear_gen: %d\n",
                          atomic_read(&java_stats_clear_generation));

      offset +=
          scnprintf(reader->buf + offset, reader_capacity - offset,
                    "stats_mode: cumulative_session\n");

      offset += scnprintf(reader->buf + offset, reader_capacity - offset,
                          "debug_enabled: %d\n", vpnhide_debug_is_enabled());

      rcu_read_lock();
      snapshot = rcu_dereference(global_policy_snapshot);
      offset +=
          scnprintf(reader->buf + offset, reader_capacity - offset, "lsposed_targets:");
      if (snapshot) {
        for (i = 0; i < snapshot->lsposed_count; i++) {
          offset += scnprintf(reader->buf + offset, reader_capacity - offset, " %u",
                              snapshot->lsposed_uids[i]);
        }
      }
      offset += scnprintf(reader->buf + offset, reader_capacity - offset, "\n");

      offset +=
          scnprintf(reader->buf + offset, reader_capacity - offset, "iface_prefixes:");
      if (snapshot) {
        for (i = 0; i < snapshot->iface_prefixes.count; i++) {
          offset += scnprintf(reader->buf + offset, reader_capacity - offset, " %s",
                              snapshot->iface_prefixes.prefixes[i]);
        }
      }
      offset += scnprintf(reader->buf + offset, reader_capacity - offset, "\n");

      offset += scnprintf(reader->buf + offset, reader_capacity - offset,
                          "app_java_hook_mask:");
      if (snapshot) {
        for (i = 0; i < snapshot->app_hook_mask_count; i++) {
          if (!snapshot->app_hook_masks[i].has_java_override)
            continue;
          offset += scnprintf(reader->buf + offset, reader_capacity - offset, " %u:%u",
                              snapshot->app_hook_masks[i].uid,
                              snapshot->app_hook_masks[i].java_mask);
        }
      }
      offset += scnprintf(reader->buf + offset, reader_capacity - offset, "\n");
      rcu_read_unlock();

      spin_lock(&cover_ifname_lock);
      offset +=
          scnprintf(reader->buf + offset, reader_capacity - offset, "cover_iface: %s\n",
                    global_cover_ifname[0] ? global_cover_ifname : "none");
      spin_unlock(&cover_ifname_lock);

      offset += scnprintf(reader->buf + offset, reader_capacity - offset, "\n");

      reader->buf_len = offset;
    }
	mutex_unlock(&policy_apply_lock);

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
    void *payload;
    int policy_ret;

    if (copy_from_user(&request, (void __user *)arg, sizeof(request)))
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
        if (snapshot->kmod_count > VPNHIDE_LEGACY_TARGET_UIDS) {
          rcu_read_unlock();
          kfree(kdata);
          return -ENOSPC;
        }
        kdata->count = snapshot->kmod_count;
        memcpy(kdata->uids, snapshot->kmod_uids,
               kdata->count * sizeof(kdata->uids[0]));
      } else {
        if (snapshot->lsposed_count > VPNHIDE_LEGACY_TARGET_UIDS) {
          rcu_read_unlock();
          kfree(kdata);
          return -ENOSPC;
        }
        kdata->count = snapshot->lsposed_count;
        memcpy(kdata->uids, snapshot->lsposed_uids,
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
      vpnhide_dbg("ioctl: updated cover data: IPv4=%pI4 (%d, mtu=%u), IPv6=%pI6c (%d, mtu=%u)\n",
                  &sip.ipv4_addr, sip.has_ipv4, sip.ipv4_mtu,
                  sip.ipv6_addr, sip.has_ipv6, sip.ipv6_mtu);
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
      *idata = snapshot->iface_prefixes;
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
    int i;

    adata = kvzalloc(sizeof(*adata), GFP_KERNEL);
    if (!adata)
      return -ENOMEM;

    rcu_read_lock();
    snapshot = rcu_dereference(global_policy_snapshot);
    if (snapshot) {
      if (snapshot->app_hook_mask_count > VPNHIDE_LEGACY_TARGET_UIDS) {
        rcu_read_unlock();
        kvfree(adata);
        return -ENOSPC;
      }
      adata->count = snapshot->app_hook_mask_count;
      for (i = 0; i < adata->count; i++) {
        adata->masks[i].uid = snapshot->app_hook_masks[i].uid;
        adata->masks[i].kernel_mask = snapshot->app_hook_masks[i].kernel_mask;
        adata->masks[i].java_mask = snapshot->app_hook_masks[i].java_mask;
        adata->masks[i].has_kernel_override =
            snapshot->app_hook_masks[i].has_kernel_override;
        adata->masks[i].has_java_override =
            snapshot->app_hook_masks[i].has_java_override;
      }
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
    u32 count, allocated;
    int i;

    if (copy_from_user(&request, (void __user *)arg, sizeof(request)))
      return -EFAULT;
    if (request.capacity && !request.entries_ptr)
      return -EINVAL;

    spin_lock_irqsave(&kmod_stats_lock, flags);
    count = kmod_stats_count;
    spin_unlock_irqrestore(&kmod_stats_lock, flags);
    allocated = min(request.capacity, count);
    out = allocated ? kvmalloc_array(allocated, sizeof(*out), GFP_KERNEL) : NULL;
    if (allocated && !out)
      return -ENOMEM;

    spin_lock_irqsave(&kmod_stats_lock, flags);
    count = kmod_stats_count;
    request.sequence = atomic64_inc_return(&kmod_stats_sequence);
    request.monotonic_ns = ktime_get_ns();
    request.count = count;
    if (out && request.capacity >= count && allocated >= count) {
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
    u32 i;
    spin_lock_irqsave(&kmod_stats_lock, flags);
    for (i = 0; i < kmod_stats_count; i++) {
      uid_t uid = kmod_stats[i].uid;
      memset(&kmod_stats[i], 0, sizeof(kmod_stats[i]));
      kmod_stats[i].uid = uid;
    }
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

  case VH_SET_PORT_EVENTFD: {
    struct eventfd_ctx *new_ctx, *old_ctx;
    int event_fd;
    if (copy_from_user(&event_fd, (void __user *)arg, sizeof(event_fd)))
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
    if (copy_from_user(&update, (void __user *)arg, sizeof(update)))
      return -EFAULT;
    return replace_owned_ports(&update);
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
    {&ip_cmsg_recv_krp, "ip_cmsg_recv_offset", NULL, false, -1},
    {&ip6_cmsg_recv_krp, "ip6_datagram_recv_common_ctl", NULL, false, -1},
    {&ip6_cmsg_recv_fallback_krp, "ip6_datagram_recv_ctl", NULL, false, 17},
    {&socket_connect_krp, "__arm64_sys_connect", NULL, false, -1},
    {&socket_bind_krp, "__arm64_sys_bind", NULL, false, -1},
    {&socket_connect_krp, "security_socket_connect", NULL, false, 19},
    {&socket_bind_krp, "security_socket_bind", NULL, false, 20},
    {&inet_bind_owner_krp, "inet_bind", NULL, false, -1},
    {&inet_listen_owner_krp, "inet_listen", NULL, false, -1},
    {&inet6_bind_ll_krp, "inet6_bind", NULL, false, -1},
    {&sys_getsockname_krp, "__arm64_sys_getsockname", NULL, false, -1},
    {&inet_getname_krp, "inet_getname", NULL, false, 25},
    {&inet6_getname_krp, "inet6_getname", NULL, false, 25},
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
    {&ipv6_route_krp, "ipv6_route_seq_show", NULL, false, -1},
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
  struct vpnhide_owned_ports_snapshot *owned;
  struct eventfd_ctx *event_ctx;
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
  spin_lock(&owned_ports_lock);
  owned = rcu_dereference_protected(owned_ports_snapshot,
                                    lockdep_is_held(&owned_ports_lock));
  rcu_assign_pointer(owned_ports_snapshot, NULL);
  spin_unlock(&owned_ports_lock);
  if (owned) {
    synchronize_rcu();
    kvfree(owned);
  }
  spin_lock(&port_event_lock);
  event_ctx = port_event_ctx;
  port_event_ctx = NULL;
  spin_unlock(&port_event_lock);
  if (event_ctx)
    eventfd_ctx_put(event_ctx);
  kvfree(kmod_stats);
  kmod_stats = NULL;
  kmod_stats_count = 0;
  vpnhide_udp_rates_destroy();

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
