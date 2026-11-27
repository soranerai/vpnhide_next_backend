#include "vpnhide_kmod.h"

/* --- dev_ioctl hook --- */

struct dev_ioctl_data {
  unsigned int cmd;
  struct ifreq *kifr;
};

static int dev_ioctl_entry(struct kretprobe_instance *ri,
                           struct pt_regs *regs) {
  struct dev_ioctl_data *data;
  if (!is_hook_active(HOOK_DEV_IOCTL, from_kuid(&init_user_ns, current_uid())))
    return 1;

  if (!is_target_uid())
    return 1;

  data = (void *)ri->data;
  data->cmd = (unsigned int)regs->regs[1];
  data->kifr = (struct ifreq *)regs->regs[2];

  vpnhide_dbg("dev_ioctl_entry: uid=%u cmd=0x%x\n",
              from_kuid(&init_user_ns, current_uid()), data->cmd);
  return 0;
}

static int dev_ioctl_ret(struct kretprobe_instance *ri, struct pt_regs *regs) {
  struct dev_ioctl_data *data = (void *)ri->data;
  char name[IFNAMSIZ];

  if (regs_return_value(regs) != 0)
    return 0;

  if (!data->kifr)
    return 0;

  memcpy(name, data->kifr->ifr_name, IFNAMSIZ);
  name[IFNAMSIZ - 1] = '\0';

  if (is_active_vpn_ifname(name)) {
    vpnhide_dbg("dev_ioctl_ret: hiding iface=%s cmd=0x%x\n", name, data->cmd);
    record_kmod_intercept(from_kuid(&init_user_ns, current_uid()), 0);
    regs_set_return_value(regs, -ENODEV);
  }

  return 0;
}

struct kretprobe dev_ioctl_krp = {
    .handler = dev_ioctl_ret,
    .entry_handler = dev_ioctl_entry,
    .data_size = sizeof(struct dev_ioctl_data),
    .maxactive = VPNHIDE_KRETPROBE_MAXACTIVE,
    .kp.symbol_name = "dev_ioctl",
};

/* IPv4 address ioctls are handled by devinet_ioctl with a kernel-space
 * ifreq. Return ENODEV there, before inet_ioctl can copy the successful
 * result to userspace. A return probe on inet_ioctl is too late: it can
 * change errno but cannot undo the already-visible address. */
struct kretprobe devinet_ioctl_krp = {
    .handler = dev_ioctl_ret,
    .entry_handler = dev_ioctl_entry,
    .data_size = sizeof(struct dev_ioctl_data),
    .maxactive = VPNHIDE_KRETPROBE_MAXACTIVE,
    .kp.symbol_name = "devinet_ioctl",
};

/* --- SIOCGIFCONF filtering before copying entries to userspace --- */

/* dev_ifconf calls inet_gifconf once per network device for both the NULL
 * size query and the actual output. Skipping the hidden device at entry keeps
 * the count and list consistent without touching unused userspace memory.
 * The caller holds RTNL, so the device remains valid throughout the call. */
static int inet_gifconf_pre(struct kprobe *kp, struct pt_regs *regs) {
  struct net_device *dev = (struct net_device *)regs->regs[0];
  uid_t uid = from_kuid(&init_user_ns, current_uid());

  (void)kp;
  if (!dev || !is_hook_active(HOOK_SOCK_IOCTL, uid) || !is_target_uid_val(uid) ||
      !is_active_vpn_ifindex(dev->ifindex))
    return 0;

  record_kmod_intercept(uid, 0);
  /* inet_gifconf returns the number of bytes written. Zero entries is the
   * same result it would return for a device without IPv4 addresses. */
  regs->regs[0] = 0;
  regs->pc = regs->regs[30];
  return 1;
}

/* A post-handler prevents optimized probes from ignoring the PC change. */
static void inet_gifconf_post(struct kprobe *kp, struct pt_regs *regs,
                              unsigned long flags) {
  (void)kp;
  (void)regs;
  (void)flags;
}

struct kprobe inet_gifconf_kp = {
    .symbol_name = "inet_gifconf",
    .pre_handler = inet_gifconf_pre,
    .post_handler = inet_gifconf_post,
};

/* --- Netlink link/address info hooks --- */

struct rtnl_fill_data {
  struct sk_buff *skb;
  unsigned int saved_len;
  bool should_filter;
};

static int rtnl_fill_entry(struct kretprobe_instance *ri,
                           struct pt_regs *regs) {
  struct rtnl_fill_data *data;
  struct net_device *dev;

  if (!is_hook_active(HOOK_RTNL_FILL, from_kuid(&init_user_ns, current_uid())))
    return 1;

  if (!is_target_uid())
    return 1;

  dev = (struct net_device *)regs->regs[1];
  if (!dev || !is_active_vpn_ifindex(dev->ifindex))
    return 1;

  data = (void *)ri->data;
  data->skb = (struct sk_buff *)regs->regs[0];
  data->saved_len = data->skb ? data->skb->len : 0;
  data->should_filter = true;

  vpnhide_dbg("rtnl_fill_entry: uid=%u target=1 iface=%s -> filter\n",
              from_kuid(&init_user_ns, current_uid()), dev->name);

  return 0;
}

static int rtnl_fill_ret(struct kretprobe_instance *ri, struct pt_regs *regs) {
  struct rtnl_fill_data *data = (void *)ri->data;

  if (!data->should_filter || !data->skb)
    return 0;

  vpnhide_dbg("rtnl_fill_ret: trimming skb %u -> %u\n", data->skb->len,
              data->saved_len);
  record_kmod_intercept(from_kuid(&init_user_ns, current_uid()), 1);
  skb_trim(data->skb, data->saved_len);
  regs_set_return_value(regs, 0);
  return 0;
}

struct kretprobe rtnl_fill_krp = {
    .handler = rtnl_fill_ret,
    .entry_handler = rtnl_fill_entry,
    .data_size = sizeof(struct rtnl_fill_data),
    .maxactive = VPNHIDE_KRETPROBE_MAXACTIVE,
    .kp.symbol_name = "rtnl_fill_ifinfo",
};

struct inet6_fill_data {
  struct sk_buff *skb;
  unsigned int saved_len;
  bool should_filter;
};

static int inet6_fill_entry(struct kretprobe_instance *ri,
                            struct pt_regs *regs) {
  struct inet6_fill_data *data;
  struct inet6_ifaddr *ifa;

  if (!is_hook_active(HOOK_INET6_FILL, from_kuid(&init_user_ns, current_uid())))
    return 1;

  if (!is_target_uid())
    return 1;

  ifa = (struct inet6_ifaddr *)regs->regs[1];
  if (!ifa || !ifa->idev || !ifa->idev->dev ||
      !is_active_vpn_ifindex(ifa->idev->dev->ifindex))
    return 1;

  data = (void *)ri->data;
  data->skb = (struct sk_buff *)regs->regs[0];
  data->saved_len = data->skb ? data->skb->len : 0;
  data->should_filter = true;
  vpnhide_dbg("inet6_fill_entry: uid=%u iface=%s -> filter\n",
              from_kuid(&init_user_ns, current_uid()), ifa->idev->dev->name);

  return 0;
}

static int inet6_fill_ret(struct kretprobe_instance *ri, struct pt_regs *regs) {
  struct inet6_fill_data *data = (void *)ri->data;

  if (!data->should_filter || !data->skb)
    return 0;

  vpnhide_dbg("inet6_fill_ret: trimming skb %u -> %u\n", data->skb->len,
              data->saved_len);
  record_kmod_intercept(from_kuid(&init_user_ns, current_uid()), 1);
  skb_trim(data->skb, data->saved_len);
  regs_set_return_value(regs, 0);
  return 0;
}

struct kretprobe inet6_fill_krp = {
    .handler = inet6_fill_ret,
    .entry_handler = inet6_fill_entry,
    .data_size = sizeof(struct inet6_fill_data),
    .maxactive = VPNHIDE_KRETPROBE_MAXACTIVE,
    .kp.symbol_name = "inet6_fill_ifaddr",
};

struct inet_fill_data {
  struct sk_buff *skb;
  unsigned int saved_len;
  bool should_filter;
};

static int inet_fill_entry(struct kretprobe_instance *ri,
                           struct pt_regs *regs) {
  struct inet_fill_data *data;
  struct in_ifaddr *ifa;

  if (!is_hook_active(HOOK_INET_FILL, from_kuid(&init_user_ns, current_uid())))
    return 1;

  if (!is_target_uid())
    return 1;

  ifa = (struct in_ifaddr *)regs->regs[1];
  if (!ifa || !ifa->ifa_dev || !ifa->ifa_dev->dev ||
      !is_active_vpn_ifindex(ifa->ifa_dev->dev->ifindex))
    return 1;

  data = (void *)ri->data;
  data->skb = (struct sk_buff *)regs->regs[0];
  data->saved_len = data->skb ? data->skb->len : 0;
  data->should_filter = true;
  vpnhide_dbg("inet_fill_entry: uid=%u iface=%s -> filter\n",
              from_kuid(&init_user_ns, current_uid()), ifa->ifa_dev->dev->name);

  return 0;
}

static int inet_fill_ret(struct kretprobe_instance *ri, struct pt_regs *regs) {
  struct inet_fill_data *data = (void *)ri->data;

  if (!data->should_filter || !data->skb)
    return 0;

  vpnhide_dbg("inet_fill_ret: trimming skb %u -> %u\n", data->skb->len,
              data->saved_len);
  record_kmod_intercept(from_kuid(&init_user_ns, current_uid()), 1);
  skb_trim(data->skb, data->saved_len);
  regs_set_return_value(regs, 0);
  return 0;
}

struct kretprobe inet_fill_krp = {
    .handler = inet_fill_ret,
    .entry_handler = inet_fill_entry,
    .data_size = sizeof(struct inet_fill_data),
    .maxactive = VPNHIDE_KRETPROBE_MAXACTIVE,
    .kp.symbol_name = "inet_fill_ifaddr",
};

/* --- Routing seq show hooks --- */

struct fib_route_data {
  struct seq_file *seq;
  size_t start_count;
};

static int fib_route_entry(struct kretprobe_instance *ri,
                           struct pt_regs *regs) {
  struct fib_route_data *data;
  if (!is_hook_active(HOOK_FIB_ROUTE, from_kuid(&init_user_ns, current_uid())))
    return 1;

  if (!is_target_uid())
    return 1;

  data = (void *)ri->data;
  data->seq = (struct seq_file *)regs->regs[0];
  data->start_count = data->seq ? data->seq->count : 0;

  vpnhide_dbg("fib_route_entry: uid=%u target=1\n",
              from_kuid(&init_user_ns, current_uid()));

  return 0;
}

static int fib_route_ret(struct kretprobe_instance *ri, struct pt_regs *regs) {
  struct fib_route_data *data = (void *)ri->data;
  struct seq_file *seq = data->seq;
  char *buf, *src, *dst, *end;
  char ifname[IFNAMSIZ];
  int j;

  if (!seq || !seq->buf)
    return 0;

  if (seq->count <= data->start_count)
    return 0;

  buf = seq->buf;
  src = buf + data->start_count;
  dst = src;
  end = buf + seq->count;

  while (src < end) {
    char *nl = memchr(src, '\n', end - src);
    char *line_end = nl ? nl + 1 : end;
    size_t line_len = line_end - src;

    for (j = 0; j < IFNAMSIZ - 1 && j < (int)line_len && src[j] != '\t' &&
                src[j] != '\n';
         j++)
      ifname[j] = src[j];
    ifname[j] = '\0';

    if (is_active_vpn_ifname(ifname)) {
      vpnhide_dbg("fib_route_ret: hiding route for %s\n", ifname);
      record_kmod_intercept(from_kuid(&init_user_ns, current_uid()), 2);
      src = line_end;
      continue;
    }

    if (dst != src)
      memmove(dst, src, line_len);
    dst += line_len;
    src = line_end;
  }

  seq->count = dst - buf;
  return 0;
}

struct kretprobe fib_route_krp = {
    .handler = fib_route_ret,
    .entry_handler = fib_route_entry,
    .data_size = sizeof(struct fib_route_data),
    .maxactive = VPNHIDE_KRETPROBE_MAXACTIVE,
    .kp.symbol_name = "fib_route_seq_show",
};

static int ipv6_route_entry(struct kretprobe_instance *ri,
                            struct pt_regs *regs) {
  struct fib_route_data *data;
  if (!is_hook_active(HOOK_IPV6_ROUTE, from_kuid(&init_user_ns, current_uid())))
    return 1;

  if (!is_target_uid())
    return 1;

  data = (void *)ri->data;
  data->seq = (struct seq_file *)regs->regs[0];
  data->start_count = data->seq ? data->seq->count : 0;

  vpnhide_dbg("ipv6_route_entry: uid=%u target=1\n",
              from_kuid(&init_user_ns, current_uid()));

  return 0;
}

static int ipv6_route_ret(struct kretprobe_instance *ri, struct pt_regs *regs) {
  struct fib_route_data *data = (void *)ri->data;
  struct seq_file *seq = data->seq;
  char *buf, *src, *dst, *end;
  char ifname[IFNAMSIZ];
  int j;

  if (!seq || !seq->buf)
    return 0;

  if (seq->count <= data->start_count)
    return 0;

  buf = seq->buf;
  src = buf + data->start_count;
  dst = src;
  end = buf + seq->count;

  while (src < end) {
    char *nl = memchr(src, '\n', end - src);
    char *line_end = nl ? nl + 1 : end;
    size_t line_len = line_end - src;
    char *p;

    p = line_end - 1;
    while (p >= src && (*p == '\n' || *p == '\r' || *p == ' ' || *p == '\t'))
      p--;

    j = 0;
    while (p >= src && *p != ' ' && *p != '\t' && j < IFNAMSIZ - 1) {
      j++;
      p--;
    }
    p++;

    for (j = 0; j < IFNAMSIZ - 1 && (p + j) < line_end && p[j] != ' ' &&
                p[j] != '\t' && p[j] != '\n';
         j++)
      ifname[j] = p[j];
    ifname[j] = '\0';

    if (is_active_vpn_ifname(ifname)) {
      vpnhide_dbg("ipv6_route_ret: hiding IPv6 route for %s\n", ifname);
      record_kmod_intercept(from_kuid(&init_user_ns, current_uid()), 2);
      src = line_end;
      continue;
    }

    if (dst != src)
      memmove(dst, src, line_len);
    dst += line_len;
    src = line_end;
  }

  seq->count = dst - buf;
  return 0;
}

struct kretprobe ipv6_route_krp = {
    .handler = ipv6_route_ret,
    .entry_handler = ipv6_route_entry,
    .data_size = sizeof(struct fib_route_data),
    .maxactive = VPNHIDE_KRETPROBE_MAXACTIVE,
    .kp.symbol_name = "ipv6_route_seq_show",
};

static int dev_seq_entry(struct kretprobe_instance *ri, struct pt_regs *regs) {
  struct fib_route_data *data;
  if (!is_hook_active(HOOK_DEV_SEQ, from_kuid(&init_user_ns, current_uid())))
    return 1;

  if (!is_target_uid())
    return 1;

  data = (void *)ri->data;
  data->seq = (struct seq_file *)regs->regs[0];
  data->start_count = data->seq ? data->seq->count : 0;

  vpnhide_dbg("dev_seq_entry: uid=%u target=1\n",
              from_kuid(&init_user_ns, current_uid()));

  return 0;
}

static int dev_seq_ret(struct kretprobe_instance *ri, struct pt_regs *regs) {
  struct fib_route_data *data = (void *)ri->data;
  struct seq_file *seq = data->seq;
  char *buf, *src, *dst, *end;
  char ifname[IFNAMSIZ];
  int j;

  if (!seq || !seq->buf)
    return 0;

  if (seq->count <= data->start_count)
    return 0;

  buf = seq->buf;
  src = buf + data->start_count;
  dst = src;
  end = buf + seq->count;

  while (src < end) {
    char *nl = memchr(src, '\n', end - src);
    char *line_end = nl ? nl + 1 : end;
    size_t line_len = line_end - src;
    char *p = src;

    while (p < line_end && (*p == ' ' || *p == '\t'))
      p++;

    j = 0;
    while (p < line_end && *p != ':' && *p != ' ' && *p != '\t' && *p != '\n' &&
           j < IFNAMSIZ - 1) {
      ifname[j++] = *p++;
    }
    ifname[j] = '\0';

    if (j > 0 && is_active_vpn_ifname(ifname)) {
      vpnhide_dbg("dev_seq_ret: hiding statistics for %s\n", ifname);
      record_kmod_intercept(from_kuid(&init_user_ns, current_uid()), 2);
      src = line_end;
      continue;
    }

    if (dst != src)
      memmove(dst, src, line_len);
    dst += line_len;
    src = line_end;
  }

  seq->count = dst - buf;
  return 0;
}

struct kretprobe dev_seq_krp = {
    .handler = dev_seq_ret,
    .entry_handler = dev_seq_entry,
    .data_size = sizeof(struct fib_route_data),
    .maxactive = VPNHIDE_KRETPROBE_MAXACTIVE,
    .kp.symbol_name = "dev_seq_show",
};

static int if6_seq_entry(struct kretprobe_instance *ri, struct pt_regs *regs) {
  struct fib_route_data *data;
  if (!is_hook_active(HOOK_IF6_SEQ, from_kuid(&init_user_ns, current_uid())))
    return 1;

  if (!is_target_uid())
    return 1;

  data = (void *)ri->data;
  data->seq = (struct seq_file *)regs->regs[0];
  data->start_count = data->seq ? data->seq->count : 0;

  vpnhide_dbg("if6_seq_entry: uid=%u target=1\n",
              from_kuid(&init_user_ns, current_uid()));

  return 0;
}

static int if6_seq_ret(struct kretprobe_instance *ri, struct pt_regs *regs) {
  struct fib_route_data *data = (void *)ri->data;
  struct seq_file *seq = data->seq;
  char *buf, *src, *dst, *end;
  char ifname[IFNAMSIZ];
  int j;

  if (!seq || !seq->buf)
    return 0;

  if (seq->count <= data->start_count)
    return 0;

  buf = seq->buf;
  src = buf + data->start_count;
  dst = src;
  end = buf + seq->count;

  while (src < end) {
    char *nl = memchr(src, '\n', end - src);
    char *line_end = nl ? nl + 1 : end;
    size_t line_len = line_end - src;
    char *p;

    p = line_end - 1;
    while (p >= src && (*p == '\n' || *p == '\r' || *p == ' ' || *p == '\t'))
      p--;

    j = 0;
    while (p >= src && *p != ' ' && *p != '\t' && j < IFNAMSIZ - 1) {
      j++;
      p--;
    }
    p++;

    for (j = 0; j < IFNAMSIZ - 1 && (p + j) < line_end && p[j] != ' ' &&
                p[j] != '\t' && p[j] != '\n';
         j++)
      ifname[j] = p[j];
    ifname[j] = '\0';

    if (is_active_vpn_ifname(ifname)) {
      vpnhide_dbg("if6_seq_ret: hiding interface %s\n", ifname);
      record_kmod_intercept(from_kuid(&init_user_ns, current_uid()), 2);
      src = line_end;
      continue;
    }

    if (dst != src)
      memmove(dst, src, line_len);
    dst += line_len;
    src = line_end;
  }

  seq->count = dst - buf;
  return 0;
}

struct kretprobe if6_seq_krp = {
    .handler = if6_seq_ret,
    .entry_handler = if6_seq_entry,
    .data_size = sizeof(struct fib_route_data),
    .maxactive = VPNHIDE_KRETPROBE_MAXACTIVE,
    .kp.symbol_name = "if6_seq_show",
};

struct fib_trie_data {
  struct seq_file *seq;
  size_t start_count;
};

static int fib_trie_entry(struct kretprobe_instance *ri, struct pt_regs *regs) {
  struct fib_trie_data *data;

  if (!is_hook_active(HOOK_FIB_TRIE, from_kuid(&init_user_ns, current_uid())))
    return 1;
  if (!is_target_uid())
    return 1;

  data = (void *)ri->data;
  data->seq = (struct seq_file *)regs->regs[0];
  data->start_count = data->seq ? data->seq->count : 0;
  return 0;
}

static int fib_trie_ret(struct kretprobe_instance *ri, struct pt_regs *regs) {
  struct fib_trie_data *data = (void *)ri->data;
  struct seq_file *seq = data->seq;
  char *buf, *src, *dst, *end;

  if (!seq || !seq->buf)
    return 0;
  if (seq->count <= data->start_count)
    return 0;

  buf = seq->buf;
  src = buf + data->start_count;
  dst = src;
  end = buf + seq->count;

  while (src < end) {
    char *nl = memchr(src, '\n', end - src);
    char *line_end = nl ? nl + 1 : end;
    size_t line_len = line_end - src;
    char word[IFNAMSIZ];
    char *p = src;
    bool has_vpn = false;

    while (p < line_end && !has_vpn) {
      int j = 0;

      while (p < line_end &&
             (*p == ' ' || *p == '\t' || *p == '|' || *p == '+' || *p == '-'))
        p++;
      while (p < line_end && j < IFNAMSIZ - 1 && *p != ' ' && *p != '\t' &&
             *p != '\n' && *p != '/' && *p != '|')
        word[j++] = *p++;
      word[j] = '\0';
      if (j > 0 && is_active_vpn_ifname(word))
        has_vpn = true;
    }

    if (has_vpn) {
      vpnhide_dbg("fib_trie_ret: suppressing line with VPN iface\n");
      record_kmod_intercept(from_kuid(&init_user_ns, current_uid()), 2);
      src = line_end;
      continue;
    }
    if (dst != src)
      memmove(dst, src, line_len);
    dst += line_len;
    src = line_end;
  }
  seq->count = dst - buf;
  return 0;
}

struct kretprobe fib_trie_krp = {
    .handler = fib_trie_ret,
    .entry_handler = fib_trie_entry,
    .data_size = sizeof(struct fib_trie_data),
    .maxactive = VPNHIDE_KRETPROBE_MAXACTIVE,
    .kp.symbol_name = "fib_trie_seq_show",
};

/* --- FIB info and rule/route dumps hooks --- */

static struct net_device *vpnhide_get_fib_info_dev(struct fib_info *fi) {
  struct net_device *dev = NULL;

  if (!fi)
    return NULL;

  rcu_read_lock();
  {
    struct nexthop *nh = NULL;
    if (copy_from_kernel_nofault(&nh, &fi->nh, sizeof(nh)) == 0 && nh) {
      bool is_group = false;
      copy_from_kernel_nofault(&is_group, &nh->is_group, sizeof(is_group));
      if (is_group) {
        struct nh_group *nh_grp = NULL;
        if (copy_from_kernel_nofault(&nh_grp, &nh->nh_grp, sizeof(nh_grp)) ==
                0 &&
            nh_grp) {
          u16 num_nh = 0;
          copy_from_kernel_nofault(&num_nh, &nh_grp->num_nh, sizeof(num_nh));
          if (num_nh > 0) {
            struct nexthop *nhe = NULL;
            if (copy_from_kernel_nofault(&nhe, &nh_grp->nh_entries[0].nh,
                                         sizeof(nhe)) == 0 &&
                nhe) {
              struct nh_info *nhi = NULL;
              if (copy_from_kernel_nofault(&nhi, &nhe->nh_info, sizeof(nhi)) ==
                      0 &&
                  nhi) {
                copy_from_kernel_nofault(&dev, &nhi->fib_nhc.nhc_dev,
                                         sizeof(dev));
              }
            }
          }
        }
      } else {
        struct nh_info *nhi = NULL;
        if (copy_from_kernel_nofault(&nhi, &nh->nh_info, sizeof(nhi)) == 0 &&
            nhi) {
          copy_from_kernel_nofault(&dev, &nhi->fib_nhc.nhc_dev, sizeof(dev));
        }
      }
    } else {
      int fib_nhs = 0;
      copy_from_kernel_nofault(&fib_nhs, &fi->fib_nhs, sizeof(fib_nhs));
      if (fib_nhs > 0) {
        copy_from_kernel_nofault(&dev, &fi->fib_nh[0].nh_common.nhc_dev,
                                 sizeof(dev));
      }
    }
  }
  rcu_read_unlock();

  return dev;
}

struct fib_dump_data {
  struct sk_buff *skb;
  unsigned int saved_len;
  bool should_filter;
};

static int fib_dump_entry(struct kretprobe_instance *ri, struct pt_regs *regs) {
  struct fib_dump_data *data;
  struct fib_info *fi = NULL;
  struct fib_rt_info *fri;
  struct fib_rt_info fri_copy;
  struct net_device *dev = NULL;

  if (!is_hook_active(HOOK_FIB_DUMP, from_kuid(&init_user_ns, current_uid())))
    return 1;

  if (!is_target_uid())
    return 1;

  fri = (struct fib_rt_info *)regs->regs[4];
  if (fri && copy_from_kernel_nofault(&fri_copy, fri, sizeof(fri_copy)) == 0) {
    fi = fri_copy.fi;
  }

  if (!fi)
    return 1;

  rcu_read_lock();
  dev = vpnhide_get_fib_info_dev(fi);
  if (dev && is_active_vpn_ifindex(dev->ifindex)) {
    data = (void *)ri->data;
    data->skb = (struct sk_buff *)regs->regs[0];
    data->saved_len = data->skb ? data->skb->len : 0;
    data->should_filter = true;
    vpnhide_dbg("fib_dump_entry: hiding route via %s\n", dev->name);
    rcu_read_unlock();
    return 0;
  }
  rcu_read_unlock();

  return 1;
}

static int fib_dump_ret(struct kretprobe_instance *ri, struct pt_regs *regs) {
  struct fib_dump_data *data = (void *)ri->data;
  struct nlmsghdr hdr;
  bool single = false;

  if (!data->should_filter || !data->skb)
    return 0;

  if (regs_return_value(regs) >= 0) {
    /* Dump messages are multipart. A non-multipart message is a point
     * RTM_F_FIB_MATCH reply: return an error rather than send an empty skb. */
    if (data->skb->len >= data->saved_len + sizeof(hdr) &&
        !skb_copy_bits(data->skb, data->saved_len, &hdr, sizeof(hdr)) &&
        hdr.nlmsg_type == RTM_NEWROUTE && !(hdr.nlmsg_flags & NLM_F_MULTI))
      single = true;
    record_kmod_intercept(from_kuid(&init_user_ns, current_uid()), 1);
    skb_trim(data->skb, data->saved_len);
    regs_set_return_value(regs, single ? -ENETUNREACH : 0);
  }
  return 0;
}

struct kretprobe fib_dump_krp = {
    .handler = fib_dump_ret,
    .entry_handler = fib_dump_entry,
    .data_size = sizeof(struct fib_dump_data),
    .maxactive = VPNHIDE_KRETPROBE_MAXACTIVE,
    .kp.symbol_name = "fib_dump_info",
};

struct fib_rule_dump_data {
  struct sk_buff *skb;
  unsigned int saved_len;
  bool should_filter;
};

static int fib_rule_fill_entry(struct kretprobe_instance *ri,
                               struct pt_regs *regs) {
  struct fib_rule_dump_data *data;
  struct fib_rule *rule;
  uid_t my_uid;
  bool filter = false;

  if (!is_hook_active(HOOK_FIB_RULE_FILL,
                      from_kuid(&init_user_ns, current_uid())))
    return 1;

  if (!is_target_uid())
    return 1;

  rule = (struct fib_rule *)regs->regs[1];
  if (!rule)
    return 1;

  my_uid = from_kuid(&init_user_ns, current_uid());

  rcu_read_lock();
  if ((rule->iifname[0] != '\0' && is_active_vpn_ifname(rule->iifname)) ||
      (rule->oifname[0] != '\0' && is_active_vpn_ifname(rule->oifname))) {
    filter = true;
    vpnhide_dbg("fib_rule_fill_entry: hiding rule via VPN interface %s / %s\n",
                rule->iifname, rule->oifname);
  } else {
    uid_t start = from_kuid(&init_user_ns, rule->uid_range.start);
    uid_t end = from_kuid(&init_user_ns, rule->uid_range.end);
    if (((start >= 10000 || end >= 10000) || is_target_uid_val(start) ||
         is_target_uid_val(end)) &&
        end != (uid_t)~0) {
      if (rule->table != 254 && rule->table != 255 && rule->table != 253 &&
          rule->table > 100) {
        filter = true;
        vpnhide_dbg("fib_rule_fill_entry: hiding UID split-routing rule range %u-%u, table %u\n",
                    start, end, rule->table);
      }
    }
  }
  rcu_read_unlock();

  if (!filter)
    return 1;

  data = (void *)ri->data;
  data->skb = (struct sk_buff *)regs->regs[0];
  data->saved_len = data->skb ? data->skb->len : 0;
  data->should_filter = true;

  return 0;
}

static int fib_rule_fill_ret(struct kretprobe_instance *ri,
                             struct pt_regs *regs) {
  struct fib_rule_dump_data *data = (void *)ri->data;

  if (!data->should_filter || !data->skb)
    return 0;

  if (regs_return_value(regs) >= 0) {
    record_kmod_intercept(from_kuid(&init_user_ns, current_uid()), 1);
    skb_trim(data->skb, data->saved_len);
    regs_set_return_value(regs, 0);
  }
  return 0;
}

struct kretprobe fib_rule_fill_krp = {
    .handler = fib_rule_fill_ret,
    .entry_handler = fib_rule_fill_entry,
    .data_size = sizeof(struct fib_rule_dump_data),
    .maxactive = VPNHIDE_KRETPROBE_MAXACTIVE,
    .kp.symbol_name = "fib_nl_fill_rule",
};

struct rt6_fill_data {
  struct sk_buff *skb;
  unsigned int saved_len;
  bool should_filter;
};

static int rt6_fill_entry(struct kretprobe_instance *ri, struct pt_regs *regs) {
  struct rt6_fill_data *data;
  struct fib6_info *rt;
  struct dst_entry *dst;
  bool is_vpn = false;
  const char *ifname = NULL;

  if (!is_hook_active(HOOK_RT6_FILL, from_kuid(&init_user_ns, current_uid())))
    return 1;

  if (!is_target_uid())
    return 1;

  rt = (struct fib6_info *)regs->regs[2];
  dst = (struct dst_entry *)regs->regs[3];

  rcu_read_lock();
  if (rt) {
    struct net_device *dev = rt->fib6_nh->nh_common.nhc_dev;
    if (dev && is_active_vpn_ifindex(dev->ifindex)) {
      is_vpn = true;
      ifname = dev->name;
    }
  } else if (dst && dst->dev && is_active_vpn_ifindex(dst->dev->ifindex)) {
    is_vpn = true;
    ifname = dst->dev->name;
  }

  if (is_vpn) {
    data = (void *)ri->data;
    data->skb = (struct sk_buff *)regs->regs[1];
    data->saved_len = data->skb ? data->skb->len : 0;
    data->should_filter = true;
    vpnhide_dbg("rt6_fill_entry: hiding IPv6 route via %s\n", ifname);
    rcu_read_unlock();
    return 0;
  }
  rcu_read_unlock();

  return 1;
}

static int rt6_fill_ret(struct kretprobe_instance *ri, struct pt_regs *regs) {
  struct rt6_fill_data *data = (void *)ri->data;

  if (!data->should_filter || !data->skb)
    return 0;

  if (regs_return_value(regs) >= 0) {
    record_kmod_intercept(from_kuid(&init_user_ns, current_uid()), 1);
    skb_trim(data->skb, data->saved_len);
    regs_set_return_value(regs, 0);
  }
  return 0;
}

struct kretprobe rt6_fill_krp = {
    .handler = rt6_fill_ret,
    .entry_handler = rt6_fill_entry,
    .data_size = sizeof(struct rt6_fill_data),
    .maxactive = VPNHIDE_KRETPROBE_MAXACTIVE,
    .kp.symbol_name = "rt6_fill_node",
};

/* Point route replies are serialized before netlink_unicast, avoiding the
 * LTO-dependent rt_fill_info and inlined rtnl_unicast ABIs. */
static bool vh_route_reply_has_hidden_oif(struct sk_buff *skb)
{
  struct nlmsghdr hdr;
  struct rtmsg route;
  unsigned int pos, end;

  if (!skb || skb_copy_bits(skb, 0, &hdr, sizeof(hdr)) ||
      hdr.nlmsg_type != RTM_NEWROUTE ||
      hdr.nlmsg_len < NLMSG_LENGTH(sizeof(route)) || hdr.nlmsg_len > skb->len ||
      skb_copy_bits(skb, NLMSG_HDRLEN, &route, sizeof(route)) ||
      route.rtm_family != AF_INET)
    return false;
  pos = NLMSG_LENGTH(sizeof(route));
  end = hdr.nlmsg_len;
  while (pos + sizeof(struct rtattr) <= end) {
    struct rtattr attr;
    u32 ifindex;
    unsigned int step;
    if (skb_copy_bits(skb, pos, &attr, sizeof(attr)) ||
        attr.rta_len < sizeof(attr) || attr.rta_len > end - pos)
      return false;
    if ((attr.rta_type & NLA_TYPE_MASK) == RTA_OIF &&
        attr.rta_len >= RTA_LENGTH(sizeof(ifindex)) &&
        !skb_copy_bits(skb, pos + RTA_LENGTH(0), &ifindex, sizeof(ifindex)) &&
        is_active_vpn_ifindex(ifindex))
      return true;
    step = RTA_ALIGN(attr.rta_len);
    if (step > end - pos)
      break;
    pos += step;
  }
  return false;
}

static int vh_rtnl_unicast_pre(struct kprobe *kp, struct pt_regs *regs)
{
  struct sock *sender = (struct sock *)regs->regs[0];
  struct sk_buff *skb = (struct sk_buff *)regs->regs[1];
  uid_t uid = from_kuid(&init_user_ns, current_uid());
  (void)kp;
  /* Limit interception to the network namespace's kernel routing socket. */
  if (!sender || sender->sk_protocol != NETLINK_ROUTE ||
      sock_net(sender)->rtnl != sender ||
      !is_hook_active(HOOK_RT_FILL, uid) || !is_target_uid_val(uid) ||
      !vh_route_reply_has_hidden_oif(skb))
    return 0;
  record_kmod_intercept(uid, 1);
  kfree_skb(skb);
  regs_set_return_value(regs, -ENETUNREACH);
  instruction_pointer_set(regs, regs->regs[30]);
  return 1;
}

static void vh_rtnl_unicast_post(struct kprobe *kp, struct pt_regs *regs,
                                 unsigned long flags)
{
  (void)kp; (void)regs; (void)flags;
}

struct kprobe rt_unicast_kp = {
  .symbol_name = "netlink_unicast",
  .pre_handler = vh_rtnl_unicast_pre,
  .post_handler = vh_rtnl_unicast_post,
};

/* --- TC fill qdisc hook --- */

struct tc_fill_qdisc_data {
  struct sk_buff *skb;
  int saved_len;
};

static int tc_fill_qdisc_entry(struct kretprobe_instance *ri,
                               struct pt_regs *regs) {
  struct tc_fill_qdisc_data *data;
  struct sk_buff *skb;

  if (!is_hook_active(HOOK_TC_FILL_QDISC,
                      from_kuid(&init_user_ns, current_uid())))
    return 1;
  if (!is_target_uid())
    return 1;

  skb = (struct sk_buff *)regs->regs[0];
  data = (void *)ri->data;
  data->skb = skb;
  data->saved_len = skb ? skb->len : 0;
  return 0;
}

static int tc_fill_qdisc_ret(struct kretprobe_instance *ri,
                             struct pt_regs *regs) {
  struct tc_fill_qdisc_data *data = (void *)ri->data;
  struct sk_buff *skb = data->skb;
  const size_t ifindex_off = sizeof(struct nlmsghdr) + 4;
  int ifindex = 0;

  if (regs_return_value(regs) != 0)
    return 0;
  if (!skb || !skb->data)
    return 0;
  if (skb->len < data->saved_len + (int)(ifindex_off + sizeof(int)))
    return 0;

  if (copy_from_kernel_nofault(&ifindex,
                               skb->data + data->saved_len + ifindex_off,
                               sizeof(ifindex)) != 0)
    return 0;

  if (ifindex > 0 && is_active_vpn_ifindex((u32)ifindex)) {
    vpnhide_dbg("tc_fill_qdisc_ret: hiding qdisc for VPN ifindex=%d\n",
                ifindex);
    skb_trim(skb, data->saved_len);
    record_kmod_intercept(from_kuid(&init_user_ns, current_uid()), 1);
  }
  return 0;
}

struct kretprobe tc_fill_qdisc_krp = {
    .handler = tc_fill_qdisc_ret,
    .entry_handler = tc_fill_qdisc_entry,
    .data_size = sizeof(struct tc_fill_qdisc_data),
    .maxactive = VPNHIDE_KRETPROBE_MAXACTIVE,
    .kp.symbol_name = "tc_fill_qdisc",
};
