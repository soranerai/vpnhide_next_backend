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

/* --- inet_ioctl hook --- */

struct inet_ioctl_data {
  unsigned int cmd;
  void __user *uarg;
};

static int inet_ioctl_entry(struct kretprobe_instance *ri,
                            struct pt_regs *regs) {
  struct inet_ioctl_data *data;
  unsigned int cmd = (unsigned int)regs->regs[1];

  switch (cmd) {
  case SIOCGIFADDR:
  case SIOCGIFDSTADDR:
  case SIOCGIFBRDADDR:
  case SIOCGIFNETMASK:
    break;
  default:
    return 1;
  }

  if (!is_hook_active(HOOK_DEV_IOCTL, from_kuid(&init_user_ns, current_uid())))
    return 1;

  if (!is_target_uid())
    return 1;

  data = (void *)ri->data;
  data->cmd = cmd;
  data->uarg = (void __user *)regs->regs[2];

  vpnhide_dbg("inet_ioctl_entry: uid=%u cmd=0x%x\n",
              from_kuid(&init_user_ns, current_uid()), data->cmd);
  return 0;
}

static int inet_ioctl_ret(struct kretprobe_instance *ri, struct pt_regs *regs) {
  struct inet_ioctl_data *data = (void *)ri->data;
  char name[IFNAMSIZ];

  if (regs_return_value(regs) != 0)
    return 0;

  if (!data->uarg)
    return 0;

  if (copy_from_user(name, data->uarg, IFNAMSIZ)) {
    vpnhide_dbg("inet_ioctl_ret: copy_from_user failed\n");
    return 0;
  }
  name[IFNAMSIZ - 1] = '\0';

  if (is_active_vpn_ifname(name)) {
    vpnhide_dbg("inet_ioctl_ret: hiding iface=%s cmd=0x%x\n", name, data->cmd);
    record_kmod_intercept(from_kuid(&init_user_ns, current_uid()), 0);
    regs_set_return_value(regs, -ENODEV);
  }

  return 0;
}

struct kretprobe inet_ioctl_krp = {
    .handler = inet_ioctl_ret,
    .entry_handler = inet_ioctl_entry,
    .data_size = sizeof(struct inet_ioctl_data),
    .maxactive = VPNHIDE_KRETPROBE_MAXACTIVE,
    .kp.symbol_name = "inet_ioctl",
};

/* --- sock_ioctl hook --- */

struct sock_ioctl_data {
  void __user *argp;
  struct ifreq __user *user_ifc_req;
  int ifc_capacity;
};

enum filter_ifconf_result {
  FILTER_IFCONF_NO_CHANGE,
  FILTER_IFCONF_CHANGED,
  FILTER_IFCONF_COPY_FAULT,
};

static enum filter_ifconf_result filter_ifconf_buf(struct ifreq __user *usr_ifr,
                                                   int n, int *out_len) {
  struct ifreq tmp;
  int i, dst = 0;

  for (i = 0; i < n; i++) {
    if (copy_from_user(&tmp, &usr_ifr[i], sizeof(tmp)))
      return FILTER_IFCONF_COPY_FAULT;
    tmp.ifr_name[IFNAMSIZ - 1] = '\0';
    if (is_active_vpn_ifname(tmp.ifr_name))
      continue;
    if (dst != i) {
      if (copy_to_user(&usr_ifr[dst], &tmp, sizeof(tmp)))
        return FILTER_IFCONF_COPY_FAULT;
    }
    dst++;
  }

  if (dst == n)
    return FILTER_IFCONF_NO_CHANGE;
  *out_len = dst * (int)sizeof(struct ifreq);
  return FILTER_IFCONF_CHANGED;
}

/* SIOCGIFCONF writes only the returned entries.  Anything beyond ifc_len is
 * caller-owned memory and may still contain entries from a previous query.
 * RKNHardering deliberately inspects that tail, so compacting the visible
 * entries alone is not sufficient. */
static bool clear_ifconf_tail(struct ifreq __user *usr_ifr,
                              int start_len, int capacity_len) {
  unsigned long tail_len;

  if (!usr_ifr || start_len < 0 || capacity_len <= start_len)
    return true;

  tail_len = (unsigned long)(capacity_len - start_len);
  if (clear_user((char __user *)usr_ifr + start_len, tail_len) != 0)
    return false;
  return true;
}

static int sock_ioctl_ret(struct kretprobe_instance *ri, struct pt_regs *regs) {
  struct sock_ioctl_data *data = (void *)ri->data;
  struct ifconf __user *uifc;
  struct ifconf ifc;
  int orig_len;
  int filtered_len;
  enum filter_ifconf_result res;

  vpnhide_dbg("sock_ioctl_ret: retval=%ld argp=%px\n", regs_return_value(regs),
              data->argp);

  if (regs_return_value(regs) != 0 || !data->argp)
    return 0;

  uifc = data->argp;
  if (copy_from_user(&ifc, uifc, sizeof(ifc)))
    return 0;
  if (!ifc.ifc_req || ifc.ifc_len < 0)
    return 0;

  /* Use the pointer captured before the ioctl returns.  This also prevents a
   * concurrent userspace mutation of ifc_req from changing the range we
   * compact or clear. */
  ifc.ifc_req = data->user_ifc_req;
  if (ifc.ifc_len > data->ifc_capacity)
    ifc.ifc_len = data->ifc_capacity;

  orig_len = ifc.ifc_len;
  res = filter_ifconf_buf(ifc.ifc_req, ifc.ifc_len / (int)sizeof(struct ifreq),
                          &ifc.ifc_len);

  if (res == FILTER_IFCONF_COPY_FAULT) {
    vpnhide_dbg("ifconf: copy fault during filter; ifc_len untouched\n");
    return 0;
  }

  filtered_len = ifc.ifc_len;
  if (!clear_ifconf_tail(ifc.ifc_req, filtered_len, data->ifc_capacity)) {
    vpnhide_dbg("ifconf: failed to clear tail start=%d capacity=%d\n",
                filtered_len, data->ifc_capacity);
    return 0;
  }

  if (res == FILTER_IFCONF_CHANGED) {
    if (put_user(ifc.ifc_len, &uifc->ifc_len)) {
      vpnhide_dbg("ifconf: put_user(ifc_len=%d) failed; userspace will see compacted buffer with stale length\n",
                  ifc.ifc_len);
      return 0;
    }
    record_kmod_intercept(from_kuid(&init_user_ns, current_uid()), 0);
    vpnhide_dbg("ifconf filtered %d -> %d bytes\n", orig_len, ifc.ifc_len);
  }

  return 0;
}

static int sock_ioctl_entry(struct kretprobe_instance *ri,
                            struct pt_regs *regs) {
  struct sock_ioctl_data *data;
  struct ifconf ifc;
  unsigned int cmd = (unsigned int)regs->regs[1];
  unsigned long arg = (unsigned long)regs->regs[2];

  if (!is_hook_active(HOOK_SOCK_IOCTL, from_kuid(&init_user_ns, current_uid())))
    return 1;

  if (cmd != SIOCGIFCONF)
    return 1;

  if (!is_target_uid())
    return 1;

  if (copy_from_user(&ifc, (void __user *)arg, sizeof(ifc)) ||
      !ifc.ifc_req || ifc.ifc_len <= 0)
    return 1;

  data = (void *)ri->data;
  data->argp = (void __user *)arg;
  data->user_ifc_req = ifc.ifc_req;
  data->ifc_capacity = ifc.ifc_len;
  vpnhide_dbg("sock_ioctl_entry: uid=%u SIOCGIFCONF argp=%px\n",
              from_kuid(&init_user_ns, current_uid()), data->argp);
  return 0;
}

struct kretprobe sock_ioctl_krp = {
    .handler = sock_ioctl_ret,
    .entry_handler = sock_ioctl_entry,
    .data_size = sizeof(struct sock_ioctl_data),
    .maxactive = VPNHIDE_KRETPROBE_MAXACTIVE,
    .kp.symbol_name = "sock_ioctl",
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

  if (!data->should_filter || !data->skb)
    return 0;

  if (regs_return_value(regs) >= 0) {
    record_kmod_intercept(from_kuid(&init_user_ns, current_uid()), 1);
    skb_trim(data->skb, data->saved_len);
    regs_set_return_value(regs, 0);
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

struct rt_fill_data {
  struct sk_buff *skb;
  unsigned int saved_len;
  bool should_filter;
};

static int rt_fill_entry(struct kretprobe_instance *ri, struct pt_regs *regs) {
  struct rt_fill_data *data;
  struct net_device *dev = NULL;
  struct rtable *rt = NULL;
  struct sk_buff *skb = NULL;
  struct net_device *dev_ptr = NULL;
  unsigned int temp_len = 0;
  bool is_vpn = false;

  if (!is_hook_active(HOOK_RT_FILL, from_kuid(&init_user_ns, current_uid())))
    return 1;

  if (!is_target_uid())
    return 1;

  rt = (struct rtable *)regs->regs[3];
  skb = (struct sk_buff *)regs->regs[7];

  if (rt) {
    if (copy_from_kernel_nofault(&dev_ptr, &rt->dst.dev, sizeof(dev_ptr)) ==
            0 &&
        dev_ptr) {
      dev = dev_ptr;
    }
  }

  rcu_read_lock();
  if (dev && is_active_vpn_ifindex(dev->ifindex)) {
    is_vpn = true;
  }
  rcu_read_unlock();

  if (!is_vpn)
    return 1;

  data = (void *)ri->data;
  data->should_filter = true;
  data->skb = NULL;
  data->saved_len = 0;

  if (skb) {
    if (copy_from_kernel_nofault(&temp_len, &skb->len, sizeof(temp_len)) == 0) {
      data->skb = skb;
      data->saved_len = temp_len;
    }
  }

  vpnhide_dbg("rt_fill_entry: hiding route via index %d\n", dev->ifindex);

  return 0;
}

static int rt_fill_ret(struct kretprobe_instance *ri, struct pt_regs *regs) {
  struct rt_fill_data *data = (void *)ri->data;

  if (!data->should_filter || !data->skb)
    return 0;

  if (regs_return_value(regs) >= 0) {
    record_kmod_intercept(from_kuid(&init_user_ns, current_uid()), 1);
    skb_trim(data->skb, data->saved_len);
    regs_set_return_value(regs, 0);
  }
  return 0;
}

struct kretprobe rt_fill_krp = {
    .handler = rt_fill_ret,
    .entry_handler = rt_fill_entry,
    .data_size = sizeof(struct rt_fill_data),
    .maxactive = VPNHIDE_KRETPROBE_MAXACTIVE,
    .kp.symbol_name = "rt_fill_info",
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
