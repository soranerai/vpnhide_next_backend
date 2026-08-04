#include "vpnhide_kmod.h"

/* --- setsockopt hook --- */

struct sock_setsockopt_data {
  bool override_ret;
  int deny_errno;
  bool intercepted;
  void __user *optval_ptr;
  int optlen;
  union {
    char orig_name[IFNAMSIZ];
    int orig_ifindex;
  };
  bool has_modified_name;
  bool has_modified_ifindex;
};

static int sys_setsockopt_entry(struct kretprobe_instance *ri,
                                struct pt_regs *regs) {
  struct sock_setsockopt_data *sdata;
  int fd, level, optname, optlen;
  void __user *optval_ptr;
  char name[IFNAMSIZ] = {0};

  if (!is_hook_active(HOOK_SETSOCKOPT, from_kuid(&init_user_ns, current_uid())))
    return 1;

  sdata = (void *)ri->data;
  sdata->override_ret = false;
  sdata->deny_errno = 0;
  sdata->intercepted = false;
  sdata->optval_ptr = NULL;
  sdata->optlen = 0;
  sdata->has_modified_name = false;
  sdata->has_modified_ifindex = false;

  if (sys_setsockopt_uses_wrapper) {
    struct pt_regs *user_regs = (struct pt_regs *)regs->regs[0];
    if (user_regs && (unsigned long)user_regs >= 0xFFFF000000000000ULL) {
      fd = (int)user_regs->regs[0];
      level = (int)user_regs->regs[1];
      optname = (int)user_regs->regs[2];
      optval_ptr = (void __user *)user_regs->regs[3];
      optlen = (int)user_regs->regs[4];
    } else {
      return 1;
    }
  } else {
    fd = (int)regs->regs[0];
    level = (int)regs->regs[1];
    optname = (int)regs->regs[2];
    optval_ptr = (void __user *)regs->regs[3];
    optlen = (int)regs->regs[4];
  }

  if (level == 0x5648 && optname == 0x88) {
    uid_t uid = from_kuid(&init_user_ns, current_uid());
    if (uid == 1000 || uid == 0) {
      struct vpnhide_spoof_ip sip;
      if (optlen == sizeof(sip)) {
        if (copy_from_user(&sip, optval_ptr, sizeof(sip)) == 0) {
          if (update_spoof_ip(&sip) == 0) {
            vpnhide_dbg("sys_setsockopt: updated spoof IP: IPv4=%pI4 (%d), IPv6=%pI6c (%d)\n",
                        &sip.ipv4_addr, sip.has_ipv4, sip.ipv6_addr,
                        sip.has_ipv6);
            sdata->override_ret = true;
          }
        }
      }
    }
    if (!sdata->override_ret)
      return 1;
    return 0;
  }

  if (!is_target_uid())
    return 1;

  if (level == SOL_SOCKET) {
    if (optname == SO_BINDTODEVICE) {
      if (optlen <= 0)
        return 0;
      if (optlen >= IFNAMSIZ)
        optlen = IFNAMSIZ - 1;

      if (copy_from_user(name, optval_ptr, optlen))
        return 0;
      name[optlen] = '\0';

      if (is_active_vpn_ifname(name)) {
        char fake_name[IFNAMSIZ] = "nonexistent0";
        vpnhide_dbg("sys_setsockopt: denying SO_BINDTODEVICE to VPN iface '%s' with ENODEV via userspace replace\n",
                    name);
        sdata->optval_ptr = optval_ptr;
        sdata->optlen = optlen;
        memcpy(sdata->orig_name, name, IFNAMSIZ);
        sdata->has_modified_name = true;
        sdata->intercepted = true;

        memset(fake_name + 12, 'x', IFNAMSIZ - 13);
        fake_name[IFNAMSIZ - 1] = '\0';

        if (copy_to_user(optval_ptr, fake_name, optlen)) {
          if (sys_setsockopt_uses_wrapper) {
            struct pt_regs *user_regs = (struct pt_regs *)regs->regs[0];
            if (user_regs && (unsigned long)user_regs >= 0xFFFF000000000000ULL) {
              user_regs->regs[4] = -1;
            }
          } else {
            regs->regs[4] = -1;
          }
          sdata->override_ret = true;
          sdata->deny_errno = ENODEV;
        }
      }
    } else if (optname == SO_BINDTOIFINDEX) {
      int ifindex;

      if (optlen != sizeof(int))
        return 0;
      if (get_user(ifindex, (int __user *)optval_ptr))
        return 0;

      if (ifindex <= 0)
        return 0;

      if (is_active_vpn_ifindex(ifindex)) {
        int fake_ifindex = -1;
        vpnhide_dbg("sys_setsockopt: denying SO_BINDTOIFINDEX %d with ENODEV via userspace replace\n",
                    ifindex);
        sdata->optval_ptr = optval_ptr;
        sdata->optlen = optlen;
        sdata->orig_ifindex = ifindex;
        sdata->has_modified_ifindex = true;
        sdata->intercepted = true;

        if (copy_to_user(optval_ptr, &fake_ifindex, sizeof(int))) {
          vpnhide_dbg("sys_setsockopt: copy_to_user failed for SO_BINDTOIFINDEX, falling back to override_ret\n");
          if (sys_setsockopt_uses_wrapper) {
            struct pt_regs *user_regs = (struct pt_regs *)regs->regs[0];
            if (user_regs && (unsigned long)user_regs >= 0xFFFF000000000000ULL) {
              user_regs->regs[4] = -1;
            }
          } else {
            regs->regs[4] = -1;
          }
          sdata->override_ret = true;
          sdata->deny_errno = ENODEV;
        } else {
          vpnhide_dbg("sys_setsockopt: copy_to_user succeeded for SO_BINDTOIFINDEX (wrote %d)\n", fake_ifindex);
          /* sock_bindtoindex_locked() rejects negative indexes before
           * changing sk_bound_dev_if.  Report the externally consistent
           * ENODEV after the real handler returns EINVAL. */
          sdata->override_ret = true;
          sdata->deny_errno = ENODEV;
        }
      }
    } else if (optname == SO_MARK) {
      int mark;
      if (optlen != sizeof(int))
        return 0;
      if (get_user(mark, (int __user *)optval_ptr))
        return 0;

      if (mark != 0) {
        vpnhide_dbg("sys_setsockopt: target app tried to set SO_MARK to 0x%x, overriding to 0\n",
                    mark);
        if (put_user(0, (int __user *)optval_ptr) == 0) {
          sdata->intercepted = true;
        }
      }
    } else if (optname == SO_TIMESTAMPING) {
      int flags;
      if (optlen == sizeof(int) &&
          get_user(flags, (int __user *)optval_ptr) == 0) {
        int stripped = flags & ~(SOF_TIMESTAMPING_TX_HARDWARE |
                                 SOF_TIMESTAMPING_RX_HARDWARE |
                                 SOF_TIMESTAMPING_RAW_HARDWARE);
        if (stripped != flags &&
            put_user(stripped, (int __user *)optval_ptr) == 0) {
          vpnhide_dbg("sys_setsockopt: stripped SO_TIMESTAMPING hw bits 0x%x→0x%x\n",
                      flags, stripped);
          sdata->intercepted = true;
        }
      }
    }
  } else if (level == IPPROTO_IP) {
    if (optname == IP_MTU_DISCOVER) {
      int discover;
      if (optlen == sizeof(int)) {
        if (get_user(discover, (int __user *)optval_ptr) == 0) {
          if (discover != IP_PMTUDISC_DONT) {
            if (put_user(IP_PMTUDISC_DONT, (int __user *)optval_ptr) == 0) {
              vpnhide_dbg("sys_setsockopt: spoofed IP_MTU_DISCOVER from %d to IP_PMTUDISC_DONT\n",
                          discover);
              sdata->intercepted = true;
            }
          }
        }
      }
    }
  } else if (level == IPPROTO_IPV6) {
    if (optname == IPV6_MTU_DISCOVER) {
      int discover;
      if (optlen == sizeof(int)) {
        if (get_user(discover, (int __user *)optval_ptr) == 0) {
          if (discover != IPV6_PMTUDISC_DONT) {
            if (put_user(IPV6_PMTUDISC_DONT, (int __user *)optval_ptr) == 0) {
              vpnhide_dbg("sys_setsockopt: spoofed IPV6_MTU_DISCOVER from %d to IPV6_PMTUDISC_DONT\n",
                          discover);
              sdata->intercepted = true;
            }
          }
        }
      }
    }
  } else if (level == IPPROTO_UDP) {
    if (optname == 103 /* UDP_SEGMENT */ && optlen == sizeof(int)) {
      int zero = 0;

      if (put_user(zero, (int __user *)optval_ptr) == 0) {
        vpnhide_dbg("sys_setsockopt: zeroed UDP_SEGMENT to block GSO probe uid=%u\n",
                    from_kuid(&init_user_ns, current_uid()));
        sdata->intercepted = true;
      }
    }
  }

  if (!sdata->override_ret && !sdata->intercepted)
    return 1;

  return 0;
}

static int sys_setsockopt_ret(struct kretprobe_instance *ri,
                              struct pt_regs *regs) {
  struct sock_setsockopt_data *sdata = (void *)ri->data;

  if (sdata->intercepted) {
    record_kmod_intercept(from_kuid(&init_user_ns, current_uid()), 3);
  }

  if (sdata->has_modified_name && sdata->optval_ptr) {
    if (copy_to_user(sdata->optval_ptr, sdata->orig_name, sdata->optlen)) {
      vpnhide_dbg("sys_setsockopt_ret: failed to restore original name in userspace\n");
    } else {
      vpnhide_dbg("sys_setsockopt_ret: successfully restored original name in userspace\n");
    }
  } else if (sdata->has_modified_ifindex && sdata->optval_ptr) {
    if (copy_to_user(sdata->optval_ptr, &sdata->orig_ifindex, sizeof(int))) {
      vpnhide_dbg("sys_setsockopt_ret: failed to restore original ifindex in userspace\n");
    } else {
      vpnhide_dbg("sys_setsockopt_ret: successfully restored original ifindex in userspace\n");
    }
  }

  if (sdata->override_ret) {
    regs_set_return_value(regs, sdata->deny_errno ? -sdata->deny_errno : 0);
  }
  return 0;
}

struct kretprobe sys_setsockopt_krp = {
    .handler = sys_setsockopt_ret,
    .entry_handler = sys_setsockopt_entry,
    .data_size = sizeof(struct sock_setsockopt_data),
    .maxactive = VPNHIDE_KRETPROBE_MAXACTIVE,
    .kp.symbol_name = "__arm64_sys_setsockopt",
};

/* --- getsockopt hooks --- */

struct sock_getsockopt_data {
  int level;
  int optname;
  void __user *optval;
  int __user *optlen;
  struct net *net;
  sa_family_t family;
};

static int sock_getsockopt_entry(struct kretprobe_instance *ri,
                                 struct pt_regs *regs) {
  struct sock_getsockopt_data *data;
  struct socket *sock = (struct socket *)regs->regs[0];
  int level = (int)regs->regs[1];
  int optname = (int)regs->regs[2];

  if (!is_hook_active(HOOK_GETSOCKOPT, from_kuid(&init_user_ns, current_uid())))
    return 1;

  if (level != SOL_SOCKET && level != IPPROTO_IP && level != IPPROTO_IPV6 &&
      level != IPPROTO_TCP)
    return 1;

  if (level == SOL_SOCKET && optname != SO_BINDTODEVICE &&
      optname != SO_BINDTOIFINDEX)
    return 1;
  if (level == IPPROTO_IP && optname != IP_MTU && optname != IP_MTU_DISCOVER)
    return 1;
  if (level == IPPROTO_IPV6 && optname != IPV6_MTU &&
      optname != IPV6_MTU_DISCOVER)
    return 1;
  if (level == IPPROTO_TCP && optname != TCP_MAXSEG && optname != TCP_INFO)
    return 1;

  if (!is_target_uid())
    return 1;

  data = (void *)ri->data;
  data->level = level;
  data->optname = optname;
  data->optval = (void __user *)regs->regs[3];
  data->optlen = (int __user *)regs->regs[4];
  data->net = sock && sock->sk
                  ? sock_net(sock->sk)
                  : (current->nsproxy ? current->nsproxy->net_ns : &init_net);
  data->family = sock && sock->sk ? sock->sk->sk_family : AF_UNSPEC;

  return 0;
}

static int sock_getsockopt_ret(struct kretprobe_instance *ri,
                               struct pt_regs *regs) {
  struct sock_getsockopt_data *data = (void *)ri->data;
  struct vpnhide_spoof_ip sip;
  int ret = regs_return_value(regs);

  if (ret != 0)
    return 0;

  record_kmod_intercept(from_kuid(&init_user_ns, current_uid()), 3);
  get_spoof_ip(&sip);

  if (data->level == IPPROTO_IP && data->optname == IP_MTU) {
    int mtu = 0;
    int len = 0;
    if (get_user(len, data->optlen) == 0 && len >= sizeof(int)) {
      if (get_user(mtu, (int __user *)data->optval) == 0) {
        int cover_mtu = sip.ipv4_mtu ? sip.ipv4_mtu : 1500;
        if (mtu > 0 && mtu != cover_mtu) {
          if (put_user(cover_mtu, (int __user *)data->optval) == 0) {
            vpnhide_dbg("sock_getsockopt_ret: spoofed IP_MTU from %d to %d\n",
                        mtu, cover_mtu);
          }
        }
      }
    }
    return 0;
  }

  if (data->level == IPPROTO_IPV6 && data->optname == IPV6_MTU) {
    int mtu = 0;
    int len = 0;
    if (get_user(len, data->optlen) == 0 && len >= sizeof(int)) {
      if (get_user(mtu, (int __user *)data->optval) == 0) {
        int cover_mtu = sip.ipv6_mtu ? sip.ipv6_mtu : 1500;
        if (mtu > 0 && mtu != cover_mtu) {
          if (put_user(cover_mtu, (int __user *)data->optval) == 0) {
            vpnhide_dbg("sock_getsockopt_ret: spoofed IPV6_MTU from %d to %d\n",
                        mtu, cover_mtu);
          }
        }
      }
    }
    return 0;
  }

  if (data->level == IPPROTO_IP && data->optname == IP_MTU_DISCOVER) {
    int discover = 0;
    int len = 0;
    if (get_user(len, data->optlen) == 0 && len >= sizeof(int)) {
      if (get_user(discover, (int __user *)data->optval) == 0) {
        if (discover == IP_PMTUDISC_DONT) {
          if (put_user(IP_PMTUDISC_DO, (int __user *)data->optval) == 0) {
            vpnhide_dbg("sock_getsockopt_ret: spoofed IP_MTU_DISCOVER to IP_PMTUDISC_DO\n");
          }
        }
      }
    }
    return 0;
  }

  if (data->level == IPPROTO_IPV6 && data->optname == IPV6_MTU_DISCOVER) {
    int discover = 0;
    int len = 0;
    if (get_user(len, data->optlen) == 0 && len >= sizeof(int)) {
      if (get_user(discover, (int __user *)data->optval) == 0) {
        if (discover == IPV6_PMTUDISC_DONT) {
          if (put_user(IPV6_PMTUDISC_DO, (int __user *)data->optval) == 0) {
            vpnhide_dbg("sock_getsockopt_ret: spoofed IPV6_MTU_DISCOVER to IPV6_PMTUDISC_DO\n");
          }
        }
      }
    }
    return 0;
  }

  if (data->level == IPPROTO_TCP && data->optname == TCP_MAXSEG) {
    int mss = 0;
    int len = 0;
    if (get_user(len, data->optlen) == 0 && len >= sizeof(int)) {
      if (get_user(mss, (int __user *)data->optval) == 0) {
        int mtu = data->family == AF_INET6
                      ? (sip.ipv6_mtu ? sip.ipv6_mtu : 1500)
                      : (sip.ipv4_mtu ? sip.ipv4_mtu : 1500);
        int header_len = data->family == AF_INET6 ? 60 : 40;
        int cover_mss = mtu > header_len ? mtu - header_len : 1460;
        if (mss > 0 && mss != cover_mss) {
          if (put_user(cover_mss, (int __user *)data->optval) == 0) {
            vpnhide_dbg("sock_getsockopt_ret: spoofed TCP_MAXSEG from %d to %d\n",
                        mss, cover_mss);
          }
        }
      }
    }
    return 0;
  }

  if (data->level == IPPROTO_TCP && data->optname == TCP_INFO) {
    struct {
      u8 _pre[8];
      u32 rto;
      u32 ato;
      u32 snd_mss;
      u32 rcv_mss;
    } ti;
    int len = 0;
    bool changed = false;

    if (get_user(len, data->optlen) != 0 || len < (int)sizeof(ti))
      return 0;
    if (copy_from_user(&ti, data->optval, sizeof(ti)))
      return 0;

    {
      int mtu = data->family == AF_INET6
                    ? (sip.ipv6_mtu ? sip.ipv6_mtu : 1500)
                    : (sip.ipv4_mtu ? sip.ipv4_mtu : 1500);
      int header_len = data->family == AF_INET6 ? 60 : 40;
      u32 cover_mss = mtu > header_len ? mtu - header_len : 1460;

      if (ti.snd_mss > 0 && ti.snd_mss != cover_mss) {
        ti.snd_mss = cover_mss;
        changed = true;
      }
      if (ti.rcv_mss > 0 && ti.rcv_mss != cover_mss) {
        ti.rcv_mss = cover_mss;
        changed = true;
      }
    }
    if (changed) {
      if (copy_to_user(data->optval, &ti, sizeof(ti)) == 0)
        vpnhide_dbg("sock_getsockopt_ret: spoofed TCP_INFO snd_mss/rcv_mss\n");
    }
    return 0;
  }

  if (data->level != SOL_SOCKET)
    return 0;

  if (data->optname == SO_BINDTODEVICE) {
    int len;
    char name[IFNAMSIZ];

    if (get_user(len, data->optlen))
      return 0;

    if (len <= 0)
      return 0;

    if (len >= IFNAMSIZ)
      len = IFNAMSIZ - 1;

    if (copy_from_user(name, data->optval, len))
      return 0;
    name[len] = '\0';

    if (is_active_vpn_ifname(name)) {
      vpnhide_dbg("sock_getsockopt_ret: spoofing empty SO_BINDTODEVICE (was %s)\n",
                  name);

      if (put_user('\0', (char __user *)data->optval) == 0 &&
          put_user(0, data->optlen) == 0) {
        /* Success */
      }
    }
  } else if (data->optname == SO_BINDTOIFINDEX) {
    int ifindex;

    if (get_user(ifindex, (int __user *)data->optval))
      return 0;

    if (ifindex <= 0)
      return 0;

    if (is_active_vpn_ifindex(ifindex)) {
      vpnhide_dbg("sock_getsockopt_ret: spoofing SO_BINDTOIFINDEX %d to 0\n",
                  ifindex);
      if (put_user(0, (int __user *)data->optval)) {
        /* error */
      }
    }
  }

  return 0;
}

struct kretprobe sock_getsockopt_krp = {
    .entry_handler = sock_getsockopt_entry,
    .handler = sock_getsockopt_ret,
    .maxactive = VPNHIDE_KRETPROBE_MAXACTIVE,
    .data_size = sizeof(struct sock_getsockopt_data),
    .kp.symbol_name = "sock_getsockopt",
};

static int sys_getsockopt_entry(struct kretprobe_instance *ri,
                                struct pt_regs *regs) {
  struct sock_getsockopt_data *data;
  struct socket *sock;
  int fd, err;
  int level, optname;
  void __user *optval;
  int __user *optlen;

  if (!is_hook_active(HOOK_GETSOCKOPT, from_kuid(&init_user_ns, current_uid())))
    return 1;

  if (sys_getsockopt_uses_wrapper) {
    struct pt_regs *user_regs = (struct pt_regs *)regs->regs[0];
    if (!user_regs || (unsigned long)user_regs < 0xFFFF000000000000ULL)
      return 1;
    fd = (int)user_regs->regs[0];
    level = (int)user_regs->regs[1];
    optname = (int)user_regs->regs[2];
    optval = (void __user *)user_regs->regs[3];
    optlen = (int __user *)user_regs->regs[4];
  } else {
    fd = (int)regs->regs[0];
    level = (int)regs->regs[1];
    optname = (int)regs->regs[2];
    optval = (void __user *)regs->regs[3];
    optlen = (int __user *)regs->regs[4];
  }

  if (level != SOL_SOCKET && level != IPPROTO_IP && level != IPPROTO_IPV6 &&
      level != IPPROTO_TCP)
    return 1;

  if (level == SOL_SOCKET && optname != SO_BINDTODEVICE &&
      optname != SO_BINDTOIFINDEX)
    return 1;
  if (level == IPPROTO_IP && optname != IP_MTU && optname != IP_MTU_DISCOVER)
    return 1;
  if (level == IPPROTO_IPV6 && optname != IPV6_MTU &&
      optname != IPV6_MTU_DISCOVER)
    return 1;
  if (level == IPPROTO_TCP && optname != TCP_MAXSEG && optname != TCP_INFO)
    return 1;

  if (!is_target_uid())
    return 1;

  data = (void *)ri->data;
  data->level = level;
  data->optname = optname;
  data->optval = optval;
  data->optlen = optlen;
  data->net = current->nsproxy ? current->nsproxy->net_ns : &init_net;
  data->family = level == IPPROTO_IPV6 ? AF_INET6 : AF_INET;
  sock = sockfd_lookup(fd, &err);
  if (sock) {
    if (sock->sk)
      data->family = sock->sk->sk_family;
    sockfd_put(sock);
  }

  return 0;
}

struct kretprobe sys_getsockopt_krp = {
    .entry_handler = sys_getsockopt_entry,
    .handler = sock_getsockopt_ret,
    .data_size = sizeof(struct sock_getsockopt_data),
    .maxactive = VPNHIDE_KRETPROBE_MAXACTIVE,
    .kp.symbol_name = "__arm64_sys_getsockopt",
};

static int sk_getsockopt_entry(struct kretprobe_instance *ri,
                               struct pt_regs *regs) {
  struct sock_getsockopt_data *data;
  struct sock *sk = (struct sock *)regs->regs[0];
  bool is_kernel = (bool)(regs->regs[4] & 1);
  int level = (int)regs->regs[1];
  int optname = (int)regs->regs[2];

  if (!is_hook_active(HOOK_GETSOCKOPT, from_kuid(&init_user_ns, current_uid())))
    return 1;

  if (is_kernel)
    return 1;

  if (level != SOL_SOCKET && level != IPPROTO_IP && level != IPPROTO_IPV6 &&
      level != IPPROTO_TCP)
    return 1;

  if (level == SOL_SOCKET && optname != SO_BINDTODEVICE &&
      optname != SO_BINDTOIFINDEX)
    return 1;
  if (level == IPPROTO_IP && optname != IP_MTU && optname != IP_MTU_DISCOVER)
    return 1;
  if (level == IPPROTO_IPV6 && optname != IPV6_MTU &&
      optname != IPV6_MTU_DISCOVER)
    return 1;
  if (level == IPPROTO_TCP && optname != TCP_MAXSEG && optname != TCP_INFO)
    return 1;

  if (!is_target_uid())
    return 1;

  data = (void *)ri->data;
  data->level = level;
  data->optname = optname;
  data->optval = (void __user *)regs->regs[3];
  data->optlen = (int __user *)regs->regs[5];
  data->net = sk ? sock_net(sk)
                 : (current->nsproxy ? current->nsproxy->net_ns : &init_net);
  data->family = sk ? sk->sk_family : AF_UNSPEC;

  return 0;
}

struct kretprobe sk_getsockopt_krp = {
    .entry_handler = sk_getsockopt_entry,
    .handler = sock_getsockopt_ret,
    .maxactive = VPNHIDE_KRETPROBE_MAXACTIVE,
    .data_size = sizeof(struct sock_getsockopt_data),
    .kp.symbol_name = "sk_getsockopt",
};

struct kretprobe sock_common_getsockopt_krp = {
    .entry_handler = sk_getsockopt_entry,
    .handler = sock_getsockopt_ret,
    .maxactive = VPNHIDE_KRETPROBE_MAXACTIVE,
    .data_size = sizeof(struct sock_getsockopt_data),
    .kp.symbol_name = "sock_common_getsockopt",
};

/* --- recvmsg ancillary packet-info hooks --- */

struct vh_pktinfo_recv_data {
  struct msghdr *msg;
  void __user *control_start;
  size_t controllen_start;
  uid_t uid;
  enum vpnhide_hook_idx hook;
};

struct vh_compat_cmsghdr {
  u32 cmsg_len;
  s32 cmsg_level;
  s32 cmsg_type;
};

static bool vh_spoof_pktinfo4(struct in_pktinfo *info, uid_t uid,
                              enum vpnhide_hook_idx hook) {
  int cover_ifindex;

  if (!info || !is_active_vpn_ifindex(info->ipi_ifindex))
    return false;
  if (!is_hook_active(hook, uid) || !is_target_uid_val(uid))
    return false;
  cover_ifindex = atomic_read(&global_cover_ifindex);
  if (cover_ifindex <= 0)
    return false;
  info->ipi_ifindex = cover_ifindex;
  return true;
}

static bool vh_spoof_pktinfo6(struct in6_pktinfo *info, uid_t uid,
                              enum vpnhide_hook_idx hook) {
  struct vpnhide_spoof_ip sip;
  int cover_ifindex;

  if (!info || !is_active_vpn_ifindex(info->ipi6_ifindex))
    return false;
  if (!is_hook_active(hook, uid) || !is_target_uid_val(uid))
    return false;
  cover_ifindex = atomic_read(&global_cover_ifindex);
  if (cover_ifindex <= 0)
    return false;
  info->ipi6_ifindex = cover_ifindex;
  if (ipv6_addr_type(&info->ipi6_addr) & IPV6_ADDR_LINKLOCAL) {
    get_spoof_ip(&sip);
    if (sip.has_ipv6_linklocal)
      memcpy(&info->ipi6_addr, sip.ipv6_linklocal_addr,
             sizeof(info->ipi6_addr));
  } else if (!ipv6_addr_is_multicast(&info->ipi6_addr)) {
    get_spoof_ip(&sip);
    if (sip.has_ipv6)
      memcpy(&info->ipi6_addr, sip.ipv6_addr, sizeof(info->ipi6_addr));
  }
  return true;
}

static void vh_rewrite_pktinfo_cmsgs(struct vh_pktinfo_recv_data *data) {
  struct msghdr *msg = data->msg;
  char __user *cursor = data->control_start;
  size_t used, offset = 0;
  bool compat;

  if (!msg || !cursor || !msg->msg_control_is_user ||
      msg->msg_controllen > data->controllen_start)
    return;
  used = data->controllen_start - msg->msg_controllen;
  compat = !!(msg->msg_flags & MSG_CMSG_COMPAT);

  while (offset < used) {
    size_t cmsg_len, header_len, step;
    int level, type;

    if (compat) {
      struct vh_compat_cmsghdr header;

      header_len = sizeof(header);
      if (used - offset < header_len ||
          copy_from_user(&header, cursor + offset, sizeof(header)))
        break;
      cmsg_len = header.cmsg_len;
      level = header.cmsg_level;
      type = header.cmsg_type;
      step = ALIGN(cmsg_len, sizeof(s32));
    } else {
      struct cmsghdr header;

      header_len = sizeof(header);
      if (used - offset < header_len ||
          copy_from_user(&header, cursor + offset, sizeof(header)))
        break;
      cmsg_len = header.cmsg_len;
      level = header.cmsg_level;
      type = header.cmsg_type;
      step = CMSG_ALIGN(cmsg_len);
    }
    if (cmsg_len < header_len || cmsg_len > used - offset ||
        step < cmsg_len)
      break;

    if (level == SOL_IP && type == IP_PKTINFO &&
        cmsg_len - header_len >= sizeof(struct in_pktinfo)) {
      struct in_pktinfo info;
      void __user *payload = cursor + offset + header_len;

      if (!copy_from_user(&info, payload, sizeof(info)) &&
          vh_spoof_pktinfo4(&info, data->uid, data->hook) &&
          !copy_to_user(payload, &info, sizeof(info)))
        record_kmod_intercept(data->uid, 5);
    } else if (level == SOL_IPV6 && type == IPV6_PKTINFO &&
               cmsg_len - header_len >= sizeof(struct in6_pktinfo)) {
      struct in6_pktinfo info;
      void __user *payload = cursor + offset + header_len;

      if (!copy_from_user(&info, payload, sizeof(info)) &&
          vh_spoof_pktinfo6(&info, data->uid, data->hook) &&
          !copy_to_user(payload, &info, sizeof(info)))
        record_kmod_intercept(data->uid, 5);
    }

    if (!step || step > used - offset)
      break;
    offset += step;
  }
}

static int vh_pktinfo_recv_entry(struct kretprobe_instance *ri,
                                 struct msghdr *msg,
                                 enum vpnhide_hook_idx hook) {
  struct vh_pktinfo_recv_data *data;
  uid_t uid = from_kuid(&init_user_ns, current_uid());

  if (!msg || !msg->msg_control_is_user || !msg->msg_control_user ||
      !msg->msg_controllen || !is_hook_active(hook, uid) ||
      !is_target_uid_val(uid))
    return 1;
  data = (void *)ri->data;
  data->msg = msg;
  data->control_start = msg->msg_control_user;
  data->controllen_start = msg->msg_controllen;
  data->uid = uid;
  data->hook = hook;
  return 0;
}

static int ip_cmsg_recv_entry(struct kretprobe_instance *ri,
                              struct pt_regs *regs) {
  return vh_pktinfo_recv_entry(ri, (struct msghdr *)regs->regs[0],
                               HOOK_GETNAME_INET);
}

static int ip6_cmsg_recv_entry(struct kretprobe_instance *ri,
                               struct pt_regs *regs) {
  return vh_pktinfo_recv_entry(ri, (struct msghdr *)regs->regs[1],
                               HOOK_GETNAME_INET6);
}

static int vh_pktinfo_recv_ret(struct kretprobe_instance *ri,
                               struct pt_regs *regs) {
  vh_rewrite_pktinfo_cmsgs((void *)ri->data);
  return 0;
}

struct kretprobe ip_cmsg_recv_krp = {
    .entry_handler = ip_cmsg_recv_entry,
    .handler = vh_pktinfo_recv_ret,
    .maxactive = VPNHIDE_KRETPROBE_MAXACTIVE,
    .data_size = sizeof(struct vh_pktinfo_recv_data),
    .kp.symbol_name = "ip_cmsg_recv_offset",
};

struct kretprobe ip6_cmsg_recv_krp = {
    .entry_handler = ip6_cmsg_recv_entry,
    .handler = vh_pktinfo_recv_ret,
    .maxactive = VPNHIDE_KRETPROBE_MAXACTIVE,
    .data_size = sizeof(struct vh_pktinfo_recv_data),
    .kp.symbol_name = "ip6_datagram_recv_common_ctl",
};

struct kretprobe ip6_cmsg_recv_fallback_krp = {
    .entry_handler = ip6_cmsg_recv_entry,
    .handler = vh_pktinfo_recv_ret,
    .maxactive = VPNHIDE_KRETPROBE_MAXACTIVE,
    .data_size = sizeof(struct vh_pktinfo_recv_data),
    .kp.symbol_name = "ip6_datagram_recv_ctl",
};

/* --- Socket connect, bind, names and UDP hooks --- */

static struct socket *resolve_sock_addr(struct pt_regs *regs, bool uses_wrapper,
                                        struct sockaddr *uaddr_buf,
                                        int max_uaddr_sz,
                                        struct sockaddr **out_addr,
                                        bool *put_needed, int *out_fd) {
  int fd, err;
  struct socket *sock = NULL;
  *put_needed = false;
  *out_addr = NULL;

  if (uses_wrapper) {
    struct pt_regs *user_regs = (struct pt_regs *)regs->regs[0];
    if (user_regs && (unsigned long)user_regs >= 0xFFFF000000000000ULL) {
      int addrlen = (int)user_regs->regs[2];
      int copy_sz = min_t(int, addrlen, max_uaddr_sz);
      fd = (int)user_regs->regs[0];
      if (copy_sz > 0 &&
          copy_from_user(uaddr_buf, (void __user *)user_regs->regs[1],
                         copy_sz) == 0) {
        *out_addr = uaddr_buf;
      }
      sock = sockfd_lookup(fd, &err);
      if (sock)
        *put_needed = true;
      *out_fd = fd;
    }
  } else {
    sock = (struct socket *)regs->regs[0];
    *out_addr = (struct sockaddr *)regs->regs[1];
    *out_fd = -1;
  }
  return sock;
}

static bool should_block_port(const struct vpnhide_policy_snapshot *snapshot,
                              const struct vpnhide_port_target_v3 *urules,
                              unsigned short port, unsigned char proto) {
  u32 i;
  if (urules->mode == VH_PORT_POLICY_UNRESTRICTED)
    return false;
  if (urules->mode == VH_PORT_POLICY_DENY_ALL)
    return true;
  for (i = 0; i < urules->rule_count; i++) {
    const struct vpnhide_port_rule_v3 *r =
        &snapshot->port_rules[urules->first_rule + i];
    if (port >= r->start_port && port <= r->end_port) {
      if (r->protocol == VH_PROTO_BOTH || r->protocol == proto) {
        return true;
      }
    }
  }
  return false;
}

struct socket_connect_data {
  bool should_block;
  bool intercepted;
};

static int socket_connect_entry(struct kretprobe_instance *ri,
                                struct pt_regs *regs) {
  struct socket_connect_data *data;
  struct socket *sock = NULL;
  struct sockaddr *addr = NULL;
  struct sockaddr_storage uaddr_buf;
  uid_t uid = from_kuid(&init_user_ns, current_uid());
  struct vpnhide_policy_snapshot *snapshot;
  const struct vpnhide_port_target_v3 *urules = NULL;
  int fd = -1;
  bool put_needed = false;

  if (!is_hook_active(HOOK_CONNECT, from_kuid(&init_user_ns, current_uid())))
    return 1;

  data = (void *)ri->data;
  data->should_block = false;
  data->intercepted = false;

  sock = resolve_sock_addr(regs, sys_connect_uses_wrapper,
                           (struct sockaddr *)&uaddr_buf, sizeof(uaddr_buf),
                           &addr, &put_needed, &fd);

  if (sys_connect_uses_wrapper && !sock)
    return 0;

  rcu_read_lock();
  snapshot = rcu_dereference(global_policy_snapshot);
  if (!snapshot) {
    rcu_read_unlock();
    if (put_needed)
      sockfd_put(sock);
    return 1;
  }
  urules = vpnhide_find_port_target(snapshot, uid);

  if (!urules || !addr || !sock || !sock->sk) {
    rcu_read_unlock();
    if (put_needed)
      sockfd_put(sock);
    return 1;
  }

  if (addr->sa_family == AF_INET) {
    struct sockaddr_in *sin = (struct sockaddr_in *)addr;
    if (ipv4_is_loopback(sin->sin_addr.s_addr) ||
        sin->sin_addr.s_addr == htonl(INADDR_ANY)) {
      unsigned short port = ntohs(sin->sin_port);
      unsigned char proto =
          (sock->sk->sk_type == SOCK_STREAM) ? VH_PROTO_TCP : VH_PROTO_UDP;

      if (should_block_port(snapshot, urules, port, proto) &&
          !vpnhide_uid_owns_port(uid, port, proto)) {
        data->should_block = true;
        if (sys_connect_uses_wrapper) {
          struct pt_regs *user_regs = (struct pt_regs *)regs->regs[0];
          if (user_regs) {
            user_regs->regs[1] = 0;
            data->intercepted = true;
          }
        }
        vpnhide_dbg("socket_connect: blocking IPv4 port %u (%s) for uid=%u\n",
                    port, (proto == VH_PROTO_TCP) ? "TCP" : "UDP", uid);
      }
    }
  } else if (addr->sa_family == AF_INET6) {
    struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)addr;
    bool is_loopback = false;

    if (ipv6_addr_loopback(&sin6->sin6_addr) ||
        ipv6_addr_any(&sin6->sin6_addr)) {
      is_loopback = true;
    } else if (ipv6_addr_v4mapped(&sin6->sin6_addr)) {
      __be32 v4addr = sin6->sin6_addr.s6_addr32[3];
      if (ipv4_is_loopback(v4addr) || v4addr == htonl(INADDR_ANY)) {
        is_loopback = true;
      }
    }

    if (is_loopback) {
      unsigned short port = ntohs(sin6->sin6_port);
      unsigned char proto =
          (sock->sk->sk_type == SOCK_STREAM) ? VH_PROTO_TCP : VH_PROTO_UDP;

      if (should_block_port(snapshot, urules, port, proto) &&
          !vpnhide_uid_owns_port(uid, port, proto)) {
        data->should_block = true;
        if (sys_connect_uses_wrapper) {
          struct pt_regs *user_regs = (struct pt_regs *)regs->regs[0];
          if (user_regs) {
            user_regs->regs[1] = 0;
            data->intercepted = true;
          }
        }
        vpnhide_dbg("socket_connect: blocking IPv6 port %u (%s) for uid=%u\n",
                    port, (proto == VH_PROTO_TCP) ? "TCP" : "UDP", uid);
      }
    }
  }
  rcu_read_unlock();

  if (put_needed)
    sockfd_put(sock);

  if (!data->should_block)
    return 1;

  return 0;
}

static int socket_connect_ret(struct kretprobe_instance *ri,
                              struct pt_regs *regs) {
  struct socket_connect_data *data = (void *)ri->data;
  int retval = regs_return_value(regs);

  if (data->should_block) {
    record_kmod_intercept(from_kuid(&init_user_ns, current_uid()), 6);
    if (sys_connect_uses_wrapper) {
      if (data->intercepted && retval == -EFAULT) {
        regs_set_return_value(regs, -ECONNREFUSED);
      }
    } else {
      regs_set_return_value(regs, -ECONNREFUSED);
    }
  }

  return 0;
}

struct kretprobe socket_connect_krp = {
    .handler = socket_connect_ret,
    .entry_handler = socket_connect_entry,
    .data_size = sizeof(struct socket_connect_data),
    .maxactive = VPNHIDE_KRETPROBE_MAXACTIVE,
    .kp.symbol_name = "__arm64_sys_connect",
};

struct socket_bind_data {
  struct socket *sock;
  uid_t uid;
  bool put_needed;
};

static int socket_bind_entry(struct kretprobe_instance *ri,
                             struct pt_regs *regs) {
  struct socket_bind_data *data = (void *)ri->data;
  struct socket *sock = NULL;
  struct sockaddr *addr = NULL;
  struct sockaddr_storage uaddr_buf;
  uid_t uid = from_kuid(&init_user_ns, current_uid());
  int fd = -1;
  bool put_needed = false;

  memset(data, 0, sizeof(*data));

  sock = resolve_sock_addr(regs, sys_bind_uses_wrapper,
                           (struct sockaddr *)&uaddr_buf, sizeof(uaddr_buf),
                           &addr, &put_needed, &fd);
  if (!sock)
    return 1;

  /* A bind establishes ownership; it must never be rewritten by access
   * policy.  Record the actual port after success so subsequent localhost
   * connects by the same UID bypass the port deny rules. */
  data->sock = sock;
  data->uid = uid;
  data->put_needed = put_needed;
  return 0;
}

static int socket_bind_ret(struct kretprobe_instance *ri,
                           struct pt_regs *regs) {
  struct socket_bind_data *data = (void *)ri->data;

  if (data->sock) {
    struct sock *sk = data->sock->sk;

    if (regs_return_value(regs) == 0 && sk &&
        (sk->sk_family == AF_INET || sk->sk_family == AF_INET6) &&
        (sk->sk_type == SOCK_STREAM || sk->sk_type == SOCK_DGRAM)) {
      u16 port = inet_sk(sk)->inet_num;
      u8 protocol = sk->sk_type == SOCK_STREAM ? VH_PROTO_TCP : VH_PROTO_UDP;

      vpnhide_record_bound_port(data->uid, port, protocol);
    }
    if (data->put_needed)
      sockfd_put(data->sock);
  }
  return 0;
}

struct kretprobe socket_bind_krp = {
    .handler = socket_bind_ret,
    .entry_handler = socket_bind_entry,
    .data_size = sizeof(struct socket_bind_data),
    .maxactive = VPNHIDE_KRETPROBE_MAXACTIVE,
    .kp.symbol_name = "__arm64_sys_bind",
};

struct inet_bind_owner_data {
  struct socket *sock;
  uid_t uid;
};

static int inet_bind_owner_entry(struct kretprobe_instance *ri,
                                 struct pt_regs *regs) {
  struct inet_bind_owner_data *data = (void *)ri->data;
  struct socket *sock = (struct socket *)regs->regs[0];

  memset(data, 0, sizeof(*data));
  if (!sock || !sock->sk || sock->sk->sk_family != AF_INET ||
      (sock->sk->sk_type != SOCK_STREAM && sock->sk->sk_type != SOCK_DGRAM))
    return 1;
  data->sock = sock;
  data->uid = from_kuid(&init_user_ns, current_uid());
  return 0;
}

static int inet_bind_owner_ret(struct kretprobe_instance *ri,
                               struct pt_regs *regs) {
  struct inet_bind_owner_data *data = (void *)ri->data;
  struct sock *sk = data->sock ? data->sock->sk : NULL;

  if (regs_return_value(regs) == 0 && sk) {
    u8 protocol = sk->sk_type == SOCK_STREAM ? VH_PROTO_TCP : VH_PROTO_UDP;

    vpnhide_record_bound_port(data->uid, inet_sk(sk)->inet_num, protocol);
  }
  return 0;
}

struct kretprobe inet_bind_owner_krp = {
    .handler = inet_bind_owner_ret,
    .entry_handler = inet_bind_owner_entry,
    .data_size = sizeof(struct inet_bind_owner_data),
    .maxactive = VPNHIDE_KRETPROBE_MAXACTIVE,
    .kp.symbol_name = "inet_bind",
};

struct inet_listen_owner_data {
  struct socket *sock;
  uid_t uid;
};

static int inet_listen_owner_entry(struct kretprobe_instance *ri,
                                   struct pt_regs *regs) {
  struct inet_listen_owner_data *data = (void *)ri->data;
  struct socket *sock = (struct socket *)regs->regs[0];

  memset(data, 0, sizeof(*data));
  if (!sock || !sock->sk ||
      (sock->sk->sk_family != AF_INET && sock->sk->sk_family != AF_INET6) ||
      sock->sk->sk_type != SOCK_STREAM)
    return 1;
  data->sock = sock;
  data->uid = from_kuid(&init_user_ns, current_uid());
  return 0;
}

static int inet_listen_owner_ret(struct kretprobe_instance *ri,
                                 struct pt_regs *regs) {
  struct inet_listen_owner_data *data = (void *)ri->data;
  struct sock *sk = data->sock ? data->sock->sk : NULL;

  if (regs_return_value(regs) == 0 && sk)
    vpnhide_record_bound_port(data->uid, inet_sk(sk)->inet_num, VH_PROTO_TCP);
  return 0;
}

struct kretprobe inet_listen_owner_krp = {
    .handler = inet_listen_owner_ret,
    .entry_handler = inet_listen_owner_entry,
    .data_size = sizeof(struct inet_listen_owner_data),
    .maxactive = VPNHIDE_KRETPROBE_MAXACTIVE,
    .kp.symbol_name = "inet_listen",
};

struct inet6_bind_ll_data {
  bool should_deny;
  struct socket *sock;
  uid_t uid;
};

static int inet6_bind_ll_entry(struct kretprobe_instance *ri,
                               struct pt_regs *regs) {
  struct inet6_bind_ll_data *data;
  struct sockaddr_in6 sin6;
  struct socket *sock = (struct socket *)regs->regs[0];

  data = (void *)ri->data;
  memset(data, 0, sizeof(*data));
  if (sock && sock->sk && sock->sk->sk_family == AF_INET6 &&
      (sock->sk->sk_type == SOCK_STREAM || sock->sk->sk_type == SOCK_DGRAM)) {
    data->sock = sock;
    data->uid = from_kuid(&init_user_ns, current_uid());
  }

  if (!is_hook_active(HOOK_INET6_BIND_LL, data->uid) || !is_target_uid())
    return data->sock ? 0 : 1;

  if (copy_from_kernel_nofault(&sin6, (const void *)regs->regs[1],
                               sizeof(sin6)) != 0)
    return data->sock ? 0 : 1;

  if (sin6.sin6_family != AF_INET6)
    return data->sock ? 0 : 1;

  if (sin6.sin6_addr.s6_addr[0] != 0xfe ||
      (sin6.sin6_addr.s6_addr[1] & 0xc0) != 0x80)
    return data->sock ? 0 : 1;

  if (sin6.sin6_scope_id == 0 || !is_active_vpn_ifindex(sin6.sin6_scope_id))
    return data->sock ? 0 : 1;

  data->should_deny = true;

  vpnhide_dbg("inet6_bind_ll: suppressing link-local scope_id=%u uid=%u\n",
              sin6.sin6_scope_id, from_kuid(&init_user_ns, current_uid()));
  return 0;
}

static int inet6_bind_ll_ret(struct kretprobe_instance *ri,
                             struct pt_regs *regs) {
  struct inet6_bind_ll_data *data = (void *)ri->data;
  struct sock *sk = data->sock ? data->sock->sk : NULL;

  if (!data->should_deny) {
    if (regs_return_value(regs) == 0 && sk) {
      u8 protocol = sk->sk_type == SOCK_STREAM ? VH_PROTO_TCP : VH_PROTO_UDP;

      vpnhide_record_bound_port(data->uid, inet_sk(sk)->inet_num, protocol);
    }
    return 0;
  }

  record_kmod_intercept(from_kuid(&init_user_ns, current_uid()), 4);
  regs_set_return_value(regs, -ENODEV);
  return 0;
}

struct kretprobe inet6_bind_ll_krp = {
    .handler = inet6_bind_ll_ret,
    .entry_handler = inet6_bind_ll_entry,
    .data_size = sizeof(struct inet6_bind_ll_data),
    .maxactive = VPNHIDE_KRETPROBE_MAXACTIVE,
    .kp.symbol_name = "inet6_bind",
};

struct udpv6_sendmsg_ll_data {
  bool should_deny;
  struct sock *sk;
  int orig_sndbuf;
  bool rl_spoofed;
};

static int udpv6_sendmsg_ll_entry(struct kretprobe_instance *ri,
                                  struct pt_regs *regs) {
  struct udpv6_sendmsg_ll_data *data;
  struct sock *sk;
  struct msghdr *msg;
  struct sockaddr_in6 sin6;
  bool have_sin6 = false;
  uid_t uid;

  if (!is_hook_active(HOOK_UDPV6_SENDMSG,
                      from_kuid(&init_user_ns, current_uid())))
    return 1;

  if (!is_target_uid())
    return 1;

  sk = (struct sock *)regs->regs[0];
  msg = (struct msghdr *)regs->regs[1];
  if (!sk || !msg)
    return 1;

  data = (void *)ri->data;
  data->should_deny = false;
  data->sk = sk;
  data->orig_sndbuf = sk->sk_sndbuf;
  data->rl_spoofed = false;

  if (msg->msg_name && msg->msg_namelen >= (int)sizeof(sin6) &&
      copy_from_kernel_nofault(&sin6, msg->msg_name, sizeof(sin6)) == 0 &&
      sin6.sin6_family == AF_INET6)
    have_sin6 = true;

  if (have_sin6 && sin6.sin6_addr.s6_addr[0] == 0xfe &&
      (sin6.sin6_addr.s6_addr[1] & 0xc0) == 0x80 &&
      sin6.sin6_scope_id != 0 &&
      is_active_vpn_ifindex(sin6.sin6_scope_id)) {
    data->should_deny = true;
    vpnhide_dbg("udpv6_sendmsg_ll: blocking ll sendto scope_id=%u uid=%u\n",
                sin6.sin6_scope_id, from_kuid(&init_user_ns, current_uid()));
    return 0;
  }

  /* Not a link-local VPN send — fall through to the same
   * destination-scoped backpressure emulation used by v4 UDP
   * (idx25/HOOK_UDP_SENDMSG), so v6 gets parity instead of never
   * being rate-limited at all. */
  uid = from_kuid(&init_user_ns, current_uid());
  if ((msg->msg_flags & MSG_DONTWAIT) &&
      vpnhide_udp_dst_is_vpn_bound(sk, msg)) {
    if (udp_rate_limit_exceeded(uid)) {
      sk->sk_sndbuf = 0;
      data->rl_spoofed = true;
      udelay(50);
    }
  }

  return 0;
}

static int udpv6_sendmsg_ll_ret(struct kretprobe_instance *ri,
                                struct pt_regs *regs) {
  struct udpv6_sendmsg_ll_data *data = (void *)ri->data;

  if (data->rl_spoofed && data->sk)
    data->sk->sk_sndbuf = data->orig_sndbuf;

  if (!data->should_deny)
    return 0;

  record_kmod_intercept(from_kuid(&init_user_ns, current_uid()), 4);
  regs_set_return_value(regs, -ENOBUFS);
  return 0;
}

struct kretprobe udpv6_sendmsg_ll_krp = {
    .handler = udpv6_sendmsg_ll_ret,
    .entry_handler = udpv6_sendmsg_ll_entry,
    .data_size = sizeof(struct udpv6_sendmsg_ll_data),
    .maxactive = VPNHIDE_KRETPROBE_MAXACTIVE,
    .kp.symbol_name = "udpv6_sendmsg",
};

struct sys_getsockname_data {
  void __user *uaddr;
  int ulen;
};

static int sys_getsockname_entry(struct kretprobe_instance *ri,
                                 struct pt_regs *regs) {
  struct sys_getsockname_data *data;
  struct pt_regs *user_regs;
  int ulen;

  if (!is_hook_active(HOOK_GETNAME_INET,
                      from_kuid(&init_user_ns, current_uid())) &&
      !is_hook_active(HOOK_GETNAME_INET6,
                      from_kuid(&init_user_ns, current_uid())))
    return 1;

  if (!is_target_uid())
    return 1;

  user_regs = (struct pt_regs *)regs->regs[0];
  if (!user_regs || (unsigned long)user_regs < 0xFFFF000000000000ULL)
    return 1;

  data = (void *)ri->data;
  data->uaddr = (void __user *)user_regs->regs[1];

  if (get_user(ulen, (int __user *)user_regs->regs[2]) == 0) {
    data->ulen = ulen;
  } else {
    data->ulen = 0;
  }
  return 0;
}

static void spoof_getsockname_ipv4(void __user *uaddr,
                                   struct vpnhide_spoof_ip *sip) {
  __be32 addr;
  __be32 target_ip;

  if (get_user(addr, &((struct sockaddr_in __user *)uaddr)->sin_addr.s_addr) !=
      0)
    return;

  if (addr == 0 || (ntohl(addr) & 0xFF000000) == 0x7F000000)
    return;

  target_ip = sip->has_ipv4 ? sip->ipv4_addr : htonl(0xC0000004);
  if (put_user(target_ip,
               &((struct sockaddr_in __user *)uaddr)->sin_addr.s_addr) == 0) {
    record_kmod_intercept(from_kuid(&init_user_ns, current_uid()), 5);
    vpnhide_dbg("sys_getsockname_ret: spoofed IPv4 from %pI4 to %pI4\n", &addr,
                &target_ip);
  }
}

static void spoof_getsockname_ipv6(void __user *uaddr,
                                   struct vpnhide_spoof_ip *sip) {
  struct in6_addr addr6;
  struct in6_addr old_addr;
  struct in6_addr target_ip6;

  if (copy_from_user(&addr6, &((struct sockaddr_in6 __user *)uaddr)->sin6_addr,
                     sizeof(struct in6_addr)) != 0)
    return;

  if (ipv6_addr_any(&addr6) || ipv6_addr_loopback(&addr6))
    return;

  old_addr = addr6;

  if (sip->has_ipv6) {
    memcpy(&target_ip6, sip->ipv6_addr, 16);
  } else {
    memset(&target_ip6, 0, 16);
    target_ip6.s6_addr[0] = 0x20;
    target_ip6.s6_addr[1] = 0x01;
    target_ip6.s6_addr[2] = 0x0d;
    target_ip6.s6_addr[3] = 0xb8;
    target_ip6.s6_addr[15] = 0x10;
  }

  if (copy_to_user(&((struct sockaddr_in6 __user *)uaddr)->sin6_addr,
                   &target_ip6, sizeof(struct in6_addr)) == 0) {
    record_kmod_intercept(from_kuid(&init_user_ns, current_uid()), 5);
    vpnhide_dbg("sys_getsockname_ret: spoofed IPv6 from %pI6c to %pI6c\n",
                &old_addr, &target_ip6);
  }
}

static int sys_getsockname_ret(struct kretprobe_instance *ri,
                               struct pt_regs *regs) {
  struct sys_getsockname_data *data = (void *)ri->data;
  int retval = regs_return_value(regs);
  unsigned short sa_family;
  struct vpnhide_spoof_ip sip;

  if (retval != 0 || !data->uaddr)
    return 0;

  if (get_user(sa_family, (unsigned short __user *)data->uaddr) != 0)
    return 0;

  get_spoof_ip(&sip);

  if (sa_family == AF_INET) {
    if (data->ulen >= (int)sizeof(struct sockaddr_in)) {
      spoof_getsockname_ipv4(data->uaddr, &sip);
    }
  } else if (sa_family == AF_INET6) {
    if (data->ulen >= (int)sizeof(struct sockaddr_in6)) {
      spoof_getsockname_ipv6(data->uaddr, &sip);
    }
  }

  return 0;
}

struct kretprobe sys_getsockname_krp = {
    .handler = sys_getsockname_ret,
    .entry_handler = sys_getsockname_entry,
    .data_size = sizeof(struct sys_getsockname_data),
    .maxactive = VPNHIDE_KRETPROBE_MAXACTIVE,
    .kp.symbol_name = "__arm64_sys_getsockname",
};

struct getname_data {
  struct sockaddr *uaddr;
  int peer;
};

static int inet_getname_entry(struct kretprobe_instance *ri,
                              struct pt_regs *regs) {
  struct getname_data *data;
  int peer = (int)regs->regs[2];

  if (!is_hook_active(HOOK_GETNAME_INET,
                      from_kuid(&init_user_ns, current_uid())))
    return 1;

  if (peer != 0 || !is_target_uid())
    return 1;

  data = (void *)ri->data;
  data->uaddr = (struct sockaddr *)regs->regs[1];
  data->peer = peer;
  return 0;
}

static int inet_getname_ret(struct kretprobe_instance *ri,
                            struct pt_regs *regs) {
  struct getname_data *data = (void *)ri->data;
  int retval = regs_return_value(regs);

  if (retval >= 0 && data->uaddr) {
    struct sockaddr_in *sin = (struct sockaddr_in *)data->uaddr;
    struct vpnhide_spoof_ip sip;
    get_spoof_ip(&sip);

    if (sin->sin_family == AF_INET) {
      __be32 addr = sin->sin_addr.s_addr;
      if (addr != 0 && (ntohl(addr) & 0xFF000000) != 0x7F000000) {
        __be32 target_ip =
            sip.has_ipv4 ? sip.ipv4_addr
                         : htonl(0xC0000004);
        sin->sin_addr.s_addr = target_ip;
        record_kmod_intercept(from_kuid(&init_user_ns, current_uid()), 4);
        vpnhide_dbg("inet_getname_ret: spoofed IPv4 from %pI4 to %pI4\n", &addr,
                    &target_ip);
      }
    }
  }
  return 0;
}

struct kretprobe inet_getname_krp = {
    .handler = inet_getname_ret,
    .entry_handler = inet_getname_entry,
    .data_size = sizeof(struct getname_data),
    .maxactive = VPNHIDE_KRETPROBE_MAXACTIVE,
    .kp.symbol_name = "inet_getname",
};

static int inet6_getname_entry(struct kretprobe_instance *ri,
                               struct pt_regs *regs) {
  struct getname_data *data;
  int peer = (int)regs->regs[2];

  if (!is_hook_active(HOOK_GETNAME_INET6,
                      from_kuid(&init_user_ns, current_uid())))
    return 1;

  if (peer != 0 || !is_target_uid())
    return 1;

  data = (void *)ri->data;
  data->uaddr = (struct sockaddr *)regs->regs[1];
  data->peer = peer;
  return 0;
}

static int inet6_getname_ret(struct kretprobe_instance *ri,
                             struct pt_regs *regs) {
  struct getname_data *data = (void *)ri->data;
  int retval = regs_return_value(regs);

  if (retval >= 0 && data->uaddr) {
    struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)data->uaddr;
    struct vpnhide_spoof_ip sip;
    get_spoof_ip(&sip);

    if (sin6->sin6_family == AF_INET6) {
      if (!ipv6_addr_any(&sin6->sin6_addr) &&
          !ipv6_addr_loopback(&sin6->sin6_addr)) {
        struct in6_addr old_addr = sin6->sin6_addr;
        struct in6_addr target_ip6;

        if (sip.has_ipv6) {
          memcpy(&target_ip6, sip.ipv6_addr, 16);
        } else {
          memset(&target_ip6, 0, 16);
          target_ip6.s6_addr[0] = 0x20;
          target_ip6.s6_addr[1] = 0x01;
          target_ip6.s6_addr[2] = 0x0d;
          target_ip6.s6_addr[3] = 0xb8;
          target_ip6.s6_addr[15] = 0x10;
        }

        memcpy(&sin6->sin6_addr, &target_ip6, 16);
        record_kmod_intercept(from_kuid(&init_user_ns, current_uid()), 5);
        vpnhide_dbg("inet6_getname_ret: spoofed IPv6 from %pI6c to %pI6c\n",
                    &old_addr, &target_ip6);
      }
    }
  }
  return 0;
}

struct kretprobe inet6_getname_krp = {
    .handler = inet6_getname_ret,
    .entry_handler = inet6_getname_entry,
    .data_size = sizeof(struct getname_data),
    .maxactive = VPNHIDE_KRETPROBE_MAXACTIVE,
    .kp.symbol_name = "inet6_getname",
};
