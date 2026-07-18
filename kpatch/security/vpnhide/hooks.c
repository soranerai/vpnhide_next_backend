#include "vpnhide.h"
#include <linux/netlink.h>
#include <linux/inetdevice.h>
#include <net/ip.h>
#include <net/ipv6.h>
#include <net/tcp.h>
#include <net/udp.h>
#include <linux/syscalls.h>
#include <linux/namei.h>
#include <linux/mount.h>
#include <linux/dirent.h>

static const char *const vh_guarded_dir_prefixes[] = {
    "/proc/sys/net/ipv4/conf",  "/proc/sys/net/ipv6/conf",
    "/proc/sys/net/ipv4/neigh", "/proc/sys/net/ipv6/neigh",
    "/proc/net/dev_snmp6",      "/sys/class/net",
};

struct vh_linux_dirent64 {
  u64 d_ino;
  s64 d_off;
  unsigned short d_reclen;
  unsigned char d_type;
  char d_name[];
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

static bool should_block_port(const struct vpnhide_uid_port_rules *urules,
                              unsigned short port, unsigned char proto) {
  int i;
  for (i = 0; i < urules->rule_count; i++) {
    const struct vpnhide_port_rule *r = &urules->rules[i];
    if (port >= r->start_port && port <= r->end_port) {
      if (r->protocol == VH_PROTO_BOTH || r->protocol == proto) {
        return true;
      }
    }
  }
  return false;
}

#define BUCKET_CAPACITY 250
#define TOKEN_REGEN_NS 2000000ULL

struct udp_uid_rate {
  uid_t uid;
  u64 last_time_ns;
  u32 tokens;
};

static struct udp_uid_rate udp_rates[MAX_TARGET_UIDS];
static DEFINE_SPINLOCK(udp_rates_lock);

static bool udp_rate_limit_exceeded(uid_t uid) {
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

/* ------------------------------------------------------------- */
/* Sockets Hook Implementations                                  */
/* ------------------------------------------------------------- */

bool vpnhide_should_hide_dev(const struct net_device *dev) {
  if (!dev)
    return false;

  if (!is_hook_active(HOOK_RTNL_FILL, from_kuid(&init_user_ns, current_uid())))
    return false;

  if (!is_target_uid())
    return false;

  return is_active_vpn_ifname(dev->name);
}

int vpnhide_setsockopt(int fd, int level, int optname, char __user *optval, int optlen, int *retval) {
  uid_t uid = from_kuid(&init_user_ns, current_uid());
  char name[IFNAMSIZ];

  if (!is_hook_active(HOOK_SETSOCKOPT, uid))
    return 0;

  if (level == 0x5648 && optname == 0x88) {
    if (uid == 1000 || uid == 0) {
      struct vpnhide_spoof_ip sip;
      if (optlen == sizeof(sip)) {
        if (copy_from_user(&sip, optval, sizeof(sip)) == 0) {
          if (update_spoof_ip(&sip) == 0) {
            vpnhide_dbg("sys_setsockopt: updated spoof IP via setsockopt\n");
            *retval = 0;
            return 1; /* handled */
          }
        }
      }
    }
    return 0;
  }

  if (!is_target_uid_val(uid))
    return 0;

  if (level == SOL_SOCKET) {
    if (optname == SO_BINDTODEVICE) {
      if (optlen <= 0)
        return 0;
      if (optlen >= IFNAMSIZ)
        optlen = IFNAMSIZ - 1;

      if (copy_from_user(name, optval, optlen))
        return 0;
      name[optlen] = '\0';

      if (is_active_vpn_ifname(name)) {
        vpnhide_dbg("sys_setsockopt: denying SO_BINDTODEVICE to VPN iface '%s' with ENODEV\n",
                    name);
        record_kmod_intercept(uid, 3);
        *retval = -ENODEV;
        return 1; /* handled */
      }
    } else if (optname == SO_BINDTOIFINDEX) {
      int ifindex;

      if (optlen != sizeof(int))
        return 0;
      if (get_user(ifindex, (int __user *)optval))
        return 0;

      if (ifindex <= 0)
        return 0;

      if (is_active_vpn_ifindex(ifindex)) {
        vpnhide_dbg("sys_setsockopt: denying SO_BINDTOIFINDEX %d with ENODEV\n",
                    ifindex);
        record_kmod_intercept(uid, 3);
        *retval = -ENODEV;
        return 1; /* handled */
      }
    } else if (optname == SO_MARK) {
      int mark;
      if (optlen != sizeof(int))
        return 0;
      if (get_user(mark, (int __user *)optval))
        return 0;

      if (mark != 0) {
        vpnhide_dbg("sys_setsockopt: target app tried to set SO_MARK to 0x%x, overriding to 0\n",
                    mark);
        if (put_user(0, (int __user *)optval) == 0) {
          record_kmod_intercept(uid, 3);
        }
      }
    } else if (optname == SO_TIMESTAMPING) {
      int flags;
      if (optlen == sizeof(int) &&
          get_user(flags, (int __user *)optval) == 0) {
        int stripped = flags & ~(SOF_TIMESTAMPING_TX_HARDWARE |
                                 SOF_TIMESTAMPING_RX_HARDWARE |
                                 SOF_TIMESTAMPING_RAW_HARDWARE);
        if (stripped != flags &&
            put_user(stripped, (int __user *)optval) == 0) {
          vpnhide_dbg("sys_setsockopt: stripped SO_TIMESTAMPING hw bits 0x%x→0x%x\n",
                      flags, stripped);
          record_kmod_intercept(uid, 3);
        }
      }
    }
  } else if (level == IPPROTO_IP) {
    if (optname == IP_MTU_DISCOVER) {
      int discover;
      if (optlen == sizeof(int)) {
        if (get_user(discover, (int __user *)optval) == 0) {
          if (discover != IP_PMTUDISC_DONT) {
            if (put_user(IP_PMTUDISC_DONT, (int __user *)optval) == 0) {
              vpnhide_dbg("sys_setsockopt: spoofed IP_MTU_DISCOVER from %d to IP_PMTUDISC_DONT\n",
                          discover);
              record_kmod_intercept(uid, 3);
            }
          }
        }
      }
    }
  } else if (level == IPPROTO_IPV6) {
    if (optname == IPV6_MTU_DISCOVER) {
      int discover;
      if (optlen == sizeof(int)) {
        if (get_user(discover, (int __user *)optval) == 0) {
          if (discover != IPV6_PMTUDISC_DONT) {
            if (put_user(IPV6_PMTUDISC_DONT, (int __user *)optval) == 0) {
              vpnhide_dbg("sys_setsockopt: spoofed IPV6_MTU_DISCOVER from %d to IPV6_PMTUDISC_DONT\n",
                          discover);
              record_kmod_intercept(uid, 3);
            }
          }
        }
      }
    }
  } else if (level == IPPROTO_UDP) {
    if (optname == 103 /* UDP_SEGMENT */ && optlen == sizeof(int)) {
      int zero = 0;
      if (put_user(zero, (int __user *)optval) == 0) {
        vpnhide_dbg("sys_setsockopt: zeroed UDP_SEGMENT to block GSO probe uid=%u\n", uid);
        record_kmod_intercept(uid, 3);
      }
    }
  }

  return 0;
}

int vpnhide_getsockopt(struct socket *sock, int level, int optname, char __user *optval, int __user *optlen, int *retval) {
  uid_t uid = from_kuid(&init_user_ns, current_uid());
  struct vpnhide_spoof_ip sip;
  int len;

  if (*retval != 0)
    return 0;

  if (!is_hook_active(HOOK_GETSOCKOPT, uid))
    return 0;

  if (level != SOL_SOCKET && level != IPPROTO_IP && level != IPPROTO_IPV6 &&
      level != IPPROTO_TCP)
    return 0;

  if (level == SOL_SOCKET && optname != SO_BINDTODEVICE &&
      optname != SO_BINDTOIFINDEX)
    return 0;
  if (level == IPPROTO_IP && optname != IP_MTU && optname != IP_MTU_DISCOVER)
    return 0;
  if (level == IPPROTO_IPV6 && optname != IPV6_MTU &&
      optname != IPV6_MTU_DISCOVER)
    return 0;
  if (level == IPPROTO_TCP && optname != TCP_MAXSEG && optname != TCP_INFO)
    return 0;

  if (!is_target_uid_val(uid))
    return 0;

  record_kmod_intercept(uid, 3);
  get_spoof_ip(&sip);

  if (level == IPPROTO_IP && optname == IP_MTU) {
    int mtu = 0;
    if (get_user(len, optlen) == 0 && len >= sizeof(int)) {
      if (get_user(mtu, (int __user *)optval) == 0) {
        if (mtu > 0 && mtu < 1500) {
          if (put_user(1500, (int __user *)optval) == 0) {
            vpnhide_dbg("getsockopt: spoofed IP_MTU from %d to 1500\n", mtu);
          }
        }
      }
    }
    return 0;
  }

  if (level == IPPROTO_IPV6 && optname == IPV6_MTU) {
    int mtu = 0;
    if (get_user(len, optlen) == 0 && len >= sizeof(int)) {
      if (get_user(mtu, (int __user *)optval) == 0) {
        if (mtu > 0 && mtu < 1500) {
          if (put_user(1500, (int __user *)optval) == 0) {
            vpnhide_dbg("getsockopt: spoofed IPV6_MTU from %d to 1500\n", mtu);
          }
        }
      }
    }
    return 0;
  }

  if (level == IPPROTO_IP && optname == IP_MTU_DISCOVER) {
    int discover = 0;
    if (get_user(len, optlen) == 0 && len >= sizeof(int)) {
      if (get_user(discover, (int __user *)optval) == 0) {
        if (discover == IP_PMTUDISC_DONT) {
          if (put_user(IP_PMTUDISC_DO, (int __user *)optval) == 0) {
            vpnhide_dbg("getsockopt: spoofed IP_MTU_DISCOVER to IP_PMTUDISC_DO\n");
          }
        }
      }
    }
    return 0;
  }

  if (level == IPPROTO_IPV6 && optname == IPV6_MTU_DISCOVER) {
    int discover = 0;
    if (get_user(len, optlen) == 0 && len >= sizeof(int)) {
      if (get_user(discover, (int __user *)optval) == 0) {
        if (discover == IPV6_PMTUDISC_DONT) {
          if (put_user(IPV6_PMTUDISC_DO, (int __user *)optval) == 0) {
            vpnhide_dbg("getsockopt: spoofed IPV6_MTU_DISCOVER to IPV6_PMTUDISC_DO\n");
          }
        }
      }
    }
    return 0;
  }

  if (level == IPPROTO_TCP && optname == TCP_MAXSEG) {
    int mss = 0;
    if (get_user(len, optlen) == 0 && len >= sizeof(int)) {
      if (get_user(mss, (int __user *)optval) == 0) {
        if (mss > 0 && mss < 1460) {
          if (put_user(1460, (int __user *)optval) == 0) {
            vpnhide_dbg("getsockopt: spoofed TCP_MAXSEG from %d to 1460\n", mss);
          }
        }
      }
    }
    return 0;
  }

  if (level == IPPROTO_TCP && optname == TCP_INFO) {
    struct {
      u8 _pre[8];
      u32 rto;
      u32 ato;
      u32 snd_mss;
      u32 rcv_mss;
    } ti;
    bool changed = false;

    if (get_user(len, optlen) != 0 || len < (int)sizeof(ti))
      return 0;

    if (copy_from_user(&ti, optval, sizeof(ti)) == 0) {
      if (ti.rto > 200000) {
        ti.rto = 200000;
        changed = true;
      }
      if (ti.ato > 40000) {
        ti.ato = 40000;
        changed = true;
      }
      if (ti.snd_mss < 1460) {
        ti.snd_mss = 1460;
        changed = true;
      }
      if (ti.rcv_mss < 1460) {
        ti.rcv_mss = 1460;
        changed = true;
      }
      if (changed) {
        if (copy_to_user(optval, &ti, sizeof(ti)) == 0) {
          vpnhide_dbg("getsockopt: spoofed TCP_INFO values\n");
        }
      }
    }
    return 0;
  }

  return 0;
}

int vpnhide_connect(struct socket *sock, struct sockaddr __user *uservaddr, int addrlen, int *retval) {
  struct sockaddr_storage uaddr_buf;
  struct sockaddr *addr = (struct sockaddr *)&uaddr_buf;
  uid_t uid = from_kuid(&init_user_ns, current_uid());
  struct vpnhide_port_targets *t;
  struct vpnhide_uid_port_rules *urules = NULL;
  int i;

  if (!is_hook_active(HOOK_CONNECT, uid))
    return 0;

  if (!is_target_uid_val(uid))
    return 0;

  if (addrlen > sizeof(uaddr_buf) || addrlen < sizeof(sa_family_t))
    return 0;

  if (copy_from_user(&uaddr_buf, uservaddr, addrlen))
    return 0;

  rcu_read_lock();
  t = rcu_dereference(global_port_targets);
  if (t) {
    for (i = 0; i < t->count; i++) {
      if (t->targets[i].uid == uid) {
        urules = &t->targets[i];
        break;
      }
    }
  }

  if (!urules || !sock || !sock->sk) {
    rcu_read_unlock();
    return 0;
  }

  if (addr->sa_family == AF_INET) {
    struct sockaddr_in *sin = (struct sockaddr_in *)addr;
    if (ipv4_is_loopback(sin->sin_addr.s_addr) ||
        sin->sin_addr.s_addr == htonl(INADDR_ANY)) {
      unsigned short port = ntohs(sin->sin_port);
      unsigned char proto =
          (sock->sk->sk_type == SOCK_STREAM) ? VH_PROTO_TCP : VH_PROTO_UDP;

      if (should_block_port(urules, port, proto)) {
        vpnhide_dbg("socket_connect: blocking IPv4 port %u (%s) for uid=%u\n",
                    port, (proto == VH_PROTO_TCP) ? "TCP" : "UDP", uid);
        rcu_read_unlock();
        record_kmod_intercept(uid, 6);
        *retval = -ECONNREFUSED;
        return 1; /* blocked */
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

      if (should_block_port(urules, port, proto)) {
        vpnhide_dbg("socket_connect: blocking IPv6 port %u (%s) for uid=%u\n",
                    port, (proto == VH_PROTO_TCP) ? "TCP" : "UDP", uid);
        rcu_read_unlock();
        record_kmod_intercept(uid, 6);
        *retval = -ECONNREFUSED;
        return 1; /* blocked */
      }
    }
  }
  rcu_read_unlock();
  return 0;
}

int vpnhide_bind(struct socket *sock, struct sockaddr __user *uservaddr, int addrlen) {
  struct sockaddr_storage uaddr_buf;
  struct sockaddr *addr = (struct sockaddr *)&uaddr_buf;
  uid_t uid = from_kuid(&init_user_ns, current_uid());
  struct vpnhide_port_targets *t;
  struct vpnhide_uid_port_rules *urules = NULL;
  int i;

  if (!is_hook_active(HOOK_BIND, uid))
    return 0;

  if (!is_target_uid_val(uid))
    return 0;

  if (addrlen > sizeof(uaddr_buf) || addrlen < sizeof(sa_family_t))
    return 0;

  if (copy_from_user(&uaddr_buf, uservaddr, addrlen))
    return 0;

  rcu_read_lock();
  t = rcu_dereference(global_port_targets);
  if (t) {
    for (i = 0; i < t->count; i++) {
      if (t->targets[i].uid == uid) {
        urules = &t->targets[i];
        break;
      }
    }
  }

  if (!urules || !sock || !sock->sk) {
    rcu_read_unlock();
    return 0;
  }

  if (addr->sa_family == AF_INET) {
    struct sockaddr_in *sin = (struct sockaddr_in *)addr;
    if (ipv4_is_loopback(sin->sin_addr.s_addr) ||
        sin->sin_addr.s_addr == htonl(INADDR_ANY)) {
      unsigned short port = ntohs(sin->sin_port);
      unsigned char proto =
          (sock->sk->sk_type == SOCK_STREAM) ? VH_PROTO_TCP : VH_PROTO_UDP;

      if (should_block_port(urules, port, proto)) {
        unsigned short zero_port = 0;
        if (copy_to_user(uservaddr + offsetof(struct sockaddr_in, sin_port),
                         &zero_port, sizeof(zero_port)) == 0) {
          vpnhide_dbg("socket_bind: redirected IPv4 port %u to 0 for uid=%u\n",
                      port, uid);
        }
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

      if (should_block_port(urules, port, proto)) {
        unsigned short zero_port = 0;
        if (copy_to_user(uservaddr + offsetof(struct sockaddr_in6, sin6_port),
                         &zero_port, sizeof(zero_port)) == 0) {
          vpnhide_dbg("socket_bind: redirected IPv6 port %u to 0 for uid=%u\n",
                      port, uid);
        }
      }
    }
  }
  rcu_read_unlock();
  return 0;
}

int vpnhide_getname(struct socket *sock, struct sockaddr *uaddr, int peer, int *retval) {
  uid_t uid = from_kuid(&init_user_ns, current_uid());
  struct vpnhide_spoof_ip sip;

  if (*retval < 0 || !uaddr)
    return 0;

  if (!is_hook_active(HOOK_GETNAME_INET, uid) &&
      !is_hook_active(HOOK_GETNAME_INET6, uid))
    return 0;

  if (!is_target_uid_val(uid))
    return 0;

  get_spoof_ip(&sip);

  if (uaddr->sa_family == AF_INET) {
    struct sockaddr_in *sin = (struct sockaddr_in *)uaddr;
    __be32 addr = sin->sin_addr.s_addr;
    if (addr != 0 && (ntohl(addr) & 0xFF000000) != 0x7F000000) {
      __be32 target_ip = sip.has_ipv4 ? sip.ipv4_addr : htonl(0xC0000004);
      sin->sin_addr.s_addr = target_ip;
      record_kmod_intercept(uid, 5);
      vpnhide_dbg("getname: spoofed IPv4 from %pI4 to %pI4\n", &addr, &target_ip);
    }
  } else if (uaddr->sa_family == AF_INET6) {
    struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)uaddr;
    struct in6_addr addr6 = sin6->sin6_addr;
    if (!ipv6_addr_any(&addr6) && !ipv6_addr_loopback(&addr6)) {
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
      sin6->sin6_addr = target_ip6;
      record_kmod_intercept(uid, 5);
      vpnhide_dbg("getname: spoofed IPv6 from %pI6c to %pI6c\n", &addr6, &target_ip6);
    }
  }

  return 0;
}

int vpnhide_ioctl(struct socket *sock, unsigned int cmd, unsigned long arg, int *retval) {
  uid_t uid = from_kuid(&init_user_ns, current_uid());

  if (!is_hook_active(HOOK_DEV_IOCTL, uid))
    return 0;

  if (!is_target_uid_val(uid))
    return 0;

  switch (cmd) {
  case SIOCGIFADDR:
  case SIOCGIFDSTADDR:
  case SIOCGIFBRDADDR:
  case SIOCGIFNETMASK:
  case SIOCGIFFLAGS:
  case SIOCGIFMTU:
  case SIOCGIFHWADDR:
  case SIOCGIFINDEX:
  case SIOCGIFPFLAGS: {
    struct ifreq ifr;
    if (copy_from_user(&ifr, (void __user *)arg, sizeof(ifr)) == 0) {
      ifr.ifr_name[IFNAMSIZ - 1] = '\0';
      if (is_active_vpn_ifname(ifr.ifr_name)) {
        vpnhide_dbg("ioctl: denying command 0x%x on VPN iface '%s'\n", cmd, ifr.ifr_name);
        record_kmod_intercept(uid, 0);
        *retval = -ENODEV;
        return 1; /* handled */
      }
    }
    break;
  }
  }

  return 0;
}

int vpnhide_sys_bpf(int cmd, union bpf_attr __user *uattr, unsigned int size, int *retval) {
  uid_t uid = from_kuid(&init_user_ns, current_uid());
  if (!is_hook_active(HOOK_BPF, uid))
    return 0;
  if (!is_target_uid_val(uid))
    return 0;

  /* Block BPF requests for targeted apps to hide BPF-based VPN monitors */
  vpnhide_dbg("sys_bpf: blocking command %d for uid=%u\n", cmd, uid);
  record_kmod_intercept(uid, 1);
  *retval = -EPERM;
  return 1; /* handled */
}

/* ------------------------------------------------------------- */
/* Filesystem / VFS Hook Implementations                         */
/* ------------------------------------------------------------- */

bool vpnhide_should_hide_filename(int dfd, const char *filename) {
  char path_buf[512];
  int i;

  if (!filename || filename[0] == '\0')
    return false;

  if (!is_hook_active(HOOK_OPENAT, from_kuid(&init_user_ns, current_uid())))
    return false;

  if (!is_target_uid())
    return false;

  /* If filename is absolute, copy it directly */
  if (filename[0] == '/') {
    strncpy(path_buf, filename, sizeof(path_buf) - 1);
    path_buf[sizeof(path_buf) - 1] = '\0';
  } else if (dfd == AT_FDCWD) {
    /* Simple relative path from CWD */
    strncpy(path_buf, filename, sizeof(path_buf) - 1);
    path_buf[sizeof(path_buf) - 1] = '\0';
  } else {
    /* For dfd relative paths, we let filename_lookup resolve it and check path instead */
    return false;
  }

  for (i = 0; i < ARRAY_SIZE(vh_guarded_dir_prefixes); i++) {
    size_t len = strlen(vh_guarded_dir_prefixes[i]);
    if (strncmp(path_buf, vh_guarded_dir_prefixes[i], len) == 0) {
      if (path_buf[len] == '\0' || path_buf[len] == '/') {
        const char *last_slash = strrchr(path_buf, '/');
        if (last_slash) {
          const char *iface = last_slash + 1;
          if (is_active_vpn_ifname(iface)) {
            record_kmod_intercept(from_kuid(&init_user_ns, current_uid()), 2);
            return true;
          }
        }
      }
    }
  }

  return false;
}

bool vpnhide_should_hide_path(const struct path *path) {
  char path_buf[512];
  char *path_ptr;
  int i;

  if (!path)
    return false;

  if (!is_hook_active(HOOK_OPENAT, from_kuid(&init_user_ns, current_uid())))
    return false;

  if (!is_target_uid())
    return false;

  path_ptr = d_path(path, path_buf, sizeof(path_buf));
  if (IS_ERR(path_ptr))
    return false;

  for (i = 0; i < ARRAY_SIZE(vh_guarded_dir_prefixes); i++) {
    size_t len = strlen(vh_guarded_dir_prefixes[i]);
    if (strncmp(path_ptr, vh_guarded_dir_prefixes[i], len) == 0) {
      if (path_ptr[len] == '\0' || path_ptr[len] == '/') {
        const char *last_slash = strrchr(path_ptr, '/');
        if (last_slash) {
          const char *iface = last_slash + 1;
          if (is_active_vpn_ifname(iface)) {
            record_kmod_intercept(from_kuid(&init_user_ns, current_uid()), 2);
            return true;
          }
        }
      }
    }
  }

  return false;
}

int vpnhide_filename_lookup(int dfd, struct filename *name, unsigned int flags, struct path *path, int *retval) {
  if (path && vpnhide_should_hide_path(path)) {
    path_put(path);
    *retval = -ENOENT;
    return 1; /* handled */
  }
  return 0;
}

int vpnhide_getdents64(unsigned int fd, struct linux_dirent64 __user *dirent, unsigned int count, int *retval) {
  struct fd f;
  struct file *file_ptr;
  char path_buf[256];
  bool is_guarded = false;
  u8 *buf = NULL;
  int ret_val = *retval;

  if (ret_val <= 0)
    return 0;

  if (!is_hook_active(HOOK_GETDENTS64, from_kuid(&init_user_ns, current_uid())))
    return 0;

  if (!is_target_uid())
    return 0;

  f = fdget(fd);
  file_ptr = vh_fd_file(f);
  if (file_ptr) {
    is_guarded = vh_is_path_guarded(file_ptr, path_buf, sizeof(path_buf));
  }
  fdput(f);

  if (!is_guarded)
    return 0;

  buf = kvmalloc(ret_val, GFP_ATOMIC);
  if (!buf)
    return 0;

  if (copy_from_user(buf, dirent, ret_val) == 0) {
    u8 *p = buf;
    u8 *end = buf + ret_val;
    u8 *dst = buf;
    int modified = 0;

    while (p < end) {
      struct vh_linux_dirent64 *de = (struct vh_linux_dirent64 *)p;
      if (de->d_reclen < sizeof(struct vh_linux_dirent64) ||
          p + de->d_reclen > end)
        break;

      if (vh_is_vpn_name_cached(de->d_name, strlen(de->d_name))) {
        vpnhide_dbg("vpnhide_getdents64: filtering out entry '%s'\n", de->d_name);
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
      if (copy_to_user(dirent, buf, new_len) == 0) {
        *retval = new_len;
        kvfree(buf);
        return 1; /* handled */
      }
    }
  }

  kvfree(buf);
  return 0;
}

bool vpnhide_udp_sendmsg_pre(struct sock *sk, struct msghdr *msg, size_t len, int *err) {
  uid_t uid = from_kuid(&init_user_ns, current_uid());

  if (!is_hook_active(HOOK_UDP_SENDMSG, uid))
    return false;

  if (!is_target_uid_val(uid))
    return false;

  if (!sk || !msg)
    return false;

  if (msg->msg_flags & MSG_DONTWAIT) {
    if (udp_rate_limit_exceeded(uid)) {
      udelay(50);
      *err = -EAGAIN;
      return true; /* handled */
    }
  }
  return false;
}

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

void vpnhide_bpf_lookup_elem(struct bpf_map *map, void *key, void *value) {
  if (!map || !key || !value)
    return;

  if (!is_hook_active(HOOK_BPF, from_kuid(&init_user_ns, current_uid())))
    return;

  if (is_target_uid())
    return;

  if (is_stats_or_uid_map(map->name)) {
    if (is_key_vpn_or_target_uid(map, key)) {
      memset(value, 0, map->value_size);
    } else if (strncmp(map->name, "iface_stats", 11) == 0 ||
               strncmp(map->name, "map_netd_iface_", 15) == 0 ||
               strncmp(map->name, "tether_stats", 12) == 0) {
      u32 ifaceIndex = *(u32 *)key;
      u32 cover_idx = (u32)atomic_read(&global_cover_ifindex);
      if (cover_idx && ifaceIndex == cover_idx) {
        struct vh_stats_value vpn_sum = {0};
        collect_vpn_traffic_sum(map, &vpn_sum);
        if (sv_rx_bytes(&vpn_sum) || sv_tx_bytes(&vpn_sum)) {
          struct vh_stats_value *sv = (struct vh_stats_value *)value;
          sv_add(sv, &vpn_sum);
        }
      }
    }
  }
}

void vpnhide_bpf_lookup_batch(struct bpf_map *map, const union bpf_attr *attr, union bpf_attr __user *uattr) {
  u32 count = 0;
  u32 key_size, value_size;
  void __user *usr_keys;
  void __user *usr_vals;

  if (!map || !attr || !uattr)
    return;

  if (!is_hook_active(HOOK_BPF, from_kuid(&init_user_ns, current_uid())))
    return;

  if (is_target_uid())
    return;

  if (!is_stats_or_uid_map(map->name))
    return;

  if (get_user(count, &uattr->batch.count) != 0 || count == 0)
    return;

  usr_keys = (void __user *)(unsigned long)attr->batch.keys;
  usr_vals = (void __user *)(unsigned long)attr->batch.values;
  if (!usr_keys || !usr_vals)
    return;

  key_size = map->key_size;
  value_size = map->value_size;

  {
    u8 kbuf_stack[64];
    u8 vbuf_stack[256];
    void *kbuf = (key_size <= sizeof(kbuf_stack)) ? kbuf_stack : kmalloc(key_size, GFP_KERNEL);
    void *vbuf = (value_size <= sizeof(vbuf_stack)) ? vbuf_stack : kmalloc(value_size, GFP_KERNEL);

    if (kbuf && vbuf) {
      if (strncmp(map->name, "iface_stats", 11) == 0 ||
          strncmp(map->name, "map_netd_iface_stats", 20) == 0) {
        bpf_batch_zero_iface(map, usr_keys, usr_vals, count, key_size, value_size, kbuf, vbuf);
      } else {
        bpf_batch_zero_generic(map, usr_keys, usr_vals, count, key_size, value_size, kbuf, vbuf);
      }
    }

    if (kbuf && kbuf != kbuf_stack)
      kfree(kbuf);
    if (vbuf && vbuf != vbuf_stack)
      kfree(vbuf);
  }
}
