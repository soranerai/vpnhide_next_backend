#include "daemon.h"

static bool is_interface_operstate_up(const char *ifname) {
  char path[256];
  char buf[32];
  int fd;
  ssize_t len;

  snprintf(path, sizeof(path), "/sys/class/net/%s/operstate", ifname);
  fd = open(path, O_RDONLY);
  if (fd < 0)
    return false;

  len = read(fd, buf, sizeof(buf) - 1);
  close(fd);

  if (len <= 0)
    return false;

  buf[len] = '\0';
  while (len > 0 && (buf[len - 1] == '\n' || buf[len - 1] == '\r' ||
                     buf[len - 1] == ' ')) {
    buf[--len] = '\0';
  }

  return strcmp(buf, "up") == 0 || strcmp(buf, "unknown") == 0;
}

static unsigned short interface_arphrd(const char *ifname) {
  struct ifreq ifr;
  int sock;
  unsigned short arphrd = 0;

  if (!ifname || !ifname[0])
    return 0;

  sock = socket(AF_INET, SOCK_DGRAM, 0);
  if (sock < 0)
    return 0;

  memset(&ifr, 0, sizeof(ifr));
  strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
  if (ioctl(sock, SIOCGIFHWADDR, &ifr) == 0)
    arphrd = (unsigned short)ifr.ifr_hwaddr.sa_family;

  close(sock);
  return arphrd;
}

static int test_interface_egress(const char *ifname, int af, char *out_ip,
                                 size_t max_len, unsigned int *out_mtu) {
  int sock = socket(af, SOCK_DGRAM, 0);
  int mtu = 0;
  socklen_t mtu_len = sizeof(mtu);
  int mtu_level = af == AF_INET ? IPPROTO_IP : IPPROTO_IPV6;
  int mtu_opt = af == AF_INET ? IP_MTU : IPV6_MTU;

  if (out_mtu)
    *out_mtu = 0;
  if (sock < 0)
    return 0;

  if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, ifname, strlen(ifname)) <
      0) {
    close(sock);
    return 0;
  }

  if (af == AF_INET) {
    struct sockaddr_in serv;
    memset(&serv, 0, sizeof(serv));
    serv.sin_family = AF_INET;
    serv.sin_addr.s_addr = inet_addr("8.8.8.8");
    serv.sin_port = htons(53);

    if (connect(sock, (const struct sockaddr *)&serv, sizeof(serv)) < 0) {
      close(sock);
      return 0;
    }

    struct sockaddr_in name;
    socklen_t namelen = sizeof(name);
    if (getsockname(sock, (struct sockaddr *)&name, &namelen) == 0) {
      inet_ntop(AF_INET, &name.sin_addr, out_ip, max_len);
      if (out_mtu &&
          getsockopt(sock, mtu_level, mtu_opt, &mtu, &mtu_len) == 0 && mtu > 0)
        *out_mtu = (unsigned int)mtu;
      close(sock);
      return 1;
    }
  } else if (af == AF_INET6) {
    struct sockaddr_in6 serv;
    memset(&serv, 0, sizeof(serv));
    serv.sin6_family = AF_INET6;
    if (inet_pton(AF_INET6, "2001:4860:4860::8888", &serv.sin6_addr) != 1) {
      close(sock);
      return 0;
    }
    serv.sin6_port = htons(53);

    if (connect(sock, (const struct sockaddr *)&serv, sizeof(serv)) < 0) {
      close(sock);
      return 0;
    }

    struct sockaddr_in6 name;
    socklen_t namelen = sizeof(name);
    if (getsockname(sock, (struct sockaddr *)&name, &namelen) == 0) {
      if (IN6_IS_ADDR_LINKLOCAL(&(name.sin6_addr))) {
        close(sock);
        return 0;
      }
      inet_ntop(AF_INET6, &name.sin6_addr, out_ip, max_len);
      if (out_mtu &&
          getsockopt(sock, mtu_level, mtu_opt, &mtu, &mtu_len) == 0 && mtu > 0)
        *out_mtu = (unsigned int)mtu;
      close(sock);
      return 1;
    }
  }

  close(sock);
  return 0;
}

static bool
daemon_is_vpn_ifname(const char *name,
                     const struct vpnhide_iface_ioctl_data *prefixes) {
  /* Use auto-generated static patterns */
  if (vpnhide_iface_is_vpn(name))
    return true;

  /* Configured prefixes */
  if (prefixes) {
    for (int i = 0; i < prefixes->count; i++) {
      int len = strlen(prefixes->prefixes[i]);
      if (len > 0 && strncasecmp(name, prefixes->prefixes[i], len) == 0) {
        return true;
      }
    }
  }
  return false;
}

bool update_spoof_ip(int fd, char *last_ipv4, char *last_ipv6,
                     char *last_ipv6_linklocal, unsigned int *last_ipv4_mtu,
                     unsigned int *last_ipv6_mtu) {
  bool publish_ok = true;
  struct ifaddrs *ifaddr = NULL;
  struct ifaddrs *ifa = NULL;
  char best_ifname[IFNAMSIZ];
  int best_score = -1;
  char new_ipv4[64];
  char new_ipv6[64];
  char new_ipv6_linklocal[64];
  unsigned int new_ipv4_mtu = 0;
  unsigned int new_ipv6_mtu = 0;
  struct vpnhide_iface_ioctl_data prefixes;
  struct vpnhide_vpn_ifindexes active_vpns;

  memset(&prefixes, 0, sizeof(prefixes));
  memset(&active_vpns, 0, sizeof(active_vpns));
  ioctl(fd, VH_GET_IFACE_PREFIXES, &prefixes);

  best_ifname[0] = '\0';
  strcpy(new_ipv4, "none");
  strcpy(new_ipv6, "none");
  strcpy(new_ipv6_linklocal, "none");

  if (getifaddrs(&ifaddr) == -1) {
    fprintf(stderr, "vpnhide-daemon: getifaddrs failed: %s\n", strerror(errno));
    return false;
  }

  /* Helper structures to aggregate interface info */
  struct iface_info {
    char name[IFNAMSIZ];
    char ipv4[64];
    char ipv6[64];
    char ipv6_linklocal[64];
    unsigned int ipv4_mtu;
    unsigned int ipv6_mtu;
    bool has_ipv4;
    bool has_ipv6;
    int score;
  } interfaces[32];
  int iface_count = 0;

  for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
    if (ifa->ifa_flags & IFF_LOOPBACK)
      continue;

    char *name = ifa->ifa_name;
    unsigned short arphrd = interface_arphrd(name);
    bool is_vpn = vpnhide_daemon_is_vpn_interface(
        name, (ifa->ifa_flags & IFF_POINTOPOINT) != 0, arphrd,
        daemon_is_vpn_ifname(name, &prefixes));

    if (is_vpn) {
      unsigned int vpn_idx = if_nametoindex(name);
      if (vpn_idx > 0) {
        bool dup = false;
        for (int i = 0; i < active_vpns.count; i++) {
          if (active_vpns.vpns[i].ifindex == vpn_idx) {
            dup = true;
            break;
          }
        }
        if (!dup && active_vpns.count < MAX_ACTIVE_VPNS) {
          active_vpns.vpns[active_vpns.count].ifindex = vpn_idx;
          strncpy(active_vpns.vpns[active_vpns.count].name, name,
                  MAX_IFACE_LEN - 1);
          active_vpns.vpns[active_vpns.count].name[MAX_IFACE_LEN - 1] = '\0';
          active_vpns.count++;
        }
      }
      continue;
    }

    /*
     * Keep active VPN interfaces in the snapshot even while they are
     * DOWN or transitioning.  NetworkInterface enumeration exposes
     * such netdevs too, while cover-interface selection must only use
     * an operational uplink.
     */
    if (!(ifa->ifa_flags & IFF_UP))
      continue;

    if (ifa->ifa_addr == NULL)
      continue;

    if (!vpnhide_daemon_is_cover_candidate(name))
      continue;

    if (!is_interface_operstate_up(name))
      continue;

    /* Find or create interface info slot */
    int idx = -1;
    for (int i = 0; i < iface_count; i++) {
      if (strcmp(interfaces[i].name, name) == 0) {
        idx = i;
        break;
      }
    }
    if (idx == -1 && iface_count < 32) {
      idx = iface_count++;
      memset(&interfaces[idx], 0, sizeof(struct iface_info));
      strncpy(interfaces[idx].name, name, IFNAMSIZ - 1);

      // Test IPv4 egress route
      char tmp_ipv4[64] = {0};
      if (test_interface_egress(name, AF_INET, tmp_ipv4, sizeof(tmp_ipv4),
                                &interfaces[idx].ipv4_mtu)) {
        interfaces[idx].has_ipv4 = true;
        strcpy(interfaces[idx].ipv4, tmp_ipv4);
      }

      // Test IPv6 egress route
      char tmp_ipv6[64] = {0};
      if (test_interface_egress(name, AF_INET6, tmp_ipv6, sizeof(tmp_ipv6),
                                &interfaces[idx].ipv6_mtu)) {
        interfaces[idx].has_ipv6 = true;
        strcpy(interfaces[idx].ipv6, tmp_ipv6);
      }
    }
    if (idx >= 0 && ifa->ifa_addr->sa_family == AF_INET6) {
      struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)ifa->ifa_addr;

      if (IN6_IS_ADDR_LINKLOCAL(&sin6->sin6_addr))
        inet_ntop(AF_INET6, &sin6->sin6_addr, interfaces[idx].ipv6_linklocal,
                  sizeof(interfaces[idx].ipv6_linklocal));
    }
  }

  freeifaddrs(ifaddr);

  /* Score all aggregated interfaces that have at least one active egress route
   */
  for (int i = 0; i < iface_count; i++) {
    struct iface_info *info = &interfaces[i];
    if (!info->has_ipv4 && !info->has_ipv6) {
      continue; // No internet access, ignore completely
    }

    info->score = 1000;

    if (strncmp(info->name, "eth", 3) == 0) {
      info->score = 100000;
    } else if (strncmp(info->name, "wlan", 4) == 0 ||
               strncmp(info->name, "ap", 2) == 0) {
      info->score = 50000;
    } else if (vpnhide_daemon_is_cellular_uplink(info->name)) {
      info->score = 10000;
    }

    /* Add priority for dual-stack or having active IPv4 / IPv6 */
    if (info->has_ipv4)
      info->score += 5000;
    if (info->has_ipv6)
      info->score += 5000;

    if (info->score > best_score) {
      best_score = info->score;
      strncpy(best_ifname, info->name, IFNAMSIZ - 1);
      best_ifname[IFNAMSIZ - 1] = '\0';
      if (info->has_ipv4) {
        strcpy(new_ipv4, info->ipv4);
        new_ipv4_mtu = info->ipv4_mtu;
      } else {
        strcpy(new_ipv4, "none");
      }
      if (info->has_ipv6) {
        strcpy(new_ipv6, info->ipv6);
        new_ipv6_mtu = info->ipv6_mtu;
      } else {
        strcpy(new_ipv6, "none");
      }
      if (info->ipv6_linklocal[0])
        strcpy(new_ipv6_linklocal, info->ipv6_linklocal);
    }
  }

  if (strcmp(new_ipv4, last_ipv4) != 0 || strcmp(new_ipv6, last_ipv6) != 0 ||
      strcmp(new_ipv6_linklocal, last_ipv6_linklocal) != 0 ||
      new_ipv4_mtu != *last_ipv4_mtu || new_ipv6_mtu != *last_ipv6_mtu) {
    struct vpnhide_spoof_ip spoof;
    memset(&spoof, 0, sizeof(spoof));

    if (strcmp(new_ipv4, "none") != 0) {
      if (inet_pton(AF_INET, new_ipv4, &spoof.ipv4_addr) == 1) {
        spoof.has_ipv4 = 1;
      }
    }
    if (strcmp(new_ipv6, "none") != 0) {
      if (inet_pton(AF_INET6, new_ipv6, spoof.ipv6_addr) == 1) {
        spoof.has_ipv6 = 1;
      }
    }
    if (strcmp(new_ipv6_linklocal, "none") != 0 &&
        inet_pton(AF_INET6, new_ipv6_linklocal, spoof.ipv6_linklocal_addr) == 1)
      spoof.has_ipv6_linklocal = 1;
    spoof.ipv4_mtu = new_ipv4_mtu;
    spoof.ipv6_mtu = new_ipv6_mtu;

    if (ioctl(fd, VH_SET_SPOOF_IP, &spoof) == 0) {
      strcpy(last_ipv4, new_ipv4);
      strcpy(last_ipv6, new_ipv6);
      strcpy(last_ipv6_linklocal, new_ipv6_linklocal);
      *last_ipv4_mtu = new_ipv4_mtu;
      *last_ipv6_mtu = new_ipv6_mtu;
    } else {
      fprintf(stderr, "vpnhide-daemon: failed to publish spoof IP: %s\n",
              strerror(errno));
      publish_ok = false;
    }
  }

  /* Always update cover ifindex so the kernel's BPF stats laundering
   * uses the correct interface even if the spoof IP hasn't changed. */
  if (best_ifname[0] != '\0') {
    struct vpnhide_cover_iface ci;
    ci.ifindex = if_nametoindex(best_ifname);
    if (ci.ifindex > 0) {
      if (ioctl(fd, VH_SET_COVER_IFACE, &ci) < 0) {
        fprintf(stderr, "vpnhide-daemon: failed to publish cover iface: %s\n",
                strerror(errno));
        publish_ok = false;
      }
      char buf[64];
      int len = snprintf(buf, sizeof(buf), "cover_iface:%s\n", best_ifname);
      if (len > 0) {
        if (write(fd, buf, len) < 0) {
          fprintf(stderr, "vpnhide-daemon: failed to publish cover name: %s\n",
                  strerror(errno));
          publish_ok = false;
        }
      }
    } else {
      fprintf(stderr,
              "vpnhide-daemon: cover iface disappeared before publish\n");
      publish_ok = false;
    }
  } else {
    struct vpnhide_cover_iface ci = {.ifindex = 0};
    if (ioctl(fd, VH_SET_COVER_IFACE, &ci) < 0) {
      fprintf(stderr, "vpnhide-daemon: failed to clear cover iface: %s\n",
              strerror(errno));
      publish_ok = false;
    }
    if (write(fd, "cover_iface:none\n", 17) < 0) {
      fprintf(stderr, "vpnhide-daemon: failed to clear cover name: %s\n",
              strerror(errno));
      publish_ok = false;
    }
  }

  /* Send the list of active VPNs to the kernel module */
  file_hiding_sync_interfaces(&active_vpns);
  if (ioctl(fd, VH_SET_VPN_IFINDEXES, &active_vpns) < 0) {
    fprintf(stderr, "vpnhide-daemon: failed to publish VPN interfaces: %s\n",
            strerror(errno));
    publish_ok = false;
  }

  return publish_ok;
}
