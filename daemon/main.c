#include "daemon.h"

int main(int argc, char **argv) {
  int fd, nl_fd, config_fd = -1, stats_fd = -1;
  int port_event_fd = -1, diag_events_fd = -1;
  const char *ctl = argc > 1 ? argv[1] : NULL;
  const char *config = argc > 2 ? argv[2] : NULL;
  const char *self_uid = argc > 3 ? argv[3] : NULL;
  uid_t stats_allowed_uid = (uid_t)-1;
  char config_dir[PATH_MAX];
  struct sockaddr_nl sa;
  char last_ipv4[64];
  char last_ipv6[64];
  char last_ipv6_linklocal[64];
  unsigned int last_ipv4_mtu = UINT_MAX;
  unsigned int last_ipv6_mtu = UINT_MAX;

  file_hiding_set_config_path(config);

  setbuf(stdout, NULL);
  setbuf(stderr, NULL);

  strcpy(last_ipv4, "none");
  strcpy(last_ipv6, "none");
  strcpy(last_ipv6_linklocal, "none");

  fd = open("/dev/vpnhide_ctrl", O_RDWR);
  if (fd < 0) {
    fprintf(stderr,
            "vpnhide-daemon: failed to open /dev/vpnhide_ctrl: %d (%s)\n",
            errno, strerror(errno));
    return 1;
  }

  nl_fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
  if (nl_fd < 0) {
    close(fd);
    return 1;
  }

  memset(&sa, 0, sizeof(sa));
  sa.nl_family = AF_NETLINK;
  sa.nl_groups = RTMGRP_LINK | RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR |
                 RTMGRP_IPV4_ROUTE | RTMGRP_IPV6_ROUTE;
  if (bind(nl_fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
    close(nl_fd);
    close(fd);
    return 1;
  }

  if (config && ctl) {
    const char *slash = strrchr(config, '/');
    size_t dir_len = slash ? (size_t)(slash - config) : 0;
    if (dir_len > 0 && dir_len < sizeof(config_dir)) {
      memcpy(config_dir, config, dir_len);
      config_dir[dir_len] = '\0';
      config_fd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
      if (config_fd >= 0 && inotify_add_watch(config_fd, config_dir,
                                              IN_CLOSE_WRITE | IN_MOVED_TO |
                                                  IN_CREATE | IN_ATTRIB) < 0) {
        close(config_fd);
        config_fd = -1;
      }
      if (config_fd < 0)
        fprintf(stderr, "vpnhide-daemon: config watch unavailable: %s\n",
                strerror(errno));
    }
  }
  if (self_uid && self_uid[0]) {
    char *end = NULL;
    unsigned long parsed = strtoul(self_uid, &end, 10);
    if (end && *end == '\0' && parsed <= UINT_MAX) {
      stats_allowed_uid = (uid_t)parsed;
      stats_fd = open_stats_socket(stats_allowed_uid);
    }
  }
  if (stats_fd < 0 && stats_allowed_uid != (uid_t)-1)
    fprintf(stderr, "vpnhide-daemon: statistics socket unavailable: %s\n",
            strerror(errno));

  port_event_fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
  if (port_event_fd >= 0 &&
      ioctl(fd, VH_SET_PORT_EVENTFD, &port_event_fd) < 0) {
    close(port_event_fd);
    port_event_fd = -1;
  }
  if (port_event_fd < 0)
    fprintf(stderr, "vpnhide-daemon: own-port bind events unavailable: %s\n",
            strerror(errno));
  diag_events_fd = open_diag_events();
  if (diag_events_fd < 0)
    fprintf(stderr, "vpnhide-daemon: socket destroy events unavailable: %s\n",
            strerror(errno));
  if (refresh_owned_ports(fd) < 0)
    fprintf(stderr, "vpnhide-daemon: initial own-port scan failed: %s\n",
            strerror(errno));

  // Initial update
  update_spoof_ip(fd, last_ipv4, last_ipv6, last_ipv6_linklocal, &last_ipv4_mtu,
                  &last_ipv6_mtu);
  struct daemon_stats_ring stats_ring;
  memset(&stats_ring, 0, sizeof(stats_ring));
  initialize_session_id(fd, &stats_ring);
  sample_stats(fd, &stats_ring);

  unsigned long long next_update_time = 0;
  unsigned long long next_iface_rescan =
      daemon_get_time_ms() + IFACE_RESCAN_INTERVAL_MS;
  bool update_pending = false;
  int retry_count = 0;
  unsigned long long next_stats_sample =
      daemon_get_time_ms() + STATS_RESOLUTION_SEC * 1000ULL;
  unsigned long long owned_ports_due = 0;
  unsigned long long next_owned_ports_reconcile = daemon_get_time_ms() + 60000;

  while (1) {
    int poll_timeout = -1;
    if (update_pending) {
      unsigned long long now = daemon_get_time_ms();
      if (now >= next_update_time) {
        poll_timeout = 0;
      } else {
        poll_timeout = (int)(next_update_time - now);
      }
    }
    {
      unsigned long long now = daemon_get_time_ms();
      int iface_timeout =
          now >= next_iface_rescan ? 0 : (int)(next_iface_rescan - now);
      if (poll_timeout < 0 || iface_timeout < poll_timeout)
        poll_timeout = iface_timeout;
    }
    {
      unsigned long long now = daemon_get_time_ms();
      int stats_timeout =
          now >= next_stats_sample ? 0 : (int)(next_stats_sample - now);
      if (poll_timeout < 0 || stats_timeout < poll_timeout)
        poll_timeout = stats_timeout;
    }
    {
      unsigned long long now = daemon_get_time_ms();
      unsigned long long deadline =
          owned_ports_due ? owned_ports_due : next_owned_ports_reconcile;
      int owned_timeout = now >= deadline ? 0 : (int)(deadline - now);
      if (poll_timeout < 0 || owned_timeout < poll_timeout)
        poll_timeout = owned_timeout;
    }

    struct pollfd pfds[5];
    int nfds = 1;
    int config_index = -1, stats_index = -1;
    int port_event_index = -1, diag_events_index = -1;
    memset(pfds, 0, sizeof(pfds));
    pfds[0].fd = nl_fd;
    pfds[0].events = POLLIN | POLLERR | POLLHUP | POLLNVAL;
    if (config_fd >= 0) {
      config_index = nfds;
      pfds[nfds].fd = config_fd;
      pfds[nfds].events = POLLIN;
      nfds++;
    }
    if (stats_fd >= 0) {
      stats_index = nfds;
      pfds[nfds].fd = stats_fd;
      pfds[nfds].events = POLLIN;
      nfds++;
    }
    if (port_event_fd >= 0) {
      port_event_index = nfds;
      pfds[nfds].fd = port_event_fd;
      pfds[nfds].events = POLLIN;
      nfds++;
    }
    if (diag_events_fd >= 0) {
      diag_events_index = nfds;
      pfds[nfds].fd = diag_events_fd;
      pfds[nfds].events = POLLIN;
      nfds++;
    }

    int ret = poll(pfds, nfds, poll_timeout);
    if (ret < 0) {
      if (errno == EINTR)
        continue;
      sleep(1);
      continue;
    }

    bool trigger_update = false;
    bool netlink_event = false;
    bool periodic_iface_rescan = false;

    if (ret > 0 &&
        (pfds[0].revents & (POLLIN | POLLERR | POLLHUP | POLLNVAL))) {
      char buf[4096];
      // Consume all pending data on netlink socket to clear the POLLIN state
      while (recv(nl_fd, buf, sizeof(buf), MSG_DONTWAIT) > 0)
        ;
      usleep(200000); // 200ms debounce
      trigger_update = true;
      netlink_event = true;
    }
    if (daemon_get_time_ms() >= next_iface_rescan) {
      periodic_iface_rescan = true;
      trigger_update = true;
      next_iface_rescan = daemon_get_time_ms() + IFACE_RESCAN_INTERVAL_MS;
    }
    if (config_index >= 0 && ret > 0 && (pfds[config_index].revents & POLLIN)) {
      drain_config_events(config_fd, config, ctl);
      owned_ports_due = daemon_get_time_ms() + 100;
    }
    if (stats_index >= 0) {
      if (ret > 0 && (pfds[stats_index].revents & POLLIN))
        serve_stats_client(stats_fd, stats_allowed_uid, &stats_ring);
    }
    if (port_event_index >= 0 && ret > 0 &&
        (pfds[port_event_index].revents & POLLIN)) {
      uint64_t events;
      while (read(port_event_fd, &events, sizeof(events)) > 0)
        ;
      owned_ports_due = daemon_get_time_ms() + 75;
    }
    if (diag_events_index >= 0 && ret > 0 &&
        (pfds[diag_events_index].revents & POLLIN)) {
      char buffer[8192];
      while (recv(diag_events_fd, buffer, sizeof(buffer), MSG_DONTWAIT) > 0)
        ;
      owned_ports_due = daemon_get_time_ms() + 25;
    }
    if (daemon_get_time_ms() >= next_stats_sample) {
      do {
        next_stats_sample += STATS_RESOLUTION_SEC * 1000ULL;
      } while (next_stats_sample <= daemon_get_time_ms());
      sample_stats(fd, &stats_ring);
    }
    if ((owned_ports_due && daemon_get_time_ms() >= owned_ports_due) ||
        daemon_get_time_ms() >= next_owned_ports_reconcile) {
      owned_ports_due = 0;
      next_owned_ports_reconcile = daemon_get_time_ms() + 60000;
      if (refresh_owned_ports(fd) < 0)
        fprintf(stderr, "vpnhide-daemon: own-port refresh failed: %s\n",
                strerror(errno));
    }

    if (update_pending && daemon_get_time_ms() >= next_update_time) {
      trigger_update = true;
      update_pending = false;
    }

    if (trigger_update) {
      bool publish_ok =
          update_spoof_ip(fd, last_ipv4, last_ipv6, last_ipv6_linklocal,
                          &last_ipv4_mtu, &last_ipv6_mtu);
      if (periodic_iface_rescan)
        next_iface_rescan = daemon_get_time_ms() + IFACE_RESCAN_INTERVAL_MS;
      if (!publish_ok)
        next_iface_rescan = daemon_get_time_ms() + 1000;

      if (netlink_event) {
        // Netlink event occurred, schedule follow-ups
        next_update_time = daemon_get_time_ms() + 1000;
        update_pending = true;
        retry_count = 2;
      } else if (retry_count > 0) {
        retry_count--;
        if (retry_count == 1) {
          next_update_time = daemon_get_time_ms() + 2000;
          update_pending = true;
        }
      }
    }
  }

  close(nl_fd);
  if (config_fd >= 0)
    close(config_fd);
  if (stats_fd >= 0)
    close(stats_fd);
  if (port_event_fd >= 0)
    close(port_event_fd);
  if (diag_events_fd >= 0)
    close(diag_events_fd);
  clear_stats_ring(&stats_ring);
  close(fd);
  return 0;
}
