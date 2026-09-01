#include "daemon.h"

unsigned long long daemon_get_time_ms(void) {
  struct timespec ts;

  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (unsigned long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

unsigned long long daemon_get_wall_time_ms(void) {
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);
  return (unsigned long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static void free_stats_point(struct daemon_stats_point *point) {
  free(point->entries);
  free(point->ports);
  memset(point, 0, sizeof(*point));
}

void clear_stats_ring(struct daemon_stats_ring *ring) {
  for (unsigned int i = 0; i < STATS_RING_POINTS; i++)
    free_stats_point(&ring->points[i]);
  ring->head = 0;
  ring->count = 0;
  ring->dropped_intervals = 0;
  ring->latest_sequence = 0;
  ring->previous_sequence = 0;
  ring->previous_count = 0;
  ring->previous_capacity = 0;
  ring->previous_port_count = 0;
  ring->previous_port_capacity = 0;
  ring->dropped_port_entries = 0;
  ring->baseline_valid = false;
  free(ring->previous);
  ring->previous = NULL;
  free(ring->previous_ports);
  ring->previous_ports = NULL;
}

void initialize_session_id(int fd, struct daemon_stats_ring *ring) {
  char boot_id[80] = "unknown";
  uint64_t kernel_session = 0;
  FILE *boot = fopen("/proc/sys/kernel/random/boot_id", "r");
  if (boot) {
    if (fgets(boot_id, sizeof(boot_id), boot))
      boot_id[strcspn(boot_id, "\r\n")] = '\0';
    fclose(boot);
  }
  if (ioctl(fd, VH_GET_STATS_SESSION, &kernel_session) == 0)
    snprintf(ring->session_id, sizeof(ring->session_id), "%s-%016llx", boot_id,
             (unsigned long long)kernel_session);
  else
    snprintf(ring->session_id, sizeof(ring->session_id), "%s", boot_id);
}

static const struct vpnhide_uid_stats *
find_uid_stats(const struct vpnhide_uid_stats *entries, uint32_t count,
               uid_t uid) {
  uint32_t lo = 0, hi = count;

  /* Kernel snapshots and the daemon baseline are UID-sorted. */
  while (lo < hi) {
    uint32_t mid = lo + (hi - lo) / 2;
    if (entries[mid].uid < uid)
      lo = mid + 1;
    else
      hi = mid;
  }
  if (lo < count && entries[lo].uid == uid)
    return &entries[lo];
  return NULL;
}

static const struct vpnhide_port_stats *
find_port_stats(const struct vpnhide_port_stats *entries, uint32_t count,
                uid_t uid, uint16_t port, uint8_t protocol) {
  uint32_t lo = 0, hi = count;
  while (lo < hi) {
    uint32_t mid = lo + (hi - lo) / 2;
    const struct vpnhide_port_stats *entry = &entries[mid];
    if (entry->uid < uid || (entry->uid == uid && entry->protocol < protocol) ||
        (entry->uid == uid && entry->protocol == protocol &&
         entry->port < port)) {
      lo = mid + 1;
    } else {
      hi = mid;
    }
  }
  if (lo < count && entries[lo].uid == uid && entries[lo].port == port &&
      entries[lo].protocol == protocol)
    return &entries[lo];
  return NULL;
}

static int port_stats_compare(const void *left, const void *right) {
  const struct vpnhide_port_stats *a = left, *b = right;
  if (a->uid != b->uid)
    return a->uid < b->uid ? -1 : 1;
  if (a->protocol != b->protocol)
    return (int)a->protocol - (int)b->protocol;
  if (a->port != b->port)
    return a->port < b->port ? -1 : 1;
  return 0;
}

static uint64_t stats_delta(uint64_t current, uint64_t previous) {
  /* A kernel clear or session change must not turn a reset into an enormous
   * interval. The caller detects the sequence reset and marks a gap. */
  return current >= previous ? current - previous : current;
}

static int read_kernel_stats(int fd, struct vpnhide_uid_stats **entries,
                             uint32_t *count, struct vpnhide_port_stats **ports,
                             uint32_t *port_count, uint64_t *sequence,
                             uint64_t *dropped_port_entries) {
  struct vpnhide_stats_snapshot_v2 request_v2;
  struct vpnhide_stats_snapshot request_v1;
  struct vpnhide_uid_stats *buffer = NULL;
  struct vpnhide_port_stats *port_buffer = NULL;
  uint32_t capacity = 0, port_capacity = 0;
  bool v2_supported = true;

  for (;;) {
    memset(&request_v2, 0, sizeof(request_v2));
    request_v2.uid_capacity = capacity;
    request_v2.port_capacity = port_capacity;
    request_v2.uid_entries_ptr = (uint64_t)(uintptr_t)buffer;
    request_v2.port_entries_ptr = (uint64_t)(uintptr_t)port_buffer;
    if (ioctl(fd, VH_GET_STATS_V2, &request_v2) == 0) {
      *entries = buffer;
      *count = request_v2.uid_count;
      *ports = port_buffer;
      *port_count = request_v2.port_count;
      *sequence = request_v2.sequence;
      *dropped_port_entries = request_v2.dropped_port_entries;
      return 0;
    }
    if (errno == ENOTTY) {
      v2_supported = false;
      break;
    }
    if (errno != ENOSPC || (request_v2.uid_count <= capacity &&
                            request_v2.port_count <= port_capacity)) {
      free(buffer);
      free(port_buffer);
      return -1;
    }
    if (request_v2.uid_count > capacity) {
      capacity = request_v2.uid_count;
      free(buffer);
      buffer = calloc(capacity, sizeof(*buffer));
      if (!buffer) {
        free(port_buffer);
        return -1;
      }
    }
    if (request_v2.port_count > port_capacity) {
      port_capacity = request_v2.port_count;
      free(port_buffer);
      port_buffer = calloc(port_capacity, sizeof(*port_buffer));
      if (!port_buffer) {
        free(buffer);
        return -1;
      }
    }
  }

  free(buffer);
  free(port_buffer);
  if (!v2_supported) {
    buffer = NULL;
    capacity = 0;
    for (;;) {
      memset(&request_v1, 0, sizeof(request_v1));
      request_v1.capacity = capacity;
      request_v1.entries_ptr = (uint64_t)(uintptr_t)buffer;
      if (ioctl(fd, VH_GET_STATS, &request_v1) == 0) {
        *entries = buffer;
        *count = request_v1.count;
        *ports = NULL;
        *port_count = 0;
        *sequence = request_v1.sequence;
        *dropped_port_entries = 0;
        return 0;
      }
      if (errno != ENOSPC || request_v1.count <= capacity) {
        free(buffer);
        return -1;
      }
      capacity = request_v1.count;
      free(buffer);
      buffer = calloc(capacity, sizeof(*buffer));
      if (!buffer)
        return -1;
    }
  }
  return -1;
}

static void append_stats_point(struct daemon_stats_ring *ring,
                               const struct vpnhide_uid_stats *current,
                               uint32_t current_count,
                               const struct vpnhide_port_stats *current_ports,
                               uint32_t current_port_count, uint64_t sequence,
                               uint64_t dropped_port_entries,
                               unsigned long long timestamp_ms) {
  struct daemon_stats_point point;
  bool gap = !ring->baseline_valid;
  uint32_t delta_count = 0;
  uint32_t port_delta_count = 0;
  struct vpnhide_uid_stats *grown;
  struct vpnhide_port_stats *grown_ports;

  if (current_count > ring->previous_capacity) {
    grown = realloc(ring->previous, current_count * sizeof(*grown));
    if (!grown)
      return;
    ring->previous = grown;
    ring->previous_capacity = current_count;
  }
  if (current_port_count > ring->previous_port_capacity) {
    grown_ports = realloc(ring->previous_ports,
                          current_port_count * sizeof(*grown_ports));
    if (!grown_ports)
      return;
    ring->previous_ports = grown_ports;
    ring->previous_port_capacity = current_port_count;
  }

  if (ring->baseline_valid && sequence <= ring->previous_sequence)
    gap = true;

  if (!gap) {
    for (uint32_t i = 0; i < current_count; i++) {
      const struct vpnhide_uid_stats *old =
          find_uid_stats(ring->previous, ring->previous_count, current[i].uid);
      if (!old || stats_delta(current[i].ioctl_count, old->ioctl_count) ||
          stats_delta(current[i].netlink_count, old->netlink_count) ||
          stats_delta(current[i].proc_count, old->proc_count) ||
          stats_delta(current[i].sockopt_count, old->sockopt_count) ||
          stats_delta(current[i].connect_count, old->connect_count) ||
          stats_delta(current[i].getname_count, old->getname_count) ||
          stats_delta(current[i].port_count, old->port_count) ||
          stats_delta(current[i].java_pm_count, old->java_pm_count) ||
          stats_delta(current[i].java_um_count, old->java_um_count) ||
          stats_delta(current[i].java_nc_count, old->java_nc_count) ||
          stats_delta(current[i].java_ni_count, old->java_ni_count) ||
          stats_delta(current[i].java_net_count, old->java_net_count) ||
          stats_delta(current[i].java_lp_count, old->java_lp_count) ||
          stats_delta(current[i].java_cs_count, old->java_cs_count))
        delta_count++;
    }
    for (uint32_t i = 0; i < current_port_count; i++) {
      const struct vpnhide_port_stats *old = find_port_stats(
          ring->previous_ports, ring->previous_port_count, current_ports[i].uid,
          current_ports[i].port, current_ports[i].protocol);
      if (stats_delta(current_ports[i].count, old ? old->count : 0))
        port_delta_count++;
    }
  }

  memset(&point, 0, sizeof(point));
  point.timestamp_ms = timestamp_ms;
  point.gap = gap;
  if (delta_count) {
    point.entries = calloc(delta_count, sizeof(*point.entries));
    if (!point.entries)
      return;
  }
  if (port_delta_count) {
    point.ports = calloc(port_delta_count, sizeof(*point.ports));
    if (!point.ports) {
      free(point.entries);
      return;
    }
  }
  if (!gap) {
    for (uint32_t i = 0, out = 0; i < current_count; i++) {
      const struct vpnhide_uid_stats *old =
          find_uid_stats(ring->previous, ring->previous_count, current[i].uid);
      __u64 *dst;
      if (old &&
          (!stats_delta(current[i].ioctl_count, old->ioctl_count) &&
           !stats_delta(current[i].netlink_count, old->netlink_count) &&
           !stats_delta(current[i].proc_count, old->proc_count) &&
           !stats_delta(current[i].sockopt_count, old->sockopt_count) &&
           !stats_delta(current[i].connect_count, old->connect_count) &&
           !stats_delta(current[i].getname_count, old->getname_count) &&
           !stats_delta(current[i].port_count, old->port_count) &&
           !stats_delta(current[i].java_pm_count, old->java_pm_count) &&
           !stats_delta(current[i].java_um_count, old->java_um_count) &&
           !stats_delta(current[i].java_nc_count, old->java_nc_count) &&
           !stats_delta(current[i].java_ni_count, old->java_ni_count) &&
           !stats_delta(current[i].java_net_count, old->java_net_count) &&
           !stats_delta(current[i].java_lp_count, old->java_lp_count) &&
           !stats_delta(current[i].java_cs_count, old->java_cs_count)))
        continue;
      point.entries[out].uid = current[i].uid;
      dst = &point.entries[out].ioctl_count;
      dst[0] = stats_delta(current[i].ioctl_count, old ? old->ioctl_count : 0);
      dst[1] =
          stats_delta(current[i].netlink_count, old ? old->netlink_count : 0);
      dst[2] = stats_delta(current[i].proc_count, old ? old->proc_count : 0);
      dst[3] =
          stats_delta(current[i].sockopt_count, old ? old->sockopt_count : 0);
      dst[4] =
          stats_delta(current[i].connect_count, old ? old->connect_count : 0);
      dst[5] =
          stats_delta(current[i].getname_count, old ? old->getname_count : 0);
      dst[6] = stats_delta(current[i].port_count, old ? old->port_count : 0);
      dst[7] =
          stats_delta(current[i].java_pm_count, old ? old->java_pm_count : 0);
      dst[8] =
          stats_delta(current[i].java_um_count, old ? old->java_um_count : 0);
      dst[9] =
          stats_delta(current[i].java_nc_count, old ? old->java_nc_count : 0);
      dst[10] =
          stats_delta(current[i].java_ni_count, old ? old->java_ni_count : 0);
      dst[11] =
          stats_delta(current[i].java_net_count, old ? old->java_net_count : 0);
      dst[12] =
          stats_delta(current[i].java_lp_count, old ? old->java_lp_count : 0);
      dst[13] =
          stats_delta(current[i].java_cs_count, old ? old->java_cs_count : 0);
      out++;
    }
    point.count = delta_count;
  }
  if (!gap) {
    for (uint32_t i = 0, out = 0; i < current_port_count; i++) {
      const struct vpnhide_port_stats *old = find_port_stats(
          ring->previous_ports, ring->previous_port_count, current_ports[i].uid,
          current_ports[i].port, current_ports[i].protocol);
      uint64_t delta =
          stats_delta(current_ports[i].count, old ? old->count : 0);
      if (!delta)
        continue;
      point.ports[out] = current_ports[i];
      point.ports[out].count = delta;
      out++;
    }
    point.port_count = port_delta_count;
  }

  while (ring->count && ring->points[ring->head].timestamp_ms +
                                STATS_RETENTION_SEC * 1000ULL <=
                            timestamp_ms) {
    free_stats_point(&ring->points[ring->head]);
    ring->head = (ring->head + 1) % STATS_RING_POINTS;
    ring->count--;
    ring->dropped_intervals++;
  }

  if (ring->count == STATS_RING_POINTS) {
    free_stats_point(&ring->points[ring->head]);
    ring->head = (ring->head + 1) % STATS_RING_POINTS;
    ring->dropped_intervals++;
  } else {
    ring->count++;
  }
  ring->points[(ring->head + ring->count - 1) % STATS_RING_POINTS] = point;
  memcpy(ring->previous, current, current_count * sizeof(*current));
  if (current_port_count)
    memcpy(ring->previous_ports, current_ports,
           current_port_count * sizeof(*current_ports));
  ring->previous_count = current_count;
  ring->previous_port_count = current_port_count;
  ring->previous_sequence = sequence;
  ring->latest_sequence = sequence;
  ring->dropped_port_entries = dropped_port_entries;
  ring->baseline_valid = true;
}

void sample_stats(int fd, struct daemon_stats_ring *ring) {
  struct vpnhide_uid_stats *current = NULL;
  struct vpnhide_port_stats *current_ports = NULL;
  uint32_t count, port_count;
  uint64_t sequence, dropped_port_entries;
  if (read_kernel_stats(fd, &current, &count, &current_ports, &port_count,
                        &sequence, &dropped_port_entries) == 0) {
    if (port_count > 1)
      qsort(current_ports, port_count, sizeof(*current_ports),
            port_stats_compare);
    append_stats_point(ring, current, count, current_ports, port_count,
                       sequence, dropped_port_entries,
                       daemon_get_wall_time_ms());
  }
  free(current);
  free(current_ports);
}

static void write_stats_json(FILE *out, const struct daemon_stats_ring *ring) {
  unsigned long long oldest = 0, newest = 0;
  if (ring->count) {
    oldest = ring->points[ring->head].timestamp_ms;
    newest = ring->points[(ring->head + ring->count - 1) % STATS_RING_POINTS]
                 .timestamp_ms;
  }
  fprintf(out, "{\"sessionId\":\"%s\"",
          ring->session_id[0] ? ring->session_id : "unknown");
  fprintf(
      out,
      ",\"sequence\":%llu,\"resolutionSec\":%d,\"retentionSec\":%d,\"dropped\":"
      "%s,\"droppedIntervals\":%llu,\"droppedPortEntries\":%llu,"
      "\"oldestTimestampMs\":%llu,\"newestTimestampMs\":%llu,\"points\":[",
      (unsigned long long)ring->latest_sequence, STATS_RESOLUTION_SEC,
      STATS_RETENTION_SEC,
      (ring->dropped_intervals || ring->dropped_port_entries) ? "true"
                                                              : "false",
      ring->dropped_intervals, (unsigned long long)ring->dropped_port_entries,
      oldest, newest);
  for (unsigned int n = 0; n < ring->count; n++) {
    const struct daemon_stats_point *point =
        &ring->points[(ring->head + n) % STATS_RING_POINTS];
    if (n)
      fputc(',', out);
    fprintf(out, "{\"timestampMs\":%llu,\"gap\":%s,\"uids\":[",
            point->timestamp_ms, point->gap ? "true" : "false");
    for (uint32_t i = 0; i < point->count; i++) {
      const struct vpnhide_uid_stats *s = &point->entries[i];
      if (i)
        fputc(',', out);
      fprintf(
          out,
          "{\"uid\":%u,\"ioctl\":%llu,\"netlink\":%llu,\"proc\":%llu,"
          "\"sockopt\":%llu,\"connect\":%llu,\"getname\":%llu,\"port\":%llu,"
          "\"java_pm\":%llu,\"java_um\":%llu,\"java_nc\":%llu,\"java_ni\":%llu,"
          "\"java_net\":%llu,\"java_lp\":%llu,\"java_cs\":%llu,\"ports\":[",
          s->uid, (unsigned long long)s->ioctl_count,
          (unsigned long long)s->netlink_count,
          (unsigned long long)s->proc_count,
          (unsigned long long)s->sockopt_count,
          (unsigned long long)s->connect_count,
          (unsigned long long)s->getname_count,
          (unsigned long long)s->port_count,
          (unsigned long long)s->java_pm_count,
          (unsigned long long)s->java_um_count,
          (unsigned long long)s->java_nc_count,
          (unsigned long long)s->java_ni_count,
          (unsigned long long)s->java_net_count,
          (unsigned long long)s->java_lp_count,
          (unsigned long long)s->java_cs_count);
      bool first_port = true;
      for (uint32_t p = 0; p < point->port_count; p++) {
        const struct vpnhide_port_stats *port = &point->ports[p];
        if (port->uid != s->uid)
          continue;
        if (!first_port)
          fputc(',', out);
        fprintf(out, "{\"port\":%u,\"protocol\":\"%s\",\"count\":%llu}",
                port->port, port->protocol == VH_PROTO_UDP ? "udp" : "tcp",
                (unsigned long long)port->count);
        first_port = false;
      }
      fputs("]}", out);
    }
    fputs("]}", out);
  }
  fputs("]}\n", out);
}

int open_stats_socket(uid_t allowed_uid) {
  struct sockaddr_un address;
  int fd, length;
  memset(&address, 0, sizeof(address));
  address.sun_family = AF_UNIX;
  address.sun_path[0] = '\0';
  strncpy(address.sun_path + 1, STATS_SOCKET_NAME,
          sizeof(address.sun_path) - 2);
  length = (int)(offsetof(struct sockaddr_un, sun_path) + 1 +
                 strlen(STATS_SOCKET_NAME));
  fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (fd < 0 || bind(fd, (struct sockaddr *)&address, length) < 0 ||
      listen(fd, 4) < 0) {
    if (fd >= 0)
      close(fd);
    return -1;
  }
  (void)allowed_uid;
  return fd;
}

void serve_stats_client(int listen_fd, uid_t allowed_uid,
                        struct daemon_stats_ring *ring) {
  struct ucred peer;
  socklen_t peer_len = sizeof(peer);
  char command[64];
  int client = accept4(listen_fd, NULL, NULL, SOCK_CLOEXEC);
  if (client < 0)
    return;
  if (getsockopt(client, SOL_SOCKET, SO_PEERCRED, &peer, &peer_len) < 0 ||
      (peer.uid != allowed_uid && peer.uid != 0)) {
    close(client);
    return;
  }
  ssize_t length = read(client, command, sizeof(command) - 1);
  if (length > 0) {
    command[length] = '\0';
    FILE *out = fdopen(client, "w");
    if (out) {
      if (!strncmp(command, "CLEAR_HISTORY", 13))
        clear_stats_ring(ring);
      write_stats_json(out, ring);
      fclose(out);
      return;
    }
  }
  close(client);
}
