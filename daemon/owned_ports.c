#include "daemon.h"

struct owned_port_list {
  struct vpnhide_owned_port *items;
  size_t count;
  size_t capacity;
};

static int append_owned_port(struct owned_port_list *list, uint32_t uid,
                             uint16_t port, uint8_t protocol, uint8_t family,
                             const uint32_t address[4]) {
  struct vpnhide_owned_port *grown;
  if (uid < 10000 || port == 0)
    return 0;
  if (list->count >= VPNHIDE_OWNED_PORTS_MAX)
    return -1;
  if (list->count == list->capacity) {
    size_t capacity = list->capacity ? list->capacity * 2 : 128;
    grown = realloc(list->items, capacity * sizeof(*grown));
    if (!grown)
      return -1;
    list->items = grown;
    list->capacity = capacity;
  }
  list->items[list->count++] = (struct vpnhide_owned_port){
      .uid = uid,
      .port = port,
      .protocol = protocol,
      .family = family,
  };
  memcpy(list->items[list->count - 1].address, address,
         sizeof(list->items[list->count - 1].address));
  return 0;
}

static bool diag_local_endpoint(const struct inet_diag_msg *msg,
                                uint8_t *family, uint32_t address[4]) {
  memset(address, 0, 4 * sizeof(*address));
  if (msg->idiag_family == AF_INET) {
    uint32_t addr = msg->id.idiag_src[0];
    if (addr != 0 && (ntohl(addr) >> 24) != 127)
      return false;
    *family = AF_INET;
    address[0] = addr;
    return true;
  }
  if (msg->idiag_family == AF_INET6) {
    struct in6_addr addr;
    memcpy(&addr, msg->id.idiag_src, sizeof(addr));
    if (IN6_IS_ADDR_UNSPECIFIED(&addr) || IN6_IS_ADDR_LOOPBACK(&addr)) {
      *family = AF_INET6;
      memcpy(address, &addr, sizeof(addr));
      return true;
    }
    if (IN6_IS_ADDR_V4MAPPED(&addr)) {
      uint32_t v4;
      memcpy(&v4, &addr.s6_addr[12], sizeof(v4));
      if ((ntohl(v4) >> 24) != 127)
        return false;
      *family = AF_INET;
      address[0] = v4;
      return true;
    }
  }
  return false;
}

static int dump_owned_ports_family(int fd, int family, int protocol,
                                   uint32_t sequence,
                                   struct owned_port_list *list) {
  struct {
    struct nlmsghdr nlh;
    struct inet_diag_req_v2 req;
  } request;
  struct sockaddr_nl kernel = {.nl_family = AF_NETLINK};
  char buffer[32768];

  memset(&request, 0, sizeof(request));
  request.nlh.nlmsg_len = sizeof(request);
  request.nlh.nlmsg_type = SOCK_DIAG_BY_FAMILY;
  request.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
  request.nlh.nlmsg_seq = sequence;
  request.req.sdiag_family = family;
  request.req.sdiag_protocol = protocol;
  request.req.idiag_states =
      protocol == IPPROTO_TCP ? (1U << TCP_LISTEN) : UINT32_MAX;
  if (sendto(fd, &request, sizeof(request), 0, (struct sockaddr *)&kernel,
             sizeof(kernel)) < 0)
    return -1;

  for (;;) {
    ssize_t length = recv(fd, buffer, sizeof(buffer), 0);
    struct nlmsghdr *nlh;
    if (length < 0) {
      if (errno == EINTR)
        continue;
      return -1;
    }
    for (nlh = (struct nlmsghdr *)buffer; NLMSG_OK(nlh, length);
         nlh = NLMSG_NEXT(nlh, length)) {
      struct inet_diag_msg *msg;
      uint32_t local_address[4];
      uint8_t local_family;
      if (nlh->nlmsg_seq != sequence)
        continue;
      if (nlh->nlmsg_type == NLMSG_DONE)
        return 0;
      if (nlh->nlmsg_type == NLMSG_ERROR)
        return -1;
      if (nlh->nlmsg_type != SOCK_DIAG_BY_FAMILY ||
          nlh->nlmsg_len < NLMSG_LENGTH(sizeof(*msg)))
        continue;
      msg = NLMSG_DATA(nlh);
      if (!diag_local_endpoint(msg, &local_family, local_address))
        continue;
      /* Connected UDP clients are not local services. */
      if (protocol == IPPROTO_UDP && msg->id.idiag_dport != 0)
        continue;
      if (append_owned_port(list, msg->idiag_uid, ntohs(msg->id.idiag_sport),
                            protocol == IPPROTO_TCP ? VH_PROTO_TCP
                                                    : VH_PROTO_UDP,
                            local_family, local_address) < 0)
        return -1;
    }
  }
}

static int owned_port_compare(const void *left, const void *right) {
  const struct vpnhide_owned_port *a = left, *b = right;
  if (a->uid != b->uid)
    return a->uid < b->uid ? -1 : 1;
  if (a->port != b->port)
    return a->port < b->port ? -1 : 1;
  if (a->protocol != b->protocol)
    return (int)a->protocol - (int)b->protocol;
  if (a->family != b->family)
    return (int)a->family - (int)b->family;
  return memcmp(a->address, b->address, sizeof(a->address));
}

int refresh_owned_ports(int control_fd) {
  struct owned_port_list list = {0};
  struct vpnhide_owned_ports_update update;
  int diag_fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_SOCK_DIAG);
  uint32_t sequence = 1;
  int ret = -1;

  if (diag_fd < 0)
    return -1;
  if (dump_owned_ports_family(diag_fd, AF_INET, IPPROTO_TCP, sequence++,
                              &list) ||
      dump_owned_ports_family(diag_fd, AF_INET6, IPPROTO_TCP, sequence++,
                              &list) ||
      dump_owned_ports_family(diag_fd, AF_INET, IPPROTO_UDP, sequence++,
                              &list) ||
      dump_owned_ports_family(diag_fd, AF_INET6, IPPROTO_UDP, sequence++,
                              &list))
    goto out;

  qsort(list.items, list.count, sizeof(*list.items), owned_port_compare);
  if (list.count) {
    size_t out_count = 1;
    for (size_t i = 1; i < list.count; i++)
      if (owned_port_compare(&list.items[out_count - 1], &list.items[i]))
        list.items[out_count++] = list.items[i];
    list.count = out_count;
  }
  memset(&update, 0, sizeof(update));
  update.count = (uint32_t)list.count;
  update.entries_ptr = (uint64_t)(uintptr_t)list.items;
  ret = ioctl(control_fd, VH_SET_OWNED_PORTS, &update);
out:
  close(diag_fd);
  free(list.items);
  return ret;
}

int open_diag_events(void) {
  struct sockaddr_nl address;
  int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC,
                  NETLINK_SOCK_DIAG);
  if (fd < 0)
    return -1;
  memset(&address, 0, sizeof(address));
  address.nl_family = AF_NETLINK;
  address.nl_groups = (1U << (SKNLGRP_INET_TCP_DESTROY - 1)) |
                      (1U << (SKNLGRP_INET_UDP_DESTROY - 1)) |
                      (1U << (SKNLGRP_INET6_TCP_DESTROY - 1)) |
                      (1U << (SKNLGRP_INET6_UDP_DESTROY - 1));
  if (bind(fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
    close(fd);
    return -1;
  }
  return fd;
}
