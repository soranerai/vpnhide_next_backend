  - Стоит сохранять IPv4/IPv6 route MTU физического интерфейса. Сейчас IP_MTU/IPV6_MTU и TCP MSS подменяются фиксированными 1500/1460; на PPPoE, некоторых cellular-сетях и нестандартных маршрутах это
    само может стать аномалией.

  - Адреса и cover-ifindex уже сохраняются — этого достаточно для будущей подмены IP_PKTINFO/IPV6_PKTINFO, где могут утекать локальный адрес и входной ifindex.

• Для подмены входящих IP_PKTINFO/IPV6_PKTINFO нужны не getsockopt-хуки, а post-hooks на формирование ancillary data (cmsghdr) при recvmsg.

  Оптимальные точки:

   Реализация    IPv4                                                             IPv6
  ━━━━━━━━━━━━  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
   kpatch        ip_cmsg_recv_pktinfo() либо его вызов в ip_cmsg_recv_offset()    ip6_datagram_recv_common_ctl()
  ────────────  ───────────────────────────────────────────────────────────────  ─────────────────────────────────────────────────────────────────────────────────
   kmod          kretprobe на ip_cmsg_recv_offset()                               kretprobe на ip6_datagram_recv_common_ctl(), fallback — ip6_datagram_recv_ctl()

  Именно там ядро формирует struct in_pktinfo и struct in6_pktinfo, после чего вызывает put_cmsg(): IPv4 source (https://github.com/torvalds/linux/blob/master/net/ipv4/ip_sockglue.c), IPv6 source
  (https://github.com/torvalds/linux/blob/master/net/ipv6/datagram.c#L558-L579).

  Подменять нужно:

  struct in_pktinfo {
      int         ipi_ifindex;   // -> cover_ifindex
  };

  struct in6_pktinfo {
      struct in6_addr ipi6_addr; // -> physical IPv6
      int             ipi6_ifindex; // -> cover_ifindex
  };

  Для kpatch лучше менять локальную структуру непосредственно перед put_cmsg(). Это наиболее чистый вариант: данные ещё находятся в kernel memory, размеры CMSG не меняются.

  Для kmod в entry-handler следует сохранить:

  - начальный msg->msg_control;
  - исходный msg->msg_controllen;
  - struct sock/UID.

  В return-handler — определить диапазон добавленных CMSG, пройти его с проверкой CMSG_OK, найти нужные (SOL_IP, IP_PKTINFO) и (SOL_IPV6, IPV6_PKTINFO) и переписать payload через copy_to_user().

  Почему не ограничиваться syscall-хуками:

  - Для обычного пути понадобились бы __arm64_sys_recvmsg и __arm64_sys_recvmmsg.
  - Для 32-битных приложений — ещё compat-варианты.
  - recvmmsg() содержит несколько сообщений, каждое со своим control buffer.
  - io_uring может идти напрямую через sock_recvmsg()/__sys_recvmsg_sock() и обходить syscall kretprobe; multishot-вариант вызывает sock_recvmsg() непосредственно. Linux socket receive path
    (https://github.com/torvalds/linux/blob/master/net/socket.c#L2709-L2776), io_uring receive path (https://github.com/torvalds/linux/blob/master/io_uring/net.c).

  Поэтому producer-level hooks надёжнее и автоматически покрывают:

  - recvmsg;
  - recvmmsg;
  - compat;
  - обычный io_uring recvmsg;
  - multishot io_uring;
  - UDP и raw sockets.

  Особые случаи:

  - Multicast/broadcast destination нельзя заменять физическим unicast IP: там меняется только ifindex, а group/broadcast address сохраняется.
  - Для IPv6 link-local нужен сохранённый link-local адрес cover-интерфейса и корректный scope/ifindex. Текущего глобального IPv6 недостаточно.
  - Следует обрабатывать MSG_ERRQUEUE: packet-info там тоже может содержать VPN-ifindex.
  - setsockopt(IP_PKTINFO) и setsockopt(IPV6_RECVPKTINFO) перехватывать не требуется — они лишь включают выдачу CMSG.
  - Если потребуется также исправлять исходящие ancillary data, отдельно понадобятся pre-hooks на ip_cmsg_send() и ip6_datagram_send_ctl() для sendmsg/sendmmsg.