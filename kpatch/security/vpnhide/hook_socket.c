// SPDX-License-Identifier: GPL-2.0
/*
 * vpnhide — socket hooks
 */

#include <linux/net.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/if.h>
#include <linux/file.h>
#include <linux/netdevice.h>
#include <net/sock.h>
#include <net/inet_sock.h>
#include <net/ipv6.h>
#include <net/tcp.h>

#include "vpnhide.h"

/*
 * Internal socket marker: set on sockets where we have already intercepted
 * IP_MTU_DISCOVER or UDP_SEGMENT to indicate this is a diagnostic probe.
 * The UDP rate-limiter skips these sockets to avoid dropping probe sends.
 * BIT(31) is unused by normal routing; we preserve it across SO_MARK resets.
 */
#define VH_SK_PROBE_MARK  BIT(31)

/* ------------------------------------------------------------------ */
/* setsockopt — called BEFORE the real handler                         */
/*   returns 0  → allow                                                */
/*   returns <0 → kernel returns that errno to userspace               */
/*   returns 1  → intercepted; caller maps this to 0 (success)         */
/* ------------------------------------------------------------------ */

int vpnhide_setsockopt_sock(struct socket *sock, int level, int optname,
			    sockptr_t optval, unsigned int optlen)
{
	struct sock *sk;
	uid_t uid;

	if (!sock || !sock->sk)
		return 0;

	uid = from_kuid(&init_user_ns, current_uid());
	if (!is_hook_active(HOOK_SETSOCKOPT, uid))
		return 0;
	if (!is_target_uid_val(uid))
		return 0;

	sk = sock->sk;

	if (level == SOL_SOCKET) {
		switch (optname) {
		case SO_BINDTODEVICE: {
			char devname[IFNAMSIZ] = {};

			if (optlen == 0)
				break;
			if (copy_from_sockptr(devname, optval,
					      min_t(unsigned int, optlen,
						    IFNAMSIZ - 1)))
				break;
			if (devname[0] && is_active_vpn_ifname(devname)) {
				record_kmod_intercept(uid, HOOK_SETSOCKOPT);
				return -ENODEV;
			}
			break;
		}
		case SO_BINDTOIFINDEX: {
			int ifindex = 0;

			if (optlen != sizeof(ifindex))
				break;
			if (copy_from_sockptr(&ifindex, optval,
					      sizeof(ifindex)))
				break;
			if (ifindex && is_active_vpn_ifindex(ifindex)) {
				record_kmod_intercept(uid, HOOK_SETSOCKOPT);
				return -ENODEV;
			}
			break;
		}
		case SO_MARK: {
			/* Force mark to 0 — prevents routing via VPN table.
			 * Preserve VH_SK_PROBE_MARK (bit 31): it is our internal
			 * flag, never a real routing mark. */
			u32 probe_bit = sk->sk_mark & VH_SK_PROBE_MARK;
			if (sk->sk_mark != probe_bit) {
				sk->sk_mark = probe_bit;
				record_kmod_intercept(uid, HOOK_SETSOCKOPT);
			}
			/* swallow the setsockopt normally — just pre-zero */
			break;
		}
		case SO_TIMESTAMPING: {
			u32 flags = 0;

			if (optlen != sizeof(flags))
				break;
			if (copy_from_sockptr(&flags, optval, sizeof(flags)))
				break;
			flags &= ~(SOF_TIMESTAMPING_TX_HARDWARE |
				   SOF_TIMESTAMPING_RX_HARDWARE |
				   SOF_TIMESTAMPING_RAW_HARDWARE);
			/* Replace optval in-place not possible via sockptr;
			 * instead zero HW bits on sk after the real call.
			 * We store intent: hook_socket handles post-set. */
			break;
		}
		}
	} else if (level == SOL_IP) {
		if (optname == IP_MTU_DISCOVER) {
			/* inet_sk() is only valid for IPv4 inet sockets.  The hook
			 * runs before the normal protocol handler, so do the family
			 * and ABI validation here instead of relying on it. */
			if (sk->sk_family != AF_INET || optlen != sizeof(int))
				return 0;
			/* Force PMTUDISC_DONT; set directly on sk, skip real handler.
			 * Mark socket as a probe so the UDP rate-limiter won't drop
			 * the subsequent test send (check_udp_pmtu). */
			inet_sk(sk)->pmtudisc = IP_PMTUDISC_DONT;
			sk->sk_mark |= VH_SK_PROBE_MARK;
			record_kmod_intercept(uid, HOOK_SETSOCKOPT);
			return 1;
		}
	} else if (level == SOL_IPV6) {
		if (optname == IPV6_MTU_DISCOVER) {
			if (sk->sk_family != AF_INET6 || optlen != sizeof(int))
				return 0;
			inet6_sk(sk)->pmtudisc = IPV6_PMTUDISC_DONT;
			sk->sk_mark |= VH_SK_PROBE_MARK;
			record_kmod_intercept(uid, HOOK_SETSOCKOPT);
			return 1;
		}
	} else if (level == SOL_UDP) {
		if (optname == UDP_SEGMENT) {
			/* udp_sk() is not a generic struct sock cast. */
			if (sk->sk_protocol != IPPROTO_UDP ||
			    sk->sk_type != SOCK_DGRAM ||
			    optlen != sizeof(int))
				return 0;
			/* Zero gso_size directly; skip the real handler so it
			 * cannot restore the user-supplied non-zero value.
			 * Mark socket as a probe so the rate-limiter won't drop
			 * the subsequent large test send (check_gso_asymmetry). */
			udp_sk(sk)->gso_size = 0;
			sk->sk_mark |= VH_SK_PROBE_MARK;
			record_kmod_intercept(uid, HOOK_SETSOCKOPT);
			return 1;
		}
	}
	return 0;
}
EXPORT_SYMBOL_GPL(vpnhide_setsockopt_sock);

/* ------------------------------------------------------------------ */
/* getsockopt — called AFTER the real handler with the result buffer   */
/* ------------------------------------------------------------------ */

void vpnhide_getsockopt_post(struct socket *sock, int level, int optname,
			     char __user *optval, int __user *optlen)
{
	struct sock *sk;
	struct vpnhide_spoof_ip sip;
	uid_t uid;
	int len = 0;

	if (!sock || !sock->sk || !optval || !optlen)
		return;

	uid = from_kuid(&init_user_ns, current_uid());
	if (!is_hook_active(HOOK_GETSOCKOPT, uid))
		return;
	if (!is_target_uid_val(uid))
		return;

	if (get_user(len, optlen))
		return;

	sk = sock->sk;
	get_spoof_ip(&sip);

	if (level == SOL_SOCKET) {
		switch (optname) {
		case SO_BINDTODEVICE: {
			/* Return empty string — pretend socket is unbound */
			char empty = 0;

			if (put_user(1, optlen))
				return;
			put_user(empty, optval);
			record_kmod_intercept(uid, HOOK_GETSOCKOPT);
			break;
		}
		case SO_BINDTOIFINDEX: {
			int zero = 0;

			if (len >= (int)sizeof(zero)) {
				if (!copy_to_user(optval, &zero, sizeof(zero)))
					record_kmod_intercept(uid, HOOK_GETSOCKOPT);
			}
			break;
		}
		}
	} else if (level == SOL_IP) {
		switch (optname) {
		case IP_MTU: {
			int mtu = sip.ipv4_mtu ? sip.ipv4_mtu : 1500;

			if (len >= (int)sizeof(mtu)) {
				if (!copy_to_user(optval, &mtu, sizeof(mtu)))
					record_kmod_intercept(uid, HOOK_GETSOCKOPT);
			}
			break;
		}
		case IP_MTU_DISCOVER: {
			int val = IP_PMTUDISC_DONT;

			if (len >= (int)sizeof(val)) {
				if (!copy_to_user(optval, &val, sizeof(val)))
					record_kmod_intercept(uid, HOOK_GETSOCKOPT);
			}
			break;
		}
		}
	} else if (level == SOL_IPV6) {
		if (optname == IPV6_MTU) {
			int mtu = sip.ipv6_mtu ? sip.ipv6_mtu : 1500;

			if (len >= (int)sizeof(mtu)) {
				if (!copy_to_user(optval, &mtu, sizeof(mtu)))
					record_kmod_intercept(uid, HOOK_GETSOCKOPT);
			}
		}
	} else if (level == SOL_TCP) {
		switch (optname) {
		case TCP_MAXSEG: {
			int mtu = sk->sk_family == AF_INET6
					? (sip.ipv6_mtu ? sip.ipv6_mtu : 1500)
					: (sip.ipv4_mtu ? sip.ipv4_mtu : 1500);
			int header_len = sk->sk_family == AF_INET6 ? 60 : 40;
			int mss = mtu > header_len ? mtu - header_len : 1460;

			if (len >= (int)sizeof(mss)) {
				if (!copy_to_user(optval, &mss, sizeof(mss)))
					record_kmod_intercept(uid, HOOK_GETSOCKOPT);
			}
			break;
		}
		case TCP_INFO: {
			struct tcp_info info;
			/* lib.rs passes a partial TcpInfoMss (24 bytes) — only require
			 * enough buffer to reach tcpi_rcv_mss, not the full tcp_info. */
			int need = offsetof(struct tcp_info, tcpi_rcv_mss) +
				   (int)sizeof(u32);

			if (len < need)
				break;
			if (copy_from_user(&info, optval,
					   min_t(int, len, (int)sizeof(info))))
				break;
			{
				int mtu = sk->sk_family == AF_INET6
						? (sip.ipv6_mtu ? sip.ipv6_mtu : 1500)
						: (sip.ipv4_mtu ? sip.ipv4_mtu : 1500);
				int header_len = sk->sk_family == AF_INET6 ? 60 : 40;
				u32 mss = mtu > header_len ? mtu - header_len : 1460;

				info.tcpi_snd_mss = mss;
				info.tcpi_rcv_mss = mss;
			}
			if (!copy_to_user(optval, &info,
					  min_t(int, len, (int)sizeof(info))))
				record_kmod_intercept(uid, HOOK_GETSOCKOPT);
			break;
		}
		}
	}
}
EXPORT_SYMBOL_GPL(vpnhide_getsockopt_post);

/* ------------------------------------------------------------------ */
/* recvmsg ancillary packet info                                      */
/* ------------------------------------------------------------------ */

void vpnhide_pktinfo4_post(struct in_pktinfo *info)
{
	uid_t uid;
	int cover_ifindex;

	if (!info || !is_active_vpn_ifindex(info->ipi_ifindex))
		return;
	uid = from_kuid(&init_user_ns, current_uid());
	if (!is_hook_active(HOOK_GETNAME_INET, uid) || !is_target_uid_val(uid))
		return;
	cover_ifindex = atomic_read(&global_cover_ifindex);
	if (cover_ifindex <= 0)
		return;
	info->ipi_ifindex = cover_ifindex;
	record_kmod_intercept(uid, HOOK_GETNAME_INET);
}
EXPORT_SYMBOL_GPL(vpnhide_pktinfo4_post);

void vpnhide_pktinfo6_post(struct in6_pktinfo *info)
{
	struct vpnhide_spoof_ip sip;
	uid_t uid;
	int cover_ifindex;

	if (!info || !is_active_vpn_ifindex(info->ipi6_ifindex))
		return;
	uid = from_kuid(&init_user_ns, current_uid());
	if (!is_hook_active(HOOK_GETNAME_INET6, uid) || !is_target_uid_val(uid))
		return;
	cover_ifindex = atomic_read(&global_cover_ifindex);
	if (cover_ifindex <= 0)
		return;
	info->ipi6_ifindex = cover_ifindex;
	/* Global cover addresses are invalid for multicast/link-local packets. */
	if (ipv6_addr_type(&info->ipi6_addr) & IPV6_ADDR_LINKLOCAL) {
		get_spoof_ip(&sip);
		if (sip.has_ipv6_linklocal)
			memcpy(&info->ipi6_addr, sip.ipv6_linklocal_addr,
			       sizeof(info->ipi6_addr));
	} else if (!ipv6_addr_is_multicast(&info->ipi6_addr)) {
		get_spoof_ip(&sip);
		if (sip.has_ipv6)
			memcpy(&info->ipi6_addr, sip.ipv6_addr,
			       sizeof(info->ipi6_addr));
	}
	record_kmod_intercept(uid, HOOK_GETNAME_INET6);
}
EXPORT_SYMBOL_GPL(vpnhide_pktinfo6_post);

/* ------------------------------------------------------------------ */
/* connect — block connections to loopback ports matching rules        */
/* ------------------------------------------------------------------ */

static bool should_block_port(uid_t uid, __be16 port_be,
			      unsigned char protocol)
{
	struct vpnhide_policy_snapshot *snapshot;
	const struct vpnhide_port_target_v3 *target;
	u16 port = ntohs(port_be);
	bool block = false;
	u32 j;

	rcu_read_lock();
	snapshot = rcu_dereference(global_policy_snapshot);
	target = vpnhide_find_port_target(snapshot, uid);
	if (!target)
		goto out;
	if (target->mode == VH_PORT_POLICY_UNRESTRICTED)
		goto out;
	if (target->mode == VH_PORT_POLICY_DENY_ALL) {
		block = true;
		goto out;
	}
	for (j = 0; j < target->rule_count; j++) {
		const struct vpnhide_port_rule_v3 *rule =
			&snapshot->port_rules[target->first_rule + j];
		if (port >= rule->start_port && port <= rule->end_port &&
		    (rule->protocol == VH_PROTO_BOTH || rule->protocol == protocol)) {
			block = true;
			goto out;
		}
		if (rule->start_port > port)
			break;
	}
out:
	rcu_read_unlock();
	return block;
}

int vpnhide_connect_pre(struct socket *sock,
			struct sockaddr *addr, int addrlen)
{
	uid_t uid;
	sa_family_t family;
	unsigned char protocol;

	if (!(vpnhide_active_hooks_mask() & BIT(HOOK_CONNECT)))
		return 0;
	uid = from_kuid(&init_user_ns, current_uid());
	if (!is_hook_active(HOOK_CONNECT, uid))
		return 0;
	if (!sock || !sock->sk)
		return 0;

	family = addr->sa_family;
	protocol = sock->sk->sk_type == SOCK_STREAM ?
		VH_PROTO_TCP : VH_PROTO_UDP;

	if (family == AF_INET) {
		struct sockaddr_in *sin = (struct sockaddr_in *)addr;

		if (ipv4_is_loopback(sin->sin_addr.s_addr) ||
		    sin->sin_addr.s_addr == 0) {
			u32 address[4] = { (__force u32)sin->sin_addr.s_addr, 0, 0, 0 };

			if (should_block_port(uid, sin->sin_port, protocol) &&
			    !vpnhide_uid_owns_port(uid, ntohs(sin->sin_port), protocol,
						   AF_INET, address)) {
				record_port_intercept(uid, ntohs(sin->sin_port), protocol);
				return -ECONNREFUSED;
			}
		}
	} else if (family == AF_INET6) {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)addr;

		bool local = ipv6_addr_loopback(&sin6->sin6_addr) ||
			     ipv6_addr_any(&sin6->sin6_addr);

		if (!local && ipv6_addr_v4mapped(&sin6->sin6_addr)) {
			__be32 v4addr = sin6->sin6_addr.s6_addr32[3];
			local = ipv4_is_loopback(v4addr) || v4addr == 0;
		}
		if (local) {
			u8 owner_family = AF_INET6;
			u32 owner_address[4];

			memcpy(owner_address, &sin6->sin6_addr, sizeof(owner_address));
			if (ipv6_addr_v4mapped(&sin6->sin6_addr)) {
				owner_family = AF_INET;
				owner_address[0] =
					(__force u32)sin6->sin6_addr.s6_addr32[3];
				owner_address[1] = owner_address[2] = owner_address[3] = 0;
			}
			if (should_block_port(uid, sin6->sin6_port, protocol) &&
			    !vpnhide_uid_owns_port(uid, ntohs(sin6->sin6_port), protocol,
						   owner_family, owner_address)) {
				record_port_intercept(uid, ntohs(sin6->sin6_port), protocol);
				return -ECONNREFUSED;
			}
		}
	}
	return 0;
}
EXPORT_SYMBOL_GPL(vpnhide_connect_pre);

/* ------------------------------------------------------------------ */
/* bind — establish ownership without applying connect access policy   */
/* ------------------------------------------------------------------ */

int vpnhide_bind_pre(struct socket *sock,
		     struct sockaddr *addr, int addrlen)
{
	/* A successful bind is recorded by vpnhide_bind_post().  Rewriting the
	 * requested port here would make an app unable to reach its own service. */
	(void)sock;
	(void)addr;
	(void)addrlen;
	return 0;
}
EXPORT_SYMBOL_GPL(vpnhide_bind_pre);

void vpnhide_bind_post(struct socket *sock, int error)
{
	struct sock *sk;
	uid_t uid;

	if (error || !sock || !(sk = sock->sk) ||
	    (sk->sk_family != AF_INET && sk->sk_family != AF_INET6) ||
	    sk->sk_type != SOCK_DGRAM)
		return;
	uid = from_kuid(&init_user_ns, current_uid());
	vpnhide_record_bound_socket(uid, sk);
}
EXPORT_SYMBOL_GPL(vpnhide_bind_post);

void vpnhide_listen_post(struct socket *sock, int error)
{
	struct sock *sk;
	uid_t uid;

	if (error || !sock || !(sk = sock->sk) ||
	    (sk->sk_family != AF_INET && sk->sk_family != AF_INET6) ||
	    sk->sk_type != SOCK_STREAM)
		return;
	uid = from_kuid(&init_user_ns, current_uid());
	vpnhide_record_bound_socket(uid, sk);
}
EXPORT_SYMBOL_GPL(vpnhide_listen_post);

/* ------------------------------------------------------------------ */
/* getname — spoof IP address in the returned sockaddr                 */
/* Called AFTER inet_getname / inet6_getname fills uaddr.              */
/* ------------------------------------------------------------------ */

void vpnhide_getname_post(struct socket *sock, struct sockaddr *addr, int peer)
{
	struct vpnhide_spoof_ip sip;
	uid_t uid;
	sa_family_t family;

	if (peer)
		return; /* only spoof local name */

	uid = from_kuid(&init_user_ns, current_uid());
	if (!is_hook_active(HOOK_GETNAME_INET, uid) &&
	    !is_hook_active(HOOK_GETNAME_INET6, uid))
		return;
	if (!is_target_uid_val(uid))
		return;

	/* Don't spoof sockets explicitly bound to a non-VPN interface —
	 * that would replace a valid physical IP with a VPN IP and expose
	 * the spoofing to the test. */
	if (sock->sk && sock->sk->sk_bound_dev_if &&
	    !is_active_vpn_ifindex((u32)sock->sk->sk_bound_dev_if))
		return;

	get_spoof_ip(&sip);

	family = addr->sa_family;

	if (family == AF_INET) {
		struct sockaddr_in *sin = (struct sockaddr_in *)addr;

		if (!is_hook_active(HOOK_GETNAME_INET, uid))
			return;
		if (sin->sin_addr.s_addr == 0 ||
		    (ntohl(sin->sin_addr.s_addr) & 0xFF000000) == 0x7F000000)
			return;
		/* Spoof: use configured IP, or fall back to INADDR_ANY so the
		 * real VPN address is never returned to a target process. */
		sin->sin_addr.s_addr = (sip.has_ipv4 && sip.ipv4_addr)
			? sip.ipv4_addr : 0;
		record_kmod_intercept(uid, HOOK_GETNAME_INET);
	} else if (family == AF_INET6) {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)addr;

		if (!is_hook_active(HOOK_GETNAME_INET6, uid))
			return;
		if (ipv6_addr_any(&sin6->sin6_addr) ||
		    ipv6_addr_loopback(&sin6->sin6_addr))
			return;
		if (sip.has_ipv6 &&
		    !ipv6_addr_any((struct in6_addr *)sip.ipv6_addr)) {
			memcpy(&sin6->sin6_addr, sip.ipv6_addr, 16);
		} else {
			/* default spoof: 2001:db8::10 */
			struct in6_addr spoof = IN6ADDR_ANY_INIT;
			spoof.s6_addr16[0] = htons(0x2001);
			spoof.s6_addr16[1] = htons(0x0db8);
			spoof.s6_addr[15]  = 0x10;
			sin6->sin6_addr = spoof;
		}
		record_kmod_intercept(uid, HOOK_GETNAME_INET6);
	}
}
EXPORT_SYMBOL_GPL(vpnhide_getname_post);

/* ------------------------------------------------------------------ */
/* inet6_bind_ll — block link-local bind on VPN scope_id               */
/* ------------------------------------------------------------------ */

int vpnhide_inet6_bind_ll(struct sock *sk,
			  struct sockaddr *uaddr, int addr_len)
{
	struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)uaddr;
	uid_t uid = from_kuid(&init_user_ns, current_uid());

	if (addr_len < (int)sizeof(*sin6))
		return 0;
	if (sin6->sin6_family != AF_INET6)
		return 0;
	if (!(ipv6_addr_type(&sin6->sin6_addr) & IPV6_ADDR_LINKLOCAL))
		return 0;
	if (!is_hook_active(HOOK_INET6_BIND_LL, uid))
		return 0;
	if (!is_target_uid_val(uid))
		return 0;
	if (!is_active_vpn_ifindex(sin6->sin6_scope_id)) {
		/* ifindex not tracked by daemon yet — resolve name and check */
		struct net_device *_dev;
		bool _vpn;

		if (!sin6->sin6_scope_id)
			return 0;
		_dev = dev_get_by_index(sock_net(sk), sin6->sin6_scope_id);
		if (!_dev)
			return 0;
		_vpn = is_active_vpn_ifname(_dev->name);
		dev_put(_dev);
		if (!_vpn)
			return 0;
	}

	record_kmod_intercept(uid, HOOK_INET6_BIND_LL);
	return -ENODEV;
}
EXPORT_SYMBOL_GPL(vpnhide_inet6_bind_ll);

/* ------------------------------------------------------------------ */
/* udpv6_sendmsg_ll — block UDP link-local toward VPN interface        */
/* ------------------------------------------------------------------ */

bool vpnhide_udpv6_sendmsg_ll(struct sock *sk, struct msghdr *msg)
{
	struct ipv6_pinfo *np;
	uid_t uid;
	u32 oifindex;

	if (!(vpnhide_active_hooks_mask() & BIT(HOOK_UDPV6_SENDMSG)))
		return false;
	uid = from_kuid(&init_user_ns, current_uid());
	if (!is_hook_active(HOOK_UDPV6_SENDMSG, uid))
		return false;
	if (!is_target_uid_val(uid))
		return false;

	np = inet6_sk(sk);
	if (!np)
		return false;

	oifindex = 0;
	if (msg && msg->msg_name &&
	    msg->msg_namelen >= sizeof(struct sockaddr_in6)) {
		const struct sockaddr_in6 *sin6 = msg->msg_name;
		if (sin6->sin6_family == AF_INET6 &&
		    (ipv6_addr_type(&sin6->sin6_addr) & IPV6_ADDR_LINKLOCAL))
			oifindex = sin6->sin6_scope_id;
	}
	if (!oifindex)
		oifindex = sk->sk_bound_dev_if;

	if (!is_active_vpn_ifindex(oifindex)) {
		/* ifindex not tracked by daemon yet — resolve name and check */
		struct net_device *_dev;
		bool _vpn;

		if (!oifindex)
			return false;
		_dev = dev_get_by_index(sock_net(sk), oifindex);
		if (!_dev)
			return false;
		_vpn = is_active_vpn_ifname(_dev->name);
		dev_put(_dev);
		if (!_vpn)
			return false;
	}

	record_kmod_intercept(uid, HOOK_UDPV6_SENDMSG);
	return true;
}
EXPORT_SYMBOL_GPL(vpnhide_udpv6_sendmsg_ll);

/* ------------------------------------------------------------------ */
/* UDP destination scoping — only rate-limit sends that actually       */
/* egress through a currently-hidden VPN interface. Real physical      */
/* interfaces produce genuine EAGAIN under sustained flood (BQL /      */
/* netif_stop_queue hold sk_wmem_alloc up); loopback and other local    */
/* traffic never experiences this, so throttling it unconditionally    */
/* is itself a distinguishing artifact, not a faithful emulation.      */
/* ------------------------------------------------------------------ */

static bool vpnhide_udp_dst_is_vpn(struct sock *sk, struct msghdr *msg)
{
	struct dst_entry *dst;
	bool vpn;

	/* Unconnected sendto() resolves its route inside udp_sendmsg/
	 * udpv6_sendmsg itself, after this hook already ran — there is no
	 * cheap way to learn the egress device yet. Fail open rather than
	 * duplicate the kernel's own route lookup from this context. */
	if (msg && msg->msg_name)
		return false;

	if (sk->sk_family == AF_INET6) {
		if (ipv6_addr_loopback(&sk->sk_v6_daddr))
			return false;
	} else {
		if (ipv4_is_loopback(inet_sk(sk)->inet_daddr))
			return false;
	}

	dst = sk_dst_get(sk);
	if (!dst)
		return false;
	vpn = dst->dev && is_active_vpn_ifindex(dst->dev->ifindex);
	dst_release(dst);
	return vpn;
}

/* ------------------------------------------------------------------ */
/* UDP rate limiter — token bucket per UID                             */
/* ------------------------------------------------------------------ */

static DEFINE_HASHTABLE(rl_table, 8);
static DEFINE_SPINLOCK(rl_lock);

static struct vh_udp_uid_rate *rl_find_or_alloc(uid_t uid)
{
	struct vh_udp_uid_rate *rate;
	hash_for_each_possible(rl_table, rate, node, uid)
		if (rate->uid == uid)
			return rate;
	rate = kmalloc(sizeof(*rate), GFP_ATOMIC);
	if (!rate)
		return NULL;
	rate->uid = uid;
	rate->tokens = VH_UDP_BUCKET_MAX;
	rate->last_regen = ktime_get();
	hash_add(rl_table, &rate->node, uid);
	return rate;
}

void vpnhide_udp_rates_prune(const struct vpnhide_policy_snapshot *snapshot)
{
	struct vh_udp_uid_rate *rate;
	struct hlist_node *tmp;
	unsigned int bucket;
	spin_lock(&rl_lock);
	hash_for_each_safe(rl_table, bucket, tmp, rate, node) {
		int lo = 0, hi = snapshot ? snapshot->kmod_count - 1 : -1;
		bool keep = false;
		while (lo <= hi) {
			int mid = lo + ((hi - lo) >> 1);
			if (snapshot->kmod_uids[mid] == rate->uid) {
				keep = true;
				break;
			}
			if (snapshot->kmod_uids[mid] < rate->uid)
				lo = mid + 1;
			else
				hi = mid - 1;
		}
		if (!keep) {
			hash_del(&rate->node);
			kfree(rate);
		}
	}
	spin_unlock(&rl_lock);
}

void vpnhide_udp_rates_destroy(void)
{
	vpnhide_udp_rates_prune(NULL);
}

bool vpnhide_udp_sendmsg(struct sock *sk)
{
	struct vh_udp_uid_rate *r;
	uid_t uid;
	ktime_t now;
	s64 elapsed_ns;
	int regen;
	bool drop = false;

	if (!(vpnhide_active_hooks_mask() & BIT(HOOK_UDP_SENDMSG)))
		return false;

	/* Probe sockets (IP_MTU_DISCOVER / UDP_SEGMENT intercepted) must not
	 * be rate-limited: dropping their test send would cause check_udp_pmtu
	 * to return "check error" and check_gso_asymmetry to return "VPN
	 * detected" even when all other hooks are working correctly. */
	if (READ_ONCE(sk->sk_mark) & VH_SK_PROBE_MARK)
		return false;

	uid = from_kuid(&init_user_ns, current_uid());

	if (!is_hook_active(HOOK_UDP_SENDMSG, uid))
		return false;
	if (!is_target_uid_val(uid))
		return false;

	spin_lock(&rl_lock);
	r = rl_find_or_alloc(uid);
	if (!r) {
		spin_unlock(&rl_lock);
		return false;
	}

	now = ktime_get();
	elapsed_ns = ktime_to_ns(ktime_sub(now, r->last_regen));
	regen = (int)(elapsed_ns / VH_UDP_REGEN_NS);
	if (regen > 0) {
		r->tokens = min(r->tokens + regen, VH_UDP_BUCKET_MAX);
		r->last_regen = ktime_add_ns(r->last_regen,
					     regen * VH_UDP_REGEN_NS);
	}
	if (r->tokens > 0) {
		r->tokens--;
	} else {
		drop = true;
	}
	spin_unlock(&rl_lock);

	if (drop)
		record_kmod_intercept(uid, HOOK_UDP_SENDMSG);
	return drop;
}
EXPORT_SYMBOL_GPL(vpnhide_udp_sendmsg);

bool vpnhide_udp_sendmsg_pre(struct sock *sk, struct msghdr *msg,
			     size_t len, int *err)
{
	if (sk->sk_family == AF_INET6 && vpnhide_udpv6_sendmsg_ll(sk, msg)) {
		*err = -ENODEV;
		return true;
	}

	if (!vpnhide_udp_dst_is_vpn(sk, msg))
		return false;

	if (!vpnhide_udp_sendmsg(sk))
		return false;
	/* Look like a saturated send queue (EAGAIN), not a permission
	 * failure — otherwise userspace can fingerprint the shim by its
	 * distinct errno. */
	*err = -EAGAIN;
	return true;
}
EXPORT_SYMBOL_GPL(vpnhide_udp_sendmsg_pre);

/* ------------------------------------------------------------------ */
/* Wrappers matching names injected by patch_kernel.py                 */
/* ------------------------------------------------------------------ */

void vpnhide_bind(struct socket *sock, struct sockaddr __user *umyaddr,
		  int addrlen)
{
	struct sockaddr_storage kaddr;

	if (move_addr_to_kernel(umyaddr, addrlen, &kaddr))
		return;
	vpnhide_bind_pre(sock, (struct sockaddr *)&kaddr, addrlen);
	/* Write back — vpnhide_bind_pre may have zeroed the port to trigger
	 * ephemeral allocation.  The syscall uses umyaddr, so we must reflect
	 * the change back to user space. */
	if (copy_to_user(umyaddr, &kaddr, addrlen)) {
		/* ignore failure since bind already succeeded or we are in post-hook */
	}
}
EXPORT_SYMBOL_GPL(vpnhide_bind);

bool vpnhide_connect(struct socket *sock, struct sockaddr __user *uservaddr,
		     int addrlen, int *ret)
{
	struct sockaddr_storage kaddr;

	if (move_addr_to_kernel(uservaddr, addrlen, &kaddr))
		return false;
	*ret = vpnhide_connect_pre(sock, (struct sockaddr *)&kaddr, addrlen);
	return (*ret != 0);
}
EXPORT_SYMBOL_GPL(vpnhide_connect);

void vpnhide_getname(struct socket *sock, struct sockaddr *addr,
		     int peer, int *err)
{
	vpnhide_getname_post(sock, addr, peer);
}
EXPORT_SYMBOL_GPL(vpnhide_getname);

bool vpnhide_setsockopt(int fd, int level, int optname,
			char __user *user_optval, unsigned int optlen, int *ret)
{
	struct fd f = fdget(fd);
	struct socket *sock;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 8, 0)
	struct file *ffile = fd_file(f);
#else
	struct file *ffile = f.file;
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 15, 0)
	int err = 0;
#endif
	int r;

	if (!ffile)
		return false;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 15, 0)
	sock = sock_from_file(ffile);
#else
	sock = sock_from_file(ffile, &err);
#endif
	if (!sock) {
		fdput(f);
		return false;
	}
	r = vpnhide_setsockopt_sock(sock, level, optname,
				    USER_SOCKPTR(user_optval), optlen);
	fdput(f);
	if (r) {
		*ret = r;
		return true;
	}
	return false;
}
EXPORT_SYMBOL_GPL(vpnhide_setsockopt);

void vpnhide_getsockopt(struct socket *sock, int level, int optname,
			char __user *optval, int __user *optlen, int *err)
{
	vpnhide_getsockopt_post(sock, level, optname, optval, optlen);
}
EXPORT_SYMBOL_GPL(vpnhide_getsockopt);
