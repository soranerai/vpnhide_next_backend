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
			inet6_sk(sk)->pmtudisc = IPV6_PMTUDISC_DONT;
			sk->sk_mark |= VH_SK_PROBE_MARK;
			record_kmod_intercept(uid, HOOK_SETSOCKOPT);
			return 1;
		}
	} else if (level == SOL_UDP) {
		if (optname == UDP_SEGMENT) {
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
			int mtu = 1500;

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
			int mtu = 1500;

			if (len >= (int)sizeof(mtu)) {
				if (!copy_to_user(optval, &mtu, sizeof(mtu)))
					record_kmod_intercept(uid, HOOK_GETSOCKOPT);
			}
		}
	} else if (level == SOL_TCP) {
		switch (optname) {
		case TCP_MAXSEG: {
			int mss = 1460;

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
			info.tcpi_snd_mss = 1460;
			info.tcpi_rcv_mss = 1460;
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
/* connect — block connections to loopback ports matching rules        */
/* ------------------------------------------------------------------ */

static bool should_block_port(uid_t uid, __be16 port_be, bool is_ipv6)
{
	struct vpnhide_port_targets *pt;
	u16 port = ntohs(port_be);
	bool block = false;
	int i, j;

	rcu_read_lock();
	pt = rcu_dereference(global_port_targets);
	if (!pt)
		goto out;

	for (i = 0; i < pt->count; i++) {
		if (pt->targets[i].uid != uid)
			continue;
		for (j = 0; j < pt->targets[i].rule_count; j++) {
			u16 lo = pt->targets[i].rules[j].start_port;
			u16 hi = pt->targets[i].rules[j].end_port;

			if (port >= lo && port <= hi) {
				block = true;
				goto out;
			}
		}
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

	if (!(READ_ONCE(active_hooks_mask) & BIT(HOOK_CONNECT)))
		return 0;
	uid = from_kuid(&init_user_ns, current_uid());
	if (!is_hook_active(HOOK_CONNECT, uid))
		return 0;

	family = addr->sa_family;

	if (family == AF_INET) {
		struct sockaddr_in *sin = (struct sockaddr_in *)addr;

		if (ipv4_is_loopback(sin->sin_addr.s_addr) ||
		    sin->sin_addr.s_addr == 0) {
			if (should_block_port(uid, sin->sin_port, false)) {
				record_kmod_intercept(uid, HOOK_CONNECT);
				return -ECONNREFUSED;
			}
		}
	} else if (family == AF_INET6) {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)addr;

		if (ipv6_addr_loopback(&sin6->sin6_addr) ||
		    ipv6_addr_any(&sin6->sin6_addr)) {
			if (should_block_port(uid, sin6->sin6_port, true)) {
				record_kmod_intercept(uid, HOOK_CONNECT);
				return -ECONNREFUSED;
			}
		}
	}
	return 0;
}
EXPORT_SYMBOL_GPL(vpnhide_connect_pre);

/* ------------------------------------------------------------------ */
/* bind — redirect blocked ports to 0                                  */
/* ------------------------------------------------------------------ */

int vpnhide_bind_pre(struct socket *sock,
		     struct sockaddr *addr, int addrlen)
{
	uid_t uid;
	sa_family_t family;

	if (!(READ_ONCE(active_hooks_mask) & BIT(HOOK_BIND)))
		return 0;
	uid = from_kuid(&init_user_ns, current_uid());
	if (!is_hook_active(HOOK_BIND, uid))
		return 0;

	family = addr->sa_family;

	if (family == AF_INET) {
		struct sockaddr_in *sin = (struct sockaddr_in *)addr;

		if (ipv4_is_loopback(sin->sin_addr.s_addr) &&
		    should_block_port(uid, sin->sin_port, false)) {
			sin->sin_port = 0;
			record_kmod_intercept(uid, HOOK_BIND);
		}
	} else if (family == AF_INET6) {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)addr;

		if (ipv6_addr_loopback(&sin6->sin6_addr) &&
		    should_block_port(uid, sin6->sin6_port, true)) {
			sin6->sin6_port = 0;
			record_kmod_intercept(uid, HOOK_BIND);
		}
	}
	return 0;
}
EXPORT_SYMBOL_GPL(vpnhide_bind_pre);

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
		/* Spoof: use configured IP, or fall back to INADDR_ANY so the
		 * real VPN address is never returned to a target process. */
		sin->sin_addr.s_addr = (sip.has_ipv4 && sip.ipv4_addr)
			? sip.ipv4_addr : 0;
		record_kmod_intercept(uid, HOOK_GETNAME_INET);
	} else if (family == AF_INET6) {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)addr;

		if (!is_hook_active(HOOK_GETNAME_INET6, uid))
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

	if (!(READ_ONCE(active_hooks_mask) & BIT(HOOK_UDPV6_SENDMSG)))
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
/* UDP rate limiter — token bucket per UID                             */
/* ------------------------------------------------------------------ */

#define VH_RL_MAX_UIDS 16

static struct vh_udp_uid_rate rl_table[VH_RL_MAX_UIDS];
static DEFINE_SPINLOCK(rl_lock);

static struct vh_udp_uid_rate *rl_find_or_alloc(uid_t uid)
{
	int i, empty = -1;

	for (i = 0; i < VH_RL_MAX_UIDS; i++) {
		if (rl_table[i].uid == uid)
			return &rl_table[i];
		if (rl_table[i].uid == 0 && empty < 0)
			empty = i;
	}
	if (empty >= 0) {
		rl_table[empty].uid    = uid;
		rl_table[empty].tokens = VH_UDP_BUCKET_MAX;
		rl_table[empty].last_regen = ktime_get();
		return &rl_table[empty];
	}
	return NULL;
}

bool vpnhide_udp_sendmsg(struct sock *sk)
{
	struct vh_udp_uid_rate *r;
	uid_t uid;
	ktime_t now;
	s64 elapsed_ns;
	int regen;
	bool drop = false;

	if (!(READ_ONCE(active_hooks_mask) & BIT(HOOK_UDP_SENDMSG)))
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
