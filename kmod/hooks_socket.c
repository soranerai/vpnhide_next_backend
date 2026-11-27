#include "vpnhide_kmod.h"
#include <linux/sockptr.h>
#include <net/tcp.h>
#include <net/mptcp.h>

/* --- setsockopt hook --- */

struct sock_setsockopt_data {
  bool override_ret;
  int deny_errno;
  bool intercepted;
};

static int sys_setsockopt_entry(struct kretprobe_instance *ri,
                                struct pt_regs *regs) {
  struct sock_setsockopt_data *sdata;
  int level, optname, optlen;
  void __user *optval_ptr;

  if (!is_hook_active(HOOK_SETSOCKOPT, from_kuid(&init_user_ns, current_uid())))
    return 1;

  sdata = (void *)ri->data;
  sdata->override_ret = false;
  sdata->deny_errno = 0;
  sdata->intercepted = false;

  if (sys_setsockopt_uses_wrapper) {
    struct pt_regs *user_regs = (struct pt_regs *)regs->regs[0];
    if (user_regs && (unsigned long)user_regs >= 0xFFFF000000000000ULL) {
      level = (int)user_regs->regs[1];
      optname = (int)user_regs->regs[2];
      optval_ptr = (void __user *)user_regs->regs[3];
      optlen = (int)user_regs->regs[4];
    } else {
      return 1;
    }
  } else {
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

union socket_bind_snapshot {
	char name[IFNAMSIZ];
	int ifindex;
};

enum socket_bind_action {
	VPNHIDE_BIND_PASSTHROUGH,
	VPNHIDE_BIND_FROZEN,
	VPNHIDE_BIND_DENY,
	VPNHIDE_BIND_FAULT,
};

/* Human-readable action for the debug trace. Never returns NULL. */
static __maybe_unused const char *socket_bind_action_str(enum socket_bind_action action)
{
	switch (action) {
	case VPNHIDE_BIND_PASSTHROUGH:
		return "passthrough";
	case VPNHIDE_BIND_FROZEN:
		return "frozen";
	case VPNHIDE_BIND_DENY:
		return "deny";
	case VPNHIDE_BIND_FAULT:
		return "fault";
	}
	return "?";
}

typedef struct net_device *(*dev_get_by_index_rcu_fn)(struct net *net,
						      int ifindex);

/*
 * dev_get_by_index_rcu() is exported in kallsyms but, like path_put() above,
 * is absent from some OEMs' trimmed GKI KMI module symbol table — a Xiaomi
 * HyperOS android12-5.10 build reports "Unknown symbol dev_get_by_index_rcu"
 * and refuses to load the whole .ko, taking down the core VPN-hiding hooks
 * that never touch this bind path. Resolve it at load time through a throwaway
 * kprobe (kprobes walk kallsyms, not the module export table) so the .ko links
 * with no hard reference, and call it only through the __nocfi trampoline
 * below. Stays NULL on kernels that neither export nor expose it, in which case
 * classify_bind_ifindex() fails closed.
 */
static dev_get_by_index_rcu_fn resolved_dev_get_by_index_rcu;

/* __nocfi: resolved_dev_get_by_index_rcu holds a kallsyms address recovered
 * through a kprobe, which is not a CFI jump-table entry — a checked indirect
 * call to it faults on android12/13-era jump-table CFI kernels, so bypass the
 * check the same way the VFS redirect originals do. Caller holds rcu_read_lock;
 * the returned net_device is only valid within that section. */
static noinline __nocfi struct net_device *
call_resolved_dev_get_by_index_rcu(struct net *net, int ifindex)
{
	struct net_device *dev = resolved_dev_get_by_index_rcu(net, ifindex);

	barrier();
	return dev;
}

/* 1 = VPN interface, 0 = physical/non-VPN, -1 = unknown. Unknown positive
 * indexes fail closed: sock_bindtoindex accepts a non-existent positive index,
 * which would otherwise leave observable state on the socket. An unresolved
 * dev_get_by_index_rcu (NULL pointer) also falls through to the fail-closed
 * unknown path rather than dereferencing it. */
static int classify_bind_ifindex(struct sock *sk, int ifindex)
{
	struct net_device *dev;
	int result = -1;

	if (!sk || ifindex <= 0)
		return ifindex == 0 ? 0 : -1;
	if (!resolved_dev_get_by_index_rcu)
		return -1;
	rcu_read_lock();
	dev = call_resolved_dev_get_by_index_rcu(sock_net(sk), ifindex);
	if (dev)
		result = is_active_vpn_ifname(dev->name) ? 1 : 0;
	rcu_read_unlock();
	return result;
}

static enum socket_bind_action
prepare_socket_bind(struct sock *sk, int optname, sockptr_t optval,
		    unsigned int optlen, union socket_bind_snapshot *snapshot)
{
	/* No `level` gate on purpose. Both hooked functions (sock_setsockopt,
	 * sk_setsockopt) ARE the SOL_SOCKET option handler — reaching them proves
	 * level == SOL_SOCKET by control flow. We must NOT read the ABI `level`
	 * argument: sk_setsockopt never uses it, so whole-kernel LTO elides setting
	 * it at the direct __sys_setsockopt -> sk_setsockopt call (the wrapper then
	 * sees garbage, e.g. 0, and a `level != SOL_SOCKET` check would wrongly pass
	 * the bind through — the SO_BINDTODEVICE leak on LTO GKI builds where
	 * sock_setsockopt is inlined away). Gate on the hook toggle alone. */
	if (!is_hook_active(HOOK_SETSOCKOPT, from_kuid(&init_user_ns, current_uid())) || !is_target_uid())
		return VPNHIDE_BIND_PASSTHROUGH;
	if (optname != SO_BINDTODEVICE && optname != SO_BINDTOIFINDEX)
		return VPNHIDE_BIND_PASSTHROUGH;

	memset(snapshot, 0, sizeof(*snapshot));
	if (optname == SO_BINDTODEVICE) {
		size_t n;

		/* sock_setbindtodevice takes an int and rejects this before
		 * touching optval. Preserve EINVAL and avoid needless uaccess. */
		if ((int)optlen < 0)
			return VPNHIDE_BIND_PASSTHROUGH;
		n = min_t(size_t, optlen, IFNAMSIZ - 1);

		if (n && copy_from_sockptr(snapshot->name, optval, n))
			return VPNHIDE_BIND_FAULT;
		if (snapshot->name[0] && is_active_vpn_ifname(snapshot->name))
			return VPNHIDE_BIND_DENY;
		return VPNHIDE_BIND_FROZEN;
	}

	if (optlen < sizeof(snapshot->ifindex))
		return VPNHIDE_BIND_PASSTHROUGH;
	if (copy_from_sockptr(&snapshot->ifindex, optval,
			      sizeof(snapshot->ifindex)))
		return VPNHIDE_BIND_FAULT;
	if (snapshot->ifindex > 0 &&
	    classify_bind_ifindex(sk, snapshot->ifindex) != 0)
		return VPNHIDE_BIND_DENY;
	return VPNHIDE_BIND_FROZEN;
}

typedef int (*sock_setsockopt_fn)(struct socket *, int, int, sockptr_t,
				  unsigned int);
static sock_setsockopt_fn original_sock_setsockopt;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
typedef int (*sk_setsockopt_fn)(struct sock *, int, int, sockptr_t,
				unsigned int);
static sk_setsockopt_fn original_sk_setsockopt;
#endif

/* noinline + a post-call barrier keep the original call from becoming a tail
 * branch: the redirect kprobe uses the module return address to distinguish it
 * from an external call that must be redirected. __nocfi is required for the
 * non-exported sk_setsockopt address resolved through kprobe metadata. */
static noinline __nocfi int
call_original_sock_setsockopt(struct socket *sock, int level, int optname,
			      sockptr_t optval, unsigned int optlen)
{
	int ret =
		original_sock_setsockopt(sock, level, optname, optval, optlen);

	barrier();
	return ret;
}

static noinline int vpnhide_sock_setsockopt(struct socket *sock, int level,
					    int optname, sockptr_t optval,
					    unsigned int optlen)
{
	union socket_bind_snapshot snapshot;
	enum socket_bind_action action =
		prepare_socket_bind(sock ? READ_ONCE(sock->sk) : NULL, optname,
				    optval, optlen, &snapshot);



	if (action == VPNHIDE_BIND_DENY) {
		record_kmod_intercept(from_kuid(&init_user_ns, current_uid()), 3);
		return -ENODEV;
	}
	if (action == VPNHIDE_BIND_FAULT)
		return -EFAULT;
	if (action == VPNHIDE_BIND_FROZEN)
		optval = KERNEL_SOCKPTR(&snapshot);
	return call_original_sock_setsockopt(sock, level, optname, optval,
					     optlen);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
static noinline __nocfi int call_original_sk_setsockopt(struct sock *sk,
							int level, int optname,
							sockptr_t optval,
							unsigned int optlen)
{
	int ret = original_sk_setsockopt(sk, level, optname, optval, optlen);

	barrier();
	return ret;
}

static noinline int vpnhide_sk_setsockopt(struct sock *sk, int level,
					  int optname, sockptr_t optval,
					  unsigned int optlen)
{
	union socket_bind_snapshot snapshot;
	enum socket_bind_action action =
		prepare_socket_bind(sk, optname, optval, optlen, &snapshot);



	if (action == VPNHIDE_BIND_DENY) {
		record_kmod_intercept(from_kuid(&init_user_ns, current_uid()), 3);
		return -ENODEV;
	}
	if (action == VPNHIDE_BIND_FAULT)
		return -EFAULT;
	if (action == VPNHIDE_BIND_FROZEN)
		optval = KERNEL_SOCKPTR(&snapshot);
	return call_original_sk_setsockopt(sk, level, optname, optval, optlen);
}
#endif

struct socket_bind_kprobe_hook {
	const char *name;
	unsigned long replacement;
	struct kprobe kp;
	bool registered;
};

static bool socket_bind_hooks_ready;

static int socket_bind_kprobe_pre(struct kprobe *kp, struct pt_regs *regs)
{
	struct socket_bind_kprobe_hook *hook =
		container_of(kp, struct socket_bind_kprobe_hook, kp);
	unsigned long parent_ip = regs->regs[30];

	if (!READ_ONCE(socket_bind_hooks_ready) ||
	    within_module(parent_ip, THIS_MODULE))
		return 0;
	instruction_pointer_set(regs, hook->replacement);
	/* Per Documentation/trace/kprobes.rst, !0 tells kprobes not to
	 * single-step the replaced first instruction and to resume at our PC. */
	return 1;
}

/* A post_handler keeps these probes out of the optimized-kprobe detour path,
 * where changing PC from the pre_handler is not supported. It is reached only
 * for the module's intentional call-through to the original function. */
static void socket_bind_kprobe_post(struct kprobe *kp, struct pt_regs *regs,
				    unsigned long flags)
{
	(void)kp;
	(void)regs;
	(void)flags;
}

static struct socket_bind_kprobe_hook socket_bind_kprobe_hooks[] = {
	{
		.name = "sock_setsockopt",
		.replacement = (unsigned long)vpnhide_sock_setsockopt,
		.kp = {
			.symbol_name = "sock_setsockopt",
			.pre_handler = socket_bind_kprobe_pre,
			.post_handler = socket_bind_kprobe_post,
		},
	},
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
	{
		.name = "sk_setsockopt",
		.replacement = (unsigned long)vpnhide_sk_setsockopt,
		.kp = {
			.symbol_name = "sk_setsockopt",
			.pre_handler = socket_bind_kprobe_pre,
			.post_handler = socket_bind_kprobe_post,
		},
	},
#endif
};

static bool socket_bind_hooks_registered;

/* Registration keeps redirection disabled until every required probe exists.
 * Therefore rollback cannot race a redirected wrapper and needs no runtime
 * drain protocol. Once ready becomes true the permanent module keeps these
 * probes and their replacement text resident until reboot. */
static void rollback_socket_bind_hooks(void)
{
	int i;

	for (i = ARRAY_SIZE(socket_bind_kprobe_hooks) - 1; i >= 0; i--) {
		struct socket_bind_kprobe_hook *hook =
			&socket_bind_kprobe_hooks[i];

		if (!hook->registered)
			continue;
		unregister_kprobe(&hook->kp);
		hook->registered = false;
		pr_info(MODNAME ": redirect kprobe(%s) unregistered\n",
			hook->name);
	}
	socket_bind_hooks_registered = false;
}

int register_socket_bind_hooks(void)
{
	int i, ret;

	struct kprobe lookup = { .symbol_name = "dev_get_by_index_rcu" };
	if (!register_kprobe(&lookup)) {
		resolved_dev_get_by_index_rcu = (dev_get_by_index_rcu_fn)lookup.addr;
		unregister_kprobe(&lookup);
	}
	WRITE_ONCE(socket_bind_hooks_ready, false);
	for (i = 0; i < ARRAY_SIZE(socket_bind_kprobe_hooks); i++) {
		struct socket_bind_kprobe_hook *hook =
			&socket_bind_kprobe_hooks[i];

		ret = register_kprobe(&hook->kp);
		if (ret)
			goto fail;
		hook->registered = true;
		if (i == 0)
			original_sock_setsockopt =
				(sock_setsockopt_fn)hook->kp.addr;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
		else
			original_sk_setsockopt =
				(sk_setsockopt_fn)hook->kp.addr;
#endif
		pr_info(MODNAME ": redirect kprobe(%s) registered\n",
			hook->name);
	}

	WRITE_ONCE(socket_bind_hooks_ready, true);
	socket_bind_hooks_registered = true;
	return 0;

fail:
	pr_warn(MODNAME ": redirect kprobe(%s) failed: %d\n",
		socket_bind_kprobe_hooks[i].name, ret);
	rollback_socket_bind_hooks();
	return ret;
}


#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
/* Redirect after fd lookup so both the kernel and our view use the same socket. */
typedef int (*vh_do_getsockopt_fn)(struct socket *, bool, int, int, sockptr_t, sockptr_t);
typedef int (*vh_common_getsockopt_fn)(struct socket *, int, int, char __user *, int __user *);
static vh_common_getsockopt_fn vh_original_common_getsockopt;
static bool vh_getsockopt_uses_common;
typedef int (*vh_mtu_to_mss_fn)(struct sock *, int);
static vh_do_getsockopt_fn vh_original_getsockopt;
static vh_mtu_to_mss_fn vh_mtu_to_mss;
static bool vh_getsockopt_ready;

static noinline __nocfi int vh_call_getsockopt(struct socket *sock, bool compat,
                                                int level, int optname,
                                                sockptr_t optval, sockptr_t optlen)
{
  int ret;
  if (vh_getsockopt_uses_common)
    ret = vh_original_common_getsockopt(sock, level, optname, optval.user, optlen.user);
  else
    ret = vh_original_getsockopt(sock, compat, level, optname, optval, optlen);
  barrier();
  return ret;
}

static noinline __nocfi int vh_call_mtu_to_mss(struct sock *sk, int mtu)
{
  int mss = vh_mtu_to_mss(sk, mtu);
  barrier();
  return mss;
}

static void vh_patch_field(sockptr_t value, int len, size_t offset, u32 replacement)
{
  size_t count;
  if (len <= 0 || (size_t)len <= offset)
    return;
  count = min_t(size_t, sizeof(replacement), (size_t)len - offset);
  copy_to_sockptr_offset(value, offset, &replacement, count);
}

static noinline int vh_do_getsockopt(struct socket *sock, bool compat, int level,
                                      int optname, sockptr_t value, sockptr_t length)
{
  struct sock *sk = sock ? READ_ONCE(sock->sk) : NULL;
  struct vpnhide_spoof_ip sip;
  struct dst_entry *dst;
  bool hidden = false;
  int ret, len, mtu, mss = 0;
  uid_t uid = from_kuid(&init_user_ns, current_uid());

  ret = vh_call_getsockopt(sock, compat, level, optname, value, length);
  if (ret || !sk || value.is_kernel || length.is_kernel ||
      !is_hook_active(HOOK_GETSOCKOPT, uid) || !is_target_uid_val(uid))
    return ret;
  if (!((level == IPPROTO_IP && optname == IP_MTU) ||
        (level == IPPROTO_IPV6 && optname == IPV6_MTU) ||
        (level == IPPROTO_TCP && (optname == TCP_INFO || optname == TCP_MAXSEG))))
    return ret;
  if (copy_from_sockptr(&len, length, sizeof(len)) || len <= 0)
    return ret;
  get_spoof_ip(&sip);
  mtu = sk->sk_family == AF_INET6 ? sip.ipv6_mtu : sip.ipv4_mtu;
  if (!mtu || (sk->sk_family != AF_INET && sk->sk_family != AF_INET6))
    return ret;

  lock_sock(sk);
  dst = sk_dst_get(sk);
  if (dst) {
    hidden = dst->dev && is_active_vpn_ifindex(dst->dev->ifindex);
    dst_release(dst);
  }
  if (hidden && level == IPPROTO_TCP && sk->sk_type == SOCK_STREAM &&
      sk->sk_protocol == IPPROTO_TCP && !sk_is_mptcp(sk) &&
      sk->sk_state != TCP_CLOSE && sk->sk_state != TCP_LISTEN && vh_mtu_to_mss) {
    struct tcp_sock *tp = tcp_sk(sk);
    struct inet_connection_sock *icsk = inet_csk(sk);
    mss = vh_call_mtu_to_mss(sk, mtu);
    mss = tcp_bound_to_half_wnd(tp, mss);
    if (icsk->icsk_mtup.enabled)
      mss = min(mss, vh_call_mtu_to_mss(sk, icsk->icsk_mtup.search_low));
    if (mss <= 0)
      mss = 0;
  }
  release_sock(sk);
  if (!hidden)
    return ret;
  if ((level == IPPROTO_IP && optname == IP_MTU) ||
      (level == IPPROTO_IPV6 && optname == IPV6_MTU))
    vh_patch_field(value, len, 0, mtu);
  else if (mss && optname == TCP_MAXSEG)
    vh_patch_field(value, len, 0, mss);
  else if (mss && optname == TCP_INFO) {
    vh_patch_field(value, len, offsetof(struct tcp_info, tcpi_snd_mss), mss);
    vh_patch_field(value, len, offsetof(struct tcp_info, tcpi_pmtu), mtu);
  }
  return ret;
}

static noinline int vh_common_getsockopt(struct socket *sock, int level, int optname,
                                          char __user *value, int __user *length)
{
  return vh_do_getsockopt(sock, false, level, optname, USER_SOCKPTR(value), USER_SOCKPTR(length));
}

static int vh_getsockopt_pre(struct kprobe *kp, struct pt_regs *regs)
{
  (void)kp;
  if (!READ_ONCE(vh_getsockopt_ready) || within_module(regs->regs[30], THIS_MODULE))
    return 0;
  instruction_pointer_set(regs, vh_getsockopt_uses_common ?
                          (unsigned long)vh_common_getsockopt :
                          (unsigned long)vh_do_getsockopt);
  return 1;
}
static void vh_getsockopt_post(struct kprobe *kp, struct pt_regs *regs, unsigned long flags)
{
  (void)kp; (void)regs; (void)flags;
}
static struct kprobe vh_getsockopt_kp = {
  .symbol_name = "do_sock_getsockopt",
  .pre_handler = vh_getsockopt_pre,
  .post_handler = vh_getsockopt_post,
};
int register_getsockopt_redirect(void)
{
  struct kprobe lookup = { .symbol_name = "tcp_mtu_to_mss" };
  int ret = register_kprobe(&lookup);
  if (ret)
    return ret;
  vh_mtu_to_mss = (vh_mtu_to_mss_fn)lookup.addr;
  unregister_kprobe(&lookup);
  ret = register_kprobe(&vh_getsockopt_kp);
  if (ret) {
    vh_getsockopt_uses_common = true;
    vh_getsockopt_kp.symbol_name = "sock_common_getsockopt";
    ret = register_kprobe(&vh_getsockopt_kp);
    if (ret)
      return ret;
    vh_original_common_getsockopt = (vh_common_getsockopt_fn)vh_getsockopt_kp.addr;
  } else {
    vh_original_getsockopt = (vh_do_getsockopt_fn)vh_getsockopt_kp.addr;
  }
  return 0;
}
void enable_getsockopt_redirect(void) { WRITE_ONCE(vh_getsockopt_ready, true); }
void rollback_getsockopt_redirect(void) { unregister_kprobe(&vh_getsockopt_kp); }
#endif

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

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
  if (level != SOL_SOCKET)
    return 1;
#endif
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

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
  if (level != SOL_SOCKET)
    return 1;
#endif
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

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
  if (level != SOL_SOCKET)
    return 1;
#endif
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
    if (r->start_port > port)
      break;
  }
  return false;
}

static bool direct_connect_should_block(struct socket *sock,
                                        struct sockaddr *addr, uid_t uid,
                                        u16 *blocked_port, u8 *blocked_proto) {
  struct vpnhide_policy_snapshot *snapshot;
  const struct vpnhide_port_target_v3 *urules;
  bool block = false;

  if (!sock || !sock->sk || !addr)
    return false;

  rcu_read_lock();
  snapshot = rcu_dereference(global_policy_snapshot);
  urules = vpnhide_find_port_target(snapshot, uid);
  if (!urules)
    goto out;

  if (addr->sa_family == AF_INET) {
    struct sockaddr_in *sin = (struct sockaddr_in *)addr;
    unsigned short port = ntohs(sin->sin_port);
    unsigned char proto = sock->sk->sk_type == SOCK_STREAM ?
                              VH_PROTO_TCP : VH_PROTO_UDP;
    u32 address[4] = {(__force u32)sin->sin_addr.s_addr, 0, 0, 0};

    if ((ipv4_is_loopback(sin->sin_addr.s_addr) ||
         sin->sin_addr.s_addr == htonl(INADDR_ANY)) &&
        should_block_port(snapshot, urules, port, proto) &&
        !vpnhide_uid_owns_port(uid, port, proto, AF_INET, address))
      block = true;
    if (block) {
      *blocked_port = port;
      *blocked_proto = proto;
    }
  } else if (addr->sa_family == AF_INET6) {
    struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)addr;
    unsigned short port = ntohs(sin6->sin6_port);
    unsigned char proto = sock->sk->sk_type == SOCK_STREAM ?
                              VH_PROTO_TCP : VH_PROTO_UDP;
    u8 family = AF_INET6;
    u32 address[4];
    bool local = ipv6_addr_loopback(&sin6->sin6_addr) ||
                 ipv6_addr_any(&sin6->sin6_addr);

    memcpy(address, &sin6->sin6_addr, sizeof(address));
    if (ipv6_addr_v4mapped(&sin6->sin6_addr)) {
      __be32 v4addr = sin6->sin6_addr.s6_addr32[3];

      local = ipv4_is_loopback(v4addr) || v4addr == htonl(INADDR_ANY);
      family = AF_INET;
      address[0] = (__force u32)v4addr;
      address[1] = address[2] = address[3] = 0;
    }
    if (local && should_block_port(snapshot, urules, port, proto) &&
        !vpnhide_uid_owns_port(uid, port, proto, family, address))
      block = true;
    if (block) {
      *blocked_port = port;
      *blocked_proto = proto;
    }
  }
out:
  rcu_read_unlock();
  return block;
}

struct socket_connect_data {
  bool should_block;
  bool intercepted;
  u16 port;
  u8 protocol;
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
  data->port = 0;
  data->protocol = VH_PROTO_TCP;

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
      u32 address[4] = {(__force u32)sin->sin_addr.s_addr, 0, 0, 0};

      if (should_block_port(snapshot, urules, port, proto) &&
          !vpnhide_uid_owns_port(uid, port, proto, AF_INET, address)) {
        data->should_block = true;
        data->port = port;
        data->protocol = proto;
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
      u8 family = AF_INET6;
      u32 address[4];

      memcpy(address, &sin6->sin6_addr, sizeof(address));
      if (ipv6_addr_v4mapped(&sin6->sin6_addr)) {
        family = AF_INET;
        address[0] = (__force u32)sin6->sin6_addr.s6_addr32[3];
        address[1] = address[2] = address[3] = 0;
      }

      if (should_block_port(snapshot, urules, port, proto) &&
          !vpnhide_uid_owns_port(uid, port, proto, family, address)) {
        data->should_block = true;
        data->port = port;
        data->protocol = proto;
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
    record_port_intercept(from_kuid(&init_user_ns, current_uid()), data->port,
                          data->protocol);
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

static int security_socket_connect_entry(struct kretprobe_instance *ri,
                                         struct pt_regs *regs) {
  struct socket_connect_data *data = (void *)ri->data;
  uid_t uid = from_kuid(&init_user_ns, current_uid());

  data->should_block = false;
  data->intercepted = false;
  data->port = 0;
  data->protocol = VH_PROTO_TCP;
  if (!is_hook_active(HOOK_CONNECT, uid))
    return 1;
  data->should_block = direct_connect_should_block(
      (struct socket *)regs->regs[0], (struct sockaddr *)regs->regs[1], uid,
      &data->port, &data->protocol);
  return data->should_block ? 0 : 1;
}

static int security_socket_connect_ret(struct kretprobe_instance *ri,
                                       struct pt_regs *regs) {
  struct socket_connect_data *data = (void *)ri->data;

  if (data->should_block) {
    record_port_intercept(from_kuid(&init_user_ns, current_uid()), data->port,
                          data->protocol);
    regs_set_return_value(regs, -ECONNREFUSED);
  }
  return 0;
}

struct kretprobe security_socket_connect_krp = {
    .handler = security_socket_connect_ret,
    .entry_handler = security_socket_connect_entry,
    .data_size = sizeof(struct socket_connect_data),
    .maxactive = VPNHIDE_KRETPROBE_MAXACTIVE,
    .kp.symbol_name = "security_socket_connect",
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
        sk->sk_type == SOCK_DGRAM)
      vpnhide_record_bound_socket(data->uid, sk);
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
      sock->sk->sk_type != SOCK_DGRAM)
    return 1;
  data->sock = sock;
  data->uid = from_kuid(&init_user_ns, current_uid());
  return 0;
}

static int inet_bind_owner_ret(struct kretprobe_instance *ri,
                               struct pt_regs *regs) {
  struct inet_bind_owner_data *data = (void *)ri->data;
  struct sock *sk = data->sock ? data->sock->sk : NULL;

  if (regs_return_value(regs) == 0 && sk)
    vpnhide_record_bound_socket(data->uid, sk);
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
    vpnhide_record_bound_socket(data->uid, sk);
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
      sock->sk->sk_type == SOCK_DGRAM) {
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
    /* __arm64_sys_bind already records successful UDP binds.  inet6_bind is
     * also a policy hook, so it remains registered; only use its ownership
     * side effect when the syscall-level probe was unavailable. */
    if (!sys_bind_uses_wrapper && regs_return_value(regs) == 0 && sk)
      vpnhide_record_bound_socket(data->uid, sk);
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
    /* Keep the return handler installed until it restores the socket. */
    if (udp_rate_limit_exceeded(uid) && try_module_get(THIS_MODULE)) {
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

  if (data->rl_spoofed && data->sk) {
    data->sk->sk_sndbuf = data->orig_sndbuf;
    module_put(THIS_MODULE);
  }

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
  struct net *net;
};

/* Walk device addresses in the socket's namespace under RCU. */
static bool hidden_ipv4_address(struct net *net, __be32 address) {
  struct net_device *dev;
  struct in_device *in_dev;
  struct in_ifaddr *ifa;
  bool found = false;

  if (!net || !address)
    return false;
  rcu_read_lock();
  for_each_netdev_rcu(net, dev) {
    if (!is_active_vpn_ifindex(dev->ifindex))
      continue;
    in_dev = __in_dev_get_rcu(dev);
    if (!in_dev)
      continue;
    in_dev_for_each_ifa_rcu(ifa, in_dev) {
      if (ifa->ifa_local == address) {
        found = true;
        goto out;
      }
    }
  }
out:
  rcu_read_unlock();
  return found;
}

static bool hidden_ipv6_address(struct net *net, const struct in6_addr *address) {
  struct net_device *dev;
  struct inet6_dev *in6_dev;
  struct inet6_ifaddr *ifa;
  bool found = false;

  if (!net || !address)
    return false;
  if (ipv6_addr_v4mapped(address))
    return hidden_ipv4_address(net, address->s6_addr32[3]);
  rcu_read_lock();
  for_each_netdev_rcu(net, dev) {
    if (!is_active_vpn_ifindex(dev->ifindex))
      continue;
    in6_dev = __in6_dev_get(dev);
    if (!in6_dev)
      continue;
    list_for_each_entry_rcu(ifa, &in6_dev->addr_list, if_list) {
      if (ipv6_addr_equal(&ifa->addr, address)) {
        found = true;
        goto out;
      }
    }
  }
out:
  rcu_read_unlock();
  return found;
}

static int sys_getsockname_entry(struct kretprobe_instance *ri,
                                 struct pt_regs *regs) {
  struct sys_getsockname_data *data;
  struct pt_regs *user_regs;
  struct socket *sock;
  int ulen, err;

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
  data->net = NULL;
  sock = sockfd_lookup((int)user_regs->regs[0], &err);
  if (sock) {
    if (sock->sk)
      data->net = get_net(sock_net(sock->sk));
    sockfd_put(sock);
  }

  if (get_user(ulen, (int __user *)user_regs->regs[2]) == 0) {
    data->ulen = ulen;
  } else {
    data->ulen = 0;
  }
  return 0;
}

static void spoof_getsockname_ipv4(void __user *uaddr,
                                   struct vpnhide_spoof_ip *sip,
                                   struct net *net) {
  __be32 addr;
  __be32 target_ip;

  if (get_user(addr, &((struct sockaddr_in __user *)uaddr)->sin_addr.s_addr) !=
      0)
    return;

  if (!hidden_ipv4_address(net, addr))
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
                                   struct vpnhide_spoof_ip *sip,
                                   struct net *net) {
  struct in6_addr addr6;
  struct in6_addr old_addr;
  struct in6_addr target_ip6;

  if (copy_from_user(&addr6, &((struct sockaddr_in6 __user *)uaddr)->sin6_addr,
                     sizeof(struct in6_addr)) != 0)
    return;

  if (!hidden_ipv6_address(net, &addr6))
    return;

  old_addr = addr6;

  if (ipv6_addr_v4mapped(&addr6)) {
    ipv6_addr_set_v4mapped(sip->has_ipv4 ? sip->ipv4_addr : htonl(0xC0000004),
                           &target_ip6);
  } else if (sip->has_ipv6) {
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
    goto out;

  if (get_user(sa_family, (unsigned short __user *)data->uaddr) != 0)
    goto out;

  get_spoof_ip(&sip);

  if (sa_family == AF_INET &&
      is_hook_active(HOOK_GETNAME_INET, from_kuid(&init_user_ns, current_uid()))) {
    if (data->ulen >= (int)(offsetof(struct sockaddr_in, sin_addr) +
                            sizeof(struct in_addr))) {
      spoof_getsockname_ipv4(data->uaddr, &sip, data->net);
    }
  } else if (sa_family == AF_INET6 &&
             is_hook_active(HOOK_GETNAME_INET6, from_kuid(&init_user_ns, current_uid()))) {
    if (data->ulen >= (int)(offsetof(struct sockaddr_in6, sin6_addr) +
                            sizeof(struct in6_addr))) {
      spoof_getsockname_ipv6(data->uaddr, &sip, data->net);
    }
  }

out:
  if (data->net)
    put_net(data->net);
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
  struct net *net;
};

static int inet_getname_entry(struct kretprobe_instance *ri,
                              struct pt_regs *regs) {
  struct getname_data *data;
  struct socket *sock = (struct socket *)regs->regs[0];
  int peer = (int)regs->regs[2];

  if (!is_hook_active(HOOK_GETNAME_INET,
                      from_kuid(&init_user_ns, current_uid())))
    return 1;

  if (peer != 0 || !sock || !is_target_uid())
    return 1;

  data = (void *)ri->data;
  data->uaddr = (struct sockaddr *)regs->regs[1];
  data->peer = peer;
  data->net = sock->sk ? sock_net(sock->sk) : NULL;
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
      if (hidden_ipv4_address(data->net, addr)) {
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
  struct socket *sock = (struct socket *)regs->regs[0];
  int peer = (int)regs->regs[2];

  if (!is_hook_active(HOOK_GETNAME_INET6,
                      from_kuid(&init_user_ns, current_uid())))
    return 1;

  if (peer != 0 || !sock || !is_target_uid())
    return 1;

  data = (void *)ri->data;
  data->uaddr = (struct sockaddr *)regs->regs[1];
  data->peer = peer;
  data->net = sock->sk ? sock_net(sock->sk) : NULL;
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
      if (hidden_ipv6_address(data->net, &sin6->sin6_addr)) {
        struct in6_addr old_addr = sin6->sin6_addr;
        struct in6_addr target_ip6;

        if (ipv6_addr_v4mapped(&sin6->sin6_addr)) {
          ipv6_addr_set_v4mapped(sip.has_ipv4 ? sip.ipv4_addr : htonl(0xC0000004),
                                 &target_ip6);
        } else if (sip.has_ipv6) {
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
