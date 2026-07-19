/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_VPNHIDE_H
#define _LINUX_VPNHIDE_H

/*
 * Public vpnhide API included by patched kernel subsystems.
 * When CONFIG_VPNHIDE=n every function compiles to an immediate
 * false/0/void so the compiler optimises the call sites away.
 */

#ifdef CONFIG_VPNHIDE

#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/seq_file.h>
#include <linux/bpf.h>
#include <linux/socket.h>
#include <linux/fs.h>
#include <linux/dirent.h>

struct inet6_ifaddr;
struct in_ifaddr;
struct fib_info;
struct fib_rule;
struct rt6_info;
struct rtable;
struct qdisc_dump_args;
struct Qdisc;
struct proc_dir_entry;

/* ------------------------------------------------------------------ */
/* Netlink / routing                                                    */
/* ------------------------------------------------------------------ */

bool vpnhide_skip_iflink(struct sk_buff *skb, const struct net_device *dev);
bool vpnhide_skip_inet6_ifaddr(struct sk_buff *skb, struct inet6_ifaddr *ifa);
bool vpnhide_skip_inet_ifaddr(struct sk_buff *skb, struct in_ifaddr *ifa);
bool vpnhide_skip_fib_dump(struct sk_buff *skb, struct fib_info *fi, int nhsel);
bool vpnhide_skip_fib_rule(struct sk_buff *skb, struct fib_rule *rule);
bool vpnhide_skip_rt6(struct sk_buff *skb, struct fib6_info *rt);
bool vpnhide_skip_rt4(struct sk_buff *skb, struct rtable *rt);
bool vpnhide_skip_dev_seq(struct seq_file *seq, const struct net_device *dev);
bool vpnhide_skip_if6_seq(struct seq_file *seq, struct inet6_ifaddr *ifa);
bool vpnhide_skip_tc_qdisc(struct sk_buff *skb, const struct Qdisc *q);
void vpnhide_filter_seq_line(struct seq_file *seq, int saved_count);
bool vpnhide_should_hide_dev(const struct net_device *dev);

/* ------------------------------------------------------------------ */
/* ioctl                                                                */
/* ------------------------------------------------------------------ */

bool vpnhide_ioctl_ifname_block(const char *ifname);
void vpnhide_filter_ifconf(void __user *data);

/* ------------------------------------------------------------------ */
/* Socket                                                               */
/* ------------------------------------------------------------------ */

int  vpnhide_setsockopt_sock(struct socket *sock, int level, int optname,
			     sockptr_t optval, unsigned int optlen);
void vpnhide_getsockopt_post(struct socket *sock, int level, int optname,
			     char __user *optval, int __user *optlen);
int  vpnhide_connect_pre(struct socket *sock,
			 struct sockaddr *addr, int addrlen);
int  vpnhide_bind_pre(struct socket *sock,
		      struct sockaddr *addr, int addrlen);
void vpnhide_getname_post(struct socket *sock, struct sockaddr *addr, int peer);
/* Wrappers matching patch_kernel.py injection names */
void vpnhide_bind(struct socket *sock, struct sockaddr __user *umyaddr,
		  int addrlen);
bool vpnhide_connect(struct socket *sock, struct sockaddr __user *uservaddr,
		     int addrlen, int *ret);
void vpnhide_getname(struct socket *sock, struct sockaddr *addr,
		     int peer, int *err);
bool vpnhide_setsockopt(int fd, int level, int optname,
			char __user *user_optval, unsigned int optlen, int *ret);
void vpnhide_getsockopt(struct socket *sock, int level, int optname,
			char __user *optval, int __user *optlen, int *err);
int  vpnhide_inet6_bind_ll(struct sock *sk,
			   struct sockaddr *uaddr, int addr_len);
bool vpnhide_udpv6_sendmsg_ll(struct sock *sk);
bool vpnhide_udp_sendmsg(struct sock *sk);
bool vpnhide_udp_sendmsg_pre(struct sock *sk, struct msghdr *msg,
			     size_t len, int *err);

/* ------------------------------------------------------------------ */
/* BPF                                                                  */
/* ------------------------------------------------------------------ */

void vpnhide_bpf_lookup_elem(struct bpf_map *map, void *key, void *value);
void vpnhide_bpf_lookup_batch(struct bpf_map *map,
			      const union bpf_attr *attr,
			      union bpf_attr __user *uattr);

/* ------------------------------------------------------------------ */
/* Filesystem / VFS                                                     */
/* ------------------------------------------------------------------ */

bool vpnhide_should_hide_path(const struct path *path);
bool vpnhide_filter_sysctl(struct inode *dir,
			   const char *name, size_t namelen);
bool vpnhide_getdents64(unsigned int fd,
			struct linux_dirent64 __user *dirent,
			unsigned int count, int *retval);

#else /* !CONFIG_VPNHIDE */

#include <linux/types.h>

struct sk_buff;
struct net_device;
struct seq_file;
struct inet6_ifaddr;
struct in_ifaddr;
struct fib_info;
struct fib_rule;
struct fib6_info;
struct rtable;
struct Qdisc;
struct socket;
struct sockaddr;
struct sock;
struct bpf_map;
union bpf_attr;
struct path;
struct linux_dirent64;
struct inode;
#ifndef _LINUX_SOCKPTR_H
typedef struct { const void *user; bool is_kernel; } sockptr_t;
#endif

static inline bool vpnhide_skip_iflink(struct sk_buff *s,
	const struct net_device *d) { return false; }
static inline bool vpnhide_skip_inet6_ifaddr(struct sk_buff *s,
	struct inet6_ifaddr *i) { return false; }
static inline bool vpnhide_skip_inet_ifaddr(struct sk_buff *s,
	struct in_ifaddr *i) { return false; }
static inline bool vpnhide_skip_fib_dump(struct sk_buff *s,
	struct fib_info *fi, int n) { return false; }
static inline bool vpnhide_skip_fib_rule(struct sk_buff *s,
	struct fib_rule *r) { return false; }
static inline bool vpnhide_skip_rt6(struct sk_buff *s,
	struct fib6_info *r) { return false; }
static inline bool vpnhide_skip_rt4(struct sk_buff *s,
	struct rtable *r) { return false; }
static inline bool vpnhide_skip_dev_seq(struct seq_file *s,
	const struct net_device *d) { return false; }
static inline bool vpnhide_skip_if6_seq(struct seq_file *s,
	struct inet6_ifaddr *i) { return false; }
static inline bool vpnhide_skip_tc_qdisc(struct sk_buff *s,
	const struct Qdisc *q) { return false; }
static inline void vpnhide_filter_seq_line(struct seq_file *s,
	int c) {}
static inline bool vpnhide_should_hide_dev(const struct net_device *d)
	{ return false; }
static inline bool vpnhide_ioctl_ifname_block(const char *n) { return false; }
static inline void vpnhide_filter_ifconf(void __user *d) {}
static inline int vpnhide_setsockopt_sock(struct socket *sock, int lv, int opt,
	sockptr_t v, unsigned int l) { return 0; }
static inline void vpnhide_getsockopt_post(struct socket *sock, int lv,
	int opt, char __user *v, int __user *l) {}
static inline int vpnhide_connect_pre(struct socket *sock,
	struct sockaddr *a, int l) { return 0; }
static inline int vpnhide_bind_pre(struct socket *sock,
	struct sockaddr *a, int l) { return 0; }
static inline void vpnhide_getname_post(struct socket *sock,
	struct sockaddr *a, int p) {}
static inline void vpnhide_bind(struct socket *sock,
	struct sockaddr __user *u, int l) {}
static inline bool vpnhide_connect(struct socket *sock,
	struct sockaddr __user *u, int l, int *r) { return false; }
static inline void vpnhide_getname(struct socket *sock,
	struct sockaddr *a, int p, int *e) {}
static inline bool vpnhide_setsockopt(int fd, int lv, int opt,
	char __user *v, unsigned int l, int *r) { return false; }
static inline void vpnhide_getsockopt(struct socket *sock, int lv, int opt,
	char __user *v, int __user *l, int *e) {}
static inline int vpnhide_inet6_bind_ll(struct sock *sk,
	struct sockaddr *a, int l) { return 0; }
static inline bool vpnhide_udpv6_sendmsg_ll(struct sock *sk) { return false; }
static inline bool vpnhide_udp_sendmsg(struct sock *sk) { return false; }
static inline bool vpnhide_udp_sendmsg_pre(struct sock *sk,
	struct msghdr *msg, size_t len, int *err) { return false; }
static inline void vpnhide_bpf_lookup_elem(struct bpf_map *m,
	void *k, void *v) {}
static inline void vpnhide_bpf_lookup_batch(struct bpf_map *m,
	const union bpf_attr *a, union bpf_attr __user *u) {}
static inline bool vpnhide_should_hide_path(const struct path *p)
	{ return false; }
static inline bool vpnhide_filter_sysctl(struct inode *dir,
	const char *n, size_t l) { return false; }
static inline bool vpnhide_getdents64(unsigned int fd,
	struct linux_dirent64 __user *d, unsigned int c, int *r)
	{ return false; }

#endif /* CONFIG_VPNHIDE */
#endif /* _LINUX_VPNHIDE_H */
