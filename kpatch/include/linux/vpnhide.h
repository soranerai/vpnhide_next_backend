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
#include <linux/in.h>
#include <linux/ipv6.h>
#include <linux/fs.h>
#include <linux/dirent.h>

/* ------------------------------------------------------------------ */
/* Netlink / routing                                                    */
/* ------------------------------------------------------------------ */

bool vpnhide_should_hide_dev(const struct net_device *dev);
bool vpnhide_should_hide_ifname(const char *ifname);

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
void vpnhide_pktinfo4_post(struct in_pktinfo *info);
void vpnhide_pktinfo6_post(struct in6_pktinfo *info);
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
bool vpnhide_udpv6_sendmsg_ll(struct sock *sk, struct msghdr *msg);
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
void vpnhide_filename_lookup(int dfd, struct filename *name,
			     unsigned flags, struct path *path, int *retval);

#else /* !CONFIG_VPNHIDE */

#include <linux/types.h>
#include <linux/sockptr.h>

struct msghdr;
struct sk_buff;
struct net_device;
struct seq_file;
struct socket;
struct sockaddr;
struct sock;
struct bpf_map;
union bpf_attr;
struct path;
struct linux_dirent64;
struct inode;
struct filename;
struct in_pktinfo;
struct in6_pktinfo;

static inline bool vpnhide_should_hide_dev(const struct net_device *d)
	{ return false; }
static inline bool vpnhide_should_hide_ifname(const char *n) { return false; }
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
static inline void vpnhide_pktinfo4_post(struct in_pktinfo *i) {}
static inline void vpnhide_pktinfo6_post(struct in6_pktinfo *i) {}
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
static inline bool vpnhide_udpv6_sendmsg_ll(struct sock *sk, struct msghdr *msg) { return false; }
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
static inline void vpnhide_filename_lookup(int dfd, struct filename *name,
	unsigned flags, struct path *path, int *r) {}

#endif /* CONFIG_VPNHIDE */
#endif /* _LINUX_VPNHIDE_H */
