#!/usr/bin/env python3
"""
VPNHide in-tree kernel patcher.

Applies VPNHide hooks to a GKI kernel source tree. Designed to produce
changes that `git diff` will export as a proper unified diff patch.

Compatible with GKI2: android12-5.10, android13-5.15, android14-6.1,
                      android15-6.6, android16-6.12
"""
import sys
import os
import re

# Global configurations
DEV_FIELD = 'nh_dev'
HAS_FIB_RULE_UID = False  # set by main() after reading include/net/fib_rules.h

# ---------------------------------------------------------------------------
# Low-level helpers
# ---------------------------------------------------------------------------

def read(path):
    if not os.path.exists(path):
        print(f"ERROR: File not found: {path}")
        sys.exit(1)
    with open(path, 'r') as f:
        return f.read()

def write(path, content):
    with open(path, 'w') as f:
        f.write(content)

def insert_after(content, anchor, insertion):
    """Insert `insertion` right after the first occurrence of `anchor`.
    Returns (content, False) unchanged when anchor is not found so callers
    can safely chain multiple fallback attempts without a None-crash."""
    idx = content.find(anchor)
    if idx == -1:
        return content, False
    pos = idx + len(anchor)
    return content[:pos] + '\n' + insertion + content[pos:], True

def insert_before(content, anchor, insertion):
    """Insert `insertion` right before the first occurrence of `anchor`.
    Returns (content, False) unchanged when anchor is not found."""
    idx = content.find(anchor)
    if idx == -1:
        return content, False
    return content[:idx] + insertion + '\n' + content[idx:], True

def guard(toggle_guard):
    """Wrap `toggle_guard` in CONFIG_VPNHIDE guards."""
    return f'#ifdef CONFIG_VPNHIDE\n{toggle_guard}#endif\n'

_DECL_STARTERS = (
    'struct ', 'union ', 'enum ', 'const ', 'static ', 'volatile ',
    'unsigned ', 'signed ', 'int ', 'long ', 'short ', 'char ', 'void ',
    'bool ', 'size_t ', 'ssize_t ',
    'u8 ', 'u16 ', 'u32 ', 'u64 ', 's8 ', 's16 ', 's32 ', 's64 ',
    '__u8 ', '__u16 ', '__u32 ', '__u64 ', '__s8 ', '__s16 ', '__s32 ', '__s64 ',
    '__le16 ', '__le32 ', '__le64 ', '__be16 ', '__be32 ', '__be64 ',
    'atomic_t ', 'gfp_t ', 'kuid_t ', 'kgid_t ',
)

def find_after_decls(content, body_open):
    """Given the index of a function body's opening '{', return the offset
    just after the block's leading local-variable declarations (skipping
    blank lines and comments). GKI kernels build with
    -Wdeclaration-after-statement as an error, so any statement we inject
    must land after existing declarations, not right after '{'."""
    pos = body_open + 1
    n = len(content)
    last_decl_end = pos
    while pos < n:
        line_end = content.find('\n', pos)
        if line_end == -1:
            break
        line = content[pos:line_end]
        stripped = line.strip()
        if not stripped or stripped.startswith('//') or stripped.startswith('/*') or stripped.startswith('*'):
            pos = line_end + 1
            continue
        if any(stripped.startswith(s) for s in _DECL_STARTERS):
            pos = line_end + 1
            last_decl_end = pos
            continue
        # first non-declaration statement — stop here
        break
    return last_decl_end

def patch_file(path, fn):
    """
    Apply `fn(content) -> (new_content, changed)` to a file.
    Prints status.  Aborts on error.
    """
    content = read(path)
    rel = os.path.relpath(path)
    result = fn(content)
    if result is None or result[0] is None:
        print(f"ERROR: Patch anchor not found in {rel}")
        sys.exit(1)
    new_content, changed = result
    if not changed:
        print(f"INFO:  Already patched: {rel}")
        return
    write(path, new_content)
    print(f"OK:    Patched {rel}")


def add_include(content, our_include, anchor_candidates):
    """Insert our_include after the first matching anchor from the list."""
    if our_include.strip() in content:
        return content, False
    for anchor in anchor_candidates:
        if anchor in content:
            new_content, ok = insert_after(content, anchor, our_include)
            if ok:
                return new_content, True
    # Last resort: append after the last #include line
    lines = content.splitlines(keepends=True)
    last_inc_idx = 0
    for i, line in enumerate(lines):
        if line.startswith('#include'):
            last_inc_idx = i
    insert_pos = sum(len(l) for l in lines[:last_inc_idx + 1])
    content = content[:insert_pos] + our_include + '\n' + content[insert_pos:]
    return content, True


# ---------------------------------------------------------------------------
# Per-file patch functions
# ---------------------------------------------------------------------------

def patch_security_kconfig(content):
    needle = 'source "security/vpnhide/Kconfig"'
    if needle in content:
        return content, False
    # Insert before endmenu (the very last one)
    new = re.sub(r'(endmenu\s*)$', needle + '\n\n' + r'\1', content,
                 count=1, flags=re.MULTILINE)
    return new, new != content


def patch_security_makefile(content):
    insert = 'obj-$(CONFIG_VPNHIDE)\t\t\t+= vpnhide/'
    if insert in content:
        return content, False
    return content.rstrip() + '\n' + insert + '\n', True


def patch_net_socket_c(content):
    changed = False

    # 1. Include guard
    anchor_inc = '#include <linux/compat.h>'
    insert_inc = guard('#include "../security/vpnhide/vpnhide.h"\n')
    if '#include "../security/vpnhide/vpnhide.h"' not in content:
        content, ok = insert_after(content, anchor_inc, insert_inc)
        if not ok:
            print("ERROR: anchor '#include <linux/compat.h>' not found in net/socket.c")
            sys.exit(1)
        changed = True

    # 2. __sys_bind: hook before ops->bind. `address` is the kernel-space
    # copy already produced by move_addr_to_kernel() — ops->bind() uses
    # `address`, not umyaddr, so we must mutate `address` directly rather
    # than round-tripping through user space.
    bind_anchor = '\t\t\terr = sock->ops->bind(sock,'
    bind_hook = guard(
        '\t\tvpnhide_bind_pre(sock, (struct sockaddr *)&address, addrlen);\n'
    )
    if 'vpnhide_bind_pre' not in content:
        content, ok = insert_before(content, bind_anchor, bind_hook)
        if not ok:
            # Try single-tab variant (different kernel versions)
            bind_anchor = '\t\t\t\t\t\terr = sock->ops->bind(sock,'
            content, ok = insert_before(content, bind_anchor, bind_hook)
        if not ok:
            print("WARNING: bind anchor not found in net/socket.c, trying fallback")
            bind_anchor2 = 'err = sock->ops->bind(sock,'
            content, ok = insert_before(content, bind_anchor2, bind_hook)
        if ok:
            changed = True
        else:
            print("ERROR: Could not find bind hook anchor in net/socket.c")
            sys.exit(1)

    # 3. __sys_connect: hook inside __sys_connect after fdget
    connect_hook = guard(
        '\t{\n'
        '\t\tstruct fd _f = fdget(fd);\n'
        '\t\tif (_f.file) {\n'
        '\t\t\tint _err = 0;\n'
        '\t\t\tstruct socket *_sock = sock_from_file(_f.file, &_err);\n'
        '\t\t\tif (_sock) {\n'
        '\t\t\t\tint _ret = 0;\n'
        '\t\t\t\tif (vpnhide_connect(_sock, uservaddr, addrlen, &_ret)) {\n'
        '\t\t\t\t\tfdput(_f);\n'
        '\t\t\t\t\treturn _ret;\n'
        '\t\t\t\t}\n'
        '\t\t\t}\n'
        '\t\t\tfdput(_f);\n'
        '\t\t}\n'
        '\t}\n'
    )
    if 'vpnhide_connect' not in content:
        func_idx = content.find('int __sys_connect(int fd, struct sockaddr __user *uservaddr, int addrlen)')
        if func_idx != -1:
            fdget_idx = content.find('\tf = fdget(fd);', func_idx)
            if fdget_idx != -1:
                content = content[:fdget_idx] + connect_hook + content[fdget_idx:]
                changed = True
            else:
                print("WARNING: fdget(fd) anchor not found inside __sys_connect")
        else:
            print("WARNING: __sys_connect definition not found in net/socket.c")

    # 4. __sys_getsockname: hook BEFORE move_addr_to_user so the spoofed
    # address (not the real one) gets copied to user space.
    getsockname_anchor = 'err = move_addr_to_user(&address, err, usockaddr, usockaddr_len);'
    getsockname_hook = guard(
        '\tvpnhide_getname(sock, (struct sockaddr *)&address, 0, &err);\n'
    )
    if 'vpnhide_getname(sock, (struct sockaddr *)&address, 0' not in content:
        sockname_idx = content.find('int __sys_getsockname(')
        anchor_idx = content.find(getsockname_anchor, sockname_idx) if sockname_idx != -1 else -1
        if anchor_idx != -1:
            content = content[:anchor_idx] + getsockname_hook + content[anchor_idx:]
            changed = True
        else:
            print("WARNING: getsockname anchor not found")

    # 5. __sys_getpeername: hook BEFORE move_addr_to_user, inside the
    # `if (err >= 0)` success branch. That branch has no braces in the
    # original source (`if (err >= 0)\n\t\t\t/* comment */\n\t\t\terr = ...;`)
    # — inserting a second statement without adding braces would pull
    # move_addr_to_user() out from under the if, running it unconditionally
    # and tripping BUG_ON(klen > sizeof(sockaddr_storage)) when err < 0.
    if 'vpnhide_getname(sock, (struct sockaddr *)&address, 1' not in content:
        peer_idx = content.find('int __sys_getpeername(')
        if peer_idx != -1:
            if_idx = content.find('\t\terr = sock->ops->getname(sock, (struct sockaddr *)&address, 1);',
                                   peer_idx)
            if_idx = content.find('if (err >= 0)', if_idx) if if_idx != -1 else -1
            err_assign_idx = content.find('\t\t\terr = move_addr_to_user(&address, err, usockaddr,',
                                          if_idx) if if_idx != -1 else -1
            stmt_end = content.find(';\n', err_assign_idx) + 2 if err_assign_idx != -1 else -1
            if if_idx != -1 and err_assign_idx != -1:
                # Everything between the `if (...)` line and the `err = ...;`
                # statement (e.g. a comment line) stays as-is; we only need
                # to add braces around the (previously single-statement) body
                # so the inserted hook line doesn't fall outside the if.
                if_line_end = content.find('\n', if_idx) + 1
                body_prefix = content[if_line_end:err_assign_idx]
                new_block = (
                    'if (err >= 0) {\n'
                    + body_prefix
                    + '\t\t\tvpnhide_getname(sock, (struct sockaddr *)&address, 1, &err);\n'
                    + content[err_assign_idx:stmt_end]
                    + '\t\t}\n'
                )
                content = content[:if_idx] + new_block + content[stmt_end:]
                changed = True
            else:
                print("WARNING: move_addr_to_user anchor not found inside __sys_getpeername")
        else:
            print("WARNING: __sys_getpeername not found in net/socket.c")

    # 6. __sys_setsockopt: hook at entry before SOL_SOCKET check
    setsockopt_anchor = 'if (level == SOL_SOCKET'
    setsockopt_hook = guard(
        '\t{\n'
        '\t\tint _ret = 0;\n'
        '\t\tif (vpnhide_setsockopt(fd, level, optname, user_optval, optlen, &_ret)) {\n'
        '\t\t\terr = _ret;\n'
        '\t\t\tfput_light(sock->file, fput_needed);\n'
        '\t\t\treturn err;\n'
        '\t\t}\n'
        '\t}\n'
    )
    if 'vpnhide_setsockopt' not in content:
        content, ok = insert_before(content, setsockopt_anchor, setsockopt_hook)
        if ok:
            changed = True
        else:
            print("WARNING: setsockopt anchor not found")

    # 7. __sys_getsockopt: hook at end (before final return)
    getsockopt_anchor = '\treturn err;\n}\n\nSYSCALL_DEFINE5(getsockopt,'
    getsockopt_hook = guard(
        '\tvpnhide_getsockopt(sock, level, optname, optval, optlen, &err);\n'
    )
    if 'vpnhide_getsockopt' not in content:
        content, ok = insert_before(
            content, '\treturn err;\n}\n\nSYSCALL_DEFINE5(getsockopt,', getsockopt_hook)
        if ok:
            changed = True
        else:
            print("WARNING: getsockopt return anchor not found")

    return content, changed


def patch_fs_namei_c(content):
    changed = False

    anchor_inc = '#include <linux/personality.h>'
    insert_inc = guard('#include "../security/vpnhide/vpnhide.h"\n')
    if '#include "../security/vpnhide/vpnhide.h"' not in content:
        content, ok = insert_after(content, anchor_inc, insert_inc)
        if ok:
            changed = True

    # filename_lookup: hook if lookup succeeded — 5.10 uses "unsigned flags" (no int).
    #
    # The hook MUST run before putname(name). On 5.10 filename_lookup owns the
    # `name` reference and releases it with putname(name) right before
    # `return retval;`; the hook takes `name` and, on a hidden path, does
    # path_put(path)+sets retval. Injecting it after putname(name) (i.e. right
    # before `return retval;`) meant the fixup ran against already-torn-down
    # state, wedging the entire VFS on the first intercepted sysfs/proc lookup.
    # restore_nameidata() is called by every GKI2 version immediately before the
    # (version-dependent) putname(name) + return retval, so anchor on it: the
    # hook lands after nameidata restore but before name is released, on 5.10
    # and on 5.15+ (where filename_lookup no longer calls putname) alike.
    fname_anchor = 'filename_lookup(int dfd, struct filename *name, unsigned'
    if 'vpnhide_filename_lookup' not in content:
        idx = content.find(fname_anchor)
        if idx != -1:
            restore_anchor = '\trestore_nameidata();\n'
            r_idx = content.find(restore_anchor, idx)
            if r_idx != -1:
                pos = r_idx + len(restore_anchor)
                hook = (
                    '\n#ifdef CONFIG_VPNHIDE\n'
                    '\tif (!retval)\n'
                    '\t\tvpnhide_filename_lookup(dfd, name, flags, path, &retval);\n'
                    '#endif\n'
                )
                content = content[:pos] + hook + content[pos:]
                changed = True
            else:
                print("WARNING: restore_nameidata anchor not found in filename_lookup (namei.c)")

    return content, changed


def patch_fs_readdir_c(content):
    changed = False

    # Include: readdir.c already has <linux/security.h>, use <linux/syscalls.h> as anchor
    anchor_inc = '#include <linux/security.h>'
    insert_inc = guard('#include "../security/vpnhide/vpnhide.h"\n')
    if '#include "../security/vpnhide/vpnhide.h"' not in content:
        content, ok = insert_after(content, anchor_inc, insert_inc)
        if ok:
            changed = True
        else:
            content, ok = insert_after(content, '#include <linux/syscalls.h>', insert_inc)
            if ok:
                changed = True

    # SYSCALL_DEFINE3(getdents64): hook right before the final
    # `fdput_pos(f); return error;` — NOT right after iterate_dir(). The
    # syscall body still overwrites `error` twice after iterate_dir()
    # returns (`error = buf.error;`, then possibly
    # `error = count - buf.count;` inside the `buf.prev_reclen` block), so
    # hooking earlier gets our filtered byte count clobbered by the
    # original unfiltered one before it reaches userspace.
    hook_iter = (
        '#ifdef CONFIG_VPNHIDE\n'
        '        {\n'
        '                int _g64 = error;\n'
        '                if (vpnhide_getdents64(fd, dirent, count, &_g64))\n'
        '                        error = _g64;\n'
        '        }\n'
        '#endif\n'
    )
    if 'vpnhide_getdents64' not in content:
        sys_idx = content.find('SYSCALL_DEFINE3(getdents64,')
        if sys_idx != -1:
            fdput_anchor = '\tfdput_pos(f);\n\treturn error;'
            fdput_idx = content.find(fdput_anchor, sys_idx)
            if fdput_idx != -1:
                content = (content[:fdput_idx] + hook_iter +
                           content[fdput_idx:])
                changed = True
            else:
                print("WARNING: getdents64 fdput_pos/return anchor not found")
        else:
            print("WARNING: SYSCALL_DEFINE3(getdents64 not found in readdir.c")

    return content, changed


def patch_net_core_rtnetlink_c(content):
    changed = False

    anchor_inc = '#include <net/sock.h>'
    insert_inc = guard('#include "../../security/vpnhide/vpnhide.h"\n')
    if '#include "../../security/vpnhide/vpnhide.h"' not in content:
        content, ok = insert_after(content, anchor_inc, insert_inc)
        if ok:
            changed = True

    # rtnl_fill_ifinfo builds every RTM_NEWLINK message (dump, single-device
    # get, and change notifications) — hooking it directly covers all of
    # those call sites in one place. The dump loop itself walks
    # hlist_for_each_entry(dev, head, index_hlist), not for_each_netdev(),
    # so hooking the loop (as before) missed RTM_GETLINK dumps entirely.
    # Inject after the function's local declarations (not by searching for
    # nlmsg_put's pid arg, which is renamed portid in GKI2 kernels — that
    # anchor silently missed and left RTM_GETLINK unhooked). This is also
    # C90-safe: GKI builds with -Wdeclaration-after-statement as an error.
    if 'vpnhide_should_hide_dev(dev)' not in content:
        func_idx = content.find('static int rtnl_fill_ifinfo(')
        if func_idx != -1:
            body_open = content.find('{', func_idx)
            if body_open != -1:
                inject_at = find_after_decls(content, body_open)
                hook = guard(
                    '\tif (dev && vpnhide_should_hide_dev(dev))\n'
                    '\t\treturn 0;\n'
                )
                content = content[:inject_at] + hook + content[inject_at:]
                changed = True
            else:
                print("WARNING: rtnl_fill_ifinfo opening brace not found")
        else:
            print("WARNING: rtnl_fill_ifinfo not found in rtnetlink.c")

    return content, changed


def patch_net_ipv4_devinet_c(content):
    changed = False
    anchor_inc = '#include <net/ip_fib.h>'
    insert_inc = guard('#include "../../security/vpnhide/vpnhide.h"\n')
    if '#include "../../security/vpnhide/vpnhide.h"' not in content:
        content, ok = insert_after(content, anchor_inc, insert_inc)
        if ok:
            changed = True

    for anchor in ['for_each_netdev_rcu(net, dev)', 'for_each_netdev(net, dev)']:
        if anchor in content and 'vpnhide_should_hide_dev' not in content:
            hook = guard(
                '\t\t\tif (vpnhide_should_hide_dev(dev))\n'
                '\t\t\t\tcontinue;\n'
            )
            content, ok = insert_after(content, anchor + ' {', hook)
            if not ok:
                content, ok = insert_after(content, anchor, hook)
            if ok:
                changed = True
            break

    # devinet_ioctl: hide VPN device for SIOCGIFADDR/GIFDSTADDR/GIFBRDADDR/GIFNETMASK
    # Anchor: after __dev_get_by_name + !dev goto, before the colon-fix
    nodev_anchor = '\tdev = __dev_get_by_name(net, ifr->ifr_name);\n\tif (!dev)\n\t\tgoto done;\n'
    devinet_hook = guard(
        '\tif (vpnhide_should_hide_dev(dev)) {\n'
        '\t\tret = -ENODEV;\n'
        '\t\tgoto done;\n'
        '\t}\n'
    )
    if 'devinet_ioctl' in content:
        func_idx = content.find('int devinet_ioctl(')
        if func_idx != -1:
            func_end = content.find('\nstatic ', func_idx + 1)
            func_slice = content[func_idx:func_end] if func_end != -1 else content[func_idx:]
            if 'vpnhide_should_hide_dev(dev)' not in func_slice:
                nodev_idx = content.find(nodev_anchor, func_idx)
                if nodev_idx != -1:
                    pos = nodev_idx + len(nodev_anchor)
                    content = content[:pos] + devinet_hook + content[pos:]
                    changed = True
                else:
                    # fallback: simpler anchor without goto
                    alt_anchor = '\tdev = __dev_get_by_name(net, ifr->ifr_name);\n'
                    alt_idx = content.find(alt_anchor, func_idx)
                    if alt_idx != -1:
                        pos = alt_idx + len(alt_anchor)
                        content = content[:pos] + devinet_hook + content[pos:]
                        changed = True
                    else:
                        print("WARNING: devinet_ioctl __dev_get_by_name anchor not found")

    # inet_fill_ifaddr: hide VPN addresses from RTM_GETADDR dumps (ip addr show).
    # The for_each_netdev loop above may not cover all callers; hook the fill
    # function directly so any dump path is filtered.
    # Insert before nlh = nlmsg_put to stay after local declarations (C90 compat).
    inet_fill_hook = guard(
        '\tif (ifa->ifa_dev && ifa->ifa_dev->dev &&\n'
        '\t    vpnhide_should_hide_dev(ifa->ifa_dev->dev))\n'
        '\t\treturn 0;\n'
    )
    if 'inet_fill_ifaddr' in content and 'vpnhide_should_hide_dev(ifa->ifa_dev->dev)' not in content:
        fill_idx = content.find('static int inet_fill_ifaddr(')
        if fill_idx != -1:
            nlh_idx = content.find('\tnlh = nlmsg_put(', fill_idx)
            if nlh_idx == -1:
                nlh_idx = content.find('\tnlh = nlmsg_new(', fill_idx)
            if nlh_idx != -1:
                content = content[:nlh_idx] + inet_fill_hook + content[nlh_idx:]
                changed = True
            else:
                print("WARNING: inet_fill_ifaddr nlmsg_put anchor not found")
        else:
            print("WARNING: inet_fill_ifaddr not found in devinet.c")

    return content, changed


def patch_net_ipv6_addrconf_c(content):
    inc = guard('#include "../../security/vpnhide/vpnhide.h"\n')
    content, changed = add_include(content, inc, [
        '#include <trace/hooks/ipv6.h>',
        '#include <linux/seq_file.h>',
        '#include <linux/export.h>',
        '#include <net/addrconf.h>',
    ])

    for anchor in ['for_each_netdev_rcu(net, dev)', 'for_each_netdev(net, dev)']:
        if anchor in content and 'vpnhide_should_hide_dev' not in content:
            hook = guard(
                '\t\t\tif (vpnhide_should_hide_dev(dev))\n'
                '\t\t\t\tcontinue;\n'
            )
            content, ok = insert_after(content, anchor + ' {', hook)
            if not ok:
                content, ok = insert_after(content, anchor, hook)
            if ok:
                changed = True
            break

    # if6_seq_show: hide VPN interfaces from /proc/net/if_inet6
    # Inject AFTER the existing 'ifp' declaration so our if-statement doesn't
    # precede a declaration (C90 forbids declarations after statements).
    if6_anchor = 'static int if6_seq_show(struct seq_file *seq, void *v)\n{\n\tstruct inet6_ifaddr *ifp = (struct inet6_ifaddr *)v;\n'
    if6_hook = guard(
        '\tif (ifp->idev && ifp->idev->dev &&\n'
        '\t    vpnhide_should_hide_dev(ifp->idev->dev))\n'
        '\t\treturn 0;\n'
    )
    if 'vpnhide_should_hide_dev' not in content or 'if6_seq_show' in content:
        if 'if6_seq_show' in content and 'if6_seq_show_vpnhide' not in content:
            func_idx = content.find(if6_anchor)
            if func_idx != -1:
                pos = func_idx + len(if6_anchor)
                if '#ifdef CONFIG_VPNHIDE' not in content[pos:pos+60]:
                    content = content[:pos] + if6_hook + content[pos:]
                    changed = True
            else:
                # Fallback: find function body opening brace, then skip past
                # any leading declaration so we stay C90-compliant.
                func_idx2 = content.find('static int if6_seq_show(')
                if func_idx2 != -1:
                    brace_idx = content.find('\n{', func_idx2)
                    if brace_idx != -1:
                        body_start = content.find('\n', brace_idx + 2) + 1
                        # skip past first declaration line if present
                        line_end = content.find('\n', body_start)
                        if line_end != -1 and 'inet6_ifaddr' in content[body_start:line_end]:
                            pos = line_end + 1
                        else:
                            pos = body_start
                        content = content[:pos] + if6_hook + content[pos:]
                        changed = True
                else:
                    print("WARNING: if6_seq_show not found in addrconf.c")

    return content, changed


def patch_net_ipv4_fib_semantics_c(content):
    inc = guard('#include "../../security/vpnhide/vpnhide.h"\n')
    content, changed = add_include(content, inc, [
        '#include "fib_lookup.h"',
        '#include <net/fib_notifier.h>',
        '#include <net/addrconf.h>',
    ])

    anchor = 'int fib_dump_info(struct sk_buff *skb, u32 portid, u32 seq,'
    hook = guard(
        '\tif (fi && fi->fib_nh[0].{0} &&\n'
        '\t    vpnhide_should_hide_dev(fi->fib_nh[0].{0}))\n'
        '\t\treturn 0;\n'.format(DEV_FIELD)
    )
    if 'vpnhide_should_hide_dev' not in content and anchor in content:
        idx = content.find(anchor)
        # Find first statement after local declarations
        pos = content.find('nlh = nlmsg_put(skb, portid, seq, event, sizeof(*rtm), flags);', idx)
        if pos != -1:
            content = content[:pos] + hook + content[pos:]
            changed = True
        else:
            print("WARNING: nlh = nlmsg_put anchor not found in fib_dump_info")

    return content, changed


def patch_net_ipv6_route_c(content):
    inc = guard('#include "../../security/vpnhide/vpnhide.h"\n')
    content, changed = add_include(content, inc, [
        '#include <trace/events/fib6.h>',
        '#include <linux/btf_ids.h>',
        '#include <linux/sysctl.h>',
    ])

    # Robustly find the actual definition of rt6_fill_node, skipping forward declarations
    pattern = r'(static\s+int\s+rt6_fill_node\b[^;]*?\{)'
    hook = guard(
        '\t{\n'
        '\t\tstruct net_device *_dev = dst ? dst->dev : rt->fib6_nh->fib_nh_dev;\n'
        '\t\tif (_dev && vpnhide_should_hide_dev(_dev))\n'
        '\t\t\treturn 0;\n'
        '\t}\n'
    )
    if 'vpnhide_should_hide_dev' not in content:
        match = re.search(pattern, content, re.DOTALL)
        if match:
            # Insert hook AFTER local variable declarations
            pos = content.find('nlh = nlmsg_put(skb, portid, seq, type, sizeof(*rtm), flags);', match.end())
            if pos != -1:
                content = content[:pos] + hook + content[pos:]
                changed = True
            else:
                print("WARNING: nlh = nlmsg_put anchor not found in rt6_fill_node")
        else:
            print("WARNING: rt6_fill_node definition not found in route.c")

    return content, changed


def patch_net_ipv6_ip6_fib_c(content):
    inc = guard('#include "../../security/vpnhide/vpnhide.h"\n')
    content, changed = add_include(content, inc, [
        '#include <linux/btf_ids.h>',
        '#include <linux/sysctl.h>',
        '#include <linux/version.h>',
    ])

    anchor = '\tdev = fib6_nh->fib_nh_dev;'
    hook = guard(
        '\tif (dev && vpnhide_should_hide_dev(dev))\n'
        '\t\treturn 0;\n'
    )
    if 'vpnhide_should_hide_dev' not in content:
        content, ok = insert_after(content, anchor, hook)
        if ok:
            changed = True

    return content, changed


def patch_net_ipv4_fib_trie_c(content):
    inc = guard('#include "../../security/vpnhide/vpnhide.h"\n')
    content, changed = add_include(content, inc, [
        '#include "fib_lookup.h"',
        '#include <trace/events/fib.h>',
        '#include <net/fib_notifier.h>',
    ])

    if 'vpnhide_should_hide_dev' not in content:
        func_anchor = 'static int fib_route_seq_show('
        flags_anchor = 'unsigned int flags = fib_flag_trans(fa->fa_type, mask, fi);'
        hook = guard(
            '\t\tif (fi && fi->fib_nh[0].{0} &&\n'
            '\t\t    vpnhide_should_hide_dev(fi->fib_nh[0].{0}))\n'
            '\t\t\tcontinue;\n'.format(DEV_FIELD)
        )
        func_idx = content.find(func_anchor)
        if func_idx != -1:
            flags_idx = content.find(flags_anchor, func_idx)
            if flags_idx != -1:
                pos = flags_idx + len(flags_anchor)
                content = content[:pos] + '\n' + hook + content[pos:]
                changed = True
            else:
                print("WARNING: flags anchor not found in fib_route_seq_show")
        else:
            print("WARNING: fib_route_seq_show not found in fib_trie.c")

    return content, changed


def patch_net_ipv4_udp_c(content):
    inc = guard('#include "../../security/vpnhide/vpnhide.h"\n')
    content, changed = add_include(content, inc, [
        '#include <trace/hooks/ipv4.h>',
        '#include <net/udp_tunnel.h>',
        '#include <net/ipv6_stubs.h>',
    ])

    anchor = 'int udp_sendmsg(struct sock *sk, struct msghdr *msg, size_t len)\n{'
    hook = guard(
        '\t{\n'
        '\t\tint _err = 0;\n'
        '\t\tif (vpnhide_udp_sendmsg_pre(sk, msg, len, &_err))\n'
        '\t\t\treturn _err;\n'
        '\t}\n'
    )
    if 'vpnhide_udp_sendmsg_pre' not in content:
        # Insert hook after local variable declarations
        pos = content.find('\tif (len > 0xFFFF)', content.find(anchor))
        if pos != -1:
            content = content[:pos] + hook + content[pos:]
            changed = True
        else:
            print("WARNING: if (len > 0xFFFF) anchor not found in udp_sendmsg")

    return content, changed


def patch_net_ipv6_udp_c(content):
    inc = guard('#include "../../security/vpnhide/vpnhide.h"\n')
    content, changed = add_include(content, inc, [
        '#include "udp_impl.h"',
        '#include <trace/events/skb.h>',
        '#include <linux/seq_file.h>',
    ])

    anchor = 'int udpv6_sendmsg(struct sock *sk, struct msghdr *msg, size_t len)\n{'
    hook = guard(
        '\t{\n'
        '\t\tint _err = 0;\n'
        '\t\tif (vpnhide_udp_sendmsg_pre(sk, msg, len, &_err))\n'
        '\t\t\treturn _err;\n'
        '\t}\n'
    )
    if 'vpnhide_udp_sendmsg_pre' not in content:
        # Insert hook after local variable declarations
        pos = content.find('\tipcm6_init(&ipc6);', content.find(anchor))
        if pos != -1:
            content = content[:pos] + hook + content[pos:]
            changed = True
        else:
            print("WARNING: ipcm6_init(&ipc6); anchor not found in udpv6_sendmsg")

    return content, changed


def patch_net_core_dev_ioctl_c(content):
    changed = False

    inc = guard('#include "../../security/vpnhide/vpnhide.h"\n')
    content, c = add_include(content, inc, [
        '#include <net/wext.h>',
        '#include <net/dsa.h>',
        '#include <linux/wireless.h>',
        '#include <linux/rtnetlink.h>',
    ])
    if c:
        changed = True

    # dev_ifconf: skip VPN interfaces — inject AFTER 'int done;' to respect C90 decl-before-stmt
    if 'vpnhide_should_hide_dev' not in content:
        anchor = '\tfor_each_netdev(net, dev) {\n\t\tint done;\n'
        hook = guard(
            '\t\tif (vpnhide_should_hide_dev(dev))\n'
            '\t\t\tcontinue;\n'
        )
        content, ok = insert_after(content, anchor, hook)
        if not ok:
            # Fallback: inject after opening brace only
            anchor2 = '\tfor_each_netdev(net, dev) {\n'
            content, ok = insert_after(content, anchor2, hook)
        if ok:
            changed = True
        else:
            print("WARNING: dev_ifconf for_each_netdev anchor not found")

    # dev_ifsioc_locked: return -ENODEV for VPN interfaces after the NULL check
    func_idx = content.find('static int dev_ifsioc_locked(')
    if func_idx != -1:
        func_end = content.find('\nstatic ', func_idx + 1)
        func_body = content[func_idx:func_end] if func_end != -1 else content[func_idx:]
        if 'vpnhide_should_hide_dev(dev)' not in func_body:
            nodev_idx = content.find('\tif (!dev)\n\t\treturn -ENODEV;\n', func_idx)
            if nodev_idx != -1:
                pos = nodev_idx + len('\tif (!dev)\n\t\treturn -ENODEV;\n')
                hook = guard(
                    '\tif (vpnhide_should_hide_dev(dev))\n'
                    '\t\treturn -ENODEV;\n'
                )
                content = content[:pos] + hook + content[pos:]
                changed = True
            else:
                print("WARNING: dev_ifsioc_locked -ENODEV anchor not found")
    else:
        print("WARNING: dev_ifsioc_locked not found in dev_ioctl.c")

    return content, changed


def patch_net_core_fib_rules_c(content):
    changed = False

    inc = guard('#include "../../security/vpnhide/vpnhide.h"\n')
    content, c = add_include(content, inc, [
        '#include <net/fib_rules.h>',
        '#include <net/sock.h>',
        '#include <linux/module.h>',
    ])
    if c:
        changed = True

    # fib_nl_fill_rule: skip rules for VPN interfaces before building the netlink msg.
    # Also filter uid-range rules that target a shielded UID (e.g. uidrange
    # 5555-5555 added for VPN split-routing) — they have no iifname/oifname
    # to match against. Gated on is_target_uid() (the CALLING process, e.g.
    # `ip rule show`) — matching against the rule's own uid_range would hide
    # the rule from everyone, including root.
    if 'vpnhide_should_hide_ifname' not in content:
        func_idx = content.find('static int fib_nl_fill_rule(')
        if func_idx != -1:
            # Inject after the function's local declarations — more robust
            # than searching for the nlmsg_put line whose arg was renamed
            # pid→portid in GKI2 kernels (android13-5.15+), and C90-safe
            # (GKI builds with -Wdeclaration-after-statement as an error).
            body_open = content.find('{', func_idx)
            if body_open != -1:
                inject_at = find_after_decls(content, body_open)
                uid_cond = (
                    ' ||\n'
                    '\t    is_target_uid_val(from_kuid(&init_user_ns,\n'
                    '\t\t\t\t\t  rule->uid_range.start)) ||\n'
                    '\t    is_target_uid_val(from_kuid(&init_user_ns,\n'
                    '\t\t\t\t\t  rule->uid_range.end))'
                    if HAS_FIB_RULE_UID else '')
                hook = guard(
                    '\tif (is_target_uid() &&\n'
                    '\t    ((rule->iifname[0] && vpnhide_should_hide_ifname(rule->iifname)) ||\n'
                    '\t     (rule->oifname[0] && vpnhide_should_hide_ifname(rule->oifname))'
                    + uid_cond + '))\n'
                    '\t\treturn 0;\n'
                )
                content = content[:inject_at] + hook + content[inject_at:]
                changed = True
            else:
                print("WARNING: fib_nl_fill_rule opening brace not found")
        else:
            print("WARNING: fib_nl_fill_rule not found in fib_rules.c")

    return content, changed


def patch_net_ipv6_af_inet6_c(content):
    changed = False

    inc = guard('#include "../../security/vpnhide/vpnhide.h"\n')
    content, c = add_include(content, inc, [
        '#include <net/addrconf.h>',
        '#include <net/inet_common.h>',
        '#include <linux/inet.h>',
        '#include <linux/module.h>',
    ])
    if c:
        changed = True

    # __inet6_bind: call vpnhide_inet6_bind_ll right after the AF_INET6 family check
    if 'vpnhide_inet6_bind_ll' not in content:
        anchor = '\tif (addr->sin6_family != AF_INET6)\n\t\treturn -EAFNOSUPPORT;\n'
        hook = guard(
            '\t{\n'
            '\t\tint _r = vpnhide_inet6_bind_ll(sk, uaddr, addr_len);\n'
            '\t\tif (_r)\n'
            '\t\t\treturn _r;\n'
            '\t}\n'
        )
        content, ok = insert_after(content, anchor, hook)
        if ok:
            changed = True
        else:
            print("WARNING: AF_INET6 family check anchor not found in af_inet6.c")

    return content, changed


def patch_kernel_bpf_syscall_c(content):
    inc = guard('#include "../../security/vpnhide/vpnhide.h"\n')
    content, changed = add_include(content, inc, [
        '#include <linux/bpf_verifier.h>',
        '#include <linux/bpf_trace.h>',
        '#include <linux/bpf.h>',
        '#include <linux/filter.h>',
    ])

    # map_lookup_elem: hook after bpf_map_copy_value succeeds, before copy_to_user
    hook_lookup = (
        '#ifdef CONFIG_VPNHIDE\n'
        '\tvpnhide_bpf_lookup_elem(map, key, value);\n'
        '#endif\n'
    )
    if 'vpnhide_bpf_lookup_elem' not in content:
        func_idx = content.find('static int map_lookup_elem(')
        if func_idx != -1:
            cv_idx = content.find('\terr = bpf_map_copy_value(map, key, value, attr->flags);', func_idx)
            if cv_idx == -1:
                cv_idx = content.find('        err = bpf_map_copy_value(map, key, value, attr->flags);', func_idx)
            if cv_idx != -1:
                line_end = content.find('\n', cv_idx) + 1
                content = content[:line_end] + hook_lookup + content[line_end:]
                changed = True
            else:
                print("WARNING: bpf_map_copy_value anchor not found in map_lookup_elem")
        else:
            print("WARNING: map_lookup_elem not found in kernel/bpf/syscall.c")

    # bpf_map_do_batch: hook after all batch updates, before err_put to not break the if/else chain
    hook_batch = (
        '#ifdef CONFIG_VPNHIDE\n'
        '\tif (!err && (cmd == BPF_MAP_LOOKUP_BATCH ||\n'
        '\t             cmd == BPF_MAP_LOOKUP_AND_DELETE_BATCH))\n'
        '\t\tvpnhide_bpf_lookup_batch(map, attr, uattr);\n'
        '#endif\n\n'
    )
    if 'vpnhide_bpf_lookup_batch' not in content:
        if 'err_put:\n\tif (has_write)' in content:
            content, ok = insert_before(content, 'err_put:\n\tif (has_write)', hook_batch)
            if ok:
                changed = True
        else:
            # Fallback with spaces
            hook_batch_spaces = (
                '#ifdef CONFIG_VPNHIDE\n'
                '        if (!err && (cmd == BPF_MAP_LOOKUP_BATCH ||\n'
                '                     cmd == BPF_MAP_LOOKUP_AND_DELETE_BATCH))\n'
                '                vpnhide_bpf_lookup_batch(map, attr, uattr);\n'
                '#endif\n\n'
            )
            content, ok = insert_before(content, 'err_put:\n        if (has_write)', hook_batch_spaces)
            if ok:
                changed = True

    return content, changed


def patch_net_core_net_procfs_c(content):
    """Patch net/core/net-procfs.c: hide VPN ifaces from /proc/net/dev."""
    changed = False

    inc = guard('#include "../../security/vpnhide/vpnhide.h"\n')
    content, c = add_include(content, inc, [
        '#include <linux/rtnetlink.h>',
        '#include <net/sock.h>',
        '#include <linux/netdevice.h>',
    ])
    if c:
        changed = True

    # dev_seq_show: when v != SEQ_START_TOKEN, v is a struct net_device*
    # Inject before dev_seq_printf_stats to skip VPN devices
    hook = guard(
        '\tif (v != SEQ_START_TOKEN && vpnhide_should_hide_dev((struct net_device *)v))\n'
        '\t\treturn 0;\n'
    )
    if 'vpnhide_should_hide_dev' not in content and 'dev_seq_show' in content:
        func_idx = content.find('static int dev_seq_show(')
        if func_idx != -1:
            brace_idx = content.find('\n{', func_idx)
            if brace_idx == -1:
                brace_idx = content.find(' {', func_idx)
            body_start = content.find('\n', brace_idx + 2) + 1 if brace_idx != -1 else -1
            if body_start > 0:
                content = content[:body_start] + hook + content[body_start:]
                changed = True
            else:
                print("WARNING: dev_seq_show body not found in net-procfs.c")
        else:
            print("WARNING: dev_seq_show not found in net-procfs.c")

    return content, changed


def patch_net_sched_sch_api_c(content):
    """Patch net/sched/sch_api.c: hide VPN interfaces from TC qdisc dumps."""
    changed = False

    inc = guard('#include "../../security/vpnhide/vpnhide.h"\n')
    content, c = add_include(content, inc, [
        '#include <net/pkt_sched.h>',
        '#include <net/rtnetlink.h>',
        '#include <linux/rtnetlink.h>',
    ])
    if c:
        changed = True

    # tc_fill_qdisc: inject after cond_resched(), before nlmsg_put
    # qdisc_dev(q) returns the net_device — use vpnhide_should_hide_dev
    hook = guard(
        '\tif (vpnhide_should_hide_dev(qdisc_dev(q)))\n'
        '\t\tgoto out_nlmsg_trim;\n'
    )
    if 'vpnhide_should_hide_dev' not in content and 'tc_fill_qdisc' in content:
        func_idx = content.find('static int tc_fill_qdisc(')
        if func_idx != -1:
            # inject after cond_resched(); — present in all GKI2
            anchor = '\tcond_resched();\n'
            cs_idx = content.find(anchor, func_idx)
            if cs_idx != -1:
                pos = cs_idx + len(anchor)
                content = content[:pos] + hook + content[pos:]
                changed = True
            else:
                # fallback: inject at start of function body
                brace_idx = content.find('\n{', func_idx)
                if brace_idx != -1:
                    body_start = content.find('\n', brace_idx + 2) + 1
                    content = content[:body_start] + hook + content[body_start:]
                    changed = True
                else:
                    print("WARNING: tc_fill_qdisc body anchor not found in sch_api.c")
        else:
            print("WARNING: tc_fill_qdisc not found in sch_api.c")

    return content, changed


def patch_fs_proc_sysctl_c(content):
    """Patch fs/proc/proc_sysctl.c: hide VPN interface sysctl dirs."""
    changed = False

    inc = guard('#include "../../../security/vpnhide/vpnhide.h"\n')
    content, c = add_include(content, inc, [
        '#include <linux/sysctl.h>',
        '#include <linux/capability.h>',
        '#include <linux/security.h>',
    ])
    if c:
        changed = True

    # proc_sys_lookup: after lookup_entry succeeds (p != NULL), filter VPN iface names
    # name->name contains the directory/file name, name->len its length
    # NOTE: do NOT call sysctl_head_finish(h) here. The `out:` label already
    # does `if (h) sysctl_head_finish(h);` and `h` is not NULLed, so finishing
    # it here too underflows the header used-count (unuse_table: !--p->used),
    # which later hangs unregister_sysctl_table on its completion. Just goto out
    # — err is still ERR_PTR(-ENOENT) at this point.
    hook = guard(
        '\tif (p) {\n'
        '\t\tconst struct qstr *_qname = &dentry->d_name;\n'
        '\t\tif (vpnhide_filter_sysctl(dir, _qname->name, _qname->len))\n'
        '\t\t\tgoto out;\n'
        '\t}\n'
    )
    if 'vpnhide_filter_sysctl' not in content and 'proc_sys_lookup' in content:
        func_idx = content.find('static struct dentry *proc_sys_lookup(')
        if func_idx != -1:
            # inject right after 'p = lookup_entry(...);\n'
            le_anchor = 'p = lookup_entry(&h, ctl_dir, name->name, name->len);\n'
            le_idx = content.find(le_anchor, func_idx)
            if le_idx != -1:
                pos = le_idx + len(le_anchor)
                content = content[:pos] + hook + content[pos:]
                changed = True
            else:
                print("WARNING: lookup_entry anchor not found in proc_sys_lookup")
        else:
            print("WARNING: proc_sys_lookup not found in fs/proc/proc_sysctl.c")

    return content, changed


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <kernel_common_dir>")
        sys.exit(1)

    d = sys.argv[1]
    if not os.path.isdir(d):
        print(f"ERROR: {d} is not a directory")
        sys.exit(1)

    # Automatically check the nexthop device field from the target source tree header
    ip_fib_h_path = os.path.join(d, "include/net/ip_fib.h")
    global DEV_FIELD, HAS_FIB_RULE_UID
    if os.path.exists(ip_fib_h_path):
        ip_fib_h = read(ip_fib_h_path)
        if 'fib_nh_dev' in ip_fib_h:
            DEV_FIELD = 'fib_nh_dev'
        else:
            DEV_FIELD = 'nh_dev'
        print(f"Detected DEV_FIELD: {DEV_FIELD}")

    # Check if struct fib_rule carries a uid range (field is
    # `struct fib_kuid_range uid_range;` on modern kernels; the uapi type
    # `struct fib_rule_uid_range` is only the netlink wire format and is not
    # the in-kernel field name — don't match against that).
    fib_rules_h_path = os.path.join(d, "include/net/fib_rules.h")
    if os.path.exists(fib_rules_h_path):
        fib_rules_h = read(fib_rules_h_path)
        HAS_FIB_RULE_UID = 'fib_kuid_range' in fib_rules_h and 'uid_range' in fib_rules_h
        print(f"Detected HAS_FIB_RULE_UID: {HAS_FIB_RULE_UID}")

    print(f"=== VPNHide patcher: {d} ===")

    patch_file(os.path.join(d, "security/Kconfig"),        patch_security_kconfig)
    patch_file(os.path.join(d, "security/Makefile"),       patch_security_makefile)
    patch_file(os.path.join(d, "net/socket.c"),            patch_net_socket_c)
    patch_file(os.path.join(d, "fs/namei.c"),              patch_fs_namei_c)
    patch_file(os.path.join(d, "fs/readdir.c"),            patch_fs_readdir_c)
    patch_file(os.path.join(d, "net/core/rtnetlink.c"),    patch_net_core_rtnetlink_c)
    patch_file(os.path.join(d, "net/ipv4/devinet.c"),      patch_net_ipv4_devinet_c)
    patch_file(os.path.join(d, "net/ipv6/addrconf.c"),     patch_net_ipv6_addrconf_c)
    patch_file(os.path.join(d, "net/ipv4/fib_semantics.c"),patch_net_ipv4_fib_semantics_c)
    patch_file(os.path.join(d, "net/ipv6/route.c"),        patch_net_ipv6_route_c)
    patch_file(os.path.join(d, "net/ipv6/ip6_fib.c"),      patch_net_ipv6_ip6_fib_c)
    patch_file(os.path.join(d, "net/ipv4/fib_trie.c"),     patch_net_ipv4_fib_trie_c)
    patch_file(os.path.join(d, "net/ipv4/udp.c"),          patch_net_ipv4_udp_c)
    patch_file(os.path.join(d, "net/ipv6/udp.c"),          patch_net_ipv6_udp_c)
    patch_file(os.path.join(d, "kernel/bpf/syscall.c"),    patch_kernel_bpf_syscall_c)
    patch_file(os.path.join(d, "net/core/dev_ioctl.c"),    patch_net_core_dev_ioctl_c)
    patch_file(os.path.join(d, "net/core/fib_rules.c"),    patch_net_core_fib_rules_c)
    patch_file(os.path.join(d, "net/ipv6/af_inet6.c"),     patch_net_ipv6_af_inet6_c)
    patch_file(os.path.join(d, "net/core/net-procfs.c"),   patch_net_core_net_procfs_c)
    patch_file(os.path.join(d, "net/sched/sch_api.c"),     patch_net_sched_sch_api_c)
    patch_file(os.path.join(d, "fs/proc/proc_sysctl.c"),   patch_fs_proc_sysctl_c)

    print("=== VPNHide patcher: done ===")


if __name__ == '__main__':
    main()
