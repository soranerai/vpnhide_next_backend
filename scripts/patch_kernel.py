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
    """Insert `insertion` right after the first occurrence of `anchor`."""
    idx = content.find(anchor)
    if idx == -1:
        return None, False
    pos = idx + len(anchor)
    return content[:pos] + '\n' + insertion + content[pos:], True

def insert_before(content, anchor, insertion):
    """Insert `insertion` right before the first occurrence of `anchor`."""
    idx = content.find(anchor)
    if idx == -1:
        return None, False
    return content[:idx] + insertion + '\n' + content[idx:], True

def guard(toggle_guard):
    """Wrap `toggle_guard` in CONFIG_VPNHIDE guards."""
    return f'#ifdef CONFIG_VPNHIDE\n{toggle_guard}#endif\n'

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

    # 2. __sys_bind: hook before ops->bind
    bind_anchor = '\t\t\terr = sock->ops->bind(sock,'
    bind_hook = guard(
        '\t\tvpnhide_bind(sock, umyaddr, addrlen);\n'
    )
    if 'vpnhide_bind' not in content:
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

    # 4. __sys_getsockname: hook after move_addr_to_user (first occurrence)
    getsockname_anchor = 'err = move_addr_to_user(&address, err, usockaddr, usockaddr_len);'
    getsockname_hook = guard(
        '\tvpnhide_getname(sock, (struct sockaddr *)&address, 0, &err);\n'
    )
    if 'vpnhide_getname(sock, (struct sockaddr *)&address, 0' not in content:
        content, ok = insert_after(content, getsockname_anchor, getsockname_hook)
        if ok:
            changed = True
        else:
            print("WARNING: getsockname anchor not found")

    # 5. __sys_getpeername: hook after second move_addr_to_user
    getpeername_anchor = 'err = move_addr_to_user(&address, err, usockaddr, usockaddr_len);'
    getpeername_hook = guard(
        '\tvpnhide_getname(sock, (struct sockaddr *)&address, 1, &err);\n'
    )
    if 'vpnhide_getname(sock, (struct sockaddr *)&address, 1' not in content:
        # Find second occurrence
        idx = content.find(getsockname_anchor)
        if idx != -1:
            idx2 = content.find(getsockname_anchor, idx + len(getsockname_anchor))
            if idx2 != -1:
                pos = idx2 + len(getsockname_anchor)
                content = content[:pos] + '\n' + getpeername_hook + content[pos:]
                changed = True

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

    # filename_lookup: hook if lookup succeeded (err == 0)
    fname_anchor = 'filename_lookup(int dfd, struct filename *name, unsigned int flags,'
    if 'vpnhide_filename_lookup' not in content:
        idx = content.find(fname_anchor)
        if idx != -1:
            ret_anchor = '\treturn err;\n}'
            idx2 = content.find(ret_anchor, idx)
            if idx2 != -1:
                hook = (
                    '\n#ifdef CONFIG_VPNHIDE\n'
                    '\tif (!err)\n'
                    '\t\tvpnhide_filename_lookup(dfd, name, flags, path, &err);\n'
                    '#endif\n'
                )
                content = content[:idx2] + hook + content[idx2:]
                changed = True

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

    # SYSCALL_DEFINE3(getdents64): hook after iterate_dir call.
    anchor_iter = 'error = iterate_dir(f.file, &buf.ctx);\n        if (error >= 0)'
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
            iter_idx = content.find('error = iterate_dir(f.file, &buf.ctx);', sys_idx)
            if iter_idx != -1:
                pos = iter_idx + len('error = iterate_dir(f.file, &buf.ctx);')
                content = content[:pos] + '\n' + hook_iter + content[pos:]
                changed = True
            else:
                print("WARNING: getdents64 iterate_dir anchor not found")
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

    # rtnl_dump_ifinfo: skip hidden devices in the for_each_netdev loop
    for anchor in [
        'for_each_netdev_dump(net, dev, ctx->ifindex)',
        'for_each_netdev(net, dev)',
        'for_each_netdev_rcu(net, dev)',
    ]:
        if anchor in content and 'vpnhide_should_hide_dev(dev)' not in content:
            hook = guard(
                '\t\tif (vpnhide_should_hide_dev(dev))\n'
                '\t\t\tcontinue;\n'
            )
            content, ok = insert_after(content, anchor + ' {', hook)
            if not ok:
                content, ok = insert_after(content, anchor, hook)
            if ok:
                changed = True
            break

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
    global DEV_FIELD
    if os.path.exists(ip_fib_h_path):
        ip_fib_h = read(ip_fib_h_path)
        if 'fib_nh_dev' in ip_fib_h:
            DEV_FIELD = 'fib_nh_dev'
        else:
            DEV_FIELD = 'nh_dev'
        print(f"Detected DEV_FIELD: {DEV_FIELD}")

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

    print("=== VPNHide patcher: done ===")


if __name__ == '__main__':
    main()
