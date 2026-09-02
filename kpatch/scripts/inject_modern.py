#!/usr/bin/env python3
"""Structure-aware VPNHide injector for Android common 5.10 and newer.

This intentionally edits only named functions and fails when an expected
anchor is absent or ambiguous.  Legacy 4.19/5.4 use the sibling
``inject_legacy.py`` profile-specific structural injector.
"""

from __future__ import annotations

from pathlib import Path
import subprocess
import sys


ROOT: Path


class InjectError(RuntimeError):
    pass


def fail(message: str) -> None:
    raise InjectError(message)


def read(relpath: str) -> str:
    path = ROOT / relpath
    if not path.is_file():
        fail(f"missing source file: {relpath}")
    return path.read_text()


def write(relpath: str, text: str) -> None:
    (ROOT / relpath).write_text(text)


def function_span(text: str, name: str) -> tuple[int, int]:
    """Return the byte span of a C function identified by its name."""
    needle = f"{name}("
    starts = []
    offset = 0
    while True:
        index = text.find(needle, offset)
        if index < 0:
            break
        if index > 0 and (text[index - 1].isalnum() or text[index - 1] == "_"):
            offset = index + len(needle)
            continue
        line_start = text.rfind("\n", 0, index) + 1
        prefix = text[line_start:index].strip()
        # Every target currently has its return type on the same, unindented
        # line.  This excludes calls in `if (...) {`, which otherwise also
        # have an opening brace before their next semicolon.
        if not (prefix.startswith("static ") or prefix in ("int", "__be32")):
            offset = index + len(needle)
            continue
        # Function calls are normally indented; declarations start at column 0
        # or after `static`/a return type.  Find an opening brace before the
        # next semicolon and reject call sites/prototypes.
        brace = text.find("{", index)
        semi = text.find(";", index)
        if brace >= 0 and (semi < 0 or brace < semi):
            starts.append((index, brace))
        offset = index + len(needle)
    if len(starts) != 1:
        # Older kernels implement socket entrypoints directly through the
        # SYSCALL_DEFINE<n>() macro instead of __sys_* helpers.
        macro_indices = []
        for argc in range(7):
            macro = f"SYSCALL_DEFINE{argc}({name},"
            index = text.find(macro)
            if index >= 0 and text.find(macro, index + 1) < 0:
                macro_indices.append(index)
        if len(macro_indices) == 1:
            macro_index = macro_indices[0]
            brace = text.find("{", macro_index)
            semi = text.find(";", macro_index)
            if brace >= 0 and (semi < 0 or brace < semi):
                starts.append((macro_index, brace))
        if len(starts) != 1:
            fail(f"{name}: expected one function definition, found {len(starts)}")
    start, brace = starts[0]
    depth = 0
    for end in range(brace, len(text)):
        if text[end] == "{":
            depth += 1
        elif text[end] == "}":
            depth -= 1
            if depth == 0:
                return start, end + 1
    fail(f"{name}: unmatched opening brace")


def ensure_include(relpath: str) -> None:
    text = read(relpath)
    include = "#include <linux/vpnhide.h>\n"
    if include in text:
        return
    first_include = text.find("#include ")
    if first_include < 0:
        fail(f"{relpath}: no include insertion point")
    write(relpath, text[:first_include] + include + text[first_include:])


def insert_in_function(relpath: str, function: str, anchor: str, block: str,
                       *, before: bool = True, marker: str | None = None) -> None:
    text = read(relpath)
    start, end = function_span(text, function)
    body = text[start:end]
    marker = marker or block.strip()
    if marker in body:
        return
    count = body.count(anchor)
    if count != 1:
        fail(f"{relpath}:{function}: expected one anchor {anchor!r}, found {count}")
    index = start + body.index(anchor)
    if not before:
        index += len(anchor)
    write(relpath, text[:index] + block + text[index:])


def insert_at_compatible_anchor(relpath: str, function: str,
                                anchors: tuple[str, ...], block: str,
                                marker: str) -> None:
    """Insert before exactly one of several known API-era anchors."""
    text = read(relpath)
    start, end = function_span(text, function)
    body = text[start:end]
    if marker in body:
        return
    matches = [(anchor, body.count(anchor)) for anchor in anchors]
    usable = [anchor for anchor, count in matches if count == 1]
    if len(usable) != 1:
        detail = ", ".join(f"{anchor!r}={count}" for anchor, count in matches)
        fail(f"{relpath}:{function}: expected one compatible anchor ({detail})")
    index = start + body.index(usable[0])
    write(relpath, text[:index] + block + text[index:])


def replace_in_function(relpath: str, function: str, old: str, new: str,
                        marker: str) -> None:
    text = read(relpath)
    start, end = function_span(text, function)
    body = text[start:end]
    if marker in body:
        return
    count = body.count(old)
    if count != 1:
        fail(f"{relpath}:{function}: expected one replacement anchor, found {count}")
    write(relpath, text[:start] + body.replace(old, new, 1) + text[end:])


def inject_build_files() -> None:
    kconfig = read("security/Kconfig")
    source = 'source "security/vpnhide/Kconfig"\n'
    if source not in kconfig:
        count = kconfig.count("endmenu")
        if count != 1:
            fail(f"security/Kconfig: expected one endmenu, found {count}")
        kconfig = kconfig.replace("endmenu", "\n" + source + "endmenu", 1)
        write("security/Kconfig", kconfig)

    makefile = read("security/Makefile")
    line = "obj-$(CONFIG_VPNHIDE)\t\t\t+= vpnhide/\n"
    if "CONFIG_VPNHIDE" not in makefile:
        write("security/Makefile", makefile.rstrip() + "\n" + line)


def inject_bpf() -> None:
    rel = "kernel/bpf/syscall.c"
    ensure_include(rel)
    insert_in_function(
        rel, "map_lookup_elem", "\tif (copy_to_user(uvalue, value, value_size) != 0)",
        "#ifdef CONFIG_VPNHIDE\n\tvpnhide_bpf_lookup_elem(map, key, value);\n#endif\n\n",
        marker="vpnhide_bpf_lookup_elem",
    )
    insert_in_function(
        rel, "bpf_map_do_batch", "err_put:",
        "#ifdef CONFIG_VPNHIDE\n"
        "\tif (!err && (cmd == BPF_MAP_LOOKUP_BATCH ||\n"
        "\t             cmd == BPF_MAP_LOOKUP_AND_DELETE_BATCH))\n"
        "\t\tvpnhide_bpf_lookup_batch(map, attr, uattr);\n"
        "#endif\n\n",
        marker="vpnhide_bpf_lookup_batch",
    )


def inject_dev_ioctl() -> None:
    rel = "net/core/dev_ioctl.c"
    ensure_include(rel)
    text = read(rel)
    start, end = function_span(text, "dev_ifname")
    body = text[start:end]
    if "vpnhide_should_hide_ifname" not in body:
        old = "\treturn netdev_get_name(net, ifr->ifr_name, ifr->ifr_ifindex);"
        if old in body:
            declaration_at = text.find("{\n", start, end)
            if declaration_at < 0:
                fail(f"{rel}:dev_ifname: no opening brace")
            text = text[:declaration_at + 2] + "\tint _ret;\n" + text[declaration_at + 2:]
            start, end = function_span(text, "dev_ifname")
            body = text[start:end]
            new = "\t_ret = netdev_get_name(net, ifr->ifr_name, ifr->ifr_ifindex);\n"
            new += "#ifdef CONFIG_VPNHIDE\n"
            new += "\tif (_ret == 0 && vpnhide_should_hide_ifname(ifr->ifr_name))\n"
            new += "\t\treturn -ENODEV;\n"
            new += "#endif\n"
            new += "\treturn _ret;"
            text = text[:start] + body.replace(old, new, 1) + text[end:]
        else:
            # Linux 4.14 stores the result in `error` and checks it on the
            # following line before copying the ifreq back to userspace.
            old = "\terror = netdev_get_name(net, ifr.ifr_name, ifr.ifr_ifindex);"
            new = old + "\n#ifdef CONFIG_VPNHIDE\n"
            new += "\tif (!error && vpnhide_should_hide_ifname(ifr.ifr_name))\n"
            new += "\t\treturn -ENODEV;\n"
            new += "#endif"
            if body.count(old) != 1:
                fail(f"{rel}:dev_ifname: expected one netdev_get_name result")
            text = text[:start] + body.replace(old, new, 1) + text[end:]
        write(rel, text)
    # Old 5.10 sublevels declare `int done;` as the first item inside the
    # loop.  Keep the hook after that declaration to satisfy C90; newer trees
    # can receive it directly after the loop opener.
    text = read(rel)
    start, end = function_span(text, "dev_ifconf")
    body = text[start:end]
    marker = "vpnhide_should_hide_dev(dev)"
    if marker not in body:
        anchor = "for_each_netdev(net, dev) {"
        if body.count(anchor) != 1:
            fail(f"{rel}:dev_ifconf: expected one netdev loop")
        insert_at = start + body.index(anchor) + len(anchor)
        tail = text[insert_at:end]
        leading = 0
        while leading < len(tail) and tail[leading] in " \t\n":
            leading += 1
        first_line_end = tail.find("\n", leading)
        first_line = tail[leading:first_line_end] if first_line_end >= 0 else tail[leading:]
        if "int done;" in first_line:
            insert_at += first_line_end + 1
        hook = "\n#ifdef CONFIG_VPNHIDE\n\t\tif (vpnhide_should_hide_dev(dev))\n\t\t\tcontinue;\n#endif\n"
        write(rel, text[:insert_at] + hook + text[insert_at:])
    insert_in_function(
        rel, "dev_ifsioc_locked", "\tswitch (cmd) {",
        "#ifdef CONFIG_VPNHIDE\n\tif (vpnhide_should_hide_dev(dev))\n\t\treturn -ENODEV;\n#endif\n\n",
        marker="vpnhide_should_hide_dev(dev)",
    )


def inject_filters() -> None:
    specs = [
        ("net/core/fib_rules.c", "fib_nl_fill_rule", "\tnlh = nlmsg_put(",
         "#ifdef CONFIG_VPNHIDE\n"
         "\tif (is_target_uid()) {\n"
         "\t\tif ((rule->iifname[0] && vpnhide_should_hide_ifname(rule->iifname)) ||\n"
         "\t\t    (rule->oifname[0] && vpnhide_should_hide_ifname(rule->oifname)))\n"
         "\t\t\treturn 0;\n"
         "\t\t{\n"
         "\t\t\tuid_t _s = from_kuid(&init_user_ns, rule->uid_range.start);\n"
         "\t\t\tuid_t _e = from_kuid(&init_user_ns, rule->uid_range.end);\n"
         "\t\t\tif (_e != (uid_t)~0 &&\n"
         "\t\t\t    (_s >= 10000 || _e >= 10000 ||\n"
         "\t\t\t     is_target_uid_val(_s) || is_target_uid_val(_e)) &&\n"
         "\t\t\t    rule->table != 253 && rule->table != 254 &&\n"
         "\t\t\t    rule->table != 255 && rule->table > 100)\n"
         "\t\t\t\treturn 0;\n"
         "\t\t}\n"
         "\t}\n"
         "#endif\n\n", "vpnhide_should_hide_ifname(rule->iifname)"),
        ("net/core/net-procfs.c", "dev_seq_show", "\tif (v == SEQ_START_TOKEN)",
         "#ifdef CONFIG_VPNHIDE\n"
         "\tif (v != SEQ_START_TOKEN && vpnhide_should_hide_dev((struct net_device *)v))\n"
         "\t\treturn 0;\n"
         "#endif\n", "vpnhide_should_hide_dev((struct net_device *)v)"),
        ("net/core/rtnetlink.c", "rtnl_fill_ifinfo", "\tASSERT_RTNL();",
         "#ifdef CONFIG_VPNHIDE\n\tif (dev && vpnhide_should_hide_dev(dev))\n\t\treturn 0;\n#endif\n\n",
         "vpnhide_should_hide_dev(dev)"),
        ("net/ipv4/fib_semantics.c", "fib_dump_info", "\tnlh = nlmsg_put(",
         "#ifdef CONFIG_VPNHIDE\n"
         "\tif (fi && !fi->nh && fi->fib_nh[0].fib_nh_dev &&\n"
         "\t    vpnhide_should_hide_dev(fi->fib_nh[0].fib_nh_dev))\n"
         "\t\treturn 0;\n"
         "#endif\n", "vpnhide_should_hide_dev(fi->fib_nh[0].fib_nh_dev)"),
        ("net/ipv4/fib_trie.c", "fib_route_seq_show", "\t\tif ((fa->fa_type",
         "#ifdef CONFIG_VPNHIDE\n"
         "\t\tif (fi && !fi->nh && fi->fib_nh[0].fib_nh_dev &&\n"
         "\t\t    vpnhide_should_hide_dev(fi->fib_nh[0].fib_nh_dev))\n"
         "\t\t\tcontinue;\n"
         "#endif\n\n", "vpnhide_should_hide_dev(fi->fib_nh[0].fib_nh_dev)"),
        ("net/ipv6/ip6_fib.c", "ipv6_route_native_seq_show", "\tdev = fib6_nh->fib_nh_dev;",
         "\n#ifdef CONFIG_VPNHIDE\n\tif (dev && vpnhide_should_hide_dev(dev))\n\t\treturn 0;\n#endif\n\n",
         "vpnhide_should_hide_dev(dev)", True),
        ("net/ipv6/route.c", "rt6_fill_node", "\tnlh = nlmsg_put(",
         "#ifdef CONFIG_VPNHIDE\n"
         "\t{\n"
         "\t\tstruct net_device *_dev = dst ? dst->dev : rt->fib6_nh->fib_nh_dev;\n"
         "\t\tif (_dev && vpnhide_should_hide_dev(_dev))\n"
         "\t\t\treturn 0;\n"
         "\t}\n"
         "#endif\n", "vpnhide_should_hide_dev(_dev)"),
        ("net/sched/sch_api.c", "tc_fill_qdisc", "\tnlh = nlmsg_put(",
         "#ifdef CONFIG_VPNHIDE\n\tif (vpnhide_should_hide_dev(qdisc_dev(q)))\n\t\tgoto out_nlmsg_trim;\n#endif\n",
         "vpnhide_should_hide_dev(qdisc_dev(q))"),
    ]
    for spec in specs:
        rel, func, anchor, block, marker, *after = spec
        ensure_include(rel)
        insert_in_function(rel, func, anchor, block, marker=marker,
                           before=not bool(after and after[0]))


def inject_address_paths() -> None:
    rel = "net/ipv4/devinet.c"
    ensure_include(rel)
    insert_in_function(
        rel, "devinet_ioctl", "\tif (!dev)\n\t\tgoto done;",
        "\n#ifdef CONFIG_VPNHIDE\n"
        "\tif (vpnhide_should_hide_dev(dev)) {\n"
        "\t\tret = -ENODEV;\n"
        "\t\tgoto done;\n"
        "\t}\n"
        "#endif\n\n", before=False, marker="vpnhide_should_hide_dev(dev)",
    )
    insert_in_function(
        rel, "inet_select_addr", "\t\tif (l3mdev_master_ifindex_rcu(dev)",
        "#ifdef CONFIG_VPNHIDE\n\t\tif (vpnhide_should_hide_dev(dev))\n\t\t\tcontinue;\n#endif\n\n",
        marker="vpnhide_should_hide_dev(dev)",
    )
    insert_in_function(
        rel, "inet_fill_ifaddr", "\tnlh = nlmsg_put(",
        "#ifdef CONFIG_VPNHIDE\n"
        "\tif (ifa->ifa_dev && ifa->ifa_dev->dev &&\n"
        "\t    vpnhide_should_hide_dev(ifa->ifa_dev->dev))\n"
        "\t\treturn 0;\n"
        "#endif\n", marker="vpnhide_should_hide_dev(ifa->ifa_dev->dev)",
    )

    rel = "net/ipv6/addrconf.c"
    ensure_include(rel)
    insert_in_function(
        rel, "ipv6_dev_get_saddr", "\t\t/* only consider addresses on devices",
        "#ifdef CONFIG_VPNHIDE\n\t\tif (vpnhide_should_hide_dev(dev))\n\t\t\tcontinue;\n#endif\n\n",
        marker="vpnhide_should_hide_dev(dev)",
    )
    insert_in_function(
        rel, "if6_seq_show", "\tseq_printf(",
        "#ifdef CONFIG_VPNHIDE\n"
        "\tif (ifp->idev && ifp->idev->dev &&\n"
        "\t    vpnhide_should_hide_dev(ifp->idev->dev))\n"
        "\t\treturn 0;\n"
        "#endif\n", marker="vpnhide_should_hide_dev(ifp->idev->dev)",
    )
    insert_in_function(
        rel, "inet6_fill_ifaddr", "\tnlh = nlmsg_put(",
        "#ifdef CONFIG_VPNHIDE\n"
        "\tif (ifa->idev && ifa->idev->dev &&\n"
        "\t    unlikely(vpnhide_should_hide_dev(ifa->idev->dev)))\n"
        "\t\treturn 0;\n"
        "#endif\n", marker="vpnhide_should_hide_dev(ifa->idev->dev)",
    )


def inject_socket_adjacent() -> None:
    rel = "net/ipv4/udp.c"
    ensure_include(rel)
    insert_in_function(
        rel, "udp_sendmsg", "\tif (len > 0xFFFF)",
        "#ifdef CONFIG_VPNHIDE\n\t{\n\t\tint _err = 0;\n"
        "\t\tif (vpnhide_udp_sendmsg_pre(sk, msg, len, &_err))\n"
        "\t\t\treturn _err;\n\t}\n#endif\n",
        marker="vpnhide_udp_sendmsg_pre",
    )
    rel = "net/ipv6/udp.c"
    ensure_include(rel)
    insert_at_compatible_anchor(
        rel, "udpv6_sendmsg", ("\tipcm6_init_sk(", "\tipcm6_init(&ipc6);"),
        "#ifdef CONFIG_VPNHIDE\n\t{\n\t\tint _err = 0;\n"
        "\t\tif (vpnhide_udp_sendmsg_pre(sk, msg, len, &_err))\n"
        "\t\t\treturn _err;\n\t}\n#endif\n",
        marker="vpnhide_udp_sendmsg_pre",
    )
    rel = "net/ipv6/af_inet6.c"
    ensure_include(rel)
    insert_in_function(
        rel, "__inet6_bind", "\taddr_type = ipv6_addr_type(",
        "#ifdef CONFIG_VPNHIDE\n\t{\n"
        "\t\tint _r = vpnhide_inet6_bind_ll(sk, uaddr, addr_len);\n"
        "\t\tif (_r)\n\t\t\treturn _r;\n"
        "\t}\n#endif\n\n", marker="vpnhide_inet6_bind_ll",
    )


def inject_socket() -> None:
    rel = "net/socket.c"
    ensure_include(rel)
    script = Path(__file__).with_name("fix_socket_hooks.py")
    subprocess.run([sys.executable, str(script), str(ROOT / rel),
                    "--setsockopt", "--connect", "--bind-getname"], check=True)
    text = read(rel)
    required = (
        "vpnhide_getsockopt", "vpnhide_setsockopt", "vpnhide_connect(",
        "vpnhide_listen_post", "vpnhide_bind_pre", "vpnhide_bind_post",
        "vpnhide_getname(sock, (struct sockaddr *)&address, 0,",
        "vpnhide_getname(sock, (struct sockaddr *)&address, 1,",
    )
    missing = [marker for marker in required if marker not in text]
    if missing:
        fail(f"net/socket.c: socket injector missed {', '.join(missing)}")


def inject_cmsg() -> None:
    script = Path(__file__).with_name("fix_cmsg_hooks.py")
    subprocess.run([sys.executable, str(script), str(ROOT)], check=True)
    required = {
        "net/ipv4/ip_sockglue.c": "vpnhide_pktinfo4_post",
        "net/ipv6/datagram.c": "vpnhide_pktinfo6_post",
    }
    for relpath, marker in required.items():
        if marker not in read(relpath):
            fail(f"{relpath}: ancillary-data injector missed {marker}")


def main() -> int:
    global ROOT
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} <kernel-common-dir>", file=sys.stderr)
        return 2
    ROOT = Path(sys.argv[1]).resolve()
    if not ROOT.is_dir():
        print(f"kernel directory not found: {ROOT}", file=sys.stderr)
        return 2
    try:
        inject_build_files()
        inject_bpf()
        inject_dev_ioctl()
        inject_filters()
        inject_address_paths()
        inject_socket_adjacent()
        inject_socket()
        inject_cmsg()
    except InjectError as exc:
        print(f"inject_modern.py: ERROR: {exc}", file=sys.stderr)
        return 1
    print("inject_modern.py: VPNHide hooks injected successfully")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
