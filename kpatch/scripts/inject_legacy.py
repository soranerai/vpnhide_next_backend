#!/usr/bin/env python3
"""Structure-aware VPNHide injector for upstream 4.14/4.19 and Android common 5.4.

The two legacy profiles share the same set of hooks, but a few networking
structures changed between them.  Keep those differences explicit here rather
than carrying two context diffs that silently drift away from the sources.
"""

from __future__ import annotations

from pathlib import Path
import subprocess
import sys

import inject_modern as common


def insert(rel: str, function: str, anchor: str, block: str, marker: str,
           *, before: bool = True) -> None:
    common.ensure_include(rel)
    common.insert_in_function(rel, function, anchor, block, marker=marker,
                              before=before)


def inject_bpf() -> None:
    rel = "kernel/bpf/syscall.c"
    insert(rel, "map_lookup_elem", "\tif (copy_to_user(uvalue, value, value_size) != 0)",
           "#ifdef CONFIG_VPNHIDE\n\tvpnhide_bpf_lookup_elem(map, key, value);\n#endif\n\n",
           "vpnhide_bpf_lookup_elem")


def ipv6_route_show_function() -> str:
    """Return the conventional IPv6 route renderer for a legacy tree."""
    ip6_fib = common.read("net/ipv6/ip6_fib.c")
    # A BPF-iterator backport keeps ipv6_route_seq_show() as a dispatcher and
    # moves the proc renderer into the native function.
    if "ipv6_route_native_seq_show(" in ip6_fib:
        return "ipv6_route_native_seq_show"
    return "ipv6_route_seq_show"


def fib_info_uses_nexthop() -> bool:
    """Return whether this legacy tree has the backported nexthop member."""
    ip_fib = common.read("include/net/ip_fib.h")
    return "struct nexthop\t\t*nh;" in ip_fib or "struct nexthop *nh;" in ip_fib


def fib6_info_uses_nexthop_array() -> bool:
    """Return whether fib6_info stores direct nexthops in its flexible array."""
    ip6_fib = common.read("include/net/ip6_fib.h")
    return "struct fib6_nh\t\t\tfib6_nh[0];" in ip6_fib or "struct fib6_nh fib6_nh[0];" in ip6_fib


def fib_nh_uses_fib_nh_dev() -> bool:
    """Return whether the legacy fib_nh member uses the backported name."""
    return "fib_nh_dev" in common.read("include/net/ip_fib.h")


def inject_filters(profile: str) -> None:
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
         "\t\t\tif (_e != (uid_t)~0 && (_s >= 10000 || _e >= 10000 ||\n"
         "\t\t\t    is_target_uid_val(_s) || is_target_uid_val(_e)) &&\n"
         "\t\t\t    rule->table != 253 && rule->table != 254 &&\n"
         "\t\t\t    rule->table != 255 && rule->table > 100)\n"
         "\t\t\t\treturn 0;\n"
         "\t\t}\n\t}\n#endif\n\n", "vpnhide_should_hide_ifname(rule->iifname)"),
        ("net/core/net-procfs.c", "dev_seq_show", "\tif (v == SEQ_START_TOKEN)",
         "#ifdef CONFIG_VPNHIDE\n\tif (v != SEQ_START_TOKEN && vpnhide_should_hide_dev((struct net_device *)v))\n\t\treturn 0;\n#endif\n",
         "vpnhide_should_hide_dev((struct net_device *)v)"),
        ("net/core/rtnetlink.c", "rtnl_fill_ifinfo", "\tASSERT_RTNL();",
         "#ifdef CONFIG_VPNHIDE\n\tif (dev && vpnhide_should_hide_dev(dev))\n\t\treturn 0;\n#endif\n\n",
         "vpnhide_should_hide_dev(dev)"),
        ("net/sched/sch_api.c", "tc_fill_qdisc", "\tnlh = nlmsg_put(",
         "#ifdef CONFIG_VPNHIDE\n\tif (vpnhide_should_hide_dev(qdisc_dev(q)))\n\t\tgoto out_nlmsg_trim;\n#endif\n",
         "vpnhide_should_hide_dev(qdisc_dev(q))"),
    ]
    if profile == "android12-5.4":
        # Some Android common 5.4 derivatives backport BPF iterators for
        # ipv6_route.  That backport moves the conventional proc renderer
        # from ipv6_route_seq_show() into ipv6_route_native_seq_show(), while
        # retaining the former as a dispatcher.  Put the hook in the native
        # renderer when it exists; unmodified 5.4 trees keep the old function.
        ipv6_route_show = ipv6_route_show_function()
        specs += [
            ("net/ipv4/fib_semantics.c", "fib_dump_info", "\tnlh = nlmsg_put(",
             "#ifdef CONFIG_VPNHIDE\n\tif (fi && fi->fib_nh[0].fib_nh_dev &&\n\t    vpnhide_should_hide_dev(fi->fib_nh[0].fib_nh_dev))\n\t\treturn 0;\n#endif\n",
             "vpnhide_should_hide_dev(fi->fib_nh[0].fib_nh_dev)"),
            ("net/ipv4/fib_trie.c", "fib_route_seq_show", "\t\tif ((fa->fa_type",
             "#ifdef CONFIG_VPNHIDE\n\t\tif (fi && fi->fib_nh[0].fib_nh_dev &&\n\t\t    vpnhide_should_hide_dev(fi->fib_nh[0].fib_nh_dev))\n\t\t\tcontinue;\n#endif\n\n",
             "vpnhide_should_hide_dev(fi->fib_nh[0].fib_nh_dev)"),
            ("net/ipv6/ip6_fib.c", ipv6_route_show, "\tdev = fib6_nh->fib_nh_dev;",
             "\n#ifdef CONFIG_VPNHIDE\n\tif (dev && vpnhide_should_hide_dev(dev))\n\t\treturn 0;\n#endif\n\n",
             "vpnhide_should_hide_dev(dev)", True),
            ("net/ipv6/route.c", "rt6_fill_node", "\tnlh = nlmsg_put(",
             "#ifdef CONFIG_VPNHIDE\n\t{\n\t\tstruct net_device *_dev = dst ? dst->dev : rt->fib6_nh->fib_nh_dev;\n\t\tif (_dev && vpnhide_should_hide_dev(_dev))\n\t\t\treturn 0;\n\t}\n#endif\n",
             "vpnhide_should_hide_dev(_dev)"),
        ]
    elif profile == "upstream-4.14":
        # Android 4.14 trees can backport the BPF iterator just as 4.19/5.4
        # do.  Its renderer is renamed to ipv6_route_native_seq_show(); the
        # dispatcher has two preprocessor alternatives, so never inject it.
        ipv6_route_show = ipv6_route_show_function()
        if ipv6_route_show == "ipv6_route_native_seq_show":
            ipv6_anchor = "\tdev = rt->fib6_nh.nh_dev;"
            ipv6_filter = (
                "\n#ifdef CONFIG_VPNHIDE\n\tif (dev && vpnhide_should_hide_dev(dev)) {\n"
                "\t\titer->w.leaf = NULL;\n\t\treturn 0;\n\t}\n#endif\n\n"
            )
            ipv6_marker = "vpnhide_should_hide_dev(dev)"
        else:
            ipv6_anchor = "\tseq_printf(seq, \"%pi6 %02x \", &rt->rt6i_dst.addr, rt->rt6i_dst.plen);"
            ipv6_filter = (
                "#ifdef CONFIG_VPNHIDE\n\tif (rt->dst.dev && vpnhide_should_hide_dev(rt->dst.dev)) {\n"
                "\t\titer->w.leaf = NULL;\n\t\treturn 0;\n\t}\n#endif\n\n"
            )
            ipv6_marker = "vpnhide_should_hide_dev(rt->dst.dev)"
        fib_nh_dev = "fib_nh_dev" if fib_nh_uses_fib_nh_dev() else "nh_dev"
        rt6_source = common.read("net/ipv6/route.c")
        if "struct fib6_info *rt, struct dst_entry *dst" in rt6_source:
            rt6_dev = "dst ? dst->dev : rt->fib6_nh.nh_dev"
        else:
            rt6_dev = "rt->dst.dev"
        specs += [
            ("net/ipv4/fib_semantics.c", "fib_dump_info", "\tnlh = nlmsg_put(",
             f"#ifdef CONFIG_VPNHIDE\n\tif (fi && fi->fib_nh->{fib_nh_dev} &&\n\t    vpnhide_should_hide_dev(fi->fib_nh->{fib_nh_dev}))\n\t\treturn 0;\n#endif\n",
             f"vpnhide_should_hide_dev(fi->fib_nh->{fib_nh_dev})"),
            ("net/ipv4/fib_trie.c", "fib_route_seq_show", "\t\tif ((fa->fa_type",
             "#ifdef CONFIG_VPNHIDE\n\t\tif (fi && fi->fib_dev && vpnhide_should_hide_dev(fi->fib_dev))\n\t\t\tcontinue;\n#endif\n\n",
             "vpnhide_should_hide_dev(fi->fib_dev)"),
            ("net/ipv6/ip6_fib.c", ipv6_route_show, ipv6_anchor,
             ipv6_filter, ipv6_marker),
            ("net/ipv6/route.c", "rt6_fill_node", "\tnlh = nlmsg_put(",
             f"#ifdef CONFIG_VPNHIDE\n\t{{\n\t\tstruct net_device *_dev = {rt6_dev};\n\t\tif (_dev && vpnhide_should_hide_dev(_dev))\n\t\t\treturn 0;\n\t}}\n#endif\n\n",
             "vpnhide_should_hide_dev(_dev)"),
        ]
    else:
        ipv6_route_show = ipv6_route_show_function()
        # Android 4.19 vendor trees can backport the nexthop infrastructure
        # from newer kernels.  Its fib_info has no fib_dev; keep the original
        # upstream-4.19 expression for ordinary trees, but use the same safe
        # direct-nexthop condition as newer profiles when the member exists.
        if fib_info_uses_nexthop():
            fib_dump_filter = (
                "#ifdef CONFIG_VPNHIDE\n\tif (fi && !fi->nh && fi->fib_nh[0].fib_nh_dev &&\n"
                "\t    vpnhide_should_hide_dev(fi->fib_nh[0].fib_nh_dev))\n\t\treturn 0;\n#endif\n"
            )
            fib_trie_filter = (
                "#ifdef CONFIG_VPNHIDE\n\t\tif (fi && !fi->nh && fi->fib_nh[0].fib_nh_dev &&\n"
                "\t\t    vpnhide_should_hide_dev(fi->fib_nh[0].fib_nh_dev))\n\t\t\tcontinue;\n#endif\n\n"
            )
            fib_marker = "vpnhide_should_hide_dev(fi->fib_nh[0].fib_nh_dev)"
        else:
            fib_dump_filter = (
                "#ifdef CONFIG_VPNHIDE\n\tif (fi && fi->fib_dev && vpnhide_should_hide_dev(fi->fib_dev))\n\t\treturn 0;\n#endif\n"
            )
            fib_trie_filter = (
                "#ifdef CONFIG_VPNHIDE\n\t\tif (fi && fi->fib_dev && vpnhide_should_hide_dev(fi->fib_dev))\n\t\t\tcontinue;\n#endif\n\n"
            )
            fib_marker = "vpnhide_should_hide_dev(fi->fib_dev)"
        if fib6_info_uses_nexthop_array():
            rt6_dev = "dst ? dst->dev : (!rt->nh ? rt->fib6_nh[0].fib_nh_dev : NULL)"
        else:
            rt6_dev = "dst ? dst->dev : rt->fib6_nh.nh_dev"
        specs += [
            ("net/ipv4/fib_semantics.c", "fib_dump_info", "\tnlh = nlmsg_put(",
             fib_dump_filter, fib_marker),
            ("net/ipv4/fib_trie.c", "fib_route_seq_show", "\t\tif ((fa->fa_type",
             fib_trie_filter, fib_marker),
            ("net/ipv6/ip6_fib.c", ipv6_route_show, "\tseq_printf(seq, \" %08x",
             "#ifdef CONFIG_VPNHIDE\n\tif (dev && vpnhide_should_hide_dev(dev)) {\n\t\titer->w.leaf = NULL;\n\t\treturn 0;\n\t}\n#endif\n\n",
             "vpnhide_should_hide_dev(dev)"),
            ("net/ipv6/route.c", "rt6_fill_node", "\tnlh = nlmsg_put(",
             f"#ifdef CONFIG_VPNHIDE\n\t{{\n\t\tstruct net_device *_dev = {rt6_dev};\n\t\tif (_dev && vpnhide_should_hide_dev(_dev))\n\t\t\treturn 0;\n\t}}\n#endif\n",
             "vpnhide_should_hide_dev(_dev)"),
        ]
    for spec in specs:
        rel, func, anchor, block, marker, *after = spec
        insert(rel, func, anchor, block, marker, before=not bool(after and after[0]))


def inject_socket() -> None:
    rel = "net/socket.c"
    common.ensure_include(rel)
    subprocess.run([sys.executable, str(Path(__file__).with_name("fix_socket_hooks.py")),
                    str(common.ROOT / rel), "--setsockopt", "--connect", "--bind-getname",
                    "--legacy"],
                   check=True)
    text = common.read(rel)
    required = ("vpnhide_getsockopt", "vpnhide_setsockopt", "vpnhide_connect(",
                "vpnhide_listen_post", "vpnhide_bind_pre", "vpnhide_bind_post",
                "vpnhide_getname(sock, (struct sockaddr *)&address, 0,",
                "vpnhide_getname(sock, (struct sockaddr *)&address, 1,")
    missing = [marker for marker in required if marker not in text]
    if missing:
        common.fail(f"net/socket.c: legacy socket injector missed {', '.join(missing)}")


def inject_socket_adjacent_414() -> None:
    """Inject UDP and IPv6 bind hooks at their pre-5.4 call sites."""
    rel = "net/ipv4/udp.c"
    common.ensure_include(rel)
    common.insert_in_function(
        rel, "udp_sendmsg", "\tif (len > 0xFFFF)",
        "#ifdef CONFIG_VPNHIDE\n\t{\n\t\tint _err = 0;\n"
        "\t\tif (vpnhide_udp_sendmsg_pre(sk, msg, len, &_err))\n"
        "\t\t\treturn _err;\n\t}\n#endif\n",
        marker="vpnhide_udp_sendmsg_pre",
    )
    rel = "net/ipv6/udp.c"
    common.ensure_include(rel)
    common.insert_in_function(
        rel, "udpv6_sendmsg", "\tsockc.tsflags = sk->sk_tsflags;",
        "#ifdef CONFIG_VPNHIDE\n\t{\n\t\tint _err = 0;\n"
        "\t\tif (vpnhide_udp_sendmsg_pre(sk, msg, len, &_err))\n"
        "\t\t\treturn _err;\n\t}\n#endif\n",
        marker="vpnhide_udp_sendmsg_pre",
    )
    rel = "net/ipv6/af_inet6.c"
    common.ensure_include(rel)
    # Android 4.14 backports can split the binding implementation into
    # __inet6_bind(), leaving inet6_bind() as a thin BPF-CGROUP wrapper.
    # Hook the implementation that actually owns addr_type in either shape.
    inet6_source = common.read(rel)
    inet6_bind_function = "__inet6_bind" if "__inet6_bind(" in inet6_source else "inet6_bind"
    common.insert_in_function(
        rel, inet6_bind_function, "\taddr_type = ipv6_addr_type(",
        "#ifdef CONFIG_VPNHIDE\n\t{\n"
        "\t\tint _r = vpnhide_inet6_bind_ll(sk, uaddr, addr_len);\n"
        "\t\tif (_r)\n\t\t\treturn _r;\n"
        "\t}\n#endif\n\n",
        marker="vpnhide_inet6_bind_ll",
    )


def inject_socket_414() -> None:
    """Inject socket syscall hooks for the pre-__sys_* 4.14 implementation."""
    rel = "net/socket.c"
    common.ensure_include(rel)
    socket_source = common.read(rel)
    common.replace_in_function(
        rel, "bind",
        "\t\t\tif (!err)\n"
        "\t\t\t\terr = sock->ops->bind(sock,\n"
        "\t\t\t\t\t\t      (struct sockaddr *)\n"
        "\t\t\t\t\t\t      &address, addrlen);",
        "\t\t\tif (!err) {\n"
        "#ifdef CONFIG_VPNHIDE\n"
        "\t\t\t\tvpnhide_bind_pre(sock, (struct sockaddr *)&address, addrlen);\n"
        "#endif\n"
        "\t\t\t\terr = sock->ops->bind(sock, (struct sockaddr *)&address, addrlen);\n"
        "#ifdef CONFIG_VPNHIDE\n"
        "\t\t\t\tvpnhide_bind_post(sock, err);\n"
        "#endif\n"
        "\t\t\t}",
        marker="vpnhide_bind_post",
    )
    common.replace_in_function(
        rel, "listen",
        "\t\tif (!err)\n\t\t\terr = sock->ops->listen(sock, backlog);",
        "\t\tif (!err) {\n"
        "\t\t\terr = sock->ops->listen(sock, backlog);\n"
        "#ifdef CONFIG_VPNHIDE\n\t\t\tvpnhide_listen_post(sock, err);\n#endif\n"
        "\t\t}",
        marker="vpnhide_listen_post",
    )
    common.replace_in_function(
        rel, "connect",
        "\terr = sock->ops->connect(sock, (struct sockaddr *)&address, addrlen,\n"
        "\t\t\t\t sock->file->f_flags);",
        "#ifdef CONFIG_VPNHIDE\n"
        "\terr = vpnhide_connect_pre(sock, (struct sockaddr *)&address, addrlen);\n"
        "\tif (!err)\n"
        "#endif\n"
        "\t\terr = sock->ops->connect(sock, (struct sockaddr *)&address, addrlen,\n"
        "\t\t\t\t sock->file->f_flags);",
        marker="vpnhide_connect_pre",
    )
    common.insert_in_function(
        rel, "getsockname", "\terr = move_addr_to_user(&address, len, usockaddr, usockaddr_len);",
        "#ifdef CONFIG_VPNHIDE\n"
        "\tvpnhide_getname(sock, (struct sockaddr *)&address, 0, &err);\n"
        "#endif\n",
        marker="vpnhide_getname(sock, (struct sockaddr *)&address, 0,",
    )
    common.replace_in_function(
        rel, "getpeername",
        "\t\tif (!err)\n"
        "\t\t\terr = move_addr_to_user(&address, len, usockaddr,\n"
        "\t\t\t\t\t\tusockaddr_len);",
        "\t\tif (!err) {\n"
        "#ifdef CONFIG_VPNHIDE\n"
        "\t\t\tvpnhide_getname(sock, (struct sockaddr *)&address, 1, &err);\n"
        "#endif\n"
        "\t\t\terr = move_addr_to_user(&address, len, usockaddr,\n"
        "\t\t\t\t\t\tusockaddr_len);\n"
        "\t\t}",
        marker="vpnhide_getname(sock, (struct sockaddr *)&address, 1,",
    )
    setsockopt_function = "__sys_setsockopt" if "__sys_setsockopt(" in socket_source else "setsockopt"
    common.insert_in_function(
        rel, setsockopt_function, "\tif (sock != NULL) {",
        "\n#ifdef CONFIG_VPNHIDE\n\t\t{\n"
        "\t\t\tint _vret = vpnhide_setsockopt_sock(sock, level, optname, optval, optlen);\n"
        "\t\t\tif (_vret) {\n\t\t\t\terr = (_vret > 0) ? 0 : _vret;\n"
        "\t\t\t\tgoto out_put;\n\t\t\t}\n\t\t}\n#endif\n",
        before=False, marker="vpnhide_setsockopt_sock",
    )
    getsockopt_function = "__sys_getsockopt" if "__sys_getsockopt(" in socket_source else "getsockopt"
    common.insert_in_function(
        rel, getsockopt_function, "out_put:",
        "#ifdef CONFIG_VPNHIDE\n"
        "\tif (!err)\n\t\tvpnhide_getsockopt(sock, level, optname, optval, optlen, &err);\n"
        "#endif\n",
        marker="vpnhide_getsockopt(sock, level, optname, optval, optlen, &err)",
    )


def main() -> int:
    if len(sys.argv) != 3 or sys.argv[2] not in ("upstream-4.14", "upstream-4.19", "android12-5.4"):
        print(f"usage: {sys.argv[0]} <kernel-dir> <upstream-4.14|upstream-4.19|android12-5.4>", file=sys.stderr)
        return 2
    common.ROOT = Path(sys.argv[1]).resolve()
    if not common.ROOT.is_dir():
        print(f"kernel directory not found: {common.ROOT}", file=sys.stderr)
        return 2
    try:
        common.inject_build_files()
        inject_bpf()
        common.inject_dev_ioctl()
        inject_filters(sys.argv[2])
        common.inject_address_paths()
        if sys.argv[2] == "upstream-4.14":
            inject_socket_adjacent_414()
        else:
            common.inject_socket_adjacent()
        if sys.argv[2] == "upstream-4.14":
            inject_socket_414()
        else:
            inject_socket()
        common.inject_cmsg()
    except common.InjectError as exc:
        print(f"inject_legacy.py: ERROR: {exc}", file=sys.stderr)
        return 1
    print(f"inject_legacy.py: VPNHide hooks injected successfully for {sys.argv[2]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
