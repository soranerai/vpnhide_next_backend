#!/usr/bin/env python3
"""Structure-aware VPNHide injector for the 4.19 and Android common 5.4 trees.

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
        specs += [
            ("net/ipv4/fib_semantics.c", "fib_dump_info", "\tnlh = nlmsg_put(",
             "#ifdef CONFIG_VPNHIDE\n\tif (fi && fi->fib_nh[0].fib_nh_dev &&\n\t    vpnhide_should_hide_dev(fi->fib_nh[0].fib_nh_dev))\n\t\treturn 0;\n#endif\n",
             "vpnhide_should_hide_dev(fi->fib_nh[0].fib_nh_dev)"),
            ("net/ipv4/fib_trie.c", "fib_route_seq_show", "\t\tif ((fa->fa_type",
             "#ifdef CONFIG_VPNHIDE\n\t\tif (fi && fi->fib_nh[0].fib_nh_dev &&\n\t\t    vpnhide_should_hide_dev(fi->fib_nh[0].fib_nh_dev))\n\t\t\tcontinue;\n#endif\n\n",
             "vpnhide_should_hide_dev(fi->fib_nh[0].fib_nh_dev)"),
            ("net/ipv6/ip6_fib.c", "ipv6_route_seq_show", "\tdev = fib6_nh->fib_nh_dev;",
             "\n#ifdef CONFIG_VPNHIDE\n\tif (dev && vpnhide_should_hide_dev(dev))\n\t\treturn 0;\n#endif\n\n",
             "vpnhide_should_hide_dev(dev)", True),
            ("net/ipv6/route.c", "rt6_fill_node", "\tnlh = nlmsg_put(",
             "#ifdef CONFIG_VPNHIDE\n\t{\n\t\tstruct net_device *_dev = dst ? dst->dev : rt->fib6_nh->fib_nh_dev;\n\t\tif (_dev && vpnhide_should_hide_dev(_dev))\n\t\t\treturn 0;\n\t}\n#endif\n",
             "vpnhide_should_hide_dev(_dev)"),
        ]
    else:
        specs += [
            ("net/ipv4/fib_semantics.c", "fib_dump_info", "\tnlh = nlmsg_put(",
             "#ifdef CONFIG_VPNHIDE\n\tif (fi && fi->fib_dev && vpnhide_should_hide_dev(fi->fib_dev))\n\t\treturn 0;\n#endif\n",
             "vpnhide_should_hide_dev(fi->fib_dev)"),
            ("net/ipv4/fib_trie.c", "fib_route_seq_show", "\t\tif ((fa->fa_type",
             "#ifdef CONFIG_VPNHIDE\n\t\tif (fi && fi->fib_dev && vpnhide_should_hide_dev(fi->fib_dev))\n\t\t\tcontinue;\n#endif\n\n",
             "vpnhide_should_hide_dev(fi->fib_dev)"),
            ("net/ipv6/ip6_fib.c", "ipv6_route_seq_show", "\tseq_printf(seq, \" %08x",
             "#ifdef CONFIG_VPNHIDE\n\tif (dev && vpnhide_should_hide_dev(dev)) {\n\t\titer->w.leaf = NULL;\n\t\treturn 0;\n\t}\n#endif\n\n",
             "vpnhide_should_hide_dev(dev)"),
            ("net/ipv6/route.c", "rt6_fill_node", "\tnlh = nlmsg_put(",
             "#ifdef CONFIG_VPNHIDE\n\t{\n\t\tstruct net_device *_dev = dst ? dst->dev : rt->fib6_nh.nh_dev;\n\t\tif (_dev && vpnhide_should_hide_dev(_dev))\n\t\t\treturn 0;\n\t}\n#endif\n",
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


def main() -> int:
    if len(sys.argv) != 3 or sys.argv[2] not in ("upstream-4.19", "android12-5.4"):
        print(f"usage: {sys.argv[0]} <kernel-dir> <upstream-4.19|android12-5.4>", file=sys.stderr)
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
        common.inject_socket_adjacent()
        inject_socket()
        common.inject_cmsg()
    except common.InjectError as exc:
        print(f"inject_legacy.py: ERROR: {exc}", file=sys.stderr)
        return 1
    print(f"inject_legacy.py: VPNHide hooks injected successfully for {sys.argv[2]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
