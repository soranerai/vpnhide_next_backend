#!/usr/bin/env python3
"""Regression tests for legacy IPv6 route hook placement."""

from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

import inject_legacy as legacy


common = legacy.common


class LegacyIpv6RouteInjectorTest(unittest.TestCase):
    hook = "vpnhide_should_hide_dev(dev)"
    anchor = "\tdev = fib6_nh->fib_nh_dev;"

    def inject_ipv6_spec(self, source: str, anchor: str | None = None) -> str:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            rel = "net/ipv6/ip6_fib.c"
            path = root / rel
            path.parent.mkdir(parents=True)
            path.write_text(source)
            common.ROOT = root

            # Exercise the same function choice and insertion primitive used
            # by inject_filters(), without requiring a complete kernel tree.
            show = legacy.ipv6_route_show_function()
            legacy.insert(
                rel,
                show,
                anchor or self.anchor,
                "\n#ifdef CONFIG_VPNHIDE\n"
                "\tif (dev && vpnhide_should_hide_dev(dev))\n"
                "\t\treturn 0;\n"
                "#endif\n\n",
                self.hook,
                before=False,
            )
            return common.read(rel)

    def test_unmodified_54_uses_original_renderer(self) -> None:
        result = self.inject_ipv6_spec(
            "#include <linux/seq_file.h>\n"
            "static int ipv6_route_seq_show(struct seq_file *seq, void *v)\n"
            "{\n"
            "\tdev = fib6_nh->fib_nh_dev;\n"
            "\treturn 0;\n"
            "}\n"
        )

        self.assertEqual(result.count(self.hook), 1)
        self.assertLess(result.index(self.anchor), result.index(self.hook))

    def test_bpf_iterator_backport_uses_native_renderer(self) -> None:
        result = self.inject_ipv6_spec(
            "#include <linux/seq_file.h>\n"
            "static int ipv6_route_native_seq_show(struct seq_file *seq, void *v)\n"
            "{\n"
            "\tdev = fib6_nh->fib_nh_dev;\n"
            "\treturn 0;\n"
            "}\n\n"
            "static int ipv6_route_seq_show(struct seq_file *seq, void *v)\n"
            "{\n"
            "\treturn ipv6_route_native_seq_show(seq, v);\n"
            "}\n"
        )

        native_start = result.index("ipv6_route_native_seq_show(")
        dispatcher_start = result.index("ipv6_route_seq_show(")
        self.assertEqual(result.count(self.hook), 1)
        self.assertGreater(result.index(self.hook), native_start)
        self.assertLess(result.index(self.hook), dispatcher_start)

    def test_bpf_backport_avoids_duplicate_419_dispatchers(self) -> None:
        result = self.inject_ipv6_spec(
            "#include <linux/seq_file.h>\n"
            "static int ipv6_route_native_seq_show(struct seq_file *seq, void *v)\n"
            "{\n\tseq_printf(seq, \" %08x\", 0);\n\treturn 0;\n}\n"
            "#if defined(CONFIG_BPF_SYSCALL)\n"
            "static int ipv6_route_seq_show(struct seq_file *seq, void *v)\n"
            "{\n\treturn ipv6_route_native_seq_show(seq, v);\n}\n"
            "#else\n"
            "static int ipv6_route_seq_show(struct seq_file *seq, void *v)\n"
            "{\n\treturn ipv6_route_native_seq_show(seq, v);\n}\n"
            "#endif\n",
            '\tseq_printf(seq, " %08x',
        )

        self.assertEqual(result.count(self.hook), 1)
        self.assertLess(
            result.index(self.hook),
            result.index("ipv6_route_seq_show("),
        )

    def test_function_span_accepts_legacy_syscall_macro(self) -> None:
        source = (
            "SYSCALL_DEFINE5(setsockopt, int, fd, int, level, int, optname,\n"
            "\t\tchar __user *, optval, int, optlen)\n"
            "{\n"
            "\treturn 0;\n"
            "}\n"
        )

        start, end = common.function_span(source, "setsockopt")
        self.assertIn("SYSCALL_DEFINE5(setsockopt", source[start:end])
        self.assertIn("return 0", source[start:end])

    def test_upstream_419_nexthop_backport_uses_fib_nh(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "include/net/ip_fib.h"
            path.parent.mkdir(parents=True)
            path.write_text("struct fib_info {\n\tstruct nexthop\t\t*nh;\n};\n")
            common.ROOT = root
            self.assertTrue(legacy.fib_info_uses_nexthop())

    def test_upstream_419_regular_tree_uses_fib_dev(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "include/net/ip_fib.h"
            path.parent.mkdir(parents=True)
            path.write_text("struct fib_info {\n\tstruct net_device *fib_dev;\n};\n")
            common.ROOT = root
            self.assertFalse(legacy.fib_info_uses_nexthop())

    def test_upstream_419_nexthop_array_uses_fib6_nh_index(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "include/net/ip6_fib.h"
            path.parent.mkdir(parents=True)
            path.write_text("struct fib6_info {\n\tstruct fib6_nh\t\t\tfib6_nh[0];\n};\n")
            common.ROOT = root
            self.assertTrue(legacy.fib6_info_uses_nexthop_array())

    def test_upstream_414_backported_fib_nh_device_member(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "include/net/ip_fib.h"
            path.parent.mkdir(parents=True)
            path.write_text("struct fib_nh { struct net_device *fib_nh_dev; };\n")
            common.ROOT = root
            self.assertTrue(legacy.fib_nh_uses_fib_nh_dev())

    def test_dev_ifname_accepts_both_414_and_newer_shapes(self) -> None:
        templates = (
            (
                "\tint error;\n"
                "\terror = netdev_get_name(net, ifr.ifr_name, ifr.ifr_ifindex);\n"
                "\tif (error)\n\t\treturn error;",
                "vpnhide_should_hide_ifname(ifr.ifr_name)",
            ),
            (
                "\treturn netdev_get_name(net, ifr->ifr_name, ifr->ifr_ifindex);",
                "vpnhide_should_hide_ifname(ifr->ifr_name)",
            ),
        )
        for dev_ifname_body, expected_hook in templates:
            with self.subTest(expected_hook=expected_hook), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                path = root / "net/core/dev_ioctl.c"
                path.parent.mkdir(parents=True)
                path.write_text(
                    "#include <linux/netdevice.h>\n"
                    "static int dev_ifname(void)\n{\n" + dev_ifname_body + "\n}\n"
                    "static int dev_ifconf(void)\n{\n"
                    "\tfor_each_netdev(net, dev) {\n\t\tint done;\n\t}\n}\n"
                    "static int dev_ifsioc_locked(void)\n{\n\tswitch (cmd) {\n\t}\n}\n"
                )
                common.ROOT = root
                common.inject_dev_ioctl()
                result = path.read_text()
                self.assertIn(expected_hook, result)


if __name__ == "__main__":
    unittest.main()
