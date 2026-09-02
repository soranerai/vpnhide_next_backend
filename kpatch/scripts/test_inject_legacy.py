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

    def inject_ipv6_spec(self, source: str) -> str:
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
                self.anchor,
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


if __name__ == "__main__":
    unittest.main()
