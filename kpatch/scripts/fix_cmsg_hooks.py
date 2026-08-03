#!/usr/bin/env python3
"""Inject VPNHide packet-info hooks at the ancillary-data producers."""

from pathlib import Path
import sys


def inject(path: Path, needle: str, replacement: str, marker: str) -> None:
    text = path.read_text()
    if marker in text:
        return
    count = text.count(needle)
    if count != 1:
        raise SystemExit(f"{path}: expected one hook site, found {count}")
    path.write_text(text.replace(needle, replacement, 1))


def inject_include(path: Path) -> None:
    text = path.read_text()
    include = "#include <linux/vpnhide.h>\n"
    if include in text:
        return
    first_include = text.find("#include ")
    if first_include < 0:
        raise SystemExit(f"{path}: no include insertion point")
    path.write_text(text[:first_include] + include + text[first_include:])


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit(f"usage: {sys.argv[0]} <kernel-dir>")
    root = Path(sys.argv[1])
    inject_include(root / "net/ipv4/ip_sockglue.c")
    inject_include(root / "net/ipv6/datagram.c")
    inject(
        root / "net/ipv4/ip_sockglue.c",
        "\tinfo.ipi_addr.s_addr = ip_hdr(skb)->daddr;\n\n"
        "\tput_cmsg(msg, SOL_IP, IP_PKTINFO, sizeof(info), &info);",
        "\tinfo.ipi_addr.s_addr = ip_hdr(skb)->daddr;\n"
        "\tvpnhide_pktinfo4_post(&info);\n\n"
        "\tput_cmsg(msg, SOL_IP, IP_PKTINFO, sizeof(info), &info);",
        "vpnhide_pktinfo4_post(&info)",
    )
    inject(
        root / "net/ipv6/datagram.c",
        "\t\tif (src_info.ipi6_ifindex >= 0)\n"
        "\t\t\tput_cmsg(msg, SOL_IPV6, IPV6_PKTINFO,",
        "\t\tvpnhide_pktinfo6_post(&src_info);\n\n"
        "\t\tif (src_info.ipi6_ifindex >= 0)\n"
        "\t\t\tput_cmsg(msg, SOL_IPV6, IPV6_PKTINFO,",
        "vpnhide_pktinfo6_post(&src_info)",
    )


if __name__ == "__main__":
    main()
