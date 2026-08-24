#!/usr/bin/env python3
"""Insert the inet6_fill_ifaddr hook after the 6.18 declaration block."""

from pathlib import Path
import sys


def main() -> None:
    path = Path(sys.argv[1])
    lines = path.read_text().splitlines(keepends=True)
    start = next(i for i, line in enumerate(lines)
                 if line.startswith("static int inet6_fill_ifaddr("))
    end = next(i for i in range(start + 1, len(lines))
               if lines[i].startswith("static ") and "inet6_fill_ifaddr" not in lines[i])
    if any("vpnhide_should_hide_dev(ifa->idev->dev)" in line
           for line in lines[start:end]):
        return
    target = next(i for i in range(start, end)
                  if lines[i].lstrip().startswith("nlh = nlmsg_put("))
    hook = [
        "#ifdef CONFIG_VPNHIDE\n",
        "\tif (ifa->idev && ifa->idev->dev &&\n",
        "\t    unlikely(vpnhide_should_hide_dev(ifa->idev->dev)))\n",
        "\t\treturn 0;\n",
        "#endif\n",
    ]
    lines[target:target] = hook
    path.write_text("".join(lines))


if __name__ == "__main__":
    main()
