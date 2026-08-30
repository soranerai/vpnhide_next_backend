#!/usr/bin/env python3
"""Print the effective build version for vpnhide_next artifacts.

Used by every packaging step (module.prop and CI artifact names), so dev
builds are unambiguously identifiable at a glance. It stays stdlib-only for
minimal build environments.
"""

from __future__ import annotations

import sys

from build_lib import get_build_version


def main() -> int:
    print(get_build_version())
    return 0


if __name__ == "__main__":
    sys.exit(main())
