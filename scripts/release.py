#!/usr/bin/env python3
#
# /// script
# requires-python = ">=3.12"
# dependencies = [
#   "rich",
# ]
# ///
"""Cut a new release: propagate the new version number to the kernel module properties file.

Usage:
  release.py X.Y.Z
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

from rich.console import Console

# Resolve repo root relative to scripts directory
REPO_ROOT = Path(__file__).resolve().parent.parent
VERSION_RE = re.compile(r"^\d+\.\d+\.\d+$")


def parse_version(raw: str) -> tuple[str, int]:
    if not VERSION_RE.match(raw):
        raise SystemExit(f"error: expected MAJOR.MINOR.PATCH, got {raw!r}")
    major, minor, patch = (int(p) for p in raw.split("."))
    return raw, major * 10000 + minor * 100 + patch


def patch_file(path: Path, replacements: list[tuple[re.Pattern[str], str]]) -> None:
    """Apply each pattern → replacement once."""
    text = path.read_text(encoding="utf-8")
    new_text = text
    for pattern, replacement in replacements:
        new_text, n = pattern.subn(replacement, new_text, count=1)
        if n == 0:
            raise SystemExit(
                f"error: pattern {pattern.pattern!r} did not match in {path}. "
                f"File format probably changed — update release.py."
            )
    if new_text != text:
        path.write_text(new_text, encoding="utf-8")


def update_module_prop(path: Path, version: str, version_code: int) -> None:
    patch_file(
        path,
        [
            (re.compile(r"^version=.*$", re.M), f"version=v{version}"),
            (re.compile(r"^versionCode=.*$", re.M), f"versionCode={version_code}"),
        ],
    )


def update_version_header(path: Path, version_code: int) -> None:
    patch_file(
        path,
        [
            (re.compile(r"^#define VPNHIDE_VERSION_CODE \d+$", re.M), f"#define VPNHIDE_VERSION_CODE {version_code}"),
        ],
    )


def main() -> int:
    console = Console()
    if len(sys.argv) != 2:
        console.print("[red]usage:[/red] release.py X.Y.Z")
        return 2

    version, version_code = parse_version(sys.argv[1])
    console.print(
        f"[bold]Updating module version to v{version}[/bold] [dim](versionCode {version_code})[/dim]"
    )

    module_prop_kmod = REPO_ROOT / "kmod/module/module.prop"
    module_prop_kpatch = REPO_ROOT / "kpatch/module/module.prop"
    header_kmod = REPO_ROOT / "kmod/include/vpnhide.h"
    header_kpatch = REPO_ROOT / "kpatch/security/vpnhide/vpnhide_uapi.h"

    for path in (module_prop_kmod, module_prop_kpatch, header_kmod, header_kpatch):
        if not path.exists():
            console.print(f"[red]missing:[/red] {path.relative_to(REPO_ROOT)}")
            return 1

    update_module_prop(module_prop_kmod, version, version_code)
    console.print("  [green]✓[/green] kmod/module/module.prop updated successfully")

    update_module_prop(module_prop_kpatch, version, version_code)
    console.print("  [green]✓[/green] kpatch/module/module.prop updated successfully")

    update_version_header(header_kmod, version_code)
    console.print("  [green]✓[/green] kmod/include/vpnhide.h updated successfully")

    update_version_header(header_kpatch, version_code)
    console.print("  [green]✓[/green] kpatch/security/vpnhide/vpnhide_uapi.h updated successfully")

    return 0


if __name__ == "__main__":
    sys.exit(main())
