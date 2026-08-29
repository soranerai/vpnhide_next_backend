#!/usr/bin/env python3
#
# /// script
# requires-python = ">=3.12"
# dependencies = [
#   "rich",
# ]
# ///
"""Cut a release and selectively update native component versions.

Usage:
  release.py X.Y.Z [--kmod-version X.Y.Z] [--kpatch-version X.Y.Z]

The positional version updates VERSION. With no component options, both kmod
and KPatch receive that version. Passing a component option updates only that
component; the other component remains untouched. --built-in-version is kept
as a deprecated alias for --kpatch-version.
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
            (
                re.compile(r"^#define VPNHIDE_VERSION_CODE \d+$", re.M),
                f"#define VPNHIDE_VERSION_CODE {version_code}",
            ),
        ],
    )


def module_version(path: Path) -> str:
    text = path.read_text(encoding="utf-8")
    match = re.search(r"^version=v?([^\n]+)$", text, flags=re.MULTILINE)
    if not match:
        raise SystemExit(f"error: no version in {path.relative_to(REPO_ROOT)}")
    return match.group(1).strip()


def write_version_file(version: str) -> None:
    (REPO_ROOT / "VERSION").write_text(f"{version}\n", encoding="utf-8")


def main() -> int:
    console = Console()
    args = sys.argv[1:]
    if not args or len(args) % 2 == 0:
        console.print(
            "[red]usage:[/red] release.py X.Y.Z [--kmod-version X.Y.Z] [--kpatch-version X.Y.Z]"
        )
        return 2

    version, _ = parse_version(args[0])
    option_pairs = list(zip(args[1::2], args[2::2]))
    options = dict(option_pairs)
    allowed_options = {"--kmod-version", "--kpatch-version", "--built-in-version"}
    if set(options) - allowed_options or len(options) != len(option_pairs):
        console.print("[red]error:[/red] unknown or duplicate option")
        return 2
    if "--kpatch-version" in options and "--built-in-version" in options:
        console.print("[red]error:[/red] use only --kpatch-version, not both aliases")
        return 2
    if "--built-in-version" in options:
        console.print(
            "[yellow]warning:[/yellow] --built-in-version is deprecated; use --kpatch-version"
        )
    kpatch_version = options.get("--kpatch-version", options.get("--built-in-version"))
    console.print(f"[bold]Updating native component versions for v{version}[/bold]")

    module_prop_kmod = REPO_ROOT / "kmod/module/module.prop"
    module_prop_kpatch = REPO_ROOT / "kpatch/module/module.prop"
    header_kmod = REPO_ROOT / "kmod/include/vpnhide.h"
    header_kpatch = REPO_ROOT / "kpatch/security/vpnhide/vpnhide_uapi.h"

    for path in (module_prop_kmod, module_prop_kpatch, header_kmod, header_kpatch):
        if not path.exists():
            console.print(f"[red]missing:[/red] {path.relative_to(REPO_ROOT)}")
            return 1

    if not options:
        # Backward-compatible mode: release.py X.Y.Z updates both native
        # components, exactly as the old script did.
        kmod_version = kpatch_version = version
    else:
        kmod_version = options.get("--kmod-version")

    write_version_file(version)
    console.print("  [green]✓[/green] VERSION")

    if kmod_version is not None:
        _, kmod_code = parse_version(kmod_version)
        update_module_prop(module_prop_kmod, kmod_version, kmod_code)
        update_version_header(header_kmod, kmod_code)
        console.print("  [green]✓[/green] kmod/module/module.prop")
        console.print("  [green]✓[/green] kmod/include/vpnhide.h")

    if kpatch_version is not None:
        _, kpatch_code = parse_version(kpatch_version)
        update_module_prop(module_prop_kpatch, kpatch_version, kpatch_code)
        update_version_header(header_kpatch, kpatch_code)
        console.print("  [green]✓[/green] kpatch/module/module.prop")
        console.print("  [green]✓[/green] kpatch/security/vpnhide/vpnhide_uapi.h")

    return 0


if __name__ == "__main__":
    sys.exit(main())
