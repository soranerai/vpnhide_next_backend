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
  release.py X.Y.Z [--kmod-version X.Y.Z] [--built-in-version X.Y.Z]

The positional version is the release identifier. Native component versions
default to their currently committed module.prop versions, so a release can
update only kmod or only built-in. Passing both component options preserves
the old all-components-at-once behavior.
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


def main() -> int:
    console = Console()
    if len(sys.argv) not in (2, 4, 6):
        console.print(
            "[red]usage:[/red] release.py X.Y.Z [--kmod-version X.Y.Z] [--built-in-version X.Y.Z]"
        )
        return 2

    version, _ = parse_version(sys.argv[1])
    options = dict(zip(sys.argv[2::2], sys.argv[3::2]))
    allowed_options = {"--kmod-version", "--built-in-version"}
    if set(options) - allowed_options:
        console.print("[red]error:[/red] unknown option")
        return 2
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
        kmod_version = built_in_version = version
    else:
        kmod_version = options.get("--kmod-version", module_version(module_prop_kmod))
        built_in_version = options.get(
            "--built-in-version", module_version(module_prop_kpatch)
        )
    _, kmod_code = parse_version(kmod_version)
    _, built_in_code = parse_version(built_in_version)

    update_module_prop(module_prop_kmod, kmod_version, kmod_code)
    console.print("  [green]✓[/green] kmod/module/module.prop updated successfully")

    update_module_prop(module_prop_kpatch, built_in_version, built_in_code)
    console.print("  [green]✓[/green] kpatch/module/module.prop updated successfully")

    update_version_header(header_kmod, kmod_code)
    console.print("  [green]✓[/green] kmod/include/vpnhide.h updated successfully")

    update_version_header(header_kpatch, built_in_code)
    console.print(
        "  [green]✓[/green] kpatch/security/vpnhide/vpnhide_uapi.h updated successfully"
    )

    return 0


if __name__ == "__main__":
    sys.exit(main())
