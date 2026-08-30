#!/usr/bin/env python3
"""Run all repo-wide lints and formatters locally.

Matches the CI lint pipeline defined in `.github/workflows/ci.yml`.
Supports formatting (autofix) by default, and a strict `--check` mode.
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

# Root directory of the repository
ROOT_DIR = Path(__file__).resolve().parent.parent


def run_command(
    args: list[str], cwd: Path = ROOT_DIR, check: bool = True
) -> subprocess.CompletedProcess[str]:
    """Run a subprocess command and display it."""
    print(f"--> Running: {' '.join(args)} (in {cwd.relative_to(ROOT_DIR) or '.'})")
    try:
        return subprocess.run(
            args, cwd=cwd, check=check, text=True, capture_output=False
        )
    except subprocess.CalledProcessError as e:
        print(f"Error: Command failed with exit code {e.returncode}")
        if not check:
            raise e
        sys.exit(e.returncode)


def is_tool_available(name: str) -> bool:
    """Check if a tool is available in PATH."""
    return shutil.which(name) is not None


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run local lints and formatters matching the CI pipeline."
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Only check files without modifying them (CI mode)",
    )
    args = parser.parse_args()

    # Keep track of failed checks if we want to run all and report at the end
    failed = False

    print("=== Step 1: Python (ruff) ===")
    if is_tool_available("ruff"):
        # Format
        ruff_fmt = ["ruff", "format"]
        if args.check:
            ruff_fmt.append("--check")
        try:
            run_command(ruff_fmt)
        except subprocess.CalledProcessError:
            failed = True

        # Check / Lint
        ruff_check = ["ruff", "check"]
        if not args.check:
            ruff_check.append("--fix")
        try:
            run_command(ruff_check)
        except subprocess.CalledProcessError:
            failed = True
    else:
        print("Warning: 'ruff' not found. Skipping Python lint/format.")

    print("\n=== Step 2: Shell scripts (shellcheck) ===")
    if is_tool_available("shellcheck"):
        shell_files = [
            "kmod/module/kmi-check.sh",
            "kmod/module/customize.sh",
            "kmod/module/post-fs-data.sh",
            "kmod/module/service.sh",
            "scripts/clean-device.sh",
            "scripts/update-json.sh",
            "kmod/test/run.sh",
            "kmod/test/build-kernel.sh",
            "kmod/test/init.sh",
            "kmod/test/test_kmi_check.sh",
            "kpatch/module/kernel-update.sh",
            "kpatch/module/customize.sh",
            "kpatch/test/test_kernel_update.sh",
        ]
        # Filter files that exist
        existing_shell_files = [f for f in shell_files if (ROOT_DIR / f).exists()]
        if existing_shell_files:
            try:
                run_command(
                    ["shellcheck", "-x", "-e", "SC2034,SC3043"] + existing_shell_files
                )
            except subprocess.CalledProcessError:
                failed = True
    else:
        print("Warning: 'shellcheck' not found. Skipping shell script lint.")

    print("\n=== Step 3: C (clang-format + host test) ===")
    # clang-format
    if is_tool_available("clang-format"):
        c_fmt = ["clang-format"]
        if args.check:
            c_fmt.extend(["--dry-run", "--Werror"])
        else:
            c_fmt.append("-i")
        c_files = sorted(
            str(path.relative_to(ROOT_DIR)) for path in (ROOT_DIR / "kmod").glob("*.c")
        )
        if c_files:
            try:
                run_command(c_fmt + c_files)
            except subprocess.CalledProcessError:
                failed = True
    else:
        print("Warning: 'clang-format' not found. Skipping C formatting.")

    # host test
    if is_tool_available("gcc"):
        iface_test_bin = ROOT_DIR / "kmod/test_iface_lists"
        daemon_test_bin = ROOT_DIR / "kmod/test/daemon_iface_test"
        try:
            run_command(
                [
                    "gcc",
                    "-O2",
                    "-Wall",
                    "-Werror",
                    "-o",
                    str(iface_test_bin),
                    "kmod/test_iface_lists.c",
                ]
            )
            run_command([str(iface_test_bin)])
            run_command(
                [
                    "gcc",
                    "-O2",
                    "-Wall",
                    "-Werror",
                    "-o",
                    str(daemon_test_bin),
                    "kmod/test/daemon_iface_test.c",
                ]
            )
            run_command([str(daemon_test_bin)])
        except subprocess.CalledProcessError:
            failed = True
        finally:
            for test_bin in (iface_test_bin, daemon_test_bin):
                if test_bin.exists():
                    test_bin.unlink()
    else:
        print("Warning: 'gcc' not found. Skipping host C test.")

    if failed:
        print("\n[!] Some lint checks or tests FAILED.")
        return 1

    print("\n[+] All checks and formatters completed successfully!")
    return 0


if __name__ == "__main__":
    sys.exit(main())
