#!/usr/bin/env bash
# =============================================================================
# apply.sh — apply VPNHide in-tree patches to a GKI kernel source tree
#
# Usage: apply.sh <kernel_common_dir> <version>
#   version: android12-5.10 | android13-5.15 | android14-6.1 |
#            android15-6.6  | android16-6.12
# =============================================================================
set -euo pipefail

KERNEL_DIR="${1:?Usage: $0 <kernel_common_dir> <version>}"
VERSION="${2:?Usage: $0 <kernel_common_dir> <version>}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
KPATCH_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

PATCHES_DIR="$KPATCH_DIR/versions/$VERSION"
DRIVER_DIR="$KPATCH_DIR/security/vpnhide"
HEADER="$KPATCH_DIR/include/linux/vpnhide.h"

# --------------------------------------------------------------------------
log() { echo "[apply.sh] $*"; }
die() { echo "[apply.sh] ERROR: $*" >&2; exit 1; }

[ -d "$KERNEL_DIR" ]  || die "kernel dir not found: $KERNEL_DIR"
[ -d "$PATCHES_DIR" ] || die "no patches for version '$VERSION' (dir missing: $PATCHES_DIR)"
[ -d "$DRIVER_DIR" ]  || die "driver source not found: $DRIVER_DIR"
[ -f "$HEADER" ]      || die "vpnhide.h not found: $HEADER"

# --------------------------------------------------------------------------
# 1. Copy the in-tree driver
# --------------------------------------------------------------------------
log "Copying security/vpnhide driver..."
rm -rf "$KERNEL_DIR/security/vpnhide"
cp -r "$DRIVER_DIR" "$KERNEL_DIR/security/vpnhide"

# --------------------------------------------------------------------------
# 2. Copy the public header
# --------------------------------------------------------------------------
log "Copying include/linux/vpnhide.h..."
cp "$HEADER" "$KERNEL_DIR/include/linux/vpnhide.h"

# --------------------------------------------------------------------------
# 3. Apply per-file patches in sorted order
# --------------------------------------------------------------------------
PATCH_COUNT=0
for p in $(ls "$PATCHES_DIR"/*.patch 2>/dev/null | sort); do
    log "Applying $(basename "$p")..."
    patch -p1 --forward --no-backup-if-mismatch -d "$KERNEL_DIR" < "$p" \
        || die "patch failed: $p"
    PATCH_COUNT=$(( PATCH_COUNT + 1 ))
done

if [ "$PATCH_COUNT" -eq 0 ]; then
    die "No .patch files found in $PATCHES_DIR"
fi

log "Done. Applied $PATCH_COUNT patches for $VERSION."
