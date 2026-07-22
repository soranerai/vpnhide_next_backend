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
    patch -p1 --forward --fuzz=3 --no-backup-if-mismatch -d "$KERNEL_DIR" < "$p" \
        || die "patch failed: $p"
    PATCH_COUNT=$(( PATCH_COUNT + 1 ))
done

if [ "$PATCH_COUNT" -eq 0 ]; then
    die "No .patch files found in $PATCHES_DIR"
fi

# --------------------------------------------------------------------------
# 4. Version-specific sed fixups for hooks that can't be reliably patched
#    due to structural differences between kernel sublevels.
# --------------------------------------------------------------------------

# android12/13-5.10: dev_ifconf loop body varies between sublevels
# (older: gifconf_list[i] loop; newer: inet_gifconf).
# The patch only covers the inet_gifconf variant; apply the hook via sed
# for all sublevels so it lands correctly regardless of sublevel.
if [[ "$VERSION" == android12-5.10 || "$VERSION" == android13-5.10 ]]; then
    DEV_IOCTL="$KERNEL_DIR/net/core/dev_ioctl.c"
    if ! grep -q "vpnhide_should_hide_dev" "$DEV_IOCTL"; then
        log "Applying sed fixup: dev_ifconf vpnhide hook in $DEV_IOCTL..."
        sed -i '/for_each_netdev(net, dev) {/a\\t\tif (vpnhide_should_hide_dev(dev)) continue;' \
            "$DEV_IOCTL" \
            || die "sed fixup failed for $DEV_IOCTL"
    else
        log "dev_ifconf vpnhide hook already present, skipping sed fixup."
    fi
fi

log "Done. Applied $PATCH_COUNT patches for $VERSION."
