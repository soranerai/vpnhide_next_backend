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
    if ! grep -A1 "for_each_netdev(net, dev) {" "$DEV_IOCTL" | grep -q "vpnhide_should_hide_dev"; then
        log "Applying sed fixup: dev_ifconf vpnhide hook in $DEV_IOCTL..."
        if grep -A1 "for_each_netdev(net, dev) {" "$DEV_IOCTL" | grep -q "int done;"; then
            # Older sublevel: 'int done;' is the very first line inside the loop.
            # Insert the check AFTER it to avoid C90 declaration-after-statement.
            sed -i '/for_each_netdev(net, dev) {/{n; s/\(.*int done;\)/\1\n\t\tif (vpnhide_should_hide_dev(dev)) continue;/}' \
                "$DEV_IOCTL" \
                || die "sed fixup (older) failed for $DEV_IOCTL"
        else
            # Newer sublevel: 'int done;' is in a nested block — safe to insert
            # right after for_each_netdev without violating C90.
            sed -i '/for_each_netdev(net, dev) {/a\\t\tif (vpnhide_should_hide_dev(dev)) continue;' \
                "$DEV_IOCTL" \
                || die "sed fixup (newer) failed for $DEV_IOCTL"
        fi
    else
        log "dev_ifconf vpnhide hook already present, skipping sed fixup."
    fi
fi

# Apply inet6_fill_ifaddr hook to net/ipv6/addrconf.c via sed for all versions
# to avoid C90/C99 declaration-after-statement and fuzz matching offset issues.
ADDRCONF="$KERNEL_DIR/net/ipv6/addrconf.c"
if [ -f "$ADDRCONF" ]; then
    if ! grep -q "vpnhide_should_hide_dev(ifa->idev->dev)" "$ADDRCONF"; then
        log "Applying sed fixup: inet6_fill_ifaddr vpnhide hook in $ADDRCONF..."
        sed -i '/u32 preferred, valid;/a\\n#ifdef CONFIG_VPNHIDE\n\tif (ifa->idev \&\& ifa->idev->dev \&\&\n\t    unlikely(vpnhide_should_hide_dev(ifa->idev->dev)))\n\t\treturn 0;\n#endif' "$ADDRCONF" \
            || die "sed fixup failed for $ADDRCONF"
    else
        log "inet6_fill_ifaddr vpnhide hook already present, skipping sed fixup."
    fi
fi

# Apply getsockopt/setsockopt/bind/connect/getname hooks to net/socket.c
# using a Python script instead of a context patch (setsockopt is injected
# dynamically for android15-6.6 due to sublevel structure differences;
# android16-6.12 needs all of bind/connect/getsockname/getpeername/setsockopt
# done dynamically too, since that branch spans both the GKI shape
# (sockfd_lookup_light/fput_light) and a CLASS(fd, f) scoped-cleanup shape
# that some 6.12 sublevels have picked up from upstream -- a context diff
# can't span both without silently mis-applying under --fuzz).
SOCKET_C="$KERNEL_DIR/net/socket.c"
if [ -f "$SOCKET_C" ]; then
    log "Applying socket vpnhide hooks in $SOCKET_C..."
    EXTRA_FLAGS=()
    if [[ "$VERSION" == "android15-6.6" || "$VERSION" == "android16-6.12" ]]; then
        EXTRA_FLAGS+=("--setsockopt")
    fi
    if [[ "$VERSION" == "android16-6.12" ]]; then
        EXTRA_FLAGS+=("--bind-connect-getname")
    fi
    "$SCRIPT_DIR/fix_socket_hooks.py" "$SOCKET_C" "${EXTRA_FLAGS[@]}" \
        || die "socket hook injection failed for $SOCKET_C"
fi

log "Done. Applied $PATCH_COUNT patches for $VERSION."


