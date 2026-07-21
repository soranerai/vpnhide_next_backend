#!/usr/bin/env bash
# =============================================================================
# apply_ksu_susfs.sh — apply KernelSU-Next + SUSFS to a clean kernel staging tree.
#
# Called by build_kernel_local.sh after the AOSP source is staged.
# Source trees are kept in native AOSP state; this script applies everything
# on-the-fly into the disposable staging copy.
#
# Usage:
#   apply_ksu_susfs.sh <STAGING_COMMON> <SRC_ROOT> <VERSION>
#
#   STAGING_COMMON  — path to the staged kernel/common directory (read-write)
#   SRC_ROOT        — path to the kernel-build-<version> source root (read-only)
#                     must contain susfs4ksu/kernel_patches/
#   VERSION         — KMI string, e.g. android14-6.1
# =============================================================================
set -euo pipefail

STAGING_COMMON="${1:?usage: apply_ksu_susfs.sh <staging_common> <src_root> <version>}"
SRC_ROOT="${2:?}"
VERSION="${3:?}"

GKI_ROOT="$(cd "$SRC_ROOT/.." && pwd)"

log()  { echo "[ksu+susfs/$VERSION] $*"; }
die()  { echo "[ksu+susfs/$VERSION] ERROR: $*" >&2; exit 1; }

PATCHES_DIR="$SRC_ROOT/susfs4ksu/kernel_patches"
[ -d "$PATCHES_DIR" ] || die "susfs4ksu/kernel_patches not found at $PATCHES_DIR"

SUSFS_PATCH="$PATCHES_DIR/50_add_susfs_in_gki-${VERSION}.patch"
[ -f "$SUSFS_PATCH" ] || die "no SUSFS patch for $VERSION at $SUSFS_PATCH"

KSU_SUSFS_PATCH="$PATCHES_DIR/KernelSU/10_enable_susfs_for_ksu.patch"
[ -f "$KSU_SUSFS_PATCH" ] || die "KernelSU susfs patch missing: $KSU_SUSFS_PATCH"

# ── 1. KernelSU-Next source ───────────────────────────────────────────────────
# Canonical location: $GKI_ROOT/KernelSU-Next (set up once by the user).
# Fallbacks: any other tree in GKI_ROOT that still has a copy.
KSU_NEXT_DST="$STAGING_COMMON/KernelSU-Next"

find_ksu_next_src() {
    for candidate in \
        "$GKI_ROOT/KernelSU-Next" \
        "$SRC_ROOT/KernelSU-Next" \
        "$GKI_ROOT"/kernel-build-*/KernelSU-Next \
        "$GKI_ROOT"/kernel-build-*/common/KernelSU-Next
    do
        [ -d "$candidate/kernel" ] && echo "$candidate" && return 0
    done
    return 1
}

if [ ! -d "$KSU_NEXT_DST/kernel" ]; then
    KSU_SRC="$(find_ksu_next_src)" \
        || die "KernelSU-Next not found. Expected at $GKI_ROOT/KernelSU-Next"
    log "Copying KernelSU-Next from $(basename "$KSU_SRC") ..."
    cp -al "$KSU_SRC" "$KSU_NEXT_DST"
fi

# ── 2. Apply KernelSU SUSFS integration patch ─────────────────────────────────
if grep -q "config KSU_SUSFS" "$KSU_NEXT_DST/kernel/Kconfig"; then
    log "KernelSU-Next is already patched with SUSFS, skipping patch application."
else
    log "Applying KernelSU SUSFS patch ..."
    patch -d "$KSU_NEXT_DST" -p1 --forward --fuzz=3 \
        < "$KSU_SUSFS_PATCH" 2>&1 | grep -v '^Hunk .* succeeded' || true
fi

# ── 3. Wire KernelSU into drivers/ ────────────────────────────────────────────
log "Wiring KernelSU into drivers/ ..."

# symlink: drivers/kernelsu -> ../KernelSU-Next/kernel
KERNELSU_LINK="$STAGING_COMMON/drivers/kernelsu"
if [ ! -L "$KERNELSU_LINK" ] && [ ! -e "$KERNELSU_LINK" ]; then
    ln -s ../KernelSU-Next/kernel "$KERNELSU_LINK"
fi

# drivers/Kconfig — add source before endmenu
# Break hardlink before sed -i so source tree stays pristine
if ! grep -q 'kernelsu/Kconfig' "$STAGING_COMMON/drivers/Kconfig"; then
    cp "$STAGING_COMMON/drivers/Kconfig" "$STAGING_COMMON/drivers/Kconfig.tmp" \
        && mv "$STAGING_COMMON/drivers/Kconfig.tmp" "$STAGING_COMMON/drivers/Kconfig"
    sed -i 's|^endmenu|source "drivers/kernelsu/Kconfig"\nendmenu|' \
        "$STAGING_COMMON/drivers/Kconfig"
fi

# drivers/Makefile — add obj-$(CONFIG_KSU)
# Break hardlink before >> so source tree stays pristine
if ! grep -q 'CONFIG_KSU' "$STAGING_COMMON/drivers/Makefile"; then
    cp "$STAGING_COMMON/drivers/Makefile" "$STAGING_COMMON/drivers/Makefile.tmp" \
        && mv "$STAGING_COMMON/drivers/Makefile.tmp" "$STAGING_COMMON/drivers/Makefile"
    printf '\nobj-$(CONFIG_KSU) += kernelsu/\n' >> "$STAGING_COMMON/drivers/Makefile"
fi

# ── 4. Copy SUSFS source files ────────────────────────────────────────────────
log "Copying SUSFS source files ..."
cp "$PATCHES_DIR/fs/susfs.c"                "$STAGING_COMMON/fs/susfs.c"
cp "$PATCHES_DIR/include/linux/susfs.h"     "$STAGING_COMMON/include/linux/susfs.h"
cp "$PATCHES_DIR/include/linux/susfs_def.h" "$STAGING_COMMON/include/linux/susfs_def.h"

# ── 5. Apply SUSFS kernel patch ───────────────────────────────────────────────
log "Applying SUSFS kernel patch ..."
patch -d "$STAGING_COMMON" -p1 --forward --fuzz=3 --no-backup-if-mismatch \
    < "$SUSFS_PATCH" 2>&1 | grep -v '^Hunk .* succeeded' || true

# Remove any .orig backup files patch may have created (they must not leak to source)
find "$STAGING_COMMON" -name '*.orig' -delete 2>/dev/null || true

# Fail if any hunks were rejected
REJECTS=$(find "$STAGING_COMMON" -name '*.rej' -newer "$SUSFS_PATCH" 2>/dev/null | wc -l)
[ "$REJECTS" -eq 0 ] || {
    echo "[ksu+susfs] Rejected hunks:"
    find "$STAGING_COMMON" -name '*.rej' -newer "$SUSFS_PATCH"
    die "$REJECTS hunk(s) rejected — SUSFS patch does not apply cleanly to $VERSION"
}

log "KSU+SUSFS applied successfully."
