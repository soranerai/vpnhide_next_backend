#!/usr/bin/env bash
# =============================================================================
# build_kernel_local.sh — version-aware VPNHide GKI kernel builder.
#
# Workflow (per the "pristine sources" contract):
#   1. Resolve the pre-synced source tree for the requested GKI generation.
#      Sources MUST sit at the clean "ksu+susfs baseline" git commit.
#   2. Hardlink-clone that tree into a disposable  .staging-<version>  dir
#      (instant, ~0 GB; patch/sed break hardlinks so sources stay untouched).
#   3. Apply the VPNHide in-tree patches + config fragment INTO the staging copy.
#   4. Compile the kernel from staging (legacy build.sh or kleaf/bazel).
#   5. Copy the resulting Image to  artifacts/<version>/Image .
#   6. Remove the staging copy. Only the pristine sources remain.
#
# Usage:
#   ./scripts/build_kernel_local.sh [VERSION] [flags]
#
#   VERSION : android12-5.10 (default) | android13-5.15 | android14-6.1 |
#             android15-6.6 | android16-6.12
#
#   Flags:
#     --keep-staging   Do not delete the staging dir after the build (debug).
#     --real-copy      Use a full physical copy instead of a hardlink clone.
#     --skip-config    Do not append the CONFIG fragment to gki_defconfig.
#     --no-build       Stage + patch + config only, then stop (skip compile).
#     --jobs N         Parallel jobs (default: nproc).
#     -h | --help      Show this help.
# =============================================================================
set -euo pipefail

# ----------------------------- Static paths ----------------------------------
GKI_ROOT="/home/sorane/projects/GKI_KernelSU_SUSFS_VPNHIDE_NEXT"
VPNHIDE_PRIVATE="/home/sorane/projects/vpnhide_next_private"
ARTIFACTS_DIR="$GKI_ROOT/artifacts"

# ----------------------------- Defaults / args -------------------------------
VERSION="android12-5.10"
KEEP_STAGING=false
REAL_COPY=false
SKIP_CONFIG=false
NO_BUILD=false
JOBS="$(nproc)"

usage() { sed -n '2,27p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }

while [ $# -gt 0 ]; do
    case "$1" in
        android*)        VERSION="$1" ;;
        --keep-staging)  KEEP_STAGING=true ;;
        --real-copy)     REAL_COPY=true ;;
        --skip-config)   SKIP_CONFIG=true ;;
        --no-build)      NO_BUILD=true ;;
        --jobs)          JOBS="${2:?--jobs needs a number}"; shift ;;
        --jobs=*)        JOBS="${1#*=}" ;;
        -h|--help)       usage 0 ;;
        *) echo "Unknown argument: $1" >&2; usage 1 ;;
    esac
    shift
done

# ----------------------------- Helpers ----------------------------------------
log()  { echo "[$(date '+%H:%M:%S')] $*"; }
die()  { echo "[build] ERROR: $*" >&2; exit 1; }

# ----------------------------- Version -> source dir --------------------------
case "$VERSION" in
    # android12-5.10 uses its own dedicated tree (AOSP branch predates kleaf).
    # android13-5.10 shares the same 5.10 kernel + identical patchset; once its
    # tree is set up at the ksu+susfs baseline, android12-5.10 can be pointed there.
    android12-5.10) SRC_DIR="$GKI_ROOT/kernel-build-android12-5.10"; BUILD_SYS="legacy" ;;
    android13-5.10) SRC_DIR="$GKI_ROOT/kernel-build-android13-5.10"; BUILD_SYS="kleaf" ;;
    android13-5.15) SRC_DIR="$GKI_ROOT/kernel-build-android13-5.15"; BUILD_SYS="kleaf" ;;
    android14-5.15) SRC_DIR="$GKI_ROOT/kernel-build-android13-5.15"; BUILD_SYS="kleaf" ;;
    android14-6.1)  SRC_DIR="$GKI_ROOT/kernel-build-android14-6.1";  BUILD_SYS="kleaf" ;;
    android15-6.6)  SRC_DIR="$GKI_ROOT/kernel-build-android15-6.6";  BUILD_SYS="kleaf" ;;
    android16-6.12) SRC_DIR="$GKI_ROOT/kernel-build-android16-6.12"; BUILD_SYS="kleaf" ;;
    *) die "Unsupported VERSION '$VERSION'" ;;
esac

STAGING_DIR="$GKI_ROOT/.staging-$VERSION"

log "=== VPNHide kernel build ==="
log "Version     : $VERSION"
log "Source tree : $SRC_DIR"
log "Build system: $BUILD_SYS"
log "Staging     : $STAGING_DIR"

# ----------------------------- Step 1: Validate source ------------------------
[ -d "$SRC_DIR/common" ] || die "source tree missing: $SRC_DIR/common (repo not synced?)"

cd "$SRC_DIR/common"
git config user.email "ci@vpnhide" 2>/dev/null || true
git config user.name  "VPNHide CI"  2>/dev/null || true

HEAD_SUBJECT="$(git log --oneline -1 2>/dev/null || echo '')"

DIRTY_COUNT="$(git diff --name-only HEAD | wc -l)"
if [ "$DIRTY_COUNT" -ne 0 ]; then
    die "source common/ is dirty ($DIRTY_COUNT changed files). VPNHide patches must NOT
        live in the source tree — they belong in staging only. Run:
          git -C '$SRC_DIR/common' reset --hard HEAD && git -C '$SRC_DIR/common' clean -fd security/vpnhide
          rm -f '$SRC_DIR/common/include/linux/vpnhide.h'"
fi
log "Source tree: ${HEAD_SUBJECT}"
cd "$SRC_DIR"

# ----------------------------- Step 2: Create staging clone -------------------
if [ -e "$STAGING_DIR" ]; then
    log "Removing stale staging dir..."
    rm -rf "$STAGING_DIR"
fi
mkdir -p "$STAGING_DIR"

# We only need the buildable workspace, never .repo (sync metadata) or a stale
# out/ from a previous build. Everything else (build/, prebuilts/, external/,
# common/, susfs4ksu, symlinks, ...) must be present for both build systems.
log "Cloning source -> staging ($([ "$REAL_COPY" = true ] && echo 'full copy' || echo 'hardlink clone'))..."
CLONE_OPTS=(-a)
[ "$REAL_COPY" = false ] && CLONE_OPTS=(-al)   # hardlink clone: instant, ~0 GB

shopt -s dotglob
for entry in "$SRC_DIR"/*; do
    name="$(basename "$entry")"
    case "$name" in
        .repo|out) continue ;;                 # skip sync metadata + stale output
    esac
    cp "${CLONE_OPTS[@]}" "$entry" "$STAGING_DIR/"
done
shopt -u dotglob

# repo-managed trees expose common/.git as a symlink into .repo (which we
# excluded). Left dangling, any stray `git` call in staging would traverse UP
# and resolve to the GKI_ROOT repo — misleading status and, if
# LOCALVERSION_AUTO were on, a wrong SHA stamp. Drop dangling .git symlinks so
# staging/common is simply a non-git tree (the build does not need git here).
while IFS= read -r -d '' gitlink; do
    [ -e "$gitlink" ] || { rm -f "$gitlink"; log "Neutralized dangling .git: ${gitlink#$STAGING_DIR/}"; }
done < <(find "$STAGING_DIR" -maxdepth 3 -name .git -type l -print0)
log "Staging clone ready."

# The staging tree is disposable — always clean it up on exit unless asked not to.
cleanup() {
    local rc=$?
    if [ "$KEEP_STAGING" = true ]; then
        log "--keep-staging set; leaving $STAGING_DIR in place."
    else
        log "Cleaning up staging dir..."
        rm -rf "$STAGING_DIR"
    fi
    exit "$rc"
}
trap cleanup EXIT

# ----------------------------- Step 3: Apply KSU+SUSFS -----------------------
log "--- Applying KSU+SUSFS to staging tree ---"
bash "$VPNHIDE_PRIVATE/scripts/apply_ksu_susfs.sh" \
    "$STAGING_DIR/common" "$SRC_DIR" "$VERSION"

# ----------------------------- Step 3b: Fix kernel version string -------------
# Wild kernel approach: remove dirty suffixes, then hardcode setlocalversion
# so uname -r stays at e.g. "6.1.157-android14-Wild" — matching the vermagic
# of cfg80211.ko and other GKI modules already on the device.
# Override the branding suffix via KERNEL_LOCALVERSION env var (default: -Wild).
log "--- Fixing kernel version string (branding) ---"
SETLOCALVER="$STAGING_DIR/common/scripts/setlocalversion"
STAMP_BZL="$STAGING_DIR/build/kernel/kleaf/impl/stamp.bzl"

# 1. Strip -maybe-dirty from bazel stamp (kleaf builds)
if [ -f "$STAMP_BZL" ]; then
    sed -i "/stable_scmversion_cmd/s/-maybe-dirty//g" "$STAMP_BZL"
fi
# 2. Strip -dirty from setlocalversion (both build systems)
if [ -f "$SETLOCALVER" ]; then
    sed -i 's/-dirty//' "$SETLOCALVER"
fi
# 3. Replace the last line of setlocalversion with a hardcoded version string,
#    exactly as Wild does — so git-describe never runs and adds extra commits.
ANDROID_PART="${VERSION%%-*}"   # e.g. android14
BRANDING="${KERNEL_LOCALVERSION:-"-Wild"}"
if [ -f "$SETLOCALVER" ]; then
    # Remove last line, append hardcoded echo
    sed -i '$d' "$SETLOCALVER"
    echo "echo \"-${ANDROID_PART}${BRANDING}\"" >> "$SETLOCALVER"
    chmod +x "$SETLOCALVER"
    log "setlocalversion -> uname will show: $(uname -r | cut -d- -f1-2)-${ANDROID_PART}${BRANDING}"
fi

# ----------------------------- Step 3c: Bypass module version check -----------
# Same as Wild kernel "bypass hack": patch bad_version: label in module/version.c
# to return 1 instead of 0, so the kernel accepts vendor *.ko files regardless
# of CRC/vermagic mismatch (needed for WiFi/BT modules on stock vendor_dlkm).
log "--- Applying module version bypass patch ---"
if [[ "$VERSION" == "android14-6.1" || "$VERSION" == "android15-6.6" || "$VERSION" == "android16-6.12" ]]; then
    MODULE_VERSION_C="$STAGING_DIR/common/kernel/module/version.c"
else
    MODULE_VERSION_C="$STAGING_DIR/common/kernel/module.c"
fi

if [ -f "$MODULE_VERSION_C" ]; then
    # Break hardlink before sed -i
    cp "$MODULE_VERSION_C" "$MODULE_VERSION_C.unshare" && mv "$MODULE_VERSION_C.unshare" "$MODULE_VERSION_C"
    sed -i '/bad_version:/{:a;n;/return 0;/{s/return 0;/return 1;/;b};ba}' "$MODULE_VERSION_C"
    if grep -A 5 "bad_version:" "$MODULE_VERSION_C" | grep -q "return 1;"; then
        log "Module version bypass: applied to ${MODULE_VERSION_C#$STAGING_DIR/}"
    else
        die "Module version bypass: patch failed — 'return 1' not found after bad_version:"
    fi
else
    log "WARNING: $MODULE_VERSION_C not found, skipping bypass patch"
fi

# ----------------------------- Step 4: Apply VPNHide patches ------------------
log "--- Applying VPNHide static patches for $VERSION ---"
bash "$VPNHIDE_PRIVATE/kpatch/scripts/apply.sh" "$STAGING_DIR/common" "$VERSION"

# ----------------------------- Step 5: Append config fragment -----------------
if [ "$SKIP_CONFIG" = false ]; then
    CFG_FILE="$STAGING_DIR/common/arch/arm64/configs/gki_defconfig"
    if ! grep -q "CONFIG_VPNHIDE" "$CFG_FILE"; then
        log "--- Appending CONFIG fragment to gki_defconfig ---"
        # IMPORTANT: gki_defconfig is a hardlink to the source inode. `cat >>`
        # appends THROUGH the shared inode and would corrupt the pristine source.
        # Break the hardlink first by materialising a private copy.
        cp "$CFG_FILE" "$CFG_FILE.unshare" && mv "$CFG_FILE.unshare" "$CFG_FILE"
        cat >> "$CFG_FILE" <<'EOF'
CONFIG_KSU=y
CONFIG_KSU_SUSFS=y
CONFIG_KSU_SUSFS_SUS_PATH=y
CONFIG_KSU_SUSFS_SUS_MOUNT=y
CONFIG_KSU_SUSFS_SUS_KSTAT=y
CONFIG_KSU_SUSFS_SPOOF_UNAME=y
CONFIG_KSU_SUSFS_ENABLE_LOG=y
CONFIG_KSU_SUSFS_HIDE_KSU_SUSFS_SYMBOLS=y
CONFIG_KSU_SUSFS_SPOOF_CMDLINE_OR_BOOTCONFIG=y
CONFIG_KSU_SUSFS_OPEN_REDIRECT=y
CONFIG_KSU_SUSFS_SUS_MAP=y
CONFIG_VPNHIDE=y
EOF
    fi
    # Same hardlink hazard: sed -i writes a new inode, so this is safe, but only
    # touch the file if the marker is present.
    if [ -f "$STAGING_DIR/common/build.config.gki" ]; then
        sed -i 's/check_defconfig//' "$STAGING_DIR/common/build.config.gki" || true
    fi
fi

# ----------------------------- Step 5: Build ----------------------------------
if [ "$NO_BUILD" = true ]; then
    log "--no-build set; staging prepared and patched. Skipping compile."
    log "Inspect staging at: $STAGING_DIR (use --keep-staging to retain it)."
    exit 0
fi

mkdir -p "$ARTIFACTS_DIR/$VERSION"
IMAGE_OUT="$ARTIFACTS_DIR/$VERSION/Image"

cd "$STAGING_DIR"
if [ "$BUILD_SYS" = "legacy" ]; then
    log "--- Building (legacy build/build.sh) ---"
    BUILD_GKI_ARTIFACTS="" \
    BUILD_GKI_CERTIFICATION_TOOLS=0 \
    BUILD_SYSTEM_DLKM=0 \
    SKIP_VENDOR_BOOT=1 \
    SKIP_EXT_MODULES=1 \
    SKIP_CP_KERNEL_HDR=1 \
    OUT_DIR="$STAGING_DIR/out" \
    LTO=thin \
    BUILD_CONFIG=common/build.config.gki.aarch64 \
    build/build.sh -j"$JOBS"

    STAGED_IMAGE="$STAGING_DIR/out/dist/Image"
else
    log "--- Building (kleaf: //common:kernel_aarch64_dist) ---"
    DIST_DIR="$STAGING_DIR/dist"
    tools/bazel run \
        --config=fast \
        --lto=thin \
        --jobs="$JOBS" \
        //common:kernel_aarch64_dist \
        -- --dist_dir="$DIST_DIR"

    STAGED_IMAGE="$DIST_DIR/Image"
fi

# ----------------------------- Step 6: Collect artifact -----------------------
[ -f "$STAGED_IMAGE" ] || die "build finished but Image not found at $STAGED_IMAGE"
cp "$STAGED_IMAGE" "$IMAGE_OUT"
log "=== Build complete ==="
log "Image: $IMAGE_OUT ($(du -h "$IMAGE_OUT" | cut -f1))"
# staging removed by the EXIT trap.
