#!/usr/bin/env bash
# =============================================================================
# Build script: download GKI kernel, apply KSU-Next + SUSFS + VPNHide,
# generate a proper git unified diff patch, and compile.
#
# Usage: ./scripts/build_kernel_local.sh [--skip-sync] [--skip-patch-gen]
# =============================================================================

set -euo pipefail

# ----------------------------- Configuration ----------------------------------
VERSION="android12-5.10"
ANDROID_VERSION="android12"
KERNEL_VERSION="5.10"
OS_PATCH_LEVEL="2024-05"

WORKSPACE="/home/sorane/projects/GKI_KernelSU_SUSFS_VPNHIDE_NEXT/kernel-build-local"
VPNHIDE_PRIVATE="/home/sorane/projects/vpnhide_next_private"

SKIP_SYNC=false
SKIP_PATCH_GEN=false

for arg in "$@"; do
    case "$arg" in
        --skip-sync)      SKIP_SYNC=true ;;
        --skip-patch-gen) SKIP_PATCH_GEN=true ;;
    esac
done

# ----------------------------- Functions --------------------------------------
log() { echo "[$(date '+%H:%M:%S')] $*"; }

# ----------------------------- Step 0: Cleanup --------------------------------
if [ "$SKIP_SYNC" = false ]; then
    log "=== Cleaning previous build workspace ==="
    rm -rf "$WORKSPACE"
    mkdir -p "$WORKSPACE"
fi

cd "$WORKSPACE"

# ----------------------------- Step 1: repo tool ------------------------------
mkdir -p bin
export PATH="$WORKSPACE/bin:$PATH"

if [ ! -f "bin/repo" ]; then
    log "--- Downloading repo tool ---"
    curl -sS https://storage.googleapis.com/git-repo-downloads/repo > bin/repo
    chmod a+x bin/repo
fi

# ----------------------------- Step 2: repo init + sync -----------------------
if [ "$SKIP_SYNC" = false ]; then
    log "--- Repo init: common-${ANDROID_VERSION}-${KERNEL_VERSION}-${OS_PATCH_LEVEL} ---"
    repo init \
        -u https://android.googlesource.com/kernel/manifest \
        -b "common-${ANDROID_VERSION}-${KERNEL_VERSION}-${OS_PATCH_LEVEL}" \
        --depth=1 \
        --no-clone-bundle

    # Fix deprecated branch in manifest if needed
    DEFAULT_MANIFEST_PATH=".repo/manifests/default.xml"
    REMOTE_BRANCH=$(git ls-remote https://android.googlesource.com/kernel/common \
        "${ANDROID_VERSION}-${KERNEL_VERSION}-${OS_PATCH_LEVEL}" 2>/dev/null || echo "")
    if grep -q "deprecated" <<< "$REMOTE_BRANCH"; then
        log "--- Detected deprecated branch, patching manifest ---"
        sed -i "s/\"${ANDROID_VERSION}-${KERNEL_VERSION}-${OS_PATCH_LEVEL}\"/\"deprecated\/${ANDROID_VERSION}-${KERNEL_VERSION}-${OS_PATCH_LEVEL}\"/g" \
            "$DEFAULT_MANIFEST_PATH"
    fi

    log "--- Syncing Sources ---"
    repo sync -c --current-branch --no-clone-bundle --no-tags --jobs-checkout=4 -j4
fi

# ----------------------------- Step 3: KernelSU-Next --------------------------
log "--- Applying KernelSU-Next ---"
if [ ! -d "common/KernelSU-Next" ]; then
    cd common
    curl -LSs "https://raw.githubusercontent.com/pershoot/KernelSU-Next/dev-susfs/kernel/setup.sh" \
        | bash -s dev-susfs
    cd ..
fi

# ----------------------------- Step 4: SUSFS ----------------------------------
log "--- Applying SUSFS ---"
if [ ! -d "susfs4ksu" ]; then
    git clone https://gitlab.com/simonpunk/susfs4ksu.git -b "gki-${VERSION}" susfs4ksu

    cp susfs4ksu/kernel_patches/fs/* common/fs/
    cp susfs4ksu/kernel_patches/include/linux/* common/include/linux/

    cd common
    patch -p1 < ../susfs4ksu/kernel_patches/50_add_susfs_in_gki-${VERSION}.patch
    cd ..
fi

# ----------------------------- Step 5: Git snapshot (KSU+SUSFS baseline) ------
log "--- Creating KSU+SUSFS baseline git snapshot ---"
cd common
git config user.email "ci@vpnhide" 2>/dev/null || true
git config user.name "VPNHide CI" 2>/dev/null || true
if ! git log --oneline -1 2>/dev/null | grep -q "ksu+susfs"; then
    git add -A
    git commit -m "ksu+susfs baseline" --allow-empty
fi
BASELINE_COMMIT=$(git rev-parse HEAD)
log "Baseline commit: $BASELINE_COMMIT"
cd ..

# ----------------------------- Step 6: Copy VPNHide driver source -------------
log "--- Copying VPNHide in-tree driver source ---"
if [ ! -d "common/security/vpnhide" ]; then
    cp -r "$VPNHIDE_PRIVATE/kpatch/security/vpnhide" common/security/
fi

# ----------------------------- Step 7: Apply Python patcher -------------------
if [ "$SKIP_PATCH_GEN" = false ]; then
    log "--- Applying VPNHide hooks via Python patcher ---"
    python3 "$VPNHIDE_PRIVATE/scripts/patch_kernel.py" "$WORKSPACE/common"
fi

# ----------------------------- Step 8: Generate unified diff patch ------------
if [ "$SKIP_PATCH_GEN" = false ]; then
    log "--- Generating vpnhide_${VERSION}.patch ---"
    OUT_PATCH="$VPNHIDE_PRIVATE/kpatch/vpnhide_${VERSION}.patch"

    cd common
    # Stage all changes on top of our KSU+SUSFS baseline
    git add -A
    # Generate patch from baseline
    git diff --cached HEAD > "$OUT_PATCH"
    cd ..

    log "Patch saved to: $OUT_PATCH"
    wc -l "$OUT_PATCH"
fi

# ----------------------------- Step 9: Apply configs -------------------------
log "--- Appending configs to gki_defconfig ---"
CFG_FILE="common/arch/arm64/configs/gki_defconfig"
if ! grep -q "CONFIG_VPNHIDE" "$CFG_FILE"; then
    cat <<EOF >> "$CFG_FILE"
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

sed -i 's/check_defconfig//' common/build.config.gki || true

# ----------------------------- Step 10: Build ---------------------------------
log "--- Launching Kernel Build ---"
BUILD_GKI_ARTIFACTS="" \
BUILD_GKI_CERTIFICATION_TOOLS=0 \
BUILD_SYSTEM_DLKM=0 \
SKIP_VENDOR_BOOT=1 \
SKIP_EXT_MODULES=1 \
SKIP_CP_KERNEL_HDR=1 \
OUT_DIR="$WORKSPACE/out" \
LTO=thin \
BUILD_CONFIG=common/build.config.gki.aarch64 \
build/build.sh -j"$(nproc)"

log "=== Build complete. Image at: $WORKSPACE/out/dist/Image ==="
