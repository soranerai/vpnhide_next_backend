#!/usr/bin/env bash
# Local script to build static binaries and run kmod vector tests inside the ddk-qemu podman/docker container.
#
# Usage: ./kmod/test/run-local-container.sh [kmi] (default: android14-6.1)
# Performance mode: VPNHIDE_TEST_MODE=perf ./kmod/test/run-local-container.sh <kmi>
set -euo pipefail

# Default list of all GKI versions supported in the CI matrix
KMIS=(
    "android12-5.10"
    "android13-5.10"
    "android13-5.15"
    "android14-5.15"
    "android14-6.1"
    "android15-6.6"
    "android16-6.12"
    "android17-6.18"
)

# Overwrite list if specific KMI(s) passed as arguments
if [ $# -gt 0 ]; then
    KMIS=("$@")
fi

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"

# 1. Locate NDK on the host
NDK_HOME="${ANDROID_NDK_HOME:-}"
if [ -z "$NDK_HOME" ]; then
    # Try searching standard paths
    if [ -d "$HOME/android-sdk/ndk/28.0.13004108" ]; then
        NDK_HOME="$HOME/android-sdk/ndk/28.0.13004108"
    elif [ -d "$HOME/android-sdk/ndk" ]; then
        latest_ndk=$(ls -d "$HOME/android-sdk/ndk"/*/ 2>/dev/null | sort -V | tail -n 1)
        if [ -n "$latest_ndk" ]; then
            NDK_HOME="${latest_ndk%/}"
        fi
    elif [ -d "$HOME/Android/Sdk/ndk" ]; then
        latest_ndk=$(ls -d "$HOME/Android/Sdk/ndk"/*/ 2>/dev/null | sort -V | tail -n 1)
        if [ -n "$latest_ndk" ]; then
            NDK_HOME="${latest_ndk%/}"
        fi
    fi
fi

if [ -z "$NDK_HOME" ] || [ ! -d "$NDK_HOME" ]; then
    echo "ERROR: ANDROID_NDK_HOME is not set and could not find NDK in standard paths."
    exit 1
fi

echo "[local-container] Using NDK at: $NDK_HOME"

# Find aarch64-linux-android-clang
CLANG_BIN=$(find "$NDK_HOME" -name "aarch64-linux-android*-clang" | head -n 1)
STRIP_BIN=$(find "$NDK_HOME" -name "llvm-strip" | head -n 1)

if [ -z "$CLANG_BIN" ] || [ ! -f "$CLANG_BIN" ]; then
    echo "ERROR: NDK aarch64 clang not found"
    exit 1
fi

# 2. Build host utilities statically using NDK clang (built once)
echo "[local-container] Compiling static host binaries..."
"$CLANG_BIN" -O2 -Wall -static "$REPO/kmod/vpnhide_ctl.c" "$REPO/kmod/vpnhide_policy.c" "$REPO/kmod/parson.c" -o "$REPO/kmod/vpnhide-ctl-host"
if [ -f "$STRIP_BIN" ]; then
    "$STRIP_BIN" "$REPO/kmod/vpnhide-ctl-host"
fi

"$CLANG_BIN" -O2 -Wall -static \
    "$REPO/daemon/main.c" "$REPO/daemon/config_watch.c" "$REPO/daemon/file_hiding.c" \
    "$REPO/daemon/network.c" "$REPO/daemon/stats.c" \
    "$REPO/daemon/owned_ports.c" -o "$REPO/kmod/vpnhide-daemon-host"
if [ -f "$STRIP_BIN" ]; then
    "$STRIP_BIN" "$REPO/kmod/vpnhide-daemon-host"
fi

# 3. Determine podman/docker executable
DOCKER_CMD="podman"
if ! command -v podman >/dev/null 2>&1; then
    if command -v docker >/dev/null 2>&1; then
        DOCKER_CMD="docker"
    else
        echo "ERROR: neither podman nor docker found"
        exit 1
    fi
fi

USERNS_ARG=""
if [ "$DOCKER_CMD" = "podman" ]; then
    USERNS_ARG="--userns=keep-id"
fi

# 4. Prepare images (tag local okhsunrog ones, or pull from your repo)
echo "[local-container] Preparing container images..."
for KMI in "${KMIS[@]}"; do
    IMAGE_NAME="ghcr.io/soranerai/vpnhide_next/ddk-qemu:$KMI"
    ALT_IMAGE="ghcr.io/okhsunrog/vpnhide/ddk-qemu:$KMI"
    
    # Check if user image already exists locally
    if "$DOCKER_CMD" image inspect "$IMAGE_NAME" >/dev/null 2>&1; then
        echo "[local-container] [$KMI] Found local image: $IMAGE_NAME"
    # Otherwise, check if the alternative okhsunrog image exists locally and tag it
    elif "$DOCKER_CMD" image inspect "$ALT_IMAGE" >/dev/null 2>&1; then
        echo "[local-container] [$KMI] Found local alternative image: $ALT_IMAGE. Tagging as $IMAGE_NAME..."
        "$DOCKER_CMD" tag "$ALT_IMAGE" "$IMAGE_NAME"
    # Otherwise, pull only from the user's repository
    else
        echo "[local-container] [$KMI] Image not found locally. Pulling $IMAGE_NAME..."
        if ! "$DOCKER_CMD" pull "$IMAGE_NAME"; then
            echo "ERROR: Could not find or pull $IMAGE_NAME, and no local alternative exists."
            exit 1
        fi
    fi
done

BUILD_JOBS="${VPNHIDE_BUILD_JOBS:-32}"
BUILD_MEMORY="${VPNHIDE_BUILD_MEMORY:-11g}"
echo "[local-container] Starting bounded sequential tests (jobs=$BUILD_JOBS memory=$BUILD_MEMORY): ${KMIS[*]}"

failed=0

# 4. Build and test one KMI at a time. Multiple concurrent kernel-module
# linkers and QEMU guests can exhaust WSL2 memory even when each one is small.
for KMI in "${KMIS[@]}"; do
    IMAGE_NAME="ghcr.io/soranerai/vpnhide_next/ddk-qemu:$KMI"
    LOG_FILE="/tmp/vpnhide-test-$KMI.log"
    echo "[local-container] [$KMI] Starting container run (logging to $LOG_FILE)..."

    if "$DOCKER_CMD" run --rm $USERNS_ARG \
        --memory "$BUILD_MEMORY" --memory-swap "$BUILD_MEMORY" \
        -v "$REPO:/repo:Z" \
        -w /repo \
        -e KMI="$KMI" \
        -e VPNHIDE_BUILD_JOBS="$BUILD_JOBS" \
        -e VPNHIDE_QEMU_MEM="${VPNHIDE_QEMU_MEM:-512M}" \
        -e VPNHIDE_QEMU_SMP="${VPNHIDE_QEMU_SMP:-1}" \
        -e VPNHIDE_QEMU_TIMEOUT="${VPNHIDE_QEMU_TIMEOUT:-300}" \
        -e VPNHIDE_TEST_MODE="${VPNHIDE_TEST_MODE:-normal}" \
        -e VPNHIDE_PERF_ITERATIONS="${VPNHIDE_PERF_ITERATIONS:-20000}" \
        -e VPNHIDE_PERF_REPEATS="${VPNHIDE_PERF_REPEATS:-5}" \
        "$IMAGE_NAME" \
        bash -c '
            set -euo pipefail
            CLANG_BIN="$(ls -d /opt/ddk/clang/*/bin | head -1)"
            
            echo "[container] Copying kmod code to private workspace to avoid parallel build collisions..."
            mkdir -p /tmp/kmod-build
            cp -r /repo/kmod/* /tmp/kmod-build/
            
            echo "[container] Building optimized kernel module..."
            make -C /tmp/kmod-build KERNEL_SRC="$VPNHIDE_QEMU_KSRC" \
                CLANG_DIR="$CLANG_BIN" -j"${VPNHIDE_BUILD_JOBS:-1}"

            if [ "${VPNHIDE_TEST_MODE:-normal}" = "perf" ]; then
                echo "[container] Building baseline module from HEAD^..."
                rm -rf /tmp/kmod-baseline
                mkdir -p /tmp/kmod-baseline
                BASELINE_REF="${VPNHIDE_PERF_BASELINE_REF:-origin/main}"
                if ! git -C /repo rev-parse --verify "$BASELINE_REF" >/dev/null 2>&1; then
                    BASELINE_REF="HEAD^"
                fi
                echo "[container] Using performance baseline: $BASELINE_REF"
                git -C /repo archive "$BASELINE_REF" kmod | tar -x -C /tmp/kmod-baseline
                make -C /tmp/kmod-baseline/kmod KERNEL_SRC="$VPNHIDE_QEMU_KSRC" \
                    CLANG_DIR="$CLANG_BIN" -j"${VPNHIDE_BUILD_JOBS:-1}"

                echo "[container] Running baseline/optimized QEMU performance comparison..."
                VPNHIDE_PERF_BASELINE_IMAGE="$VPNHIDE_QEMU_KSRC/arch/arm64/boot/Image" \
                VPNHIDE_PERF_OPTIMIZED_IMAGE="$VPNHIDE_QEMU_KSRC/arch/arm64/boot/Image" \
                VPNHIDE_PERF_BASELINE_KO="/tmp/kmod-baseline/kmod/vpnhide_kmod.ko" \
                VPNHIDE_PERF_OPTIMIZED_KO="/tmp/kmod-build/vpnhide_kmod.ko" \
                VPNHIDE_QEMU_ROOTFS="/opt/qemu/alpine-minirootfs.tar.gz" \
                    /repo/kmod/test/run-perf.sh "$KMI"
            else
                echo "[container] Running QEMU test runner..."
                VPNHIDE_QEMU_KO="/tmp/kmod-build/vpnhide_kmod.ko" /repo/kmod/test/run.sh "$KMI"
            fi
        ' > "$LOG_FILE" 2>&1; then
        echo "[local-container] [$KMI] PASSED"
    else
        rc=$?
        echo ""
        echo "=== [local-container] [$KMI] FAILED (exit code: $rc) ==="
        cat "$LOG_FILE"
        failed=$((failed + 1))
    fi
done

if [ $failed -eq 0 ]; then
    echo "[local-container] SUCCESS: All tests passed!"
    exit 0
else
    echo "[local-container] ERROR: $failed target(s) failed."
    exit 1
fi
