#!/usr/bin/env bash
# Build kpatch kernel (incremental) and run QEMU vector tests for all GKI KMIs.
#
# Unlike kmod, there is no .ko — VPNHide is baked into the Image.
# We use the pre-built kernel source already in the ddk-qemu container
# ($VPNHIDE_QEMU_KSRC = /opt/qemu/linux) and do an incremental make Image
# after applying kpatch patches.  This avoids a full clone+build (saves ~20-40 min).
#
# Usage:  kpatch/test/run-local-container.sh [kmi ...]
#         (no args = one KMI at a time; builds/tests are always serialized)
set -euo pipefail

KMIS_DEFAULT=(
	"upstream-4.19"
	"android12-5.4"
	"android12-5.10"
    "android13-5.10"
    "android13-5.15"
    "android14-5.15"
    "android14-6.1"
    "android15-6.6"
    "android16-6.12"
    "android17-6.18"
)

if [ $# -gt 0 ]; then
    KMIS=("$@")
else
    KMIS=("${KMIS_DEFAULT[@]}")
fi

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"

# ---- build static ctl/daemon binaries once on the host (NDK) ----------------
NDK_HOME="${ANDROID_NDK_HOME:-}"
if [ -z "$NDK_HOME" ]; then
    for p in \
        "$HOME/android-sdk/ndk/28.0.13004108" \
        "$HOME/Android/Sdk/ndk" \
        "$HOME/android-sdk/ndk"; do
        [ -d "$p" ] || continue
        latest=$(ls -d "$p"/*/ 2>/dev/null | sort -V | tail -1)
        [ -n "$latest" ] && NDK_HOME="${latest%/}" && break
    done
fi
[ -n "$NDK_HOME" ] && [ -d "$NDK_HOME" ] || {
    echo "ERROR: ANDROID_NDK_HOME not set and NDK not found in standard paths."
    exit 1
}
echo "[kpatch] NDK: $NDK_HOME"

CLANG_BIN=$(find "$NDK_HOME" -name "aarch64-linux-android*-clang" | head -1)
STRIP_BIN=$(find "$NDK_HOME" -name "llvm-strip" | head -1)
[ -f "$CLANG_BIN" ] || { echo "ERROR: NDK aarch64 clang not found"; exit 1; }

CTL_OUT="$REPO/kmod/vpnhide-ctl-host"
DAEMON_OUT="$REPO/kmod/vpnhide-daemon-host"

echo "[kpatch] Building static host binaries…"
"$CLANG_BIN" -O2 -Wall -static \
    "$REPO/kmod/vpnhide_ctl.c" "$REPO/kmod/vpnhide_policy.c" "$REPO/kmod/parson.c" -o "$CTL_OUT"
[ -f "$STRIP_BIN" ] && "$STRIP_BIN" "$CTL_OUT"

"$CLANG_BIN" -O2 -Wall -static \
    "$REPO/kmod/vpnhide_daemon.c" -o "$DAEMON_OUT"
[ -f "$STRIP_BIN" ] && "$STRIP_BIN" "$DAEMON_OUT"

# ---- container runtime detection --------------------------------------------
DOCKER_CMD="podman"
command -v podman >/dev/null 2>&1 || {
    command -v docker >/dev/null 2>&1 && DOCKER_CMD="docker" || {
        echo "ERROR: neither podman nor docker found"; exit 1
    }
}
USERNS_ARG=""
[ "$DOCKER_CMD" = "podman" ] && USERNS_ARG="--userns=keep-id"

# ---- ensure images exist ----------------------------------------------------
echo "[kpatch] Checking container images…"
for KMI in "${KMIS[@]}"; do
	case "$KMI" in
		upstream-4.19|*-5.4)
			echo "  [$KMI] clean-build profile (no ddk-qemu source image required)"
			continue
			;;
	esac
    IMAGE_NAME="ghcr.io/soranerai/vpnhide_next/ddk-qemu:$KMI"
    ALT_IMAGE="ghcr.io/okhsunrog/vpnhide/ddk-qemu:$KMI"
    if "$DOCKER_CMD" image inspect "$IMAGE_NAME" >/dev/null 2>&1; then
        echo "  [$KMI] $IMAGE_NAME (local)"
    elif "$DOCKER_CMD" image inspect "$ALT_IMAGE" >/dev/null 2>&1; then
        echo "  [$KMI] tagging $ALT_IMAGE → $IMAGE_NAME"
        "$DOCKER_CMD" tag "$ALT_IMAGE" "$IMAGE_NAME"
    else
        echo "  [$KMI] pulling $IMAGE_NAME…"
        "$DOCKER_CMD" pull "$IMAGE_NAME"
    fi
done

# Kernel builds and QEMU instances are intentionally serialized.  A previous
# parallel-container run exhausted WSL2 memory and destabilized the host; keep
# container concurrency fixed at one even when compiler job count is higher.
MAX_PARALLEL=1
echo "[kpatch] Starting kpatch builds+tests (max parallel=$MAX_PARALLEL): ${KMIS[*]}"
BUILD_JOBS="${VPNHIDE_BUILD_JOBS:-32}"
BUILD_MEMORY="${VPNHIDE_BUILD_MEMORY:-11g}"

pids=()
log_files=()
failed=0

for KMI in "${KMIS[@]}"; do
    LOG_FILE="/tmp/vpnhide-kpatch-test-$KMI.log"

    case "$KMI" in
        upstream-4.19|*-5.4)
            echo "[kpatch] [$KMI] starting bounded clean build + host QEMU (log: $LOG_FILE)…"
            if VPNHIDE_BUILD_JOBS="$BUILD_JOBS" \
                VPNHIDE_BUILD_MEMORY="$BUILD_MEMORY" \
                "$HERE/build-kernel.sh" "$KMI" > "$LOG_FILE" 2>&1 && \
                "$HERE/run.sh" "$KMI" >> "$LOG_FILE" 2>&1; then
                echo "[kpatch] [$KMI] PASSED"
            else
                rc=$?
                echo ""
                echo "=== [kpatch] [$KMI] FAILED (exit $rc) ==="
                cat "$LOG_FILE"
                failed=$((failed + 1))
            fi
            continue
            ;;
    esac

    IMAGE_NAME="ghcr.io/soranerai/vpnhide_next/ddk-qemu:$KMI"
    log_files+=("$LOG_FILE")
    echo "[kpatch] [$KMI] starting container (log: $LOG_FILE)…"

    # Run as root inside the container (no --userns=keep-id) so we can write
    # to /opt/qemu/linux which is owned by root in the image.
    "$DOCKER_CMD" run --rm \
        --memory "$BUILD_MEMORY" --memory-swap "$BUILD_MEMORY" \
        -v "$REPO:/repo:Z" \
        -w /repo \
        -e KMI="$KMI" \
        -e VPNHIDE_QEMU_TIMEOUT="${VPNHIDE_QEMU_TIMEOUT:-300}" \
        -e VPNHIDE_KEEP_WORKDIR="${VPNHIDE_KEEP_WORKDIR:-0}" \
        -e VPNHIDE_BUILD_JOBS="$BUILD_JOBS" \
        "$IMAGE_NAME" \
        bash -euo pipefail -c '
            CLANG_BIN="$(ls -d /opt/ddk/clang/*/bin | head -1)"
            export PATH="$CLANG_BIN:$PATH"
            KSRC="$VPNHIDE_QEMU_KSRC"   # /opt/qemu/linux (pre-built, writable in container)

            # Map the KMI to a compatibility profile. The kernel version
            # (suffix) selects the profile, not the android generation.
            case "$KMI" in
				upstream-4.19) PATCHVER=upstream-4.19 ;;
				*-5.4)   PATCHVER=android12-5.4  ;;
                *-5.10)  PATCHVER=android12-5.10 ;;
                *-5.15)  PATCHVER=android13-5.15 ;;
                *-6.1)   PATCHVER=android14-6.1  ;;
                *-6.6)   PATCHVER=android15-6.6  ;;
                *-6.12)  PATCHVER=android16-6.12 ;;
                *-6.18)  PATCHVER=android17-6.18 ;;
                *) echo "ERROR: no VPNHide compatibility profile for KMI $KMI"; exit 1 ;;
            esac

            echo "[kpatch/$KMI] Applying VPNHide in-tree integration (apply.sh, $PATCHVER)…"
            # apply.sh copies security/vpnhide + include/linux/vpnhide.h and
            # structurally injects modern GKI call sites.
            bash /repo/kpatch/scripts/apply.sh "$KSRC" "$PATCHVER"

            echo "[kpatch/$KMI] Enabling CONFIG_VPNHIDE=y (incremental)…"
            cd "$KSRC"
            # Add CONFIG_VPNHIDE=y to .config (removes any existing entry first)
            sed -i "/CONFIG_VPNHIDE/d" .config
            echo "CONFIG_VPNHIDE=y" >> .config
            # Disable LTO for test builds — full LLVM LTO needs 8+ GB RAM and OOM-kills the linker.
            sed -i "/CONFIG_LTO/d" .config
            sed -i "/CONFIG_THINLTO/d" .config
            echo "CONFIG_LTO_NONE=y" >> .config
            scripts/config --disable UAPI_HEADER_TEST || true
            make ARCH=arm64 LLVM=1 olddefconfig

            if grep -Eq "^CONFIG_(LTO_CLANG|THINLTO)=y" .config; then
                echo "ERROR: legacy QEMU build still has LLVM LTO enabled"
                exit 1
            fi

            grep -q "^CONFIG_VPNHIDE=y" .config || {
                echo "ERROR: CONFIG_VPNHIDE=y not in .config after olddefconfig — Kconfig not wired?"
                exit 1
            }

            echo "[kpatch/$KMI] Incremental build (only changed files)…"
            make ARCH=arm64 LLVM=1 -j"${VPNHIDE_BUILD_JOBS:-1}" Image

            NEW_IMAGE="$KSRC/arch/arm64/boot/Image"
            echo "[kpatch/$KMI] Image ready: $NEW_IMAGE"

            echo "[kpatch/$KMI] Running QEMU test…"
            VPNHIDE_QEMU_IMAGE="$NEW_IMAGE" \
            VPNHIDE_QEMU_ROOTFS="/opt/qemu/alpine-minirootfs.tar.gz" \
                /repo/kpatch/test/run.sh "$KMI"
        ' > "$LOG_FILE" 2>&1 &

    pids+=($!)

    # WSL-safe: never keep several kernel linkers/QEMU instances alive at once.
    if [ "$MAX_PARALLEL" -le 1 ]; then
        if ! wait "${pids[0]}"; then
            echo ""
            echo "=== [kpatch] [$KMI] FAILED ==="
            cat "$LOG_FILE"
            failed=$((failed + 1))
        else
            echo "[kpatch] [$KMI] PASSED"
        fi
        pids=()
        log_files=()
    fi
done

# ---- wait for all containers ------------------------------------------------
echo "[kpatch] Waiting for all tests to finish…"

while [ ${#pids[@]} -gt 0 ]; do
    new_pids=()
    new_logs=()
    for i in "${!pids[@]}"; do
        pid="${pids[$i]}"
        KMI="${KMIS[$i]}"
        log="${log_files[$i]}"
        if ! kill -0 "$pid" 2>/dev/null; then
            wait "$pid" && rc=0 || rc=$?
            if [ "$rc" -ne 0 ]; then
                echo ""
                echo "=== [kpatch] [$KMI] FAILED (exit $rc) ==="
                cat "$log"
                failed=$((failed + 1))
            else
                echo "[kpatch] [$KMI] PASSED"
            fi
        else
            new_pids+=("$pid")
            new_logs+=("$log")
        fi
    done
    pids=("${new_pids[@]+"${new_pids[@]}"}")
    log_files=("${new_logs[@]+"${new_logs[@]}"}")
    [ ${#pids[@]} -gt 0 ] && sleep 2
done

if [ "$failed" -eq 0 ]; then
    echo "[kpatch] SUCCESS: all KMIs passed"
    exit 0
fi
echo "[kpatch] FAILED: $failed KMI(s) failed"
exit 1
