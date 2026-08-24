#!/usr/bin/env bash
# Boot a GKI kernel with VPNHide built-in (kpatch) in QEMU and run the vector
# tests inside it.  Consumes a prebuilt kernel Image from the per-KMI cache
# (produced by build-kernel.sh); assembles an Alpine initramfs around init.sh,
# boots, and parses the serial console for RESULT/SUMMARY lines.
#
# Usage:  kpatch/test/run.sh [kmi]      (default: android12-5.10)
# Exit:   0 = all vectors PASS, no panic; non-zero otherwise.
#
# Key difference from kmod/test/run.sh:
#   - No .ko artifact needed or checked.
#   - Output contains CTRL_DEV=ok instead of INSMOD=ok.
set -euo pipefail

KMI="${1:-android12-5.10}"
HERE="$(cd "$(dirname "$0")" && pwd)"
CACHE="$HERE/.cache/$KMI"

IMAGE="${VPNHIDE_QEMU_IMAGE:-$CACHE/Image}"
QEMU_BIN="${VPNHIDE_QEMU_BIN:-qemu-system-aarch64}"

ALPINE_VER="3.21.2"
ALPINE_TAR="${VPNHIDE_QEMU_ROOTFS:-$CACHE/../alpine-minirootfs-$ALPINE_VER-aarch64.tar.gz}"
ALPINE_URL="https://dl-cdn.alpinelinux.org/alpine/v3.21/releases/aarch64/alpine-minirootfs-$ALPINE_VER-aarch64.tar.gz"

command -v "$QEMU_BIN" >/dev/null || { echo "ERROR: $QEMU_BIN not installed"; exit 2; }
[ -f "$IMAGE" ] || {
    echo "ERROR: kernel Image missing: $IMAGE"
    echo "  run: $HERE/build-kernel.sh $KMI"
    exit 2
}

# Locate static host binaries (shared with kmod)
CTL_BIN="${VPNHIDE_CTL_BIN:-}"
DAEMON_BIN="${VPNHIDE_DAEMON_BIN:-}"

for candidate in \
    "$HERE/../../kmod/vpnhide-ctl-host" \
    "$HERE/vpnhide-ctl-host"; do
    [ -z "$CTL_BIN" ] && [ -f "$candidate" ] && CTL_BIN="$candidate"
done

for candidate in \
    "$HERE/../../kmod/vpnhide-daemon-host" \
    "$HERE/vpnhide-daemon-host"; do
    [ -z "$DAEMON_BIN" ] && [ -f "$candidate" ] && DAEMON_BIN="$candidate"
done

[ -n "$CTL_BIN"    ] || { echo "ERROR: vpnhide-ctl-host not found (run kmod/test/run-local-container.sh once to build it)"; exit 2; }
[ -n "$DAEMON_BIN" ] || { echo "ERROR: vpnhide-daemon-host not found"; exit 2; }

mkdir -p "$CACHE"
[ -f "$ALPINE_TAR" ] || {
    echo "[run/kpatch] fetching Alpine minirootfs…"
    curl -fsSL "$ALPINE_URL" -o "$ALPINE_TAR"
}

WORK="$(mktemp -d)"
KEEP_WORK="${VPNHIDE_KEEP_WORKDIR:-0}"
cleanup() { [ "$KEEP_WORK" = "1" ] || rm -rf "$WORK"; }
trap cleanup EXIT
RFS="$WORK/rootfs"
mkdir -p "$RFS"
tar xzf "$ALPINE_TAR" -C "$RFS"

# Install optional ARM64 Alpine packages on the host side.  Network access
# from the guest is deliberately not required: this makes iproute2/tc and
# python3 available even when QEMU user networking or DNS is unavailable.
EXTRA_APK_DIR="${VPNHIDE_QEMU_APK_DIR:-}"
if [ -n "$EXTRA_APK_DIR" ]; then
    [ -d "$EXTRA_APK_DIR" ] || {
        echo "ERROR: VPNHIDE_QEMU_APK_DIR is not a directory: $EXTRA_APK_DIR"
        exit 2
    }
    found_apk=0
    for apk in "$EXTRA_APK_DIR"/*.apk; do
        [ -f "$apk" ] || continue
        echo "[run/kpatch] adding $(basename "$apk") to initramfs"
        tar --warning=no-unknown-keyword -xzf "$apk" -C "$RFS"
        found_apk=1
    done
    [ "$found_apk" -eq 1 ] || {
        echo "ERROR: no .apk files found in VPNHIDE_QEMU_APK_DIR=$EXTRA_APK_DIR"
        exit 2
    }
fi

cp "$CTL_BIN"    "$RFS/vpnhide-ctl"
cp "$DAEMON_BIN" "$RFS/vpnhide-daemon"
# vector_tests.py: prefer local copy, fall back to kmod's
VTESTS="$HERE/vector_tests.py"
[ -f "$VTESTS" ] || VTESTS="$HERE/../../kmod/test/vector_tests.py"
[ -f "$VTESTS" ] || { echo "ERROR: vector_tests.py not found"; exit 2; }
cp "$VTESTS"         "$RFS/vector_tests.py"
cp "$HERE/init.sh"   "$RFS/init"
chmod +x "$RFS/init" "$RFS/vpnhide-ctl" "$RFS/vpnhide-daemon" "$RFS/vector_tests.py"

( cd "$RFS" && find . | cpio -o -H newc 2>/dev/null | gzip > "$WORK/initramfs.cpio.gz" )

LOG="$WORK/serial.log"
BOOT_TIMEOUT="${VPNHIDE_QEMU_TIMEOUT:-300}"
QEMU_MEM="${VPNHIDE_QEMU_MEM:-512M}"
QEMU_SMP="${VPNHIDE_QEMU_SMP:-1}"
echo "[run/kpatch] $KMI: booting $(basename "$IMAGE") in QEMU (TCG, no KVM)…"
timeout "$BOOT_TIMEOUT" "$QEMU_BIN" \
    -machine virt,gic-version=3 -cpu cortex-a57 -accel tcg,thread=multi,tb-size=1024 \
    -smp "$QEMU_SMP" -m "$QEMU_MEM" \
    -kernel "$IMAGE" -initrd "$WORK/initramfs.cpio.gz" \
    -append "earlycon=pl011,mmio32,0x09000000 console=ttyAMA0 panic=-1 rdinit=/init" \
    -netdev user,id=n0 -device virtio-net-device,netdev=n0 \
    -display none -no-reboot -serial "file:$LOG" >/dev/null 2>&1 || true

echo "------------------------- test output -------------------------"
if ! sed -n '/VPNHIDE-QEMU-TEST START/,/VPNHIDE-QEMU-TEST END/p' "$LOG" |
        grep -E 'KREL|IPROUTE2|CTRL_DEV|REGISTERED|RESULT|PANIC|SUMMARY'; then
    echo "ERROR: no test output — kernel did not boot or init failed"
    echo "--- last 30 serial lines ---"; tail -30 "$LOG"
    exit 1
fi
echo "---------------------------------------------------------------"

summary="$(grep -oE 'SUMMARY pass=[0-9]+ fail=[0-9]+ panic=[0-9]+ registered=[0-9]+' "$LOG" | tail -1 || true)"
[ -n "$summary" ] || {
    echo "ERROR: VM did not reach SUMMARY (timed out after ${BOOT_TIMEOUT}s, boot failure, or CONFIG_VPNHIDE missing)"
    echo "--- last 60 serial lines ---"; tail -60 "$LOG"
    exit 1
}
fail="$(  sed -E 's/.*fail=([0-9]+).*/\1/'  <<<"$summary")"
panic="$( sed -E 's/.*panic=([0-9]+).*/\1/' <<<"$summary")"

if [ "$fail" -eq 0 ] && [ "$panic" -eq 0 ]; then
    echo "[run/kpatch] $KMI: PASS ($summary)"
    exit 0
fi
echo "[run/kpatch] $KMI: FAIL ($summary)"
echo "=== FULL SERIAL LOG ==="
cat "$LOG"
exit 1
