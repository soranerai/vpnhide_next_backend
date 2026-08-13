#!/usr/bin/env bash
set -euo pipefail

# Compare two already-built artifacts in identical QEMU guests.
# kmod mode compares .ko files; kpatch mode compares kernel Images.

HERE="$(cd "$(dirname "$0")" && pwd)"
KMI="${1:-android12-5.10}"
BACKEND="${PERF_BACKEND:-kmod}"
CACHE="$HERE/.cache/$KMI"
ALPINE_VER="3.21.2"
ALPINE_TAR="${VPNHIDE_QEMU_ROOTFS:-$CACHE/alpine-minirootfs-$ALPINE_VER-aarch64.tar.gz}"
ALPINE_URL="https://dl-cdn.alpinelinux.org/alpine/v3.21/releases/aarch64/alpine-minirootfs-$ALPINE_VER-aarch64.tar.gz"

BASE_IMAGE="${VPNHIDE_PERF_BASELINE_IMAGE:-$CACHE/Image-baseline}"
OPT_IMAGE="${VPNHIDE_PERF_OPTIMIZED_IMAGE:-$CACHE/Image-optimized}"
BASE_KO="${VPNHIDE_PERF_BASELINE_KO:-$CACHE/vpnhide_kmod-baseline.ko}"
OPT_KO="${VPNHIDE_PERF_OPTIMIZED_KO:-$CACHE/vpnhide_kmod-optimized.ko}"

command -v qemu-system-aarch64 >/dev/null || { echo "qemu-system-aarch64 missing"; exit 2; }
[ -f "$BASE_IMAGE" ] || { echo "missing baseline image: $BASE_IMAGE"; exit 2; }
[ -f "$OPT_IMAGE" ] || { echo "missing optimized image: $OPT_IMAGE"; exit 2; }
if [ "$BACKEND" = kmod ]; then
    [ -f "$BASE_KO" ] || { echo "missing baseline module: $BASE_KO"; exit 2; }
    [ -f "$OPT_KO" ] || { echo "missing optimized module: $OPT_KO"; exit 2; }
fi

mkdir -p "$CACHE"
[ -f "$ALPINE_TAR" ] || curl -fsSL "$ALPINE_URL" -o "$ALPINE_TAR"

run_one() {
    local variant="$1" image="$2" ko="${3:-}" work rfs log
    work="$(mktemp -d)"
    rfs="$work/rootfs"
    log="$work/serial.log"
    mkdir -p "$rfs"
    tar xzf "$ALPINE_TAR" -C "$rfs"
    cp "$HERE/perf_init.sh" "$rfs/init"
    cp "$HERE/perf_workload.py" "$rfs/perf_workload.py"
    [ -f "$HERE/../vpnhide-ctl-host" ] || {
        echo "missing $HERE/../vpnhide-ctl-host (run-local-container.sh builds it)" >&2
        rm -rf "$work"
        return 1
    }
    cp "$HERE/../vpnhide-ctl-host" "$rfs/vpnhide-ctl"
    printf '%s\n' "$BACKEND" > "$rfs/perf-backend"
    printf '%s\n' "${VPNHIDE_PERF_ITERATIONS:-20000}" > "$rfs/perf-iterations"
    printf '%s\n' "${VPNHIDE_PERF_REPEATS:-5}" > "$rfs/perf-repeats"
    if [ "$BACKEND" = kmod ]; then cp "$ko" "$rfs/vpnhide_kmod.ko"; fi
    chmod +x "$rfs/init" "$rfs/perf_workload.py" "$rfs/vpnhide-ctl"
    ( cd "$rfs" && find . | cpio -o -H newc 2>/dev/null | gzip > "$work/initramfs.cpio.gz" )

    VPNHIDE_PERF_VARIANT="$variant" timeout "${VPNHIDE_QEMU_TIMEOUT:-300}" \
    qemu-system-aarch64 -machine virt -cpu max \
        -accel tcg,thread=multi,tb-size=1024 -smp 4 -m 2G \
        -kernel "$image" -initrd "$work/initramfs.cpio.gz" \
        -append "console=ttyAMA0 panic=-1 rdinit=/init" \
        -netdev user,id=n0 -device virtio-net-pci,netdev=n0,romfile= \
        -display none -no-reboot -serial "file:$log" >/dev/null 2>&1 || true

    if grep -q 'PERF_ERROR=' "$log"; then
        grep 'PERF_ERROR=' "$log" >&2
        tail -30 "$log" >&2
        rm -rf "$work"
        return 1
    fi
    output="$(sed -n '/VPNHIDE-QEMU-PERF START/,/VPNHIDE-QEMU-PERF END/p' "$log" \
        | grep '^PERF metric=' | sed "s/^/VARIANT=$variant /" || true)"
    if [ -z "$output" ]; then
        echo "no performance output for $variant" >&2
        tail -50 "$log" >&2
        rm -rf "$work"
        return 1
    fi
    printf '%s\n' "$output"
    rm -rf "$work"
}

BASE_OUTPUT="$(run_one baseline "$BASE_IMAGE" "$BASE_KO")"
OPT_OUTPUT="$(run_one optimized "$OPT_IMAGE" "$OPT_KO")"
printf '%s\n%s\n' "$BASE_OUTPUT" "$OPT_OUTPUT"

awk '
function percent(old, new) { return old == 0 ? 0 : (new-old) * 100 / old }
function metric(field,    x) { x=field; sub(/^metric=/, "", x); return x }
function number(field,    x) { x=field; sub(/^[^=]*=/, "", x); return x }
$1 == "VARIANT=baseline" {
    name=metric($3); base_wall[name]=number($6); base_cpu[name]=number($7); next
}
$1 == "VARIANT=optimized" {
    name=metric($3); opt_wall[name]=number($6); opt_cpu[name]=number($7); next
}
END {
    for (name in opt_wall)
        printf "DELTA metric=%s wall_ns=%d wall_pct=%.2f cpu_ns=%d cpu_pct=%.2f\n",
            name, opt_wall[name]-base_wall[name],
            percent(base_wall[name], opt_wall[name]),
            opt_cpu[name]-base_cpu[name],
            percent(base_cpu[name], opt_cpu[name])
}' <<<"$BASE_OUTPUT
$OPT_OUTPUT"
