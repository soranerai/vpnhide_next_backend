#!/usr/bin/env bash
# Build a QEMU-bootable GKI kernel with VPNHide baked in (kpatch) for <kmi>.
#
# Differences from kmod/test/build-kernel.sh:
#   - kpatch/scripts/apply.sh is applied to the cloned source tree before building
#     (copies security/vpnhide/ + include/linux/vpnhide.h and applies the
#      versions/<ver>/*.patch set for the KMI's kernel version).
#   - CONFIG_VPNHIDE=y is set via qemu.config (no .ko produced or needed).
#
# Usage:  kpatch/test/build-kernel.sh <kmi>          e.g. android14-6.1
# Output: kpatch/test/.cache/<kmi>/Image
set -euo pipefail

KMI="${1:?usage: build-kernel.sh <kmi>  (e.g. android14-6.1)}"
BUILD_JOBS="${VPNHIDE_BUILD_JOBS:-32}"
BUILD_MEMORY="${VPNHIDE_BUILD_MEMORY:-11g}"
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
CACHE="$HERE/.cache/$KMI"
FRAG="$HERE/qemu.config"

DDK_IMAGE_TAG="20260313"
case "$KMI" in
	upstream-4.19|*-5.4) DDK_KMI="android12-5.10" ;;
	*)                   DDK_KMI="$KMI" ;;
esac
DDK="${VPNHIDE_DDK_IMAGE:-ghcr.io/ylarod/ddk-min:${DDK_KMI}-${DDK_IMAGE_TAG}}"

CONTAINER_CMD="${VPNHIDE_CONTAINER_RUNTIME:-}"
if [ -z "$CONTAINER_CMD" ]; then
	if command -v podman >/dev/null 2>&1; then
		CONTAINER_CMD="podman"
	elif command -v docker >/dev/null 2>&1; then
		CONTAINER_CMD="docker"
	else
		echo "ERROR: neither podman nor docker found"
		exit 1
	fi
fi

mkdir -p "$CACHE"
echo "[build-kernel/kpatch] $KMI: bounded build (jobs=$BUILD_JOBS memory=$BUILD_MEMORY)"

"$CONTAINER_CMD" run --rm \
	--memory "$BUILD_MEMORY" --memory-swap "$BUILD_MEMORY" \
	-v "$REPO:/repo:ro" -v "$CACHE:/out" -v "$FRAG:/qemu.config:ro" \
	-e KMI="$KMI" -e VPNHIDE_BUILD_JOBS="$BUILD_JOBS" "$DDK" bash -euo pipefail -c '
	CLANG_BIN="$(ls -d /opt/ddk/clang/*/bin | head -1)"
	export PATH="$CLANG_BIN:$PATH"

	# 1. Clone kernel source.  Upstream 4.19 has no Android common KMI branch.
	case "$KMI" in
		upstream-4.19) git clone --depth=1 -b v4.19.325 https://github.com/gregkh/linux.git /tmp/linux ;;
		*)             git clone --depth=1 -b "$KMI" https://android.googlesource.com/kernel/common /tmp/linux ;;
	esac
	cd /tmp/linux

	# 2. Apply VPNHide in-tree patches via apply.sh (copies security/vpnhide +
	#    include/linux/vpnhide.h and applies versions/<ver>/*.patch).
	#    The kernel version (KMI suffix) selects the patchset.
	case "$KMI" in
		upstream-4.19) PATCHVER=upstream-4.19 ;;
		*-5.4)   PATCHVER=android12-5.4  ;;
		*-5.10)  PATCHVER=android12-5.10 ;;
		*-5.15)  PATCHVER=android13-5.15 ;;
		*-6.1)   PATCHVER=android14-6.1  ;;
		*-6.6)   PATCHVER=android15-6.6  ;;
		*-6.12)  PATCHVER=android16-6.12 ;;
		*) echo "ERROR: no VPNHide patchset for KMI $KMI"; exit 1 ;;
	esac
	bash /repo/kpatch/scripts/apply.sh /tmp/linux "$PATCHVER"

	# 4. Build kernel with CONFIG_VPNHIDE=y (and virtio/PL011/DUMMY from qemu.config)
	case "$KMI" in
		upstream-4.19) make ARCH=arm64 LLVM=1 defconfig ;;
		*)             make ARCH=arm64 LLVM=1 gki_defconfig ;;
	esac
	./scripts/kconfig/merge_config.sh -m .config /qemu.config
	# Keep legacy/QEMU builds bounded and deterministic.  These options are
	# unnecessary for the vector harness and can multiply memory usage.
	scripts/config --disable LTO || true
	scripts/config --disable LTO_CLANG || true
	scripts/config --disable THINLTO || true
	scripts/config --enable LTO_NONE || true
for sym in CFI_CLANG CFI_CLANG_SHADOW DEBUG_INFO_BTF IKHEADERS UAPI_HEADER_TEST KVM KVM_ARM_HOST KVM_ARM_VGIC_V3; do
	scripts/config --disable "$sym" || true
done
	make ARCH=arm64 LLVM=1 olddefconfig
	if grep -Eq "^CONFIG_(LTO_CLANG|THINLTO)=y" .config; then
		echo "ERROR: legacy QEMU build still has LLVM LTO enabled"
		exit 1
	fi

	# Verify CONFIG_VPNHIDE=y was accepted
	if ! grep -q "^CONFIG_VPNHIDE=y" .config; then
		echo "ERROR: CONFIG_VPNHIDE=y not present in .config after merge"
		cat .config | grep VPNHIDE || true
		exit 1
	fi

	make ARCH=arm64 LLVM=1 -j"${VPNHIDE_BUILD_JOBS:-1}" Image

	cp arch/arm64/boot/Image /out/Image
	echo "[build-kernel/kpatch] built Image with CONFIG_VPNHIDE=y for $KMI"
'

echo "[build-kernel/kpatch] $KMI: done"
echo "  Image: $CACHE/Image"
