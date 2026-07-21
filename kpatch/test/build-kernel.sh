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
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
CACHE="$HERE/.cache/$KMI"
FRAG="$HERE/qemu.config"

DDK_IMAGE_TAG="20260313"
DDK="ghcr.io/ylarod/ddk-min:${KMI}-${DDK_IMAGE_TAG}"

mkdir -p "$CACHE"
echo "[build-kernel/kpatch] $KMI: cloning kernel/common + applying kpatch + building Image…"

docker run --rm \
	-v "$REPO:/repo:ro" -v "$CACHE:/out" -v "$FRAG:/qemu.config:ro" \
	-e KMI="$KMI" "$DDK" bash -euo pipefail -c '
	CLANG_BIN="$(ls -d /opt/ddk/clang/*/bin | head -1)"
	export PATH="$CLANG_BIN:$PATH"

	# 1. Clone kernel source
	git clone --depth=1 -b "$KMI" \
		https://android.googlesource.com/kernel/common /tmp/linux
	cd /tmp/linux

	# 2. Apply VPNHide in-tree patches via apply.sh (copies security/vpnhide +
	#    include/linux/vpnhide.h and applies versions/<ver>/*.patch).
	#    The kernel version (KMI suffix) selects the patchset.
	case "$KMI" in
		*-5.10)  PATCHVER=android12-5.10 ;;
		*-5.15)  PATCHVER=android13-5.15 ;;
		*-6.1)   PATCHVER=android14-6.1  ;;
		*-6.6)   PATCHVER=android15-6.6  ;;
		*-6.12)  PATCHVER=android16-6.12 ;;
		*) echo "ERROR: no VPNHide patchset for KMI $KMI"; exit 1 ;;
	esac
	bash /repo/kpatch/scripts/apply.sh /tmp/linux "$PATCHVER"

	# 4. Build kernel with CONFIG_VPNHIDE=y (and virtio/PL011/DUMMY from qemu.config)
	make ARCH=arm64 LLVM=1 gki_defconfig
	./scripts/kconfig/merge_config.sh -m .config /qemu.config
	make ARCH=arm64 LLVM=1 olddefconfig

	# Verify CONFIG_VPNHIDE=y was accepted
	if ! grep -q "^CONFIG_VPNHIDE=y" .config; then
		echo "ERROR: CONFIG_VPNHIDE=y not present in .config after merge"
		cat .config | grep VPNHIDE || true
		exit 1
	fi

	make ARCH=arm64 LLVM=1 -j"$(nproc)" Image

	cp arch/arm64/boot/Image /out/Image
	echo "[build-kernel/kpatch] built Image with CONFIG_VPNHIDE=y for $KMI"
'

echo "[build-kernel/kpatch] $KMI: done"
echo "  Image: $CACHE/Image"
