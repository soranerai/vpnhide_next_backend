#!/usr/bin/env bash
# Build a VPNHide kmod ZIP from a Google GKI kernel tree.
#
# Usage:
#   ./scripts/build-gki-kmod.sh [android17-6.18] [jobs]
#
# The kernel tree is disposable by default. Set VPNHIDE_KEEP_BUILD=1 to keep
# it under /tmp for inspection, or VPNHIDE_BUILD_ROOT to choose its location.
set -euo pipefail

KMI="${1:-android17-6.18}"
JOBS="${2:-${VPNHIDE_BUILD_JOBS:-$(nproc)}}"
REPO="$(cd "$(dirname "$0")/.." && pwd)"
KERNEL_URL="${VPNHIDE_KERNEL_URL:-https://android.googlesource.com/kernel/common}"

case "$KMI" in
  android17-6.18) ;;
  *) echo "unsupported KMI: $KMI (only android17-6.18 is automated yet)" >&2; exit 2 ;;
esac

if ! command -v git >/dev/null || ! command -v make >/dev/null; then
  echo "git and make are required" >&2
  exit 1
fi

if [ -n "${VPNHIDE_BUILD_ROOT:-}" ]; then
  BUILD_ROOT="$VPNHIDE_BUILD_ROOT/$KMI"
  if [ -e "$BUILD_ROOT" ]; then
    echo "build directory already exists: $BUILD_ROOT" >&2
    echo "remove it or set VPNHIDE_BUILD_ROOT to a new directory" >&2
    exit 1
  fi
  KEEP_BUILD=1
else
  BUILD_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/vpnhide-gki-${KMI}.XXXXXX")"
  KEEP_BUILD="${VPNHIDE_KEEP_BUILD:-0}"
fi

cleanup() {
  rc=$?
  if [ "$KEEP_BUILD" = 1 ]; then
    echo "[build] kept work directory: $BUILD_ROOT"
  else
    rm -rf "$BUILD_ROOT"
  fi
  exit "$rc"
}
trap cleanup EXIT

KERNEL_DIR="$BUILD_ROOT/kernel"
LLVM_BIN="$BUILD_ROOT/llvm-bin"
LIBDW_DIR="$BUILD_ROOT/libdw"
mkdir -p "$LLVM_BIN"

echo "[build] cloning $KERNEL_URL ($KMI)"
git clone --depth=1 --branch "$KMI" "$KERNEL_URL" "$KERNEL_DIR"

echo "[build] applying VPNHide patches"
bash "$REPO/kpatch/scripts/apply.sh" "$KERNEL_DIR" "$KMI"

echo "[build] configuring kernel"
make -C "$KERNEL_DIR" ARCH=arm64 LLVM=1 gki_defconfig
"$KERNEL_DIR/scripts/config" --enable VPNHIDE || true
# scripts/config can leave newly-added symbols disabled on some kconfig hosts.
sed -i 's/^# CONFIG_VPNHIDE is not set$/CONFIG_VPNHIDE=y/' "$KERNEL_DIR/.config"
make -C "$KERNEL_DIR" ARCH=arm64 LLVM=1 olddefconfig

CLANG_BIN="${CLANG_DIR:-}"
if [ -z "$CLANG_BIN" ]; then
  CLANG_BIN="$(dirname "$(command -v clang)")"
fi
PATH="$CLANG_BIN:$PATH"

# Ubuntu exposes LLVM 18 tools with a -18 suffix; Kbuild expects unsuffixed
# names when LLVM=1. DDK toolchains already have the unsuffixed names.
for tool in llvm-ar llvm-nm llvm-objcopy llvm-objdump llvm-readelf llvm-strip llvm-as; do
  if ! command -v "$tool" >/dev/null && command -v "${tool}-18" >/dev/null; then
    ln -s "$(command -v "${tool}-18")" "$LLVM_BIN/$tool"
  fi
done
if ! command -v clang >/dev/null; then
  echo "clang is required (set CLANG_DIR=/path/to/clang/bin)" >&2
  exit 1
fi
if command -v clang-18 >/dev/null && [ ! -x "$LLVM_BIN/clang" ]; then
  ln -s "$(command -v clang-18)" "$LLVM_BIN/clang"
fi
if command -v ld.lld-18 >/dev/null && [ ! -x "$LLVM_BIN/ld.lld" ]; then
  ln -s "$(command -v ld.lld-18)" "$LLVM_BIN/ld.lld"
fi
PATH="$LLVM_BIN:$PATH"
export PATH

HOST_CFLAGS=""
HOST_LDFLAGS=""
HOST_GENDWARF="-ldw -lelf -lz -lzstd"
if [ ! -f /usr/include/dwarf.h ]; then
  command -v apt-get >/dev/null || {
    echo "libdw-dev is required (missing /usr/include/dwarf.h)" >&2
    exit 1
  }
  mkdir -p "$LIBDW_DIR"
  echo "[build] downloading libdw-dev headers locally"
  (cd "$LIBDW_DIR" && apt-get download libdw-dev >/dev/null)
  dpkg-deb -x "$LIBDW_DIR"/libdw-dev_*.deb "$LIBDW_DIR/extracted"
  HOST_CFLAGS="-I$LIBDW_DIR/extracted/usr/include"
  DW_SO="$(find /usr/lib /lib -name 'libdw-*.so' 2>/dev/null | head -1 || true)"
  ELF_SO="$(find /usr/lib /lib -name 'libelf-*.so' 2>/dev/null | head -1 || true)"
  if [ -n "$DW_SO" ] && [ -n "$ELF_SO" ]; then
    HOST_LDFLAGS="-L$(dirname "$DW_SO")"
    HOST_GENDWARF="-l:$(basename "$DW_SO") -l:$(basename "$ELF_SO") -lz -lzstd"
  fi
fi

echo "[build] building GKI Image and symbol tables (jobs=$JOBS)"
make -C "$KERNEL_DIR" ARCH=arm64 LLVM=1 NM=llvm-nm \
  HOSTCFLAGS="$HOST_CFLAGS" HOSTLDFLAGS="$HOST_LDFLAGS" \
  HOSTLDLIBS_gendwarfksyms="$HOST_GENDWARF" -j"$JOBS" Image modules_prepare
cp "$KERNEL_DIR/vmlinux.symvers" "$KERNEL_DIR/Module.symvers"

echo "[build] building and packaging kmod"
"$REPO/kmod/build.py" --kdir "$KERNEL_DIR" --clang-dir "$LLVM_BIN" --kmi "$KMI"

echo "[build] done: $REPO/vpnhide-kmod-$KMI.zip"
