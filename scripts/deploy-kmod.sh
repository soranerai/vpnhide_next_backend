#!/usr/bin/env bash
# Build kernel module for the target GKI, push/install the ENTIRE module on a connected adb device, and reboot.
# Usage: ./scripts/deploy-kmod.sh [kmi-variant]
# Examples:
#   ./scripts/deploy-kmod.sh                    # Auto-detects KMI from adb, deploys whole module, and reboots
#   ./scripts/deploy-kmod.sh android14-6.1      # Manually specifies KMI, deploys whole module, and reboots

set -euo pipefail

# 1. Determine script and repo directories
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
. "$REPO_ROOT/kmod/module/kmi-check.sh"

# Color constants for rich aesthetics in terminal output
BOLD="\033[1m"
GREEN="\033[1;32m"
BLUE="\033[1;34m"
YELLOW="\033[1;33m"
RED="\033[1;31m"
NC="\033[0m" # No Color

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

# 2. Check ADB connection
log_info "Checking ADB device connection..."
if ! adb get-state >/dev/null 2>&1; then
    log_error "No ADB device connected or authorized. Please connect a device with USB debugging enabled."
    exit 1
fi

# 3. Parse arguments
KMI=""

for arg in "$@"; do
    if [[ "$arg" =~ ^android[0-9]+-[0-9]+\.[0-9]+$ ]]; then
        KMI="$arg"
    else
        log_error "Unknown argument: $arg"
        echo "Usage: $0 [kmi-variant]"
        exit 1
    fi
done

# 4. Detect the device KMI and reject an explicitly selected mismatch.
log_info "Detecting GKI kernel variant from device..."
UNAME_R=$(adb shell uname -r 2>/dev/null | tr -d '\r\n')
DEVICE_KMI=$(vpnhide_detect_gki "$UNAME_R") || true
if [[ -z "$DEVICE_KMI" ]]; then
    log_error "Could not determine GKI from device kernel '${UNAME_R:-unknown}'."
    exit 1
fi
log_info "Device kernel: ${BOLD}$UNAME_R${NC} (${BOLD}$DEVICE_KMI${NC})"

if [[ -z "$KMI" ]]; then
    KMI="$DEVICE_KMI"
    log_success "Auto-detected KMI variant: ${BOLD}$KMI${NC}"
elif [[ "$KMI" != "$DEVICE_KMI" ]]; then
    log_error "Refusing to deploy $KMI to a $DEVICE_KMI kernel."
    exit 1
fi

ZIP_NAME="vpnhide-kmod-${KMI}.zip"
ZIP_PATH="$REPO_ROOT/$ZIP_NAME"

# 5. Build the kernel module
log_info "Building kernel module for variant: ${BOLD}$KMI${NC}..."
# Change directory to repo root to execute build script properly
cd "$REPO_ROOT"

if ! ./kmod/build.py --kmi "$KMI"; then
    log_error "Build failed!"
    exit 1
fi
log_success "Kernel module build completed."

# 6. Verify zip exists
if [[ ! -f "$ZIP_PATH" ]]; then
    log_error "Expected build artifact not found at: $ZIP_PATH"
    exit 1
fi

# 7. Extract the entire module from zip to a temporary folder
TEMP_DIR=$(mktemp -d)
trap 'rm -rf "$TEMP_DIR"' EXIT

log_info "Extracting entire module from $ZIP_NAME..."
if command -v unzip >/dev/null 2>&1; then
    unzip -o "$ZIP_PATH" -d "$TEMP_DIR" >/dev/null
else
    python3 -c "import zipfile; zipfile.ZipFile('$ZIP_PATH').extractall('$TEMP_DIR')"
fi

# Remove flash-only files that are not needed at runtime under /data/adb/modules/vpnhide_kmod
rm -rf "$TEMP_DIR/META-INF" "$TEMP_DIR/customize.sh" 2>/dev/null

if [[ ! -f "$TEMP_DIR/vpnhide_kmod.ko" ]]; then
    log_error "Failed to extract vpnhide_kmod.ko from zip archive!"
    exit 1
fi

# 8. Push to device
DEVICE_TEMP_DIR="/data/local/tmp/vpnhide_kmod_staging"
DEVICE_TARGET_DIR="/data/adb/modules/vpnhide_kmod"

log_info "Pushing entire module to device staging path ($DEVICE_TEMP_DIR)..."
adb shell "rm -rf $DEVICE_TEMP_DIR && mkdir -p $DEVICE_TEMP_DIR"
adb push "$TEMP_DIR/." "$DEVICE_TEMP_DIR/"

log_info "Moving all module files to destination ($DEVICE_TARGET_DIR) using root permissions..."
# Ensure the module directory exists
adb shell "su -c 'mkdir -p $DEVICE_TARGET_DIR'"
# Copy over files
adb shell "su -c 'cp -rf $DEVICE_TEMP_DIR/* $DEVICE_TARGET_DIR/'"
# Remove staging folder
adb shell "rm -rf $DEVICE_TEMP_DIR"

log_info "Setting correct permissions and ownership..."
# General module ownership
adb shell "su -c 'chown -R root:root $DEVICE_TARGET_DIR'"
# 0644 for regular files and .ko
adb shell "su -c 'find $DEVICE_TARGET_DIR -type f -exec chmod 0644 {} \;'"
# 0755 for scripts and binaries
adb shell "su -c 'chmod 0755 $DEVICE_TARGET_DIR/*.sh $DEVICE_TARGET_DIR/sqlite3 $DEVICE_TARGET_DIR/vpnhide-ctl 2>/dev/null || true'"

log_success "Successfully deployed entire module to device at: ${BOLD}$DEVICE_TARGET_DIR${NC}"

# 9. Reboot the phone
log_info "Rebooting device to apply all module changes cleanly..."
if adb reboot; then
    log_success "Reboot command sent successfully! Device is restarting."
else
    log_error "Failed to send reboot command via adb. Please reboot manually."
fi
