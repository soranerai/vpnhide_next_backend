#!/system/bin/sh
# Runs early in boot. Logs the status of the built-in vpnhide driver.

MODDIR="${0%/*}"
MODULE_PROP="$MODDIR/module.prop"
STATUS_DIR="/data/adb/vpnhide_kmod"
STATUS_FILE="$STATUS_DIR/load_status"

mkdir -p "$STATUS_DIR"

NOW=$(date +%s 2>/dev/null)
BOOT_ID=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null)
UNAME_R=$(uname -r 2>/dev/null)
VERSION=$(grep '^version=' "$MODULE_PROP" 2>/dev/null | cut -d= -f2-)

if [ -c "/dev/vpnhide_ctrl" ]; then
    LOADED=1
    MSG="VPNHide Next built-in driver detected and active."
else
    LOADED=0
    MSG="VPNHide Next built-in driver (/dev/vpnhide_ctrl) not found!"
fi

{
    printf 'timestamp=%s\n' "$NOW"
    printf 'boot_id=%s\n' "$BOOT_ID"
    printf 'uname_r=%s\n' "$UNAME_R"
    printf 'loaded=%s\n' "$LOADED"
    printf 'runtime_version=%s\n' "$VERSION"
    printf 'provider=built-in\n'
    printf 'version_code=%s\n' "$(grep '^versionCode=' "$MODULE_PROP" 2>/dev/null | cut -d= -f2-)"
    printf 'msg=%s\n' "$MSG"
} > "$STATUS_FILE.tmp" && mv "$STATUS_FILE.tmp" "$STATUS_FILE"
chmod 0644 "$STATUS_FILE" 2>/dev/null

log -t vpnhide "$MSG"
