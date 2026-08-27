#!/system/bin/sh
# Runs early in boot. Logs the status of the built-in vpnhide driver.

MODDIR="${0%/*}"
MODULE_PROP="$MODDIR/module.prop"
STATUS_DIR="/data/adb/vpnhide_kmod"
STATUS_FILE="$STATUS_DIR/load_status"
CTL="$MODDIR/vpnhide-ctl"
DEV_NODE="/dev/vpnhide_ctrl"

mkdir -p "$STATUS_DIR"

NOW=$(date +%s 2>/dev/null)
BOOT_ID=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null)
UNAME_R=$(uname -r 2>/dev/null)
RUNTIME_VERSION=""
RUNTIME_VERSION_CODE=""

version_code_to_tag() {
    case "$1" in
        ''|*[!0-9]*) return 1 ;;
    esac
    printf 'v%d.%d.%d\n' "$(( $1 / 10000 ))" "$(( ($1 / 100) % 100 ))" "$(( $1 % 100 ))"
}

write_module_status() {
    status="$1"
    tmp="$MODULE_PROP.tmp"

    awk -v status="$status" '
        BEGIN { replaced = 0 }
        /^description=/ {
            if (!replaced) {
                print "description=" status
                replaced = 1
            }
            next
        }
        { print }
        END {
            if (!replaced)
                print "description=" status
        }
    ' "$MODULE_PROP" > "$tmp" && mv "$tmp" "$MODULE_PROP"
    chmod 0644 "$MODULE_PROP" 2>/dev/null
}

if [ ! -c "$DEV_NODE" ]; then
    LOADED=0
    MSG="status: error (device missing) 😵"
elif [ ! -x "$CTL" ] || ! "$CTL" hook_status >/dev/null 2>&1; then
    LOADED=0
    MSG="status: error (connection failed) 😵"
else
    LOADED=1
    MSG="status: ok 😋"
    RUNTIME_VERSION_CODE=$("$CTL" version kmod 2>/dev/null)
    RUNTIME_VERSION=$(version_code_to_tag "$RUNTIME_VERSION_CODE") || {
        LOADED=0
        RUNTIME_VERSION_CODE=""
        MSG="status: error (driver version unavailable) 😵"
    }
fi

write_module_status "$MSG"

{
    printf 'timestamp=%s\n' "$NOW"
    printf 'boot_id=%s\n' "$BOOT_ID"
    printf 'uname_r=%s\n' "$UNAME_R"
    printf 'loaded=%s\n' "$LOADED"
    printf 'runtime_version=%s\n' "$RUNTIME_VERSION"
    printf 'provider=built-in\n'
    printf 'version_code=%s\n' "$RUNTIME_VERSION_CODE"
    printf 'msg=%s\n' "$MSG"
} > "$STATUS_FILE.tmp" && mv "$STATUS_FILE.tmp" "$STATUS_FILE"
chmod 0644 "$STATUS_FILE" 2>/dev/null

log -t vpnhide "$MSG"
