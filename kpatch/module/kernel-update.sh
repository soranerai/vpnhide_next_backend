#!/system/bin/sh

VPNHIDE_KERNEL_RELEASES_API="https://api.github.com/repos/soranerai/GKI_KernelSU_SUSFS/releases?per_page=100"
VPNHIDE_KERNEL_REPO_URL="https://github.com/soranerai/GKI_KernelSU_SUSFS/releases"

vpnhide_detect_running_kernel() {
    vpnhide_release="$1"
    vpnhide_triplet=$(printf '%s\n' "$vpnhide_release" | sed -n 's/^\([0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\).*/\1/p')
    vpnhide_generation=$(printf '%s\n' "$vpnhide_release" | sed -n 's/.*\(android[0-9][0-9]*\).*/\1/p')

    [ -n "$vpnhide_triplet" ] && [ -n "$vpnhide_generation" ] || return 1
    printf '%s %s\n' "$vpnhide_triplet" "$vpnhide_generation"
}

# Select the nearest patchlevel equal to or newer than the running kernel. This
# allows reinstalling the same build, minimizes the jump from the device's
# vendor-tested kernel, and still prevents a downgrade. Input is a newline-
# separated list of browser_download_url values. Returns 0 with the URL, 2
# when compatible assets exist but all of them are older,
# and 1 when no compatible asset can be identified.
vpnhide_select_kernel_asset() {
    vpnhide_running_release="$1"
    vpnhide_asset_urls="$2"
    vpnhide_running_info=$(vpnhide_detect_running_kernel "$vpnhide_running_release") || return 1
    vpnhide_current_triplet=${vpnhide_running_info%% *}
    vpnhide_current_generation=${vpnhide_running_info#* }
    vpnhide_major_minor=${vpnhide_current_triplet%.*}
    vpnhide_current_patch=${vpnhide_current_triplet##*.}
    vpnhide_best_patch=-1
    vpnhide_best_url=""
    vpnhide_compatible=0

    while IFS= read -r vpnhide_url; do
        [ -n "$vpnhide_url" ] || continue
        vpnhide_name=${vpnhide_url##*/}
        case "$vpnhide_name" in
            "$vpnhide_major_minor."*-"$vpnhide_current_generation"-*-AnyKernel3.zip)
                vpnhide_candidate_triplet=${vpnhide_name%%-*}
                vpnhide_candidate_prefix=${vpnhide_candidate_triplet%.*}
                vpnhide_candidate_patch=${vpnhide_candidate_triplet##*.}
                [ "$vpnhide_candidate_prefix" = "$vpnhide_major_minor" ] || continue
                case "$vpnhide_candidate_patch" in
                    ''|*[!0-9]*) continue ;;
                esac
                vpnhide_compatible=1
                if [ "$vpnhide_candidate_patch" -ge "$vpnhide_current_patch" ]; then
                    if [ "$vpnhide_best_patch" -lt 0 ] || \
                       [ "$vpnhide_candidate_patch" -lt "$vpnhide_best_patch" ]; then
                        vpnhide_best_patch=$vpnhide_candidate_patch
                        vpnhide_best_url=$vpnhide_url
                    fi
                fi
                ;;
        esac
    done <<EOF
$vpnhide_asset_urls
EOF

    if [ -n "$vpnhide_best_url" ]; then
        printf '%s\n' "$vpnhide_best_url"
        return 0
    fi
    [ "$vpnhide_compatible" -eq 1 ] && return 2
    return 1
}

vpnhide_download() {
    vpnhide_download_url="$1"
    vpnhide_download_dest="$2"
    vpnhide_download_tmp="$vpnhide_download_dest.part"
    rm -f "$vpnhide_download_tmp"

    if command -v curl >/dev/null 2>&1; then
        curl -fL --connect-timeout 20 --retry 2 \
            -A "VPNHide-Bridge-Kernel-Updater" \
            "$vpnhide_download_url" -o "$vpnhide_download_tmp" || return 1
    elif command -v wget >/dev/null 2>&1; then
        wget -T 20 -t 3 -U "VPNHide-Bridge-Kernel-Updater" \
            -O "$vpnhide_download_tmp" "$vpnhide_download_url" || return 1
    elif command -v busybox >/dev/null 2>&1; then
        busybox wget -T 20 -t 3 -U "VPNHide-Bridge-Kernel-Updater" \
            -O "$vpnhide_download_tmp" "$vpnhide_download_url" || return 1
    else
        return 1
    fi

    [ -s "$vpnhide_download_tmp" ] || return 1
    mv -f "$vpnhide_download_tmp" "$vpnhide_download_dest"
}

vpnhide_extract_release_urls() {
    # GitHub emits one browser_download_url per asset. Splitting commas also
    # handles compact JSON without requiring jq on the Android device.
    tr ',' '\n' < "$1" | sed -n 's/.*"browser_download_url"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p'
}

vpnhide_extract_release_tags() {
    tr ',' '\n' < "$1" | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p'
}

vpnhide_tag_to_version_code() {
    vpnhide_tag=${1#v}
    vpnhide_tag_major=${vpnhide_tag%%.*}
    vpnhide_tag_rest=${vpnhide_tag#*.}
    [ "$vpnhide_tag_rest" != "$vpnhide_tag" ] || return 1
    vpnhide_tag_minor=${vpnhide_tag_rest%%.*}
    vpnhide_tag_patch=${vpnhide_tag_rest#*.}
    [ "$vpnhide_tag_patch" != "$vpnhide_tag_rest" ] || return 1
    case "$vpnhide_tag_major" in ''|*[!0-9]*) return 1 ;; esac
    case "$vpnhide_tag_minor" in ''|*[!0-9]*) return 1 ;; esac
    case "$vpnhide_tag_patch" in ''|*[!0-9]*) return 1 ;; esac
    [ "$vpnhide_tag_minor" -le 99 ] && [ "$vpnhide_tag_patch" -le 99 ] || return 1
    printf '%s\n' "$((vpnhide_tag_major * 10000 + vpnhide_tag_minor * 100 + vpnhide_tag_patch))"
}

vpnhide_version_code_to_tag() {
    vpnhide_code="$1"
    case "$vpnhide_code" in
        ''|*[!0-9]*) return 1 ;;
    esac
    vpnhide_code_major=$((vpnhide_code / 10000))
    vpnhide_code_minor=$(((vpnhide_code / 100) % 100))
    vpnhide_code_patch=$((vpnhide_code % 100))
    printf 'v%s.%s.%s\n' "$vpnhide_code_major" "$vpnhide_code_minor" "$vpnhide_code_patch"
}

vpnhide_read_driver_version_code() {
    [ -r /dev/vpnhide_ctrl ] || return 1
    # A second read may block until the policy generation changes, so never
    # use an unbounded `cat` here. One read contains version_code at the top.
    vpnhide_ctrl_snapshot=$(dd if=/dev/vpnhide_ctrl bs=4096 count=1 2>/dev/null) || return 1
    vpnhide_driver_code=$(printf '%s\n' "$vpnhide_ctrl_snapshot" | sed -n 's/^version_code:[[:space:]]*\([0-9][0-9]*\)[[:space:]]*$/\1/p' | head -n 1)
    [ -n "$vpnhide_driver_code" ] || return 1
    printf '%s\n' "$vpnhide_driver_code"
}

# Print the highest stable semver tag whose encoded versionCode is newer.
vpnhide_find_newer_release_tag() {
    vpnhide_installed_code="$1"
    vpnhide_release_tags="$2"
    vpnhide_newest_code=-1
    vpnhide_newest_tag=""
    while IFS= read -r vpnhide_release_tag; do
        [ -n "$vpnhide_release_tag" ] || continue
        vpnhide_release_code=$(vpnhide_tag_to_version_code "$vpnhide_release_tag") || continue
        if [ "$vpnhide_release_code" -gt "$vpnhide_installed_code" ] && \
           [ "$vpnhide_release_code" -gt "$vpnhide_newest_code" ]; then
            vpnhide_newest_code=$vpnhide_release_code
            vpnhide_newest_tag=$vpnhide_release_tag
        fi
    done <<EOF
$vpnhide_release_tags
EOF
    [ -n "$vpnhide_newest_tag" ] || return 1
    printf '%s\n' "$vpnhide_newest_tag"
}

# Keep only assets belonging to releases newer than installed_code. Passing -1
# is used when the control device is unavailable and keeps every valid release.
vpnhide_filter_release_assets() {
    vpnhide_installed_code="$1"
    vpnhide_all_urls="$2"
    while IFS= read -r vpnhide_release_url; do
        case "$vpnhide_release_url" in
            https://github.com/soranerai/GKI_KernelSU_SUSFS/releases/download/*/*)
                vpnhide_url_tail=${vpnhide_release_url#*/releases/download/}
                vpnhide_url_tag=${vpnhide_url_tail%%/*}
                vpnhide_url_code=$(vpnhide_tag_to_version_code "$vpnhide_url_tag") || continue
                [ "$vpnhide_url_code" -gt "$vpnhide_installed_code" ] && printf '%s\n' "$vpnhide_release_url"
                ;;
        esac
    done <<EOF
$vpnhide_all_urls
EOF
}

vpnhide_find_boot_block() {
    vpnhide_slot=$(getprop ro.boot.slot_suffix 2>/dev/null)
    if [ -z "$vpnhide_slot" ]; then
        vpnhide_slot=$(getprop ro.boot.slot 2>/dev/null)
        [ -n "$vpnhide_slot" ] && vpnhide_slot="_$vpnhide_slot"
    fi
    [ "$vpnhide_slot" = "normal" ] && vpnhide_slot=""
    case "$vpnhide_slot" in
        _a|_b|'') ;;
        a|b) vpnhide_slot="_$vpnhide_slot" ;;
        *) return 1 ;;
    esac

    for vpnhide_block in \
        "/dev/block/by-name/boot$vpnhide_slot" \
        "/dev/block/bootdevice/by-name/boot$vpnhide_slot"; do
        if [ -e "$vpnhide_block" ]; then
            printf '%s\n' "$vpnhide_block"
            return 0
        fi
    done

    vpnhide_block=$(find /dev/block/platform -path "*/by-name/boot$vpnhide_slot" 2>/dev/null | head -n 1)
    [ -n "$vpnhide_block" ] || return 1
    printf '%s\n' "$vpnhide_block"
}

vpnhide_backup_boot() {
    vpnhide_backup_release="$1"
    vpnhide_boot_block=$(vpnhide_find_boot_block) || return 1
    vpnhide_storage=""
    for vpnhide_dir in /sdcard /storage/emulated/0 /data/media/0; do
        if [ -d "$vpnhide_dir" ] && [ -w "$vpnhide_dir" ]; then
            vpnhide_storage="$vpnhide_dir"
            break
        fi
    done
    [ -n "$vpnhide_storage" ] || return 1

    vpnhide_safe_release=$(printf '%s' "$vpnhide_backup_release" | tr -c 'A-Za-z0-9._-' '_')
    vpnhide_backup_path="$vpnhide_storage/vpnhide-boot-backup-$vpnhide_safe_release-$(date +%Y%m%d-%H%M%S).img"
    ui_print "- Backing up $vpnhide_boot_block"
    if ! dd if="$vpnhide_boot_block" of="$vpnhide_backup_path" bs=1048576 2>/dev/null; then
        rm -f "$vpnhide_backup_path"
        return 1
    fi
    sync
    [ -s "$vpnhide_backup_path" ] || return 1
    chmod 0644 "$vpnhide_backup_path" 2>/dev/null || true
    case "$vpnhide_storage" in
        /data/media/0) chown 1023:1023 "$vpnhide_backup_path" 2>/dev/null || true ;;
    esac
    restorecon "$vpnhide_backup_path" 2>/dev/null || true
    VPNHIDE_BOOT_BACKUP="$vpnhide_backup_path"
    export VPNHIDE_BOOT_BACKUP
    ui_print "- Boot backup: $VPNHIDE_BOOT_BACKUP"
}

vpnhide_read_volume_choice() {
    vpnhide_getevent=""
    for vpnhide_tool in /system/bin/getevent /vendor/bin/getevent /sbin/getevent; do
        if [ -x "$vpnhide_tool" ]; then
            vpnhide_getevent="$vpnhide_tool"
            break
        fi
    done
    if [ -z "$vpnhide_getevent" ] && command -v getevent >/dev/null 2>&1; then
        vpnhide_getevent=$(command -v getevent)
    fi
    [ -n "$vpnhide_getevent" ] && command -v timeout >/dev/null 2>&1 || return 1

    timeout 30 "$vpnhide_getevent" -ql 2>/dev/null | awk '
        /KEY_VOLUMEUP/ && ($NF == "DOWN" || $NF == "00000001") { print "up"; exit }
        /KEY_VOLUMEDOWN/ && ($NF == "DOWN" || $NF == "00000001") { print "down"; exit }
    '
}

vpnhide_flash_ak3() {
    vpnhide_ak3_zip="$1"
    vpnhide_ak3_work="$2"
    vpnhide_ak3_installer="$vpnhide_ak3_work/META-INF/com/google/android/update-binary"
    vpnhide_ak3_pipe="$vpnhide_ak3_work/ak3-output.pipe"
    mkdir -p "$vpnhide_ak3_work"
    unzip -oq "$vpnhide_ak3_zip" 'META-INF/com/google/android/update-binary' -d "$vpnhide_ak3_work" || return 1
    [ -s "$vpnhide_ak3_installer" ] || return 1
    chmod 0755 "$vpnhide_ak3_installer"

    # AK3 writes updater-protocol records ("ui_print ..." + a terminator) to
    # OUTFD. Normalize them through a FIFO while AK3 is running so interactive
    # questions are visible before it starts waiting for a volume key.
    rm -f "$vpnhide_ak3_pipe"
    mkfifo "$vpnhide_ak3_pipe" || return 1
    # Keep ui_print in the main installer shell. Some root managers buffer UI
    # writes made by a background subshell until that subshell exits.
    AKHOME="$vpnhide_ak3_work/ak3" sh "$vpnhide_ak3_installer" 3 1 "$vpnhide_ak3_zip" > "$vpnhide_ak3_pipe" 2>&1 &
    vpnhide_ak3_pid=$!

    while IFS= read -r vpnhide_ak3_line || [ -n "$vpnhide_ak3_line" ]; do
        vpnhide_ak3_line=$(printf '%s\n' "$vpnhide_ak3_line" | sed 's/^[[:space:]]*//')
        case "$vpnhide_ak3_line" in
            ui_print) continue ;;
            ui_print\ *) vpnhide_ak3_line=${vpnhide_ak3_line#ui_print } ;;
        esac
        [ -n "$vpnhide_ak3_line" ] && ui_print "  [AK3] $vpnhide_ak3_line"
    done < "$vpnhide_ak3_pipe"

    vpnhide_ak3_rc=0
    wait "$vpnhide_ak3_pid" || vpnhide_ak3_rc=$?
    rm -f "$vpnhide_ak3_pipe"

    return "$vpnhide_ak3_rc"
}

vpnhide_offer_kernel_update() {
    ui_print " "
    ui_print "- Automatically check and update the kernel?"
    ui_print "  Vol+ = yes, Vol- = no (30 seconds)"
    vpnhide_choice=$(vpnhide_read_volume_choice) || vpnhide_choice=""
    if [ "$vpnhide_choice" != "up" ]; then
        [ -z "$vpnhide_choice" ] && ui_print "- No volume-key answer; skipping kernel update"
        [ "$vpnhide_choice" = "down" ] && ui_print "- Kernel update skipped"
        return 0
    fi

    vpnhide_running_release=$(uname -r 2>/dev/null | tr -d '\r\n')
    vpnhide_running_info=$(vpnhide_detect_running_kernel "$vpnhide_running_release") || {
        ui_print "! Could not identify the running GKI kernel: ${vpnhide_running_release:-unknown}"
        ui_print "! Find a compatible kernel manually: $VPNHIDE_KERNEL_REPO_URL"
        return 1
    }
    ui_print "- Running kernel: $vpnhide_running_release"

    vpnhide_work_root="/data/local/tmp/vpnhide-kernel-update-$$"
    mkdir -p "$vpnhide_work_root" || return 1
    vpnhide_release_json="$vpnhide_work_root/releases.json"
    vpnhide_asset_zip="$vpnhide_work_root/kernel-AnyKernel3.zip"

    ui_print "- Checking GitHub releases..."
    if ! vpnhide_download "$VPNHIDE_KERNEL_RELEASES_API" "$vpnhide_release_json"; then
        ui_print "! Could not query kernel releases"
        ui_print "! Find a compatible kernel manually: $VPNHIDE_KERNEL_REPO_URL"
        rm -rf "$vpnhide_work_root"
        return 1
    fi
    vpnhide_asset_urls=$(vpnhide_extract_release_urls "$vpnhide_release_json")
    vpnhide_release_tags=$(vpnhide_extract_release_tags "$vpnhide_release_json")
    if [ -z "$vpnhide_asset_urls" ] || [ -z "$vpnhide_release_tags" ]; then
        ui_print "! GitHub release metadata is incomplete"
        ui_print "! Find a compatible kernel manually: $VPNHIDE_KERNEL_REPO_URL"
        rm -rf "$vpnhide_work_root"
        return 1
    fi

    vpnhide_installed_code=$(vpnhide_read_driver_version_code) || vpnhide_installed_code=""
    if [ -n "$vpnhide_installed_code" ]; then
        vpnhide_installed_tag=$(vpnhide_version_code_to_tag "$vpnhide_installed_code") || vpnhide_installed_tag="unknown"
        ui_print "- Installed VPNHide kernel driver: $vpnhide_installed_tag ($vpnhide_installed_code)"
        vpnhide_new_release=$(vpnhide_find_newer_release_tag "$vpnhide_installed_code" "$vpnhide_release_tags") || vpnhide_new_release=""
        if [ -z "$vpnhide_new_release" ]; then
            ui_print "- No release newer than $vpnhide_installed_tag; update is not required"
            rm -rf "$vpnhide_work_root"
            return 0
        fi
        ui_print "- New VPNHide release found: $vpnhide_new_release"
        vpnhide_asset_urls=$(vpnhide_filter_release_assets "$vpnhide_installed_code" "$vpnhide_asset_urls")
    else
        ui_print "- VPNHide driver version is unavailable; kernel update will continue"
        # -1 admits assets from every valid release tag.
        vpnhide_asset_urls=$(vpnhide_filter_release_assets -1 "$vpnhide_asset_urls")
    fi

    vpnhide_select_rc=0
    vpnhide_selected_url=$(vpnhide_select_kernel_asset "$vpnhide_running_release" "$vpnhide_asset_urls") || vpnhide_select_rc=$?
    if [ "$vpnhide_select_rc" -eq 2 ]; then
        ui_print "! A VPNHide update is needed, but release kernels are older than the running kernel"
        ui_print "! Find a suitable kernel manually: $VPNHIDE_KERNEL_REPO_URL"
        rm -rf "$vpnhide_work_root"
        return 1
    elif [ "$vpnhide_select_rc" -ne 0 ] || [ -z "$vpnhide_selected_url" ]; then
        ui_print "! Could not find a suitable kernel for $vpnhide_running_info"
        ui_print "! Find it manually: $VPNHIDE_KERNEL_REPO_URL"
        rm -rf "$vpnhide_work_root"
        return 1
    fi

    vpnhide_selected_name=${vpnhide_selected_url##*/}
    case "$vpnhide_selected_url" in
        https://github.com/soranerai/GKI_KernelSU_SUSFS/releases/download/*) ;;
        *)
            ui_print "! GitHub returned an unexpected download URL; refusing to flash"
            rm -rf "$vpnhide_work_root"
            return 1
            ;;
    esac
    ui_print "- Selected kernel: $vpnhide_selected_name"
    ui_print "- Downloading AnyKernel3 archive..."
    if ! vpnhide_download "$vpnhide_selected_url" "$vpnhide_asset_zip" || \
       ! unzip -tq "$vpnhide_asset_zip" >/dev/null 2>&1; then
        ui_print "! Kernel download is incomplete or invalid"
        ui_print "! Download it manually: $vpnhide_selected_url"
        rm -rf "$vpnhide_work_root"
        return 1
    fi

    if ! vpnhide_backup_boot "$vpnhide_running_release"; then
        ui_print "! Could not back up the active boot partition; refusing to flash"
        rm -rf "$vpnhide_work_root"
        return 1
    fi

    ui_print "- Starting AnyKernel3..."
    if ! vpnhide_flash_ak3 "$vpnhide_asset_zip" "$vpnhide_work_root/installer"; then
        ui_print "! AnyKernel3 failed; boot backup: $VPNHIDE_BOOT_BACKUP"
        rm -rf "$vpnhide_work_root"
        return 1
    fi
    ui_print "- Kernel update completed; reboot is required"
    rm -rf "$vpnhide_work_root"
    return 0
}
