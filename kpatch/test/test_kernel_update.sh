#!/bin/sh
set -eu

HERE=$(dirname "$0")
HERE=$(cd "$HERE" && pwd)
# HERE is resolved at runtime.
# shellcheck disable=SC1090,SC1091
. "$HERE/../module/kernel-update.sh"

ASSETS='https://github.com/soranerai/GKI_KernelSU_SUSFS/releases/download/v2.2.2/6.1.145-android14-2025-08-AnyKernel3.zip
https://github.com/soranerai/GKI_KernelSU_SUSFS/releases/download/v2.2.2/6.1.175-android14-lts-AnyKernel3.zip
https://github.com/soranerai/GKI_KernelSU_SUSFS/releases/download/v2.2.2/6.1.172-android14-2026-06-AnyKernel3.zip
https://github.com/soranerai/GKI_KernelSU_SUSFS/releases/download/v2.2.2/6.1.162-android14-2026-03-AnyKernel3.zip
https://github.com/soranerai/GKI_KernelSU_SUSFS/releases/download/v2.2.2/6.6.142-android15-lts-AnyKernel3.zip
https://github.com/soranerai/GKI_KernelSU_SUSFS/releases/download/v2.2.2/5.15.211-android13-lts-AnyKernel3.zip'

selected=$(vpnhide_select_kernel_asset '6.1.157-android14-11-gabcdef' "$ASSETS")
[ "${selected##*/}" = '6.1.162-android14-2026-03-AnyKernel3.zip' ]

set +e
vpnhide_select_kernel_asset '6.1.176-android14-Wild' "$ASSETS" >/dev/null
rc=$?
set -e
[ "$rc" -eq 2 ]

selected=$(vpnhide_select_kernel_asset '6.1.175-android14-Wild' "$ASSETS")
[ "${selected##*/}" = '6.1.175-android14-lts-AnyKernel3.zip' ]

set +e
vpnhide_select_kernel_asset '6.1.157-android13-custom' "$ASSETS" >/dev/null
rc=$?
set -e
[ "$rc" -eq 1 ]

info=$(vpnhide_detect_running_kernel '5.15.194-android13-8-gabcdef')
[ "$info" = '5.15.194 android13' ]

[ "$(vpnhide_version_code_to_tag 20202)" = 'v2.2.2' ]
[ "$(vpnhide_tag_to_version_code v2.2.2)" = '20202' ]

TAGS='v2.2.0
v2.3.0
v2.2.2'
[ "$(vpnhide_find_newer_release_tag 20202 "$TAGS")" = 'v2.3.0' ]
set +e
vpnhide_find_newer_release_tag 20300 "$TAGS" >/dev/null
rc=$?
set -e
[ "$rc" -eq 1 ]

RELEASE_ASSETS='https://github.com/soranerai/GKI_KernelSU_SUSFS/releases/download/v2.2.0/6.1.157-android14-AnyKernel3.zip
https://github.com/soranerai/GKI_KernelSU_SUSFS/releases/download/v2.2.2/6.1.157-android14-AnyKernel3.zip
https://github.com/soranerai/GKI_KernelSU_SUSFS/releases/download/v2.3.0/6.1.157-android14-AnyKernel3.zip'
filtered=$(vpnhide_filter_release_assets 20202 "$RELEASE_ASSETS")
[ "$filtered" = 'https://github.com/soranerai/GKI_KernelSU_SUSFS/releases/download/v2.3.0/6.1.157-android14-AnyKernel3.zip' ]

echo 'Bridge kernel update selection: PASS'
