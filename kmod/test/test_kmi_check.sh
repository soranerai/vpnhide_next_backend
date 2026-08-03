#!/bin/sh
set -eu

HERE=$(dirname "$0")
HERE=$(cd "$HERE" && pwd)
# HERE is resolved at runtime.
# shellcheck disable=SC1090,SC1091
. "$HERE/../module/kmi-check.sh"

assert_detected() {
    expected="$1"
    release="$2"
    actual=$(vpnhide_detect_gki "$release")
    [ "$actual" = "$expected" ] || {
        echo "FAIL: $release: expected $expected, got $actual" >&2
        exit 1
    }
}

assert_detected android12-5.10 '5.10.198-android12-9-g123456789'
assert_detected android13-5.10 '5.10.218-android13-12-gabcdef'
assert_detected android13-5.15 '5.15.148-android13-8-gabcdef'
assert_detected android14-5.15 '5.15.153-android14-11-gabcdef'
assert_detected android14-6.1 '6.1.75-android14-11-gabcdef'
assert_detected android15-6.6 '6.6.30-android15-Wild'
assert_detected android16-6.12 '6.12.23-android16-4-gabcdef'

vpnhide_kmi_matches android14-6.1 '6.1.75-android14-11-gabcdef'
if vpnhide_kmi_matches android13-5.15 '5.15.153-android14-11-gabcdef'; then
    echo 'FAIL: android13 package accepted on android14 kernel' >&2
    exit 1
fi
if vpnhide_kmi_matches android14-5.15 '5.15.148-android13-8-gabcdef'; then
    echo 'FAIL: android14 package accepted on android13 kernel' >&2
    exit 1
fi
if vpnhide_detect_gki '6.1.75-custom-kernel' >/dev/null; then
    echo 'FAIL: unidentifiable custom kernel was accepted' >&2
    exit 1
fi

echo 'KMI compatibility checks: PASS'
