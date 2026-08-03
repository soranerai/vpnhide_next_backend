#!/system/bin/sh

# Print the GKI variant encoded in a kernel release (uname -r), for example
# "6.1.75-android14-11-g..." -> "android14-6.1".  Android's OS version is
# deliberately not used: the KMI generation and the userspace release are not
# guaranteed to be the same.
vpnhide_detect_gki() {
    vpnhide_uname_r="$1"
    vpnhide_kernel_version=$(printf '%s\n' "$vpnhide_uname_r" | sed -n 's/^\([0-9][0-9]*\.[0-9][0-9]*\).*/\1/p')
    vpnhide_android_generation=$(printf '%s\n' "$vpnhide_uname_r" | sed -n 's/^[^-]*-\(android[0-9][0-9]*\)\(-.*\)*$/\1/p')

    if [ -z "$vpnhide_kernel_version" ] || [ -z "$vpnhide_android_generation" ]; then
        return 1
    fi

    printf '%s-%s\n' "$vpnhide_android_generation" "$vpnhide_kernel_version"
}

# Return success only when the package KMI exactly matches the running kernel.
vpnhide_kmi_matches() {
    vpnhide_expected_gki="$1"
    vpnhide_running_release="$2"
    vpnhide_actual_gki=$(vpnhide_detect_gki "$vpnhide_running_release") || return 1
    [ "$vpnhide_expected_gki" = "$vpnhide_actual_gki" ]
}
