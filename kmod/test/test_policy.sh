#!/usr/bin/env bash
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"
OUT="/tmp/vpnhide-policy-test-$$"
ABI_OUT="${OUT}.abi"
trap 'rm -f "$OUT" "$ABI_OUT"' EXIT

PM_COMMAND="printf 'package:/system/priv-app/Settings/Settings.apk=com.android.settings uid:1000\\npackage:/data/app/manager/base.apk=dev.soranerai.vpnhidenext uid:10003\\npackage:/data/app/~~abc==/com.example.keep-def==/base.apk=com.example.keep uid:10001,110001\\npackage:/data/app/hide/base.apk=com.example.hide uid:10002\\npackage:/data/app/target/base.apk=com.example.target uid:10002\\n'"

${CC:-cc} -std=c11 -O2 -Wall -Wextra -Werror \
  -I"$REPO" -DVPNHIDE_PM_COMMAND="\"$PM_COMMAND\"" \
  "$REPO/vpnhide_ctl.c" "$REPO/vpnhide_policy.c" "$REPO/parson.c" \
  -o "$OUT"

${CC:-cc} -std=c11 -O2 -Wall -Wextra -Werror \
  -I"$REPO" "$HERE/test_policy_abi.c" -o "$ABI_OUT"
"$ABI_OUT" >/dev/null

OUTPUT="$($OUT validate "$HERE/policy_allowlist.json" 10003)"
grep -q '^mode=ALLOWLIST$' <<<"$OUTPUT"
grep -q '^kmod_targets=3$' <<<"$OUTPUT"
grep -q '^lsposed_targets=3$' <<<"$OUTPUT"
grep -q '^port_targets=4$' <<<"$OUTPUT"
grep -q '^ignored_selected_system_packages=0$' <<<"$OUTPUT"

# ALLOWLIST without any active port rules: the selected exception is explicit
# unrestricted, while unselected eligible UIDs are explicit deny-all.
OUTPUT="$($OUT preview "$HERE/policy_allowlist.json" 10003)"
grep -q '^mode=ALLOWLIST$' <<<"$OUTPUT"
grep -q '^port_targets=4$' <<<"$OUTPUT"
grep -q '^port_target\[0\]\.mode=2$' <<<"$OUTPUT"
grep -q '^port_target\[1\]\.uid=10001$' <<<"$OUTPUT"
grep -q '^port_target\[1\]\.mode=1$' <<<"$OUTPUT"

OUTPUT="$($OUT preview "$HERE/policy_allowlist_explicit.json" 10003)"
grep -q '^mode=ALLOWLIST$' <<<"$OUTPUT"
grep -q '^port_targets=4$' <<<"$OUTPUT"
grep -q '^port_target\[0\]\.uid=10003$' <<<"$OUTPUT"
grep -q '^port_target\[0\]\.mode=2$' <<<"$OUTPUT"
grep -q '^port_target\[0\]\.rule\[0\]=0-65535/2$' <<<"$OUTPUT"
grep -q '^port_target\[1\]\.uid=10001$' <<<"$OUTPUT"
grep -q '^port_target\[1\]\.mode=0$' <<<"$OUTPUT"
grep -q '^port_target\[1\]\.rule\[0\]=0-19999/2$' <<<"$OUTPUT"
grep -q '^port_target\[2\]\.uid=110001$' <<<"$OUTPUT"
grep -q '^port_target\[2\]\.mode=2$' <<<"$OUTPUT"
grep -q '^port_target\[2\]\.rule\[0\]=0-65535/2$' <<<"$OUTPUT"
grep -q '^port_target\[3\]\.uid=10002$' <<<"$OUTPUT"
grep -q '^port_target\[3\]\.mode=2$' <<<"$OUTPUT"
grep -q '^port_target\[3\]\.rule\[0\]=0-65535/2$' <<<"$OUTPUT"

OUTPUT="$($OUT validate "$HERE/policy_blacklist.json" 10003)"
grep -q '^mode=BLACKLIST$' <<<"$OUTPUT"
grep -q '^kmod_targets=2$' <<<"$OUTPUT"
grep -q '^lsposed_targets=1$' <<<"$OUTPUT"

OUTPUT="$($OUT preview "$HERE/policy_blacklist_explicit.json" 10003)"
grep -q '^mode=BLACKLIST$' <<<"$OUTPUT"
grep -q '^port_targets=1$' <<<"$OUTPUT"
grep -q '^port_target\[0\]\.uid=10002$' <<<"$OUTPUT"
grep -q '^port_target\[0\]\.rule\[0\]=8081-8081/2$' <<<"$OUTPUT"

# BLACKLIST: selected hooks are targets; selected port app receives both its
# local deny rule and the global mass deny rule.
OUTPUT="$($OUT preview "$HERE/policy_blacklist_mass_local.json" 10003)"
grep -q '^mode=BLACKLIST$' <<<"$OUTPUT"
grep -q '^kmod_targets=2$' <<<"$OUTPUT"
grep -q '^lsposed_targets=2$' <<<"$OUTPUT"
grep -q '^port_targets=1$' <<<"$OUTPUT"
grep -q '^port_target\[0\]\.uid=10002$' <<<"$OUTPUT"
grep -q '^port_target\[0\]\.rule\[0\]=8080-8080/0$' <<<"$OUTPUT"
grep -q '^port_target\[0\]\.rule\[1\]=20000-65535/2$' <<<"$OUTPUT"

# ALLOWLIST: the selected app sees local + mass allowed ranges, while every
# unselected eligible UID is denied all ports and is not given the mass rule.
OUTPUT="$($OUT preview "$HERE/policy_allowlist_local_mass.json" 10003)"
grep -q '^mode=ALLOWLIST$' <<<"$OUTPUT"
grep -q '^kmod_targets=3$' <<<"$OUTPUT"
grep -q '^lsposed_targets=3$' <<<"$OUTPUT"
grep -q '^port_targets=4$' <<<"$OUTPUT"
grep -q '^port_target\[0\]\.uid=10003$' <<<"$OUTPUT"
grep -q '^port_target\[0\]\.mode=2$' <<<"$OUTPUT"
grep -q '^port_target\[0\]\.rule\[0\]=0-65535/2$' <<<"$OUTPUT"
grep -q '^port_target\[1\]\.uid=10001$' <<<"$OUTPUT"
grep -q '^port_target\[1\]\.rule\[0\]=0-8079/2$' <<<"$OUTPUT"
grep -q '^port_target\[1\]\.rule\[1\]=8080-8080/1$' <<<"$OUTPUT"
grep -q '^port_target\[1\]\.rule\[2\]=8081-19999/2$' <<<"$OUTPUT"
grep -q '^port_target\[2\]\.uid=110001$' <<<"$OUTPUT"
grep -q '^port_target\[2\]\.mode=2$' <<<"$OUTPUT"
grep -q '^port_target\[2\]\.rule\[0\]=0-65535/2$' <<<"$OUTPUT"
grep -q '^port_target\[3\]\.uid=10002$' <<<"$OUTPUT"
grep -q '^port_target\[3\]\.mode=2$' <<<"$OUTPUT"
grep -q '^port_target\[3\]\.rule\[0\]=0-65535/2$' <<<"$OUTPUT"

echo "policy list modes: PASS"
