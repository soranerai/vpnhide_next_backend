#!/usr/bin/env bash
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"
OUT="/tmp/vpnhide-policy-test-$$"
trap 'rm -f "$OUT"' EXIT

PM_COMMAND="printf 'package:/system/priv-app/Settings/Settings.apk=com.android.settings uid:1000\\npackage:/data/app/keep/base.apk=com.example.keep uid:10001\\npackage:/data/app/hide/base.apk=com.example.hide uid:10002\\n'"

${CC:-cc} -std=c11 -O2 -Wall -Wextra -Werror \
  -I"$REPO" -DVPNHIDE_PM_COMMAND="\"$PM_COMMAND\"" \
  "$REPO/vpnhide_ctl.c" "$REPO/vpnhide_policy.c" "$REPO/parson.c" \
  -o "$OUT"

OUTPUT="$($OUT validate "$HERE/policy_allowlist.json" 10003)"
grep -q '^mode=ALLOWLIST$' <<<"$OUTPUT"
grep -q '^kmod_targets=1$' <<<"$OUTPUT"
grep -q '^lsposed_targets=1$' <<<"$OUTPUT"
grep -q '^ignored_selected_system_packages=0$' <<<"$OUTPUT"

OUTPUT="$($OUT validate "$HERE/policy_blacklist.json" 10003)"
grep -q '^mode=BLACKLIST$' <<<"$OUTPUT"
grep -q '^kmod_targets=2$' <<<"$OUTPUT"
grep -q '^lsposed_targets=1$' <<<"$OUTPUT"

echo "policy allowlist: PASS"
