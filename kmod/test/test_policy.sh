#!/usr/bin/env bash
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"
OUT="/tmp/vpnhide-policy-test-$$"
ABI_OUT="${OUT}.abi"
KPATCH_ABI_OUT="${OUT}.kpatch-abi"
PACK_OUT="${OUT}.pack"
DYNAMIC_JSON="${OUT}.dynamic.json"
trap 'rm -f "$OUT" "$ABI_OUT" "$KPATCH_ABI_OUT" "$PACK_OUT" "$DYNAMIC_JSON"' EXIT

${CC:-cc} -std=c11 -O2 -Wall -Wextra -Werror \
  -I"$REPO" "$REPO/vpnhide_ctl.c" "$REPO/vpnhide_policy.c" \
  "$REPO/parson.c" -o "$OUT"

${CC:-cc} -std=c11 -O2 -Wall -Wextra -Werror \
  -I"$REPO" "$HERE/test_policy_abi.c" -o "$ABI_OUT"
KMOD_ABI="$($ABI_OUT)"

${CC:-cc} -std=c11 -O2 -Wall -Wextra -Werror \
  -I"$REPO/.." "$REPO/../kpatch/test/test_policy_abi.c" -o "$KPATCH_ABI_OUT"
KPATCH_ABI="$($KPATCH_ABI_OUT)"
if [ "$KMOD_ABI" != "$KPATCH_ABI" ]; then
	echo "kmod/kpatch ABI fingerprint mismatch" >&2
	echo "kmod:   $KMOD_ABI" >&2
	echo "kpatch: $KPATCH_ABI" >&2
	exit 1
fi

${CC:-cc} -std=c11 -O2 -Wall -Wextra -Werror \
  -I"$REPO" "$HERE/test_policy_pack.c" "$REPO/vpnhide_policy.c" \
  "$REPO/parson.c" -o "$PACK_OUT"
"$PACK_OUT"

# ABI v4 transports exactly the application's configured UID lists. In
# ALLOWLIST they are exceptions and the kernel applies eligible && !listed.
OUTPUT="$($OUT validate "$HERE/policy_allowlist.json" 10003)"
grep -q '^mode=ALLOWLIST$' <<<"$OUTPUT"
grep -q '^match_mode=EXCLUDE$' <<<"$OUTPUT"
grep -q '^configured_entries=1$' <<<"$OUTPUT"
grep -q '^kmod_targets=1$' <<<"$OUTPUT"
grep -q '^lsposed_targets=1$' <<<"$OUTPUT"
grep -q '^port_targets=1$' <<<"$OUTPUT"

# Application-selected system packages with application-range UIDs are
# ordinary declarative entries. systemPolicyExplicit is UI metadata only.
for fixture in policy_blacklist_system_explicit.json \
               policy_blacklist_system_legacy.json \
               policy_blacklist_system_stale.json; do
	OUTPUT="$($OUT validate "$HERE/$fixture" 10003)"
	grep -q '^match_mode=INCLUDE$' <<<"$OUTPUT"
	grep -q '^kmod_targets=1$' <<<"$OUTPUT"
	grep -q '^lsposed_targets=1$' <<<"$OUTPUT"
	grep -q '^port_targets=1$' <<<"$OUTPUT"
done

# Core Android appIds are rejected in userspace and again in kernel matching.
OUTPUT="$($OUT validate "$HERE/policy_blacklist_system_core_explicit.json" 10003)"
grep -q '^rejected_core_uids=1$' <<<"$OUTPUT"
grep -q '^kmod_targets=0$' <<<"$OUTPUT"
grep -q '^lsposed_targets=0$' <<<"$OUTPUT"
grep -q '^port_targets=0$' <<<"$OUTPUT"

OUTPUT="$($OUT preview "$HERE/policy_allowlist_system_explicit.json" 10003)"
grep -q '^kmod_targets=1$' <<<"$OUTPUT"
grep -q '^lsposed_targets=2$' <<<"$OUTPUT"
grep -q '^port_targets=1$' <<<"$OUTPUT"

# In ALLOWLIST, listed port entries override the kernel's implicit deny-all
# default. No daemon-generated entries exist for unlisted UIDs.
OUTPUT="$($OUT preview "$HERE/policy_allowlist.json" 10003)"
grep -q '^port_targets=1$' <<<"$OUTPUT"
grep -q '^port_target\[0\]\.uid=10001$' <<<"$OUTPUT"
grep -q '^port_target\[0\]\.mode=1$' <<<"$OUTPUT"

OUTPUT="$($OUT preview "$HERE/policy_allowlist_explicit.json" 10003)"
grep -q '^port_targets=1$' <<<"$OUTPUT"
grep -q '^port_target\[0\]\.uid=10001$' <<<"$OUTPUT"
grep -q '^port_target\[0\]\.mode=0$' <<<"$OUTPUT"
grep -q '^port_target\[0\]\.rule\[0\]=0-19999/2$' <<<"$OUTPUT"

OUTPUT="$($OUT preview "$HERE/policy_allowlist_local_mass.json" 10003)"
grep -q '^port_targets=1$' <<<"$OUTPUT"
grep -q '^port_target\[0\]\.rule\[0\]=0-8079/2$' <<<"$OUTPUT"
grep -q '^port_target\[0\]\.rule\[1\]=8080-8080/1$' <<<"$OUTPUT"
grep -q '^port_target\[0\]\.rule\[2\]=8081-19999/2$' <<<"$OUTPUT"

OUTPUT="$($OUT validate "$HERE/policy_blacklist.json" 10003)"
grep -q '^mode=BLACKLIST$' <<<"$OUTPUT"
grep -q '^match_mode=INCLUDE$' <<<"$OUTPUT"
grep -q '^kmod_targets=1$' <<<"$OUTPUT"
grep -q '^lsposed_targets=0$' <<<"$OUTPUT"

OUTPUT="$($OUT preview "$HERE/policy_blacklist_explicit.json" 10003)"
grep -q '^port_targets=1$' <<<"$OUTPUT"
grep -q '^port_target\[0\]\.uid=10002$' <<<"$OUTPUT"
grep -q '^port_target\[0\]\.rule\[0\]=8081-8081/2$' <<<"$OUTPUT"

OUTPUT="$($OUT preview "$HERE/policy_blacklist_mass_local.json" 10003)"
grep -q '^kmod_targets=1$' <<<"$OUTPUT"
grep -q '^lsposed_targets=1$' <<<"$OUTPUT"
grep -q '^port_target\[0\]\.rule\[0\]=8080-8080/0$' <<<"$OUTPUT"
grep -q '^port_target\[0\]\.rule\[1\]=20000-65535/2$' <<<"$OUTPUT"

# Per-UID rule storage remains dynamic.
{
	printf '{"globalConfig":{"listMode":"BLACKLIST"},"apps":[{"packageName":"com.example.target","userId":0,"uid":10002,"portHiding":true}],"portRules":['
	for i in $(seq 1 17); do
		if [ "$i" -gt 1 ]; then printf ','; fi
		printf '{"packageName":"com.example.target","userId":0,"uid":10002,"startPort":%d,"endPort":%d,"protocol":"TCP","enabled":true}' "$i" "$i"
	done
	printf ']}\n'
} >"$DYNAMIC_JSON"
OUTPUT="$("$OUT" preview "$DYNAMIC_JSON" 10003)"
grep -q '^port_target\[0\]\.rule\[16\]=17-17/0$' <<<"$OUTPUT"

# Exercise declarative list allocation at the ABI maximum test scale without
# Package Manager discovery.
{
	printf '{"globalConfig":{"listMode":"ALLOWLIST"},"apps":['
	for i in $(seq 10000 14095); do
		if [ "$i" -gt 10000 ]; then printf ','; fi
		printf '{"packageName":"com.example.app%d","userId":0,"uid":%d,"kmod":true,"lsposed":true,"portHiding":true}' "$i" "$i"
	done
	printf ']}\n'
} >"$DYNAMIC_JSON"
OUTPUT="$("$OUT" validate "$DYNAMIC_JSON")"
grep -q '^configured_entries=4096$' <<<"$OUTPUT"
grep -q '^kmod_targets=4096$' <<<"$OUTPUT"
grep -q '^lsposed_targets=4096$' <<<"$OUTPUT"
grep -q '^port_targets=4096$' <<<"$OUTPUT"

if rg -n 'VPNHIDE_PM_COMMAND|pm list packages|discover_packages' \
     "$REPO/vpnhide_policy.c" "$REPO/vpnhide_daemon.c" >/dev/null; then
	echo "v4 daemon/policy must not resolve packages" >&2
	exit 1
fi

echo "policy ABI v4 list modes: PASS"
