#!/bin/sh
# In-VM test driver (PID 1 / rdinit) for the vpnhide kpatch QEMU harness.
#
# Identical to kmod/test/init.sh in what it tests, but VPNHide is compiled
# directly into the kernel — there is no .ko to load.  The misc device
# /dev/vpnhide_ctrl is registered during kernel init, so we only need to
# configure it (iface_prefixes, targets, port_rules) before running the tests.
#
# Output format is the same as the kmod harness:
#   RESULT <vector>=PASS|FAIL
#   SUMMARY pass=N fail=N panic=N registered=1
# run.sh on the host parses these lines from the serial console.
set +e
export PATH=/usr/sbin:/usr/bin:/sbin:/bin

# The minirootfs does not ship iproute2.  Its BusyBox usually contains the
# basic `ip` applet, which is sufficient to create the test topology before
# optional package installation is attempted.
if [ -x /bin/busybox ] && ! command -v ip >/dev/null 2>&1; then
	ln -sf /bin/busybox /sbin/ip
fi

mount -t proc proc /proc 2>/dev/null
mount -t sysfs sys /sys 2>/dev/null
mount -t devtmpfs dev /dev 2>/dev/null

# The Android/Bionic static ctl uses /system/bin/sh for popen().  The Alpine
# QEMU rootfs only provides /bin/sh, so provide the Android-compatible path.
mkdir -p /system/bin
ln -sf /bin/sh /system/bin/sh

echo "##### VPNHIDE-QEMU-TEST START #####"
echo "KREL=$(uname -r)"
VECTOR_ARGS=""
case "$(uname -r)" in
    4.9.*|4.14.*) VECTOR_ARGS="--legacy-pre-4.16" ;;
esac

# Use the injected iproute2 consistently for topology creation and vectors.
# The QEMU runner supplies its ARM64 runtime dependencies host-side.
ip_setup() { ip "$@"; }

# Add a non-root Android-style app user with UID 115555 (user 1, appId 15555)
echo "testuser:x:115555:115555:testuser:/home/testuser:/bin/sh" >> /etc/passwd
echo "testallow:x:115556:115556:testallow:/home/testallow:/bin/sh" >> /etc/passwd

# --- bring up user-mode networking ----------------------------------------
ip_setup link set lo up 2>/dev/null
ip_setup link set eth0 up 2>/dev/null
ip_setup addr add 10.0.2.15/24 dev eth0 2>/dev/null
ip_setup -6 addr add fd00:2::1/64 dev eth0 2>/dev/null
ip_setup route add default via 10.0.2.2 2>/dev/null
echo "nameserver 10.0.2.3" > /etc/resolv.conf
echo "http://dl-cdn.alpinelinux.org/alpine/v3.21/main" > /etc/apk/repositories
if command -v ip >/dev/null 2>&1 && command -v tc >/dev/null 2>&1 &&
   command -v python3 >/dev/null 2>&1; then
	# The host-side QEMU runner may have injected ARM64 APKs into the
	# initramfs.  Avoid an unnecessary guest-network package install.
	echo "IPROUTE2=ok"
elif timeout 12 apk add --no-cache iproute2 python3 >/dev/null 2>&1; then
	echo "IPROUTE2=ok"
else
	echo "IPROUTE2=FAIL"
fi
ip -V 2>&1 || true
tc -V 2>&1 || true
python3 --version 2>&1 || true

# --- kpatch: VPNHide is built-in, /dev/vpnhide_ctrl exists at boot ----------
# (no insmod needed — contrasts with kmod/test/init.sh which does
#  `insmod /vpnhide_kmod.ko`)
if [ -e /dev/vpnhide_ctrl ]; then
    echo "CTRL_DEV=ok"
else
    echo "CTRL_DEV=FAIL — /dev/vpnhide_ctrl missing; CONFIG_VPNHIDE=y not in kernel?"
    echo "SUMMARY pass=0 fail=1 panic=0 registered=0"
    echo "##### VPNHIDE-QEMU-TEST END #####"
    poweroff -f
fi

TEST_CONFIG=/tmp/vpnhide-test-policy.json
cat > "$TEST_CONFIG" <<'EOF'
{
  "globalConfig": {"listMode":"BLACKLIST", "kernelHookMask":4294967295, "javaHookMask":4294967295, "debugLogging":1},
  "ifacePrefixes": ["vpn"],
  "apps": [{"packageName":"com.vpnhide.test", "userId":1, "uid":115555, "kmod":true, "lsposed":true, "portHiding":true}],
  "portRules": [{"enabled":true, "packageName":"com.vpnhide.test", "userId":1, "startPort":0, "endPort":65535, "protocol":"BOTH"}]
}
EOF
apply_policy() {
	/vpnhide-ctl load "$TEST_CONFIG"
	rc=$?
	echo "POLICY_APPLY_RC=$rc"
	return "$rc"
}
ALLOWLIST_CONFIG=/tmp/vpnhide-test-allowlist.json
cat > "$ALLOWLIST_CONFIG" <<'EOF'
{
  "globalConfig": {"listMode":"ALLOWLIST", "kernelHookMask":4294967295, "javaHookMask":4294967295, "debugLogging":1},
  "ifacePrefixes": ["vpn"],
  "apps": [
    {"packageName":"com.vpnhide.keep", "userId":1, "uid":115556, "kmod":true, "lsposed":true, "portHiding":true},
    {"packageName":"com.vpnhide.test", "userId":1, "uid":115555, "kmod":false, "lsposed":false, "portHiding":false}
  ],
  "portRules": [
    {"enabled":true, "packageName":"com.vpnhide.test", "userId":1, "startPort":8080, "endPort":8080, "protocol":"BOTH"},
    {"enabled":true, "packageName":"com.vpnhide.keep", "userId":1, "startPort":8081, "endPort":8081, "protocol":"TCP"}
  ]
}
EOF
apply_allowlist() {
	/vpnhide-ctl load "$ALLOWLIST_CONFIG"
	rc=$?
	echo "ALLOWLIST_APPLY_RC=$rc"
	return "$rc"
}
REGISTERED=1
echo "REGISTERED=$REGISTERED"

# Start the daemon to auto-detect interfaces and keep active_vpns updated
/vpnhide-daemon > /tmp/daemon.log 2>&1 &
DAEMON_PID=$!
sleep 1

# --- fabricate VPN-like interface + routes + per-uid policy rule ------------
ip_setup link add vpn0 type dummy 2>/dev/null
ip_setup link set vpn0 up 2>/dev/null
tc qdisc add dev vpn0 root pfifo_fast 2>/dev/null
ip_setup addr add 10.9.0.1/24 dev vpn0 2>/dev/null
ip_setup route add 10.9.9.0/24 dev vpn0 2>/dev/null
ip_setup -6 addr add fd00:9::1/64 dev vpn0 2>/dev/null
ip_setup -6 route add fd00:99::/64 dev vpn0 2>/dev/null
ip_setup link add vpn1 type dummy 2>/dev/null
ip_setup link set vpn1 up 2>/dev/null
ip_setup addr add 10.10.0.1/24 dev vpn1 2>/dev/null
ip_setup -6 addr add fd00:10::1/64 dev vpn1 2>/dev/null
ip_setup rule add uidrange 115555-115555 table 199 2>/dev/null
ip_setup rule add iif vpn0 table 200 2>/dev/null
ip_setup rule add oif vpn0 table 201 2>/dev/null
# Give the daemon time to detect vpn0 and push its ifindex to the kernel
sleep 3

PASS=0
FAIL=0

# check <name> <shell-command> <grep-pattern>
# Asserts: non-target (root) SEES the pattern; target UID 115555 does NOT.
check() {
    _name=$1
    _cmd=$2
    _pat=$3

    apply_policy

    _nt=$(eval "$_cmd" 2>/dev/null | grep -c -- "$_pat")
    _tg=$(su testuser -c "$_cmd" 2>/dev/null | grep -c -- "$_pat")

    if [ "$_nt" -gt 0 ] && [ "$_tg" -eq 0 ]; then
        echo "RESULT $_name=PASS (nontarget=$_nt target=$_tg)"
        PASS=$((PASS + 1))
    else
        echo "RESULT $_name=FAIL (nontarget=$_nt target=$_tg)"
        FAIL=$((FAIL + 1))
    fi
}

# --- shell-level vector checks (same set as kmod) ---------------------------
check getifaddrs      "ip addr show"                 "vpn0"   # RTM_GETLINK + RTM_GETADDR
check siocgifconf     "ifconfig -a"                  "vpn0"   # SIOCGIFCONF
check proc_route_v4   "cat /proc/net/route"          "vpn0"   # fib_route_seq_show
check proc_route_v6   "cat /proc/net/ipv6_route"     "vpn0"   # ipv6_route_seq_show / ip6_fib
check netlink_route4  "ip route show table all"      "vpn0"   # fib_dump_info
check netlink_route6  "ip -6 route show table all"   "vpn0"   # rt6_fill_node
check policy_rule     "ip rule show"                 "199"    # fib_nl_fill_rule (UID split-routing rule)
check getrule_iif     "ip rule show"                 "200"    # fib_nl_fill_rule (iifname=vpn0 hidden)
check getrule_oif     "ip rule show"                 "201"    # fib_nl_fill_rule (oifname=vpn0 hidden)
check proc_net_dev    "cat /proc/net/dev"            "vpn0"   # dev_seq_show  (kpatch gap fixed)
check proc_net_if_in6 "cat /proc/net/if_inet6"       "vpn0"   # if6_seq_show  (kpatch gap fixed)
check tc_qdisc        "tc qdisc show"                "vpn0"   # tc_fill_qdisc (kpatch gap fixed)
check multi_iface_visibility "ip addr show"           "vpn[01]" # both active VPN ifindexes

# The daemon must publish both interfaces as one active snapshot. This status
# line is diagnostic only; hiding itself is exercised above through netlink
# ifindex-based hooks.
apply_policy
_active_status=$(timeout 2 cat /dev/vpnhide_ctrl 2>/dev/null || true)
if printf '%s\n' "$_active_status" | grep -Eq 'active_vpn_ifaces:.*vpn0' &&
   printf '%s\n' "$_active_status" | grep -Eq 'active_vpn_ifaces:.*vpn1'; then
    echo "RESULT multi_iface_snapshot=PASS"
    PASS=$((PASS + 1))
else
    echo "RESULT multi_iface_snapshot=FAIL"
    FAIL=$((FAIL + 1))
fi

kill "$DAEMON_PID" 2>/dev/null

# --- programmatic socket / ioctl / BPF checks (Python) ----------------------
apply_policy

python3 /vector_tests.py $VECTOR_ARGS > /tmp/py_res.log 2>&1
cat /tmp/py_res.log

while read -r line; do
    case "$line" in
        "RESULT "*=PASS*)  PASS=$((PASS + 1))  ;;
        "RESULT "*=FAIL*)  FAIL=$((FAIL + 1))  ;;
    esac
done < /tmp/py_res.log

# --- end-to-end allowlist check --------------------------------------------
# testallow is selected and must retain visibility; testuser is unselected
# and must receive the same hiding treatment as the blacklist target.
apply_allowlist
_al_status=$(timeout 2 cat /dev/vpnhide_ctrl 2>/dev/null || true)
if printf '%s\n' "$_al_status" | grep -q '^lsposed_list_mode: SHOW$' &&
   printf '%s\n' "$_al_status" | grep -Eq '^lsposed_uids:.*(^| )115556( |$)' &&
   ! printf '%s\n' "$_al_status" | grep -Eq '^lsposed_uids:.*(^| )115555( |$)'; then
    echo "RESULT allowlist_lsposed_show_list=PASS"
    PASS=$((PASS + 1))
else
    echo "RESULT allowlist_lsposed_show_list=FAIL"
    FAIL=$((FAIL + 1))
fi
_al_nt=$(ip addr show 2>/dev/null | grep -c -- "vpn0")
_al_keep=$(su testallow -c "ip addr show" 2>/dev/null | grep -c -- "vpn0")
_al_target=$(su testuser -c "ip addr show" 2>/dev/null | grep -c -- "vpn0")
if [ "$_al_nt" -gt 0 ] && [ "$_al_keep" -gt 0 ] && [ "$_al_target" -eq 0 ]; then
    echo "RESULT allowlist_visibility=PASS (root=$_al_nt allowlisted=$_al_keep target=$_al_target)"
    PASS=$((PASS + 1))
else
    echo "RESULT allowlist_visibility=FAIL (root=$_al_nt allowlisted=$_al_keep target=$_al_target)"
    FAIL=$((FAIL + 1))
fi

# A selected P app with local allow-rule 8081 must see 8081 but not 8080.
python3 /vector_tests.py --allowlist-port-only
if [ "$?" -eq 0 ]; then
    echo "RESULT allowlist_local_port=PASS"
    PASS=$((PASS + 1))
else
    echo "RESULT allowlist_local_port=FAIL"
    FAIL=$((FAIL + 1))
fi

# The existing programmatic vectors now run against the unselected UID 115555
# under the allowlist snapshot, including port and socket policy.
python3 /vector_tests.py $VECTOR_ARGS > /tmp/py_allowlist_res.log 2>&1
cat /tmp/py_allowlist_res.log
while read -r line; do
    case "$line" in
        "RESULT "*=PASS*) PASS=$((PASS + 1)) ;;
        "RESULT "*=FAIL*) FAIL=$((FAIL + 1)) ;;
    esac
done < /tmp/py_allowlist_res.log

# Old 4.14/4.19/5.4 kernels can emit non-fatal mm accounting warnings while
# tearing down short-lived test shells.  Count only fatal kernel diagnostics.
PANIC=$(dmesg | grep -ci 'Unable to handle\|Internal error\|Oops\|Kernel panic')
echo "=== DAEMON LOG ==="
cat /tmp/daemon.log
echo "=================="
echo "PANIC=$PANIC"
echo "SUMMARY pass=$PASS fail=$FAIL panic=$PANIC registered=$REGISTERED"
echo "##### VPNHIDE-QEMU-TEST END #####"

poweroff -f
