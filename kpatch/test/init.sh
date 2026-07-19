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

mount -t proc proc /proc 2>/dev/null
mount -t sysfs sys /sys 2>/dev/null
mount -t devtmpfs dev /dev 2>/dev/null

echo "##### VPNHIDE-QEMU-TEST START #####"
echo "KREL=$(uname -r)"

# Add a non-root test user with UID 5555
echo "testuser:x:5555:5555:testuser:/home/testuser:/bin/sh" >> /etc/passwd

# --- bring up user-mode networking ----------------------------------------
ip link set lo up 2>/dev/null
ip link set eth0 up 2>/dev/null
ip addr add 10.0.2.15/24 dev eth0 2>/dev/null
ip -6 addr add fd00:2::1/64 dev eth0 2>/dev/null
ip route add default via 10.0.2.2 2>/dev/null
echo "nameserver 10.0.2.3" > /etc/resolv.conf
echo "https://dl-cdn.alpinelinux.org/alpine/v3.21/main" > /etc/apk/repositories
if apk add --no-cache iproute2 python3 >/dev/null 2>&1; then echo "IPROUTE2=ok"; else echo "IPROUTE2=FAIL"; fi

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

/vpnhide-ctl iface_prefixes vpn 2>/dev/null
/vpnhide-ctl debug 1 2>/dev/null
REGISTERED=1
echo "REGISTERED=$REGISTERED"

# Start the daemon to auto-detect interfaces and keep active_vpns updated
/vpnhide-daemon > /tmp/daemon.log 2>&1 &
sleep 1

# --- fabricate VPN-like interface + routes + per-uid policy rule ------------
ip link add vpn0 type dummy 2>/dev/null
ip link set vpn0 up 2>/dev/null
tc qdisc add dev vpn0 root pfifo_fast 2>/dev/null
ip addr add 10.9.0.1/24 dev vpn0 2>/dev/null
ip route add 10.9.9.0/24 dev vpn0 2>/dev/null
ip -6 addr add fd00:9::1/64 dev vpn0 2>/dev/null
ip -6 route add fd00:99::/64 dev vpn0 2>/dev/null
ip rule add uidrange 5555-5555 table 199 2>/dev/null
# Give the daemon time to detect vpn0 and push its ifindex to the kernel
sleep 3

PASS=0
FAIL=0

# check <name> <shell-command> <grep-pattern>
# Asserts: non-target (root) SEES the pattern; target UID 5555 does NOT.
check() {
    _name=$1
    _cmd=$2
    _pat=$3

    /vpnhide-ctl targets 5555 2>/dev/null

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
check sysfs_ipv4_conf "ls /proc/sys/net/ipv4/conf"   "vpn0"   # getdents64 / proc_sys_lookup
check sysfs_ipv6_neig "ls /proc/sys/net/ipv6/neigh"  "vpn0"   # getdents64
check proc_net_dev    "cat /proc/net/dev"            "vpn0"   # dev_seq_show  (kpatch gap fixed)
check proc_net_if_in6 "cat /proc/net/if_inet6"       "vpn0"   # if6_seq_show  (kpatch gap fixed)
check tc_qdisc        "tc qdisc show"                "vpn0"   # tc_fill_qdisc (kpatch gap fixed)

# --- programmatic socket / ioctl / BPF checks (Python) ----------------------
/vpnhide-ctl targets 5555 2>/dev/null
/vpnhide-ctl port_rules 5555 1 8080 8080 2 2>/dev/null

python3 /vector_tests.py > /tmp/py_res.log 2>&1
cat /tmp/py_res.log

while read -r line; do
    case "$line" in
        "RESULT "*=PASS*)  PASS=$((PASS + 1))  ;;
        "RESULT "*=FAIL*)  FAIL=$((FAIL + 1))  ;;
    esac
done < /tmp/py_res.log

PANIC=$(dmesg | grep -ci 'Unable to handle\|Internal error\|Oops\|BUG:\|Kernel panic')
echo "=== DAEMON LOG ==="
cat /tmp/daemon.log
echo "=================="
echo "PANIC=$PANIC"
echo "SUMMARY pass=$PASS fail=$FAIL panic=$PANIC registered=$REGISTERED"
echo "##### VPNHIDE-QEMU-TEST END #####"

poweroff -f
