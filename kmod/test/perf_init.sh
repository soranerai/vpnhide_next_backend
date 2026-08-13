#!/bin/sh
set +e
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
mount -t proc proc /proc 2>/dev/null
mount -t sysfs sys /sys 2>/dev/null
mount -t devtmpfs dev /dev 2>/dev/null
mkdir -p /system/bin
ln -sf /bin/sh /system/bin/sh

if [ -r /perf-backend ]; then
    PERF_BACKEND=$(cat /perf-backend)
    export PERF_BACKEND
fi
echo "##### VPNHIDE-QEMU-PERF START #####"
echo "KREL=$(uname -r)"
echo "PERF_BACKEND=${PERF_BACKEND:-kmod}"
echo "PERF_VARIANT=${VPNHIDE_PERF_VARIANT:-unknown}"
echo "testuser:x:115555:115555:testuser:/home/testuser:/bin/sh" >> /etc/passwd

ip link set lo up 2>/dev/null
ip link set eth0 up 2>/dev/null
ip addr add 10.0.2.15/24 dev eth0 2>/dev/null
ip route add default via 10.0.2.2 2>/dev/null
echo "nameserver 10.0.2.3" > /etc/resolv.conf
echo "https://dl-cdn.alpinelinux.org/alpine/v3.21/main" > /etc/apk/repositories
apk add --no-cache python3 >/dev/null 2>&1

if [ "${PERF_BACKEND:-kmod}" = kmod ]; then
    insmod /vpnhide_kmod.ko
    if [ "$?" -ne 0 ]; then
        echo "PERF_ERROR=insmod"
        echo "##### VPNHIDE-QEMU-PERF END #####"
        poweroff -f
    fi
fi

sleep 1
cat > /tmp/vpnhide-perf-policy.json <<'EOF'
{
  "globalConfig": {"listMode":"BLACKLIST", "kernelHookMask":4294967295,
    "javaHookMask":4294967295, "debugLogging":false},
  "ifacePrefixes": ["vpn"],
  "apps": [{"packageName":"com.vpnhide.perf", "userId":1,
    "uid":115555, "kmod":true, "portHiding":true}],
  "portRules": [{"enabled":true, "packageName":"com.vpnhide.perf",
    "userId":1, "startPort":1, "endPort":65535, "protocol":"BOTH"}]
}
EOF
export VPNHIDE_PM_COMMAND="echo 'package:/data/app/perf/base.apk=com.vpnhide.perf uid:115555'"
/vpnhide-ctl load /tmp/vpnhide-perf-policy.json 0 >/tmp/perf-policy.log 2>&1
if [ "$?" -ne 0 ]; then
    echo "PERF_ERROR=policy"
    cat /tmp/perf-policy.log
    echo "##### VPNHIDE-QEMU-PERF END #####"
    poweroff -f
fi

VPNHIDE_PERF_ITERATIONS="${VPNHIDE_PERF_ITERATIONS:-20000}" \
VPNHIDE_PERF_REPEATS="${VPNHIDE_PERF_REPEATS:-5}" \
python3 /perf_workload.py
echo "##### VPNHIDE-QEMU-PERF END #####"
poweroff -f
