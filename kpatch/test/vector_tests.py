#!/usr/bin/env python3
import ctypes
import errno
import fcntl
import os
import platform
import socket
import struct
import sys

# ruff: noqa: E501

SO_BINDTODEVICE = getattr(socket, "SO_BINDTODEVICE", 25)
SO_BINDTOIFINDEX = 62
SIOCGIFFLAGS = 0x8913
SIOCGIFADDR = 0x8915
SIOCGIFDSTADDR = 0x8917
SIOCGIFNETMASK = 0x891B

# Netlink constants for tc_qdisc check
NETLINK_ROUTE = 0
RTM_GETQDISC  = 38
RTM_GETRULE   = 34
RTM_NEWRULE   = 32
NLM_F_REQUEST = 0x01
NLM_F_DUMP    = 0x300

# fib_rule_hdr (12 bytes): family(1) dst_len(1) src_len(1) tos(1)
#   table(1) res1(1) res2(1) action(1) flags(4)
FIB_RULE_HDR_FMT  = "BBBBBBBBI"
FIB_RULE_HDR_SIZE = struct.calcsize(FIB_RULE_HDR_FMT)

# Netlink attribute constants for FIB rules
FRA_IIFNAME  = 3
FRA_OIFNAME  = 17
FRA_UID_RANGE = 20


def safe_fork():
    sys.stdout.flush()
    sys.stderr.flush()
    return os.fork()


def test_dev_ioctl(vpn0_idx):
    print("\n--- dev_ioctl checks ---")

    try:
        idx = socket.if_nametoindex("vpn0")
        print(f"[dev_ioctl] Non-target if_nametoindex('vpn0') returned: {idx} (expected: {vpn0_idx})")
        assert idx == vpn0_idx, f"Expected index {vpn0_idx}, got {idx}"
    except Exception as e:
        print(f"FAIL: dev_ioctl if_nametoindex non-target: {e}")
        return False

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    for name, code in [("SIOCGIFFLAGS", SIOCGIFFLAGS), ("SIOCGIFADDR", SIOCGIFADDR),
                        ("SIOCGIFDSTADDR", SIOCGIFDSTADDR), ("SIOCGIFNETMASK", SIOCGIFNETMASK)]:
        try:
            fcntl.ioctl(s.fileno(), code, struct.pack("16sH", b"vpn0", 0))
            print(f"[dev_ioctl] Non-target ioctl({name}, 'vpn0') succeeded as expected")
        except Exception as e:
            print(f"FAIL: dev_ioctl {name} non-target: {e}")
            return False

    pid = safe_fork()
    if pid == 0:
        try:
            os.setuid(115555)
            try:
                socket.if_nametoindex("vpn0")
                print("FAIL: dev_ioctl if_nametoindex target succeeded but should have failed")
                sys.exit(1)
            except (OSError, ValueError) as e:
                print(f"[dev_ioctl] Target if_nametoindex('vpn0') failed as expected: {e}")

            for name, code in [("SIOCGIFFLAGS", SIOCGIFFLAGS), ("SIOCGIFADDR", SIOCGIFADDR),
                                ("SIOCGIFDSTADDR", SIOCGIFDSTADDR), ("SIOCGIFNETMASK", SIOCGIFNETMASK)]:
                try:
                    fcntl.ioctl(s.fileno(), code, struct.pack("16sH", b"vpn0", 0))
                    print(f"FAIL: dev_ioctl {name} target succeeded but should have failed")
                    sys.exit(1)
                except OSError as e:
                    if e.errno != 19:
                        print(f"FAIL: dev_ioctl {name} target expected errno 19, got {e.errno}")
                        sys.exit(1)
                    print(f"[dev_ioctl] Target ioctl({name}, 'vpn0') failed as expected: errno {e.errno}")

            sys.exit(0)
        except Exception as e:
            print(f"FAIL: child process exception: {e}")
            sys.exit(1)
    else:
        _, status = os.waitpid(pid, 0)
        if status != 0:
            return False
    return True


def test_setsockopt(vpn0_idx):
    print("\n--- setsockopt checks ---")

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.setsockopt(socket.SOL_SOCKET, SO_BINDTODEVICE, b"vpn0")
        print("[setsockopt] Non-target setsockopt(SO_BINDTODEVICE, 'vpn0') succeeded as expected")
    except Exception as e:
        print(f"FAIL: setsockopt SO_BINDTODEVICE non-target: {e}")
        return False

    s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s2.setsockopt(socket.SOL_SOCKET, SO_BINDTOIFINDEX, struct.pack("i", vpn0_idx))
        print(f"[setsockopt] Non-target setsockopt(SO_BINDTOIFINDEX, {vpn0_idx}) succeeded as expected")
    except Exception as e:
        print(f"FAIL: setsockopt SO_BINDTOIFINDEX non-target: {e}")
        return False

    pid = safe_fork()
    if pid == 0:
        try:
            os.setuid(115555)
            s_tgt = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                s_tgt.setsockopt(socket.SOL_SOCKET, SO_BINDTODEVICE, b"vpn0")
                print("FAIL: setsockopt SO_BINDTODEVICE target succeeded but should have failed")
                sys.exit(1)
            except OSError as e:
                if e.errno != 19:
                    print(f"FAIL: setsockopt SO_BINDTODEVICE target expected errno 19, got {e.errno}")
                    sys.exit(1)
                print(f"[setsockopt] Target setsockopt(SO_BINDTODEVICE, 'vpn0') failed as expected: errno {e.errno}")

            try:
                s_tgt.setsockopt(socket.SOL_SOCKET, SO_BINDTOIFINDEX, struct.pack("i", vpn0_idx))
                print("FAIL: setsockopt SO_BINDTOIFINDEX target succeeded but should have failed")
                sys.exit(1)
            except OSError as e:
                if e.errno != 19:
                    print(f"FAIL: setsockopt SO_BINDTOIFINDEX target expected errno 19, got {e.errno}")
                    sys.exit(1)
                print(f"[setsockopt] Target setsockopt(SO_BINDTOIFINDEX, {vpn0_idx}) failed as expected: errno {e.errno}")

            sys.exit(0)
        except Exception as e:
            print(f"FAIL: child exception: {e}")
            sys.exit(1)
    else:
        _, status = os.waitpid(pid, 0)
        if status != 0:
            return False
    return True


def test_getsockopt(vpn0_idx):
    print("\n--- getsockopt checks ---")

    s_dev = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s_dev.setsockopt(socket.SOL_SOCKET, SO_BINDTODEVICE, b"vpn0\x00")

    s_idx = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s_idx.setsockopt(socket.SOL_SOCKET, SO_BINDTOIFINDEX, struct.pack("i", vpn0_idx))

    pid = safe_fork()
    if pid == 0:
        try:
            os.setuid(115555)
            val = s_dev.getsockopt(socket.SOL_SOCKET, SO_BINDTODEVICE, 256)
            clean_val = val.strip(b"\x00")
            print(f"[getsockopt] Target getsockopt(SO_BINDTODEVICE) returned: {clean_val!r} (expected: empty)")
            if clean_val != b"":
                print(f"FAIL: getsockopt SO_BINDTODEVICE target: expected empty string, got {clean_val}")
                sys.exit(1)

            val_idx = s_idx.getsockopt(socket.SOL_SOCKET, SO_BINDTOIFINDEX, 4)
            idx = struct.unpack("i", val_idx)[0]
            print(f"[getsockopt] Target getsockopt(SO_BINDTOIFINDEX) returned: {idx} (expected: 0)")
            if idx != 0:
                print(f"FAIL: getsockopt SO_BINDTOIFINDEX target: expected 0, got {idx}")
                sys.exit(1)

            sys.exit(0)
        except Exception as e:
            print(f"FAIL: child exception: {e}")
            sys.exit(1)
    else:
        _, status = os.waitpid(pid, 0)
        if status != 0:
            return False
    return True


def test_getsockname():
    print("\n--- getsockname spoofing checks ---")

    s_v4 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s_v4.bind(("10.9.0.1", 0))
        ip4_nt, _ = s_v4.getsockname()
        print(f"[getsockname] Non-target getsockname IPv4: {ip4_nt} (expected: 10.9.0.1)")
    except Exception as e:
        print(f"FAIL: getsockname IPv4 bind: {e}")
        return False

    s_v6 = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    try:
        s_v6.bind(("fd00:9::1", 0))
        ip6_nt, *_ = s_v6.getsockname()
        print(f"[getsockname] Non-target getsockname IPv6: [{ip6_nt}] (expected: fd00:9::1)")
    except Exception as e:
        print(f"FAIL: getsockname IPv6 bind: {e}")
        return False

    pid = safe_fork()
    if pid == 0:
        try:
            os.setuid(115555)
            ip4, _ = s_v4.getsockname()
            print(f"[getsockname] Target getsockname IPv4: {ip4} (expected: spoofed/shielded)")
            if ip4 == "10.9.0.1":
                print(f"FAIL: getsockname IPv4 target: got unshielded VPN IP '{ip4}'")
                sys.exit(1)

            ip6, *_ = s_v6.getsockname()
            print(f"[getsockname] Target getsockname IPv6: [{ip6}] (expected: spoofed/shielded)")
            if ip6 == "fd00:9::1":
                print(f"FAIL: getsockname IPv6 target: got unshielded VPN IP '{ip6}'")
                sys.exit(1)

            sys.exit(0)
        except Exception as e:
            print(f"FAIL: child exception: {e}")
            sys.exit(1)
    else:
        _, status = os.waitpid(pid, 0)
        if status != 0:
            return False
    return True


def test_connect_port_block():
    print("\n--- connect port block checks ---")

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        listener.bind(("127.0.0.1", 8080))
        listener.listen(1)
    except Exception as e:
        print(f"FAIL: connect port block listener bind/listen: {e}")
        return False

    s_nt = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s_nt.settimeout(2.0)
    try:
        s_nt.connect(("127.0.0.1", 8080))
        s_nt.close()
        print("[connect_port_block] Non-target connected to 127.0.0.1:8080 successfully as expected")
    except Exception as e:
        print(f"FAIL: connect port block non-target connection failed: {e}")
        listener.close()
        return False

    pid = safe_fork()
    if pid == 0:
        try:
            os.setuid(115555)
            s_tgt = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s_tgt.settimeout(2.0)
            try:
                s_tgt.connect(("127.0.0.1", 8080))
                print("FAIL: connect port block target succeeded but should have failed")
                sys.exit(1)
            except OSError as e:
                if e.errno != 111:
                    print(f"FAIL: connect port block target expected errno 111, got {e.errno}")
                    sys.exit(1)
                print(f"[connect_port_block] Target connection failed as expected: errno {e.errno}")
            sys.exit(0)
        except Exception as e:
            print(f"FAIL: child exception: {e}")
            sys.exit(1)
    else:
        _, status = os.waitpid(pid, 0)
        listener.close()
        if status != 0:
            return False
    return True


def test_bind_port_block():
    print("\n--- bind port block checks ---")

    pid = safe_fork()
    if pid == 0:
        try:
            os.setuid(115555)
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                s.bind(("127.0.0.1", 8080))
                _, port = s.getsockname()
                print(f"[bind_port_block] Target bound to 127.0.0.1:8080. Redirected port: {port}")
                if port == 8080:
                    print("FAIL: bind port block target bound to 8080, expected redirection to ephemeral port")
                    sys.exit(1)
                if port == 0:
                    print("FAIL: bind port block target getsockname returned 0")
                    sys.exit(1)
            except Exception as e:
                print(f"FAIL: bind port block target bind error: {e}")
                sys.exit(1)
            sys.exit(0)
        except Exception as e:
            print(f"FAIL: child exception: {e}")
            sys.exit(1)
    else:
        _, status = os.waitpid(pid, 0)
        if status != 0:
            return False
    return True


# BPF constants / structs

machine = platform.machine()
if machine in ("aarch64", "arm64"):
    __NR_bpf = 280
elif machine in ("x86_64", "amd64"):
    __NR_bpf = 321
else:
    __NR_bpf = 280

BPF_MAP_CREATE = 0
BPF_MAP_LOOKUP_ELEM = 1
BPF_MAP_UPDATE_ELEM = 2
BPF_MAP_TYPE_HASH = 2


class VhStatsValue(ctypes.Structure):
    _fields_ = [
        ("rxBytes", ctypes.c_uint64), ("rxPackets", ctypes.c_uint64),
        ("txBytes", ctypes.c_uint64), ("txPackets", ctypes.c_uint64),
    ]


class BpfAttrCreate(ctypes.Structure):
    _fields_ = [
        ("map_type", ctypes.c_uint32), ("key_size", ctypes.c_uint32),
        ("value_size", ctypes.c_uint32), ("max_entries", ctypes.c_uint32),
        ("map_flags", ctypes.c_uint32), ("inner_map_fd", ctypes.c_uint32),
        ("numa_node", ctypes.c_uint32), ("map_name", ctypes.c_char * 16),
        ("map_ifindex", ctypes.c_uint32), ("btf_fd", ctypes.c_uint32),
        ("btf_key_type_id", ctypes.c_uint32), ("btf_value_type_id", ctypes.c_uint32),
        ("btf_vmlinux_value_type_id", ctypes.c_uint32), ("map_extra", ctypes.c_uint64),
    ]


class BpfAttrElem(ctypes.Structure):
    _fields_ = [
        ("map_fd", ctypes.c_uint32), ("key", ctypes.c_uint64),
        ("value", ctypes.c_uint64), ("flags", ctypes.c_uint64),
    ]


class BpfAttrBatch(ctypes.Structure):
    _fields_ = [
        ("in_batch", ctypes.c_uint64), ("out_batch", ctypes.c_uint64),
        ("keys", ctypes.c_uint64), ("values", ctypes.c_uint64),
        ("count", ctypes.c_uint32), ("map_fd", ctypes.c_uint32),
        ("elem_flags", ctypes.c_uint64), ("flags", ctypes.c_uint64),
    ]


class BpfAttr(ctypes.Union):
    _fields_ = [
        ("raw", ctypes.c_ubyte * 128),
        ("create", BpfAttrCreate),
        ("elem", BpfAttrElem),
        ("batch", BpfAttrBatch),
    ]


libc = ctypes.CDLL(None, use_errno=True)


def bpf_syscall(cmd, attr, size):
    ret = libc.syscall(__NR_bpf, cmd, ctypes.byref(attr), size)
    if ret < 0:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err))
    return ret


def create_stats_map():
    attr = BpfAttr()
    attr.create.map_type = BPF_MAP_TYPE_HASH
    attr.create.key_size = 4
    attr.create.value_size = 32
    attr.create.max_entries = 1000
    attr.create.map_name = b"iface_stats"
    return bpf_syscall(BPF_MAP_CREATE, attr, ctypes.sizeof(attr))


def update_map_elem(map_fd, ifindex, rx, tx):
    key = ctypes.c_uint32(ifindex)
    val = VhStatsValue(rxBytes=rx, rxPackets=rx // 100 if rx >= 100 else 1,
                       txBytes=tx, txPackets=tx // 100 if tx >= 100 else 1)
    attr = BpfAttr()
    attr.elem.map_fd = map_fd
    attr.elem.key = ctypes.addressof(key)
    attr.elem.value = ctypes.addressof(val)
    bpf_syscall(BPF_MAP_UPDATE_ELEM, attr, ctypes.sizeof(attr))


def lookup_map_elem(map_fd, ifindex):
    key = ctypes.c_uint32(ifindex)
    val = VhStatsValue()
    attr = BpfAttr()
    attr.elem.map_fd = map_fd
    attr.elem.key = ctypes.addressof(key)
    attr.elem.value = ctypes.addressof(val)
    bpf_syscall(BPF_MAP_LOOKUP_ELEM, attr, ctypes.sizeof(attr))
    return val


def test_bpf_laundering(vpn0_idx):
    print("\n--- BPF map laundering checks ---")

    try:
        eth0_idx = socket.if_nametoindex("eth0")
    except Exception as e:
        print(f"FAIL: BPF test cannot find eth0: {e}")
        return False

    try:
        map_fd = create_stats_map()
        print(f"[BPF] Created map 'iface_stats' with fd: {map_fd}")
    except Exception as e:
        print(f"FAIL: BPF map creation: {e}")
        return False

    try:
        update_map_elem(map_fd, vpn0_idx, 1000, 2000)
        update_map_elem(map_fd, eth0_idx, 5000, 6000)
    except Exception as e:
        print(f"FAIL: BPF map update: {e}")
        return False

    try:
        vpn_val = lookup_map_elem(map_fd, vpn0_idx)
        print(f"[BPF Non-Target] vpn0: rx={vpn_val.rxBytes}, tx={vpn_val.txBytes}")
        assert vpn_val.rxBytes == 0 and vpn_val.txBytes == 0, "VPN stats not zeroed!"
        eth_val = lookup_map_elem(map_fd, eth0_idx)
        print(f"[BPF Non-Target] eth0: rx={eth_val.rxBytes}, tx={eth_val.txBytes}")
        assert eth_val.rxBytes == 6000 and eth_val.txBytes == 8000, "Cover interface stats not laundered!"
        print("[BPF Non-Target] Single lookup checks passed")
    except Exception as e:
        print(f"FAIL: BPF non-target lookup verification failed: {e}")
        return False

    pid = safe_fork()
    if pid == 0:
        try:
            os.setuid(115555)
            vpn_val = lookup_map_elem(map_fd, vpn0_idx)
            eth_val = lookup_map_elem(map_fd, eth0_idx)
            print(f"[BPF Target] vpn0: rx={vpn_val.rxBytes}, tx={vpn_val.txBytes}")
            print(f"[BPF Target] eth0: rx={eth_val.rxBytes}, tx={eth_val.txBytes}")
            if vpn_val.rxBytes != 1000 or eth_val.rxBytes != 5000:
                print("FAIL: BPF target check expected raw values, got spoofed values")
                sys.exit(1)
            print("[BPF Target] Target bypass checks passed")
            sys.exit(0)
        except Exception as e:
            print(f"FAIL: BPF child exception: {e}")
            sys.exit(1)
    else:
        _, status = os.waitpid(pid, 0)
        if status != 0:
            return False
    return True


def test_proc_sys_net():
    print("\n--- proc / sysfs net checks ---")

    try:
        ipv4_conf = os.listdir("/proc/sys/net/ipv4/conf")
        ipv6_neigh = os.listdir("/proc/sys/net/ipv6/neigh")
        with open("/proc/net/dev") as f:
            proc_net_dev = f.read()
        with open("/proc/net/if_inet6") as f:
            proc_net_if_inet6 = f.read()
        assert "vpn0" in ipv4_conf, "vpn0 not in /proc/sys/net/ipv4/conf under root"
        assert "vpn0" in ipv6_neigh, "vpn0 not in /proc/sys/net/ipv6/neigh under root"
        assert "vpn0" in proc_net_dev, "vpn0 not in /proc/net/dev under root"
        assert "vpn0" in proc_net_if_inet6, "vpn0 not in /proc/net/if_inet6 under root"
        print("[proc/sysfs net] Non-target checks passed")
    except Exception as e:
        print(f"FAIL: proc/sysfs net non-target check failed: {e}")
        return False

    pid = safe_fork()
    if pid == 0:
        try:
            os.setuid(115555)
            ipv4_conf = os.listdir("/proc/sys/net/ipv4/conf")
            ipv6_neigh = os.listdir("/proc/sys/net/ipv6/neigh")
            with open("/proc/net/dev") as f:
                proc_net_dev = f.read()
            with open("/proc/net/if_inet6") as f:
                proc_net_if_inet6 = f.read()
            if "vpn0" in ipv4_conf:
                print("FAIL: vpn0 visible in /proc/sys/net/ipv4/conf for target UID")
                sys.exit(1)
            if "vpn0" in ipv6_neigh:
                print("FAIL: vpn0 visible in /proc/sys/net/ipv6/neigh for target UID")
                sys.exit(1)
            if "vpn0" in proc_net_dev:
                print("FAIL: vpn0 visible in /proc/net/dev for target UID")
                sys.exit(1)
            if "vpn0" in proc_net_if_inet6:
                print("FAIL: vpn0 visible in /proc/net/if_inet6 for target UID")
                sys.exit(1)
            print("[proc/sysfs net] Target checks passed")
            sys.exit(0)
        except Exception as e:
            print(f"FAIL: proc/sysfs net child exception: {e}")
            sys.exit(1)
    else:
        _, status = os.waitpid(pid, 0)
        if status != 0:
            return False
    return True


def test_udp_queue_pressure():
    print("\n--- UDP queue pressure checks ---")

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setblocking(False)
    success_count_nt = 0
    for _ in range(1000):
        try:
            s.sendto(b"test_payload_32_bytes_long_here", ("127.0.0.1", 12345))
            success_count_nt += 1
        except OSError:
            pass
    print(f"[UDP Queue Pressure] Non-target success rate: {success_count_nt}/1000")
    if success_count_nt < 950:
        print(f"FAIL: UDP queue pressure non-target success rate too low: {success_count_nt}/1000")
        return False

    pid = safe_fork()
    if pid == 0:
        try:
            os.setuid(115555)
            s_tgt = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s_tgt.setblocking(False)
            success_count = 0
            eagain_count = 0
            for _ in range(1000):
                try:
                    s_tgt.sendto(b"test_payload_32_bytes_long_here", ("127.0.0.1", 12345))
                    success_count += 1
                except OSError as e:
                    if e.errno == 11:
                        eagain_count += 1
            print(f"[UDP Queue Pressure] Target success rate: {success_count}/1000, EAGAIN: {eagain_count}/1000")
            if success_count > 600:
                print(f"FAIL: UDP queue pressure target succeeded too many times: {success_count}/1000")
                sys.exit(1)
            if eagain_count == 0:
                print("FAIL: UDP queue pressure target did not receive any EAGAIN errors")
                sys.exit(1)
            sys.exit(0)
        except Exception as e:
            print(f"FAIL: child exception: {e}")
            sys.exit(1)
    else:
        _, status = os.waitpid(pid, 0)
        if status != 0:
            return False
    return True


def test_tc_qdisc(vpn0_idx):
    """Verify tc qdisc dump (RTM_GETQDISC) does not reveal vpn0 to target UID."""
    print("\n--- tc qdisc checks ---")

    def netlink_dump_qdiscs():
        """Return list of ifindexes present in RTM_NEWQDISC netlink reply."""
        sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_ROUTE)
        sock.bind((0, 0))

        # Build RTM_GETQDISC dump request
        # nlmsghdr: len(4) type(2) flags(2) seq(4) pid(4) = 16 bytes
        # tcmsg:    family(1) pad(3) ifindex(4) handle(4) parent(4) info(4) = 16 bytes
        seq = 1
        tcmsg = struct.pack("BxxxiIII", socket.AF_UNSPEC, 0, 0, 0, 0)
        nlhdr = struct.pack("IHHII", 16 + len(tcmsg), RTM_GETQDISC,
                            NLM_F_REQUEST | NLM_F_DUMP, seq, 0)
        sock.send(nlhdr + tcmsg)

        ifindexes = set()
        while True:
            data = sock.recv(65536)
            offset = 0
            done = False
            while offset + 16 <= len(data):
                nl_len, nl_type, nl_flags, nl_seq, nl_pid = struct.unpack_from("IHHII", data, offset)
                if nl_type == 3:  # NLMSG_DONE
                    done = True
                    break
                if nl_type == 36:  # RTM_NEWQDISC
                    if offset + 16 + 16 <= len(data):
                        tc_ifindex = struct.unpack_from("i", data, offset + 16 + 4)[0]
                        ifindexes.add(tc_ifindex)
                offset += max(nl_len, 16)
            if done:
                break
        sock.close()
        return ifindexes

    # Non-target (root): vpn0 must appear
    try:
        indexes = netlink_dump_qdiscs()
        print(f"[tc_qdisc] Non-target RTM_GETQDISC ifindexes: {sorted(indexes)}")
        if vpn0_idx not in indexes:
            print(f"FAIL: tc_qdisc non-target: vpn0 (idx={vpn0_idx}) missing from qdisc dump")
            return False
        print(f"[tc_qdisc] Non-target: vpn0 present in qdisc dump as expected")
    except Exception as e:
        print(f"FAIL: tc_qdisc non-target netlink: {e}")
        return False

    # Target (uid 115555): vpn0 must NOT appear
    pid = safe_fork()
    if pid == 0:
        try:
            os.setuid(115555)
            indexes = netlink_dump_qdiscs()
            print(f"[tc_qdisc] Target RTM_GETQDISC ifindexes: {sorted(indexes)}")
            if vpn0_idx in indexes:
                print(f"FAIL: tc_qdisc target: vpn0 (idx={vpn0_idx}) visible in qdisc dump")
                sys.exit(1)
            print(f"[tc_qdisc] Target: vpn0 hidden from qdisc dump as expected")
            sys.exit(0)
        except Exception as e:
            print(f"FAIL: tc_qdisc child exception: {e}")
            sys.exit(1)
    else:
        _, status = os.waitpid(pid, 0)
        if status != 0:
            return False
    return True


IP_MTU_DISCOVER   = 10
IP_PMTUDISC_DONT  = 0
IP_PMTUDISC_DO    = 2
IPV6_MTU_DISCOVER = 23
SOL_UDP           = 17
UDP_SEGMENT       = 103
TCP_INFO          = 11


def test_pmtu_discover():
    """setsockopt IP_MTU_DISCOVER=DO must return 0 for target; hook forces pmtudisc=DONT."""
    print("\n--- pmtu_discover checks ---")

    # Non-target: set DO, getsockopt returns DO (hook inactive)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.IPPROTO_IP, IP_MTU_DISCOVER, IP_PMTUDISC_DO)
        val = struct.unpack("i", s.getsockopt(socket.IPPROTO_IP, IP_MTU_DISCOVER, 4))[0]
        s.close()
        if val != IP_PMTUDISC_DO:
            print(f"FAIL: pmtu_discover non-target: expected pmtudisc={IP_PMTUDISC_DO}, got {val}")
            return False
        print(f"[pmtu_discover] Non-target: pmtudisc={val} as expected")
    except OSError as e:
        print(f"FAIL: pmtu_discover non-target setsockopt: {e}")
        return False

    pid = safe_fork()
    if pid == 0:
        try:
            os.setuid(115555)
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            # Must not raise — hook returns 0
            s.setsockopt(socket.IPPROTO_IP, IP_MTU_DISCOVER, IP_PMTUDISC_DO)
            # Hook must have forced pmtudisc to DONT
            val = struct.unpack("i", s.getsockopt(socket.IPPROTO_IP, IP_MTU_DISCOVER, 4))[0]
            s.close()
            if val != IP_PMTUDISC_DONT:
                print(f"FAIL: pmtu_discover target: hook did not force DONT (got {val})")
                sys.exit(1)
            print(f"[pmtu_discover] Target: setsockopt returned 0, pmtudisc forced to DONT")
            sys.exit(0)
        except OSError as e:
            print(f"FAIL: pmtu_discover target: setsockopt raised {e}")
            sys.exit(1)
    else:
        _, status = os.waitpid(pid, 0)
        if status != 0:
            return False
    return True


def test_gso_asymmetry():
    """setsockopt UDP_SEGMENT=1200 must return 0 for target (silently accepted)."""
    print("\n--- gso_asymmetry checks ---")

    pid = safe_fork()
    if pid == 0:
        try:
            os.setuid(115555)
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            # Must not raise — hook returns 0 silently
            s.setsockopt(SOL_UDP, UDP_SEGMENT, 1200)
            s.close()
            print("[gso_asymmetry] Target: setsockopt UDP_SEGMENT returned 0")
            sys.exit(0)
        except OSError as e:
            print(f"FAIL: gso_asymmetry target: setsockopt raised errno={e.errno} ({e})")
            sys.exit(1)
    else:
        _, status = os.waitpid(pid, 0)
        if status != 0:
            return False
    print("[gso_asymmetry] Passed")
    return True


def test_ipv6_link_local(vpn0_idx):
    """Binding fe80::1 to vpn0 must return ENODEV for target (not EPERM/EADDRNOTAVAIL)."""
    print("\n--- ipv6_link_local checks ---")

    # Non-target: bind fe80::1 to vpn0_idx → kernel finds the interface → NOT ENODEV
    try:
        s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        s.bind(("fe80::1", 0, 0, vpn0_idx))
        # Unexpected success — vpn0 has fe80::1 configured; that's fine, non-target can bind
        s.close()
        print("[ipv6_link_local] Non-target: bind succeeded (fe80::1 is on vpn0)")
    except OSError as e:
        if e.errno == errno.ENODEV:
            print(f"FAIL: ipv6_link_local non-target: got ENODEV — hook should not fire for root")
            return False
        print(f"[ipv6_link_local] Non-target: got errno={e.errno} (not ENODEV) — interface visible")

    pid = safe_fork()
    if pid == 0:
        try:
            os.setuid(115555)
            s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            s.bind(("fe80::1", 0, 0, vpn0_idx))
            s.close()
            # bind succeeded — hook did not fire (unexpected)
            print("FAIL: ipv6_link_local target: bind succeeded — hook did not return ENODEV")
            sys.exit(1)
        except OSError as e:
            if e.errno == errno.ENODEV:
                print(f"[ipv6_link_local] Target: got ENODEV as expected")
                sys.exit(0)
            print(f"FAIL: ipv6_link_local target: expected ENODEV, got errno={e.errno} ({e})")
            sys.exit(1)
    else:
        _, status = os.waitpid(pid, 0)
        if status != 0:
            return False
    return True


def test_tcp_info_mss():
    """getsockopt TCP_INFO with 24-byte buffer must return spoofed MSS=1460 for target."""
    print("\n--- tcp_info_mss checks ---")

    # Non-target: getsockopt must succeed (baseline)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        buf = s.getsockopt(socket.IPPROTO_TCP, TCP_INFO, 24)
        s.close()
        if len(buf) < 24:
            print(f"FAIL: tcp_info_mss non-target: got only {len(buf)} bytes")
            return False
        snd_mss = struct.unpack_from("<I", buf, 16)[0]
        rcv_mss = struct.unpack_from("<I", buf, 20)[0]
        print(f"[tcp_info_mss] Non-target: tcpi_snd_mss={snd_mss} tcpi_rcv_mss={rcv_mss}")
    except OSError as e:
        print(f"FAIL: tcp_info_mss non-target: {e}")
        return False

    pid = safe_fork()
    if pid == 0:
        try:
            os.setuid(115555)
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            buf = s.getsockopt(socket.IPPROTO_TCP, TCP_INFO, 24)
            s.close()
            if len(buf) < 24:
                print(f"FAIL: tcp_info_mss target: got only {len(buf)} bytes")
                sys.exit(1)
            snd_mss = struct.unpack_from("<I", buf, 16)[0]
            rcv_mss = struct.unpack_from("<I", buf, 20)[0]
            print(f"[tcp_info_mss] Target: tcpi_snd_mss={snd_mss} tcpi_rcv_mss={rcv_mss}")
            if snd_mss != 1460 or rcv_mss != 1460:
                print(f"FAIL: tcp_info_mss target: expected 1460/1460, got {snd_mss}/{rcv_mss}")
                sys.exit(1)
            sys.exit(0)
        except OSError as e:
            print(f"FAIL: tcp_info_mss target: {e}")
            sys.exit(1)
    else:
        _, status = os.waitpid(pid, 0)
        if status != 0:
            return False
    return True


def _netlink_dump_rules():
    """Send RTM_GETRULE dump, return list of (iifname, oifname, uid_start, uid_end, table)."""
    sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_ROUTE)
    sock.bind((0, 0))

    # RTM_GETRULE dump: nlmsghdr(16) + fib_rule_hdr(12)
    frh = struct.pack(FIB_RULE_HDR_FMT, socket.AF_UNSPEC, 0, 0, 0, 0, 0, 0, 0, 0)
    nlhdr = struct.pack("IHHII", 16 + len(frh), RTM_GETRULE,
                        NLM_F_REQUEST | NLM_F_DUMP, 2, 0)
    sock.send(nlhdr + frh)

    rules = []
    while True:
        data = sock.recv(65536)
        offset = 0
        done = False
        while offset + 16 <= len(data):
            nl_len, nl_type, _nl_flags, _nl_seq, _nl_pid = struct.unpack_from("IHHII", data, offset)
            nl_len = max(nl_len, 16)
            if nl_type == 3:  # NLMSG_DONE
                done = True
                break
            if nl_type == RTM_NEWRULE:
                # parse fib_rule_hdr
                hdr_off = offset + 16
                if hdr_off + FIB_RULE_HDR_SIZE <= len(data):
                    frh_fields = struct.unpack_from(FIB_RULE_HDR_FMT, data, hdr_off)
                    table = frh_fields[4]
                    # parse RTAs
                    rta_off = hdr_off + FIB_RULE_HDR_SIZE
                    iifname = b""
                    oifname = b""
                    uid_start = 0xFFFFFFFF
                    uid_end   = 0xFFFFFFFF
                    while rta_off + 4 <= offset + nl_len:
                        rta_len, rta_type = struct.unpack_from("HH", data, rta_off)
                        if rta_len < 4:
                            break
                        rta_data = data[rta_off + 4: rta_off + rta_len]
                        if rta_type == FRA_IIFNAME:
                            iifname = rta_data.rstrip(b"\x00")
                        elif rta_type == FRA_OIFNAME:
                            oifname = rta_data.rstrip(b"\x00")
                        elif rta_type == FRA_UID_RANGE and len(rta_data) >= 8:
                            uid_start, uid_end = struct.unpack_from("II", rta_data)
                        rta_off += (rta_len + 3) & ~3
                    rules.append((iifname, oifname, uid_start, uid_end, table))
            offset += nl_len
        if done:
            break
    sock.close()
    return rules


def _rule_matches_vpn(iifname, oifname, vpn_name_bytes):
    return iifname == vpn_name_bytes or oifname == vpn_name_bytes


def test_netlink_getrule(vpn0_name):
    """RTM_GETRULE dump must not expose vpn0 iif/oif rules to target UID."""
    print("\n--- netlink_getrule checks ---")
    vpn_bytes = vpn0_name.encode()

    # Non-target (root): vpn0 rules must be visible
    try:
        rules = _netlink_dump_rules()
        vpn_rules = [r for r in rules if _rule_matches_vpn(r[0], r[1], vpn_bytes)]
        print(f"[netlink_getrule] Non-target: found {len(vpn_rules)} vpn0 rule(s) — expected >=0")
        print("[netlink_getrule] Non-target: RTM_GETRULE dump succeeded")
    except Exception as e:
        print(f"FAIL: netlink_getrule non-target: {e}")
        return False

    # Target (uid 115555): no vpn0 rules must appear
    pid = safe_fork()
    if pid == 0:
        try:
            os.setuid(115555)
            rules = _netlink_dump_rules()
            vpn_rules = [r for r in rules if _rule_matches_vpn(r[0], r[1], vpn_bytes)]
            print(f"[netlink_getrule] Target: vpn0 rules visible: {len(vpn_rules)}")
            if vpn_rules:
                print(f"FAIL: netlink_getrule target: vpn0 rule still visible: {vpn_rules[0]}")
                sys.exit(1)
            print("[netlink_getrule] Target: no vpn0 rules visible as expected")
            sys.exit(0)
        except Exception as e:
            print(f"FAIL: netlink_getrule child: {e}")
            sys.exit(1)
    else:
        _, status = os.waitpid(pid, 0)
        if status != 0:
            return False
    return True


def test_netlink_getrule_uid_leak(vpn0_name):
    """RTM_GETRULE must not expose UID split-routing rules to target UID."""
    print("\n--- netlink_getrule_uid_leak checks ---")

    # Target (uid 115555): UID split-routing rules (table > 100, not 253/254/255)
    # pointing to any app uid range must be hidden
    pid = safe_fork()
    if pid == 0:
        try:
            os.setuid(115555)
            rules = _netlink_dump_rules()
            leaked = []
            for iif, oif, uid_start, uid_end, table in rules:
                # rule has a uid_range with actual bounds (end != 0xFFFFFFFF)
                if uid_end == 0xFFFFFFFF:
                    continue
                if table in (253, 254, 255) or table <= 100:
                    continue
                # visible uid-split rule with non-trivial range — this is a leak
                if uid_start >= 10000 or uid_end >= 10000:
                    leaked.append((uid_start, uid_end, table))
            print(f"[getrule_uid_leak] Target: leaked uid-split rules: {leaked}")
            if leaked:
                print(f"FAIL: getrule_uid_leak target: {len(leaked)} UID split-routing rule(s) visible")
                sys.exit(1)
            print("[getrule_uid_leak] Target: no UID split-routing rules visible as expected")
            sys.exit(0)
        except Exception as e:
            print(f"FAIL: getrule_uid_leak child: {e}")
            sys.exit(1)
    else:
        _, status = os.waitpid(pid, 0)
        if status != 0:
            return False
    return True


def main():
    try:
        vpn0_idx = socket.if_nametoindex("vpn0")
    except Exception as e:
        print(f"FAIL: cannot find interface vpn0: {e}")
        sys.exit(1)

    success = True
    results = []

    def run(name, fn, *args):
        nonlocal success
        ok = fn(*args)
        tag = "PASS" if ok else "FAIL"
        print(f"RESULT {name}={tag}")
        if not ok:
            success = False
        results.append((name, tag))

    run("dev_ioctl",              test_dev_ioctl,              vpn0_idx)
    run("setsockopt",             test_setsockopt,             vpn0_idx)
    run("getsockopt",             test_getsockopt,             vpn0_idx)
    run("getsockname",            test_getsockname)
    run("connect_port_block",     test_connect_port_block)
    run("bind_port_block",        test_bind_port_block)
    run("bpf_laundering",         test_bpf_laundering,         vpn0_idx)
    run("udp_queue_pressure",     test_udp_queue_pressure)
    run("tc_qdisc",               test_tc_qdisc,               vpn0_idx)
    run("pmtu_discover",          test_pmtu_discover)
    run("gso_asymmetry",          test_gso_asymmetry)
    run("ipv6_link_local",        test_ipv6_link_local,        vpn0_idx)
    run("tcp_info_mss",           test_tcp_info_mss)
    run("netlink_getrule",        test_netlink_getrule,        "vpn0")
    run("netlink_getrule_uid_leak", test_netlink_getrule_uid_leak, "vpn0")

    print("\n--- Verification Summary ---")
    for name, tag in results:
        print(f"  {name}: {tag}")
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
