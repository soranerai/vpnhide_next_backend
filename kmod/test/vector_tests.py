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

# Constants
SO_BINDTODEVICE = getattr(socket, "SO_BINDTODEVICE", 25)
SO_BINDTOIFINDEX = 62  # On Linux (asm-generic/socket.h), SO_BINDTOIFINDEX is 62
SIOCGIFFLAGS = 0x8913
SIOCGIFADDR = 0x8915
SIOCGIFDSTADDR = 0x8917
SIOCGIFNETMASK = 0x891B


def safe_fork():
    """Flush buffers before forking to prevent duplicate log outputs in child processes."""
    sys.stdout.flush()
    sys.stderr.flush()
    return os.fork()


def test_dev_ioctl(vpn0_idx):
    print("\n--- dev_ioctl checks ---")

    # 1. Non-target check (root)
    try:
        idx = socket.if_nametoindex("vpn0")
        print(
            f"[dev_ioctl] Non-target if_nametoindex('vpn0') returned: {idx} (expected: {vpn0_idx})"
        )
        assert idx == vpn0_idx, f"Expected index {vpn0_idx}, got {idx}"
    except Exception as e:
        print(f"FAIL: dev_ioctl if_nametoindex non-target: {e}")
        return False

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # Test SIOCGIFFLAGS (non-target, should succeed)
    try:
        ifr = struct.pack("16sH", b"vpn0", 0)
        fcntl.ioctl(s.fileno(), SIOCGIFFLAGS, ifr)
        print(
            "[dev_ioctl] Non-target ioctl(SIOCGIFFLAGS, 'vpn0') succeeded as expected"
        )
    except Exception as e:
        print(f"FAIL: dev_ioctl SIOCGIFFLAGS non-target: {e}")
        return False

    # Test SIOCGIFADDR (non-target, should succeed)
    try:
        ifr = struct.pack("16sH", b"vpn0", 0)
        fcntl.ioctl(s.fileno(), SIOCGIFADDR, ifr)
        print("[dev_ioctl] Non-target ioctl(SIOCGIFADDR, 'vpn0') succeeded as expected")
    except Exception as e:
        print(f"FAIL: dev_ioctl SIOCGIFADDR non-target: {e}")
        return False

    # Test SIOCGIFDSTADDR (non-target, should succeed)
    try:
        ifr = struct.pack("16sH", b"vpn0", 0)
        fcntl.ioctl(s.fileno(), SIOCGIFDSTADDR, ifr)
        print(
            "[dev_ioctl] Non-target ioctl(SIOCGIFDSTADDR, 'vpn0') succeeded as expected"
        )
    except Exception as e:
        print(f"FAIL: dev_ioctl SIOCGIFDSTADDR non-target: {e}")
        return False

    # Test SIOCGIFNETMASK (non-target, should succeed)
    try:
        ifr = struct.pack("16sH", b"vpn0", 0)
        fcntl.ioctl(s.fileno(), SIOCGIFNETMASK, ifr)
        print(
            "[dev_ioctl] Non-target ioctl(SIOCGIFNETMASK, 'vpn0') succeeded as expected"
        )
    except Exception as e:
        print(f"FAIL: dev_ioctl SIOCGIFNETMASK non-target: {e}")
        return False

    # 2. Target check (UID 115555)
    pid = safe_fork()
    if pid == 0:
        # Child process
        try:
            os.setuid(115555)
            # Should fail (raises OSError/ValueError)
            try:
                socket.if_nametoindex("vpn0")
                print(
                    "FAIL: dev_ioctl if_nametoindex target succeeded but should have failed"
                )
                sys.exit(1)
            except (OSError, ValueError) as e:
                print(
                    f"[dev_ioctl] Target if_nametoindex('vpn0') failed as expected: {e}"
                )

            # Test SIOCGIFFLAGS (target, should fail with ENODEV)
            try:
                ifr = struct.pack("16sH", b"vpn0", 0)
                fcntl.ioctl(s.fileno(), SIOCGIFFLAGS, ifr)
                print(
                    "FAIL: dev_ioctl SIOCGIFFLAGS target succeeded but should have failed"
                )
                sys.exit(1)
            except OSError as e:
                if e.errno != 19:  # ENODEV
                    print(
                        f"FAIL: dev_ioctl SIOCGIFFLAGS target expected errno 19, got {e.errno}"
                    )
                    sys.exit(1)
                print(
                    f"[dev_ioctl] Target ioctl(SIOCGIFFLAGS, 'vpn0') failed as expected: errno {e.errno}"
                )

            # Test SIOCGIFADDR (target, should fail with ENODEV)
            try:
                ifr = struct.pack("16sH", b"vpn0", 0)
                fcntl.ioctl(s.fileno(), SIOCGIFADDR, ifr)
                print(
                    "FAIL: dev_ioctl SIOCGIFADDR target succeeded but should have failed"
                )
                sys.exit(1)
            except OSError as e:
                if e.errno != 19:  # ENODEV
                    print(
                        f"FAIL: dev_ioctl SIOCGIFADDR target expected errno 19, got {e.errno}"
                    )
                    sys.exit(1)
                print(
                    f"[dev_ioctl] Target ioctl(SIOCGIFADDR, 'vpn0') failed as expected: errno {e.errno}"
                )

            # Test SIOCGIFDSTADDR (target, should fail with ENODEV)
            try:
                ifr = struct.pack("16sH", b"vpn0", 0)
                fcntl.ioctl(s.fileno(), SIOCGIFDSTADDR, ifr)
                print(
                    "FAIL: dev_ioctl SIOCGIFDSTADDR target succeeded but should have failed"
                )
                sys.exit(1)
            except OSError as e:
                if e.errno != 19:  # ENODEV
                    print(
                        f"FAIL: dev_ioctl SIOCGIFDSTADDR target expected errno 19, got {e.errno}"
                    )
                    sys.exit(1)
                print(
                    f"[dev_ioctl] Target ioctl(SIOCGIFDSTADDR, 'vpn0') failed as expected: errno {e.errno}"
                )

            # Test SIOCGIFNETMASK (target, should fail with ENODEV)
            try:
                ifr = struct.pack("16sH", b"vpn0", 0)
                fcntl.ioctl(s.fileno(), SIOCGIFNETMASK, ifr)
                print(
                    "FAIL: dev_ioctl SIOCGIFNETMASK target succeeded but should have failed"
                )
                sys.exit(1)
            except OSError as e:
                if e.errno != 19:  # ENODEV
                    print(
                        f"FAIL: dev_ioctl SIOCGIFNETMASK target expected errno 19, got {e.errno}"
                    )
                    sys.exit(1)
                print(
                    f"[dev_ioctl] Target ioctl(SIOCGIFNETMASK, 'vpn0') failed as expected: errno {e.errno}"
                )

            sys.exit(0)
        except Exception as e:
            print(f"FAIL: child process exception: {e}")
            sys.exit(1)
    else:
        # Parent
        wpid, status = os.waitpid(pid, 0)
        if status != 0:
            return False
    return True


def test_setsockopt(vpn0_idx):
    print("\n--- setsockopt checks ---")

    # 1. Non-target checks (root)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.setsockopt(socket.SOL_SOCKET, SO_BINDTODEVICE, b"vpn0")
        print(
            "[setsockopt] Non-target setsockopt(SO_BINDTODEVICE, 'vpn0') succeeded as expected"
        )
    except Exception as e:
        print(f"FAIL: setsockopt SO_BINDTODEVICE non-target: {e}")
        return False

    s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s2.setsockopt(socket.SOL_SOCKET, SO_BINDTOIFINDEX, struct.pack("i", vpn0_idx))
        print(
            f"[setsockopt] Non-target setsockopt(SO_BINDTOIFINDEX, {vpn0_idx}) succeeded as expected"
        )
    except Exception as e:
        print(f"FAIL: setsockopt SO_BINDTOIFINDEX non-target: {e}")
        return False

    # 2. Target check (UID 115555). Create the socket before fork so the
    # parent can verify that a rejected bind left kernel socket state intact.
    s_tgt = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    pid = safe_fork()
    if pid == 0:
        try:
            os.setuid(115555)
            try:
                s_tgt.setsockopt(socket.SOL_SOCKET, SO_BINDTODEVICE, b"vpn0")
                print(
                    "FAIL: setsockopt SO_BINDTODEVICE target succeeded but should have failed"
                )
                sys.exit(1)
            except OSError as e:
                print(
                    f"[setsockopt] Target setsockopt(SO_BINDTODEVICE, 'vpn0') failed as expected: errno {e.errno} ({e.strerror})"
                )
                if e.errno != 19:
                    print(
                        f"FAIL: setsockopt SO_BINDTODEVICE target expected errno 19, got {e.errno}"
                    )
                    sys.exit(1)

            try:
                s_tgt.setsockopt(
                    socket.SOL_SOCKET, SO_BINDTOIFINDEX, struct.pack("i", vpn0_idx)
                )
                print(
                    "FAIL: setsockopt SO_BINDTOIFINDEX target succeeded but should have failed"
                )
                sys.exit(1)
            except OSError as e:
                print(
                    f"[setsockopt] Target setsockopt(SO_BINDTOIFINDEX, {vpn0_idx}) failed as expected: errno {e.errno} ({e.strerror})"
                )
                if e.errno != 19:
                    print(
                        f"FAIL: setsockopt SO_BINDTOIFINDEX target expected errno 19, got {e.errno}"
                    )
                    sys.exit(1)

            sys.exit(0)
        except Exception as e:
            print(f"FAIL: child exception: {e}")
            sys.exit(1)
    else:
        wpid, status = os.waitpid(pid, 0)
        if status != 0:
            return False
        bound_ifindex = struct.unpack(
            "i", s_tgt.getsockopt(socket.SOL_SOCKET, SO_BINDTOIFINDEX, 4)
        )[0]
        if bound_ifindex != 0:
            print(
                f"FAIL: rejected SO_BINDTOIFINDEX changed socket state to {bound_ifindex}"
            )
            return False
    return True


def test_getsockopt(vpn0_idx):
    print("\n--- getsockopt checks ---")

    # Setup bound sockets as root
    s_dev = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s_dev.setsockopt(socket.SOL_SOCKET, SO_BINDTODEVICE, b"vpn0\x00")

    s_idx = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s_idx.setsockopt(socket.SOL_SOCKET, SO_BINDTOIFINDEX, struct.pack("i", vpn0_idx))

    # Drop privileges to target UID (115555)
    pid = safe_fork()
    if pid == 0:
        try:
            os.setuid(115555)
            # 1. getsockopt SO_BINDTODEVICE
            val = s_dev.getsockopt(socket.SOL_SOCKET, SO_BINDTODEVICE, 256)
            clean_val = val.strip(b"\x00")
            print(
                f"[getsockopt] Target getsockopt(SO_BINDTODEVICE) returned: {clean_val!r} (expected: empty)"
            )
            if clean_val != b"":
                print(
                    f"FAIL: getsockopt SO_BINDTODEVICE target: expected empty string, got {clean_val}"
                )
                sys.exit(1)

            # 2. getsockopt SO_BINDTOIFINDEX
            val_idx = s_idx.getsockopt(socket.SOL_SOCKET, SO_BINDTOIFINDEX, 4)
            idx = struct.unpack("i", val_idx)[0]
            print(
                f"[getsockopt] Target getsockopt(SO_BINDTOIFINDEX) returned: {idx} (expected: 0)"
            )
            if idx != 0:
                print(
                    f"FAIL: getsockopt SO_BINDTOIFINDEX target: expected 0, got {idx}"
                )
                sys.exit(1)

            sys.exit(0)
        except Exception as e:
            print(f"FAIL: child exception: {e}")
            sys.exit(1)
    else:
        wpid, status = os.waitpid(pid, 0)
        if status != 0:
            return False
    return True


def test_getsockname():
    print("\n--- getsockname spoofing checks ---")

    # Bind IPv4 UDP socket to 10.9.0.1
    s_v4 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s_v4.bind(("10.9.0.1", 0))
        ip4_nt, port4_nt = s_v4.getsockname()
        print(
            f"[getsockname] Non-target getsockname IPv4: {ip4_nt}:{port4_nt} (expected: 10.9.0.1)"
        )
    except Exception as e:
        print(f"FAIL: getsockname IPv4 bind: {e}")
        return False

    # Bind IPv6 UDP socket to fd00:9::1
    s_v6 = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    try:
        s_v6.bind(("fd00:9::1", 0))
        ip6_nt, port6_nt, _, _ = s_v6.getsockname()
        print(
            f"[getsockname] Non-target getsockname IPv6: [{ip6_nt}]:{port6_nt} (expected: fd00:9::1)"
        )
    except Exception as e:
        print(f"FAIL: getsockname IPv6 bind: {e}")
        return False

    # Drop privileges to target UID (115555)
    pid = safe_fork()
    if pid == 0:
        try:
            os.setuid(115555)
            # IPv4 getsockname
            ip4, port4 = s_v4.getsockname()
            print(
                f"[getsockname] Target getsockname IPv4: {ip4}:{port4} (expected: spoofed/shielded from 10.9.0.1)"
            )
            if ip4 == "10.9.0.1":
                print(f"FAIL: getsockname IPv4 target: got unshielded VPN IP '{ip4}'")
                sys.exit(1)

            # IPv6 getsockname
            ip6, port6, flow, scope = s_v6.getsockname()
            print(
                f"[getsockname] Target getsockname IPv6: [{ip6}]:{port6} (expected: spoofed/shielded from fd00:9::1)"
            )
            if ip6 == "fd00:9::1":
                print(f"FAIL: getsockname IPv6 target: got unshielded VPN IP '{ip6}'")
                sys.exit(1)

            sys.exit(0)
        except Exception as e:
            print(f"FAIL: child exception: {e}")
            sys.exit(1)
    else:
        wpid, status = os.waitpid(pid, 0)
        if status != 0:
            return False
    return True


def test_pktinfo(vpn0_idx):
    """IP_PKTINFO must expose the cover ifindex and preserve multicast dst."""
    print("\n--- IP_PKTINFO ancillary-data checks ---")
    ip_pktinfo = getattr(socket, "IP_PKTINFO", 8)
    group = "239.255.0.1"
    receiver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    receiver.settimeout(2)
    try:
        receiver.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        receiver.setsockopt(socket.IPPROTO_IP, ip_pktinfo, 1)
        receiver.bind(("", 0))
        membership = socket.inet_aton(group) + socket.inet_aton("10.9.0.1")
        receiver.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, membership)
        sender.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF,
                          socket.inet_aton("10.9.0.1"))
        sender.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 1)
        destination = (group, receiver.getsockname()[1])

        def receive_info(payload):
            sender.sendto(payload, destination)
            data, ancillary, _, _ = receiver.recvmsg(64, 256)
            if data != payload:
                raise RuntimeError("unexpected multicast payload")
            for level, kind, value in ancillary:
                if level == socket.IPPROTO_IP and kind == ip_pktinfo:
                    ifindex, _, dst = struct.unpack("=I4s4s", value[:12])
                    return ifindex, socket.inet_ntoa(dst)
            raise RuntimeError("IP_PKTINFO CMSG missing")

        root_ifindex, root_dst = receive_info(b"root")
        if root_ifindex != vpn0_idx or root_dst != group:
            print(f"FAIL: pktinfo non-target got ifindex={root_ifindex}, dst={root_dst}")
            return False

        pid = safe_fork()
        if pid == 0:
            try:
                os.setuid(115555)
                target_ifindex, target_dst = receive_info(b"target")
                print(f"[pktinfo] Target ifindex={target_ifindex}, dst={target_dst}")
                if target_ifindex == vpn0_idx or target_ifindex <= 0:
                    print("FAIL: pktinfo target leaked VPN ifindex")
                    sys.exit(1)
                if target_dst != group:
                    print("FAIL: pktinfo target changed multicast destination")
                    sys.exit(1)
                sys.exit(0)
            except Exception as e:
                print(f"FAIL: pktinfo target: {e}")
                sys.exit(1)
        _, status = os.waitpid(pid, 0)
        return status == 0
    except Exception as e:
        print(f"FAIL: pktinfo setup/non-target: {e}")
        return False
    finally:
        receiver.close()
        sender.close()


def test_connect_port_block():
    print("\n--- connect port block checks ---")

    # Start a TCP listener on loopback port 8080 (as root)
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        listener.bind(("127.0.0.1", 8080))
        listener.listen(1)
    except Exception as e:
        print(f"FAIL: connect port block listener bind/listen: {e}")
        return False

    # First verify that non-target (root) can connect successfully
    s_nt = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s_nt.settimeout(2.0)
    try:
        s_nt.connect(("127.0.0.1", 8080))
        s_nt.close()
        print(
            "[connect_port_block] Non-target connected to 127.0.0.1:8080 successfully as expected"
        )
    except Exception as e:
        print(f"FAIL: connect port block non-target connection failed: {e}")
        listener.close()
        return False

    # Drop privileges and verify target is blocked (receives ECONNREFUSED)
    pid = safe_fork()
    if pid == 0:
        try:
            os.setuid(115555)
            s_tgt = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s_tgt.settimeout(2.0)
            try:
                s_tgt.connect(("127.0.0.1", 8080))
                print(
                    "FAIL: connect port block target succeeded but should have failed"
                )
                sys.exit(1)
            except OSError as e:
                print(
                    f"[connect_port_block] Target connection to 127.0.0.1:8080 failed as expected: errno {e.errno} ({e.strerror})"
                )
                if e.errno != 111:  # ECONNREFUSED is 111
                    print(
                        f"FAIL: connect port block target expected errno 111, got {e.errno}"
                    )
                    sys.exit(1)
            sys.exit(0)
        except Exception as e:
            print(f"FAIL: child exception: {e}")
            sys.exit(1)
    else:
        wpid, status = os.waitpid(pid, 0)
        listener.close()
        if status != 0:
            return False
    return True


def test_bind_port_block():
    print("\n--- explicit bind ownership checks ---")

    # Binding establishes ownership. Policy must not rewrite the requested
    # port, and an immediate same-UID connect must succeed.
    pid = safe_fork()
    if pid == 0:
        try:
            os.setuid(115555)
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                s.bind(("127.0.0.1", 8080))
                ip, port = s.getsockname()
                print(f"[bind_port_block] Target bound to 127.0.0.1:{port}")
                if port != 8080:
                    print(f"FAIL: explicit bind was rewritten to {port}")
                    sys.exit(1)
                s.listen(1)
                client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                client.settimeout(2)
                client.connect(("127.0.0.1", 8080))
                accepted, _ = s.accept()
                accepted.close()
                client.close()
            except Exception as e:
                print(f"FAIL: bind port block target bind error: {e}")
                sys.exit(1)
            sys.exit(0)
        except Exception as e:
            print(f"FAIL: child exception: {e}")
            sys.exit(1)
    else:
        wpid, status = os.waitpid(pid, 0)
        if status != 0:
            return False
    return True


def test_own_port_access():
    print("\n--- own port access checks ---")
    read_fd, write_fd = os.pipe()
    listener_pid = safe_fork()
    if listener_pid == 0:
        os.close(read_fd)
        try:
            os.setuid(115555)
            listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            listener.settimeout(3)
            # Deliberately rely on listen() autobind.  This exercises the
            # post-listen ownership path used when a vendor kernel does not
            # expose a usable syscall/inet bind probe.
            listener.listen(1)
            os.write(write_fd, struct.pack("I", listener.getsockname()[1]))
            connection, _ = listener.accept()
            connection.close()
            listener.close()
            os._exit(0)
        except Exception as error:
            print(f"FAIL: own port listener: {error}", flush=True)
            os._exit(1)

    os.close(write_fd)
    raw_port = os.read(read_fd, 4)
    os.close(read_fd)
    if len(raw_port) != 4:
        os.waitpid(listener_pid, 0)
        print("FAIL: own port listener did not publish its port")
        return False
    port = struct.unpack("I", raw_port)[0]

    # The transient post-bind grant must close the window before the daemon's
    # debounced SOCK_DIAG refresh lands.
    client_pid = safe_fork()
    if client_pid == 0:
        try:
            os.setuid(115555)
            client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client.settimeout(2)
            client.connect(("127.0.0.1", port))
            client.close()
            os._exit(0)
        except Exception as error:
            print(f"FAIL: own port client: {error}", flush=True)
            os._exit(1)
    _, client_status = os.waitpid(client_pid, 0)
    _, listener_status = os.waitpid(listener_pid, 0)
    if client_status == 0 and listener_status == 0:
        print(f"[own_port_access] Target UID connected to its own port {port}")
        return True
    print(
        f"FAIL: own port access client_status={client_status} listener_status={listener_status}"
    )
    return False


def test_owned_port_address_scope():
    print("\n--- owned port address-scope checks ---")
    listeners = []
    try:
        for port in (18081, 18082):
            listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind(("127.0.0.1", port))
            listener.listen(1)
            listeners.append(listener)
    except Exception as error:
        for listener in listeners:
            listener.close()
        print(f"FAIL: address-scope listener setup: {error}")
        return False

    pid = safe_fork()
    if pid == 0:
        try:
            os.setuid(115555)
            decoys = [
                (socket.AF_INET, "127.0.0.2", 18081),
                (socket.AF_INET6, "::1", 18082),
            ]
            for family, address, port in decoys:
                decoy = socket.socket(family, socket.SOCK_STREAM)
                if family == socket.AF_INET6:
                    decoy.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                decoy.bind((address, port))
                decoy.listen(1)
                client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                client.settimeout(1)
                try:
                    client.connect(("127.0.0.1", port))
                    print(f"FAIL: ownership for {address}:{port} leaked to 127.0.0.1")
                    os._exit(1)
                except OSError as error:
                    if error.errno != errno.ECONNREFUSED:
                        print(f"FAIL: address-scope errno={error.errno}")
                        os._exit(1)
                finally:
                    client.close()
                    decoy.close()
            os._exit(0)
        except Exception as error:
            print(f"FAIL: address-scope child: {error}", flush=True)
            os._exit(1)

    _, status = os.waitpid(pid, 0)
    for listener in listeners:
        listener.close()
    if status == 0:
        print("[owned_port_address_scope] exact address and family enforced")
        return True
    return False


# BPF Constants and Structs for Laundering checks

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
        ("rxBytes", ctypes.c_uint64),
        ("rxPackets", ctypes.c_uint64),
        ("txBytes", ctypes.c_uint64),
        ("txPackets", ctypes.c_uint64),
    ]


class BpfAttrCreate(ctypes.Structure):
    _fields_ = [
        ("map_type", ctypes.c_uint32),
        ("key_size", ctypes.c_uint32),
        ("value_size", ctypes.c_uint32),
        ("max_entries", ctypes.c_uint32),
        ("map_flags", ctypes.c_uint32),
        ("inner_map_fd", ctypes.c_uint32),
        ("numa_node", ctypes.c_uint32),
        ("map_name", ctypes.c_char * 16),
        ("map_ifindex", ctypes.c_uint32),
        ("btf_fd", ctypes.c_uint32),
        ("btf_key_type_id", ctypes.c_uint32),
        ("btf_value_type_id", ctypes.c_uint32),
        ("btf_vmlinux_value_type_id", ctypes.c_uint32),
        ("map_extra", ctypes.c_uint64),
    ]


class BpfAttrElem(ctypes.Structure):
    _fields_ = [
        ("map_fd", ctypes.c_uint32),
        ("key", ctypes.c_uint64),
        ("value", ctypes.c_uint64),
        ("flags", ctypes.c_uint64),
    ]


class BpfAttrBatch(ctypes.Structure):
    _fields_ = [
        ("in_batch", ctypes.c_uint64),
        ("out_batch", ctypes.c_uint64),
        ("keys", ctypes.c_uint64),
        ("values", ctypes.c_uint64),
        ("count", ctypes.c_uint32),
        ("map_fd", ctypes.c_uint32),
        ("elem_flags", ctypes.c_uint64),
        ("flags", ctypes.c_uint64),
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
    val = VhStatsValue(
        rxBytes=rx,
        rxPackets=rx // 100 if rx >= 100 else 1,
        txBytes=tx,
        txPackets=tx // 100 if tx >= 100 else 1,
    )
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

    # 1. Create BPF map as root
    try:
        map_fd = create_stats_map()
        print(f"[BPF] Created map 'iface_stats' with fd: {map_fd}")
    except Exception as e:
        print(f"FAIL: BPF map creation: {e}")
        return False

    # 2. Populate stats
    try:
        update_map_elem(map_fd, vpn0_idx, 1000, 2000)
        update_map_elem(map_fd, eth0_idx, 5000, 6000)
    except Exception as e:
        print(f"FAIL: BPF map update: {e}")
        return False

    # 3. Check under Non-target (root): laundering should occur
    try:
        # Check VPN: statistics must be hidden (zeroes)
        vpn_val = lookup_map_elem(map_fd, vpn0_idx)
        print(f"[BPF Non-Target] vpn0: rx={vpn_val.rxBytes}, tx={vpn_val.txBytes}")
        assert vpn_val.rxBytes == 0 and vpn_val.txBytes == 0, "VPN stats not zeroed!"

        # Check cover: statistics must absorb VPN traffic
        eth_val = lookup_map_elem(map_fd, eth0_idx)
        print(f"[BPF Non-Target] eth0: rx={eth_val.rxBytes}, tx={eth_val.txBytes}")
        assert eth_val.rxBytes == 6000 and eth_val.txBytes == 8000, (
            "Cover interface stats not laundered!"
        )
        print("[BPF Non-Target] Single lookup checks passed")
    except Exception as e:
        print(f"FAIL: BPF non-target lookup verification failed: {e}")
        return False

    # 4. Check under Target UID (115555): hook should be bypassed (raw stats visible)
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
        wpid, status = os.waitpid(pid, 0)
        if status != 0:
            return False

    return True


def test_proc_sys_net():
    print("\n--- proc / sysfs net checks ---")

    # 1. Non-target check (root)
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

    # 2. Target check (UID 115555)
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
        wpid, status = os.waitpid(pid, 0)
        if status != 0:
            return False

    return True


def test_udp_queue_pressure():
    print("\n--- UDP queue pressure checks ---")

    # 1. Non-target check (root)
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
        print(
            f"FAIL: UDP queue pressure non-target success rate too low: {success_count_nt}/1000"
        )
        return False

    # 2. Target check (UID 115555)
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
                    s_tgt.sendto(
                        b"test_payload_32_bytes_long_here", ("127.0.0.1", 12345)
                    )
                    success_count += 1
                except OSError as e:
                    if e.errno == 11:  # EAGAIN is 11
                        eagain_count += 1
            print(
                f"[UDP Queue Pressure] Target success rate: {success_count}/1000, EAGAIN: {eagain_count}/1000"
            )
            if success_count > 600:
                print(
                    f"FAIL: UDP queue pressure target succeeded too many times: {success_count}/1000 (should be <= 600)"
                )
                sys.exit(1)
            if eagain_count == 0:
                print(
                    "FAIL: UDP queue pressure target did not receive any EAGAIN errors"
                )
                sys.exit(1)
            sys.exit(0)
        except Exception as e:
            print(f"FAIL: child exception: {e}")
            sys.exit(1)
    else:
        wpid, status = os.waitpid(pid, 0)
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

    # Run dev_ioctl
    if not test_dev_ioctl(vpn0_idx):
        print("RESULT dev_ioctl=FAIL")
        success = False
    else:
        print("RESULT dev_ioctl=PASS")

    # Run setsockopt
    if not test_setsockopt(vpn0_idx):
        print("RESULT setsockopt=FAIL")
        success = False
    else:
        print("RESULT setsockopt=PASS")

    # Run getsockopt
    if not test_getsockopt(vpn0_idx):
        print("RESULT getsockopt=FAIL")
        success = False
    else:
        print("RESULT getsockopt=PASS")

    # Run getsockname
    if not test_getsockname():
        print("RESULT getsockname=FAIL")
        success = False
    else:
        print("RESULT getsockname=PASS")

    if not test_pktinfo(vpn0_idx):
        print("RESULT pktinfo=FAIL")
        success = False
    else:
        print("RESULT pktinfo=PASS")

    # Run connect port block
    if not test_connect_port_block():
        print("RESULT connect_port_block=FAIL")
        success = False
    else:
        print("RESULT connect_port_block=PASS")

    # Run bind port block
    if not test_bind_port_block():
        print("RESULT bind_port_block=FAIL")
        success = False
    else:
        print("RESULT bind_port_block=PASS")

    if not test_own_port_access():
        print("RESULT own_port_access=FAIL")
        success = False
    else:
        print("RESULT own_port_access=PASS")

    if not test_owned_port_address_scope():
        print("RESULT owned_port_address_scope=FAIL")
        success = False
    else:
        print("RESULT owned_port_address_scope=PASS")

    # Run BPF laundering checks
    if not test_bpf_laundering(vpn0_idx):
        print("RESULT bpf_laundering=FAIL")
        success = False
    else:
        print("RESULT bpf_laundering=PASS")

    # Run UDP queue pressure checks
    if not test_udp_queue_pressure():
        print("RESULT udp_queue_pressure=FAIL")
        success = False
    else:
        print("RESULT udp_queue_pressure=PASS")

    print("\n--- Verification Summary ---")
    if not success:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
