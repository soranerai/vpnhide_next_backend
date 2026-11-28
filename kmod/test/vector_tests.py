#!/usr/bin/env python3
import ctypes
import errno
import fcntl
import ipaddress
import mmap
import os
import platform
import socket
import struct
import sys
import tempfile

# ruff: noqa: E501

# Constants
SO_BINDTODEVICE = getattr(socket, "SO_BINDTODEVICE", 25)
SO_BINDTOIFINDEX = 62  # On Linux (asm-generic/socket.h), SO_BINDTOIFINDEX is 62
SIOCGIFFLAGS = 0x8913
SIOCGIFCONF = 0x8912
SIOCGIFADDR = 0x8915
SIOCGIFDSTADDR = 0x8917
SIOCGIFBRDADDR = 0x8919
SIOCGIFNETMASK = 0x891B


def safe_fork():
    """Flush buffers before forking to prevent duplicate log outputs in child processes."""
    sys.stdout.flush()
    sys.stderr.flush()
    return os.fork()


def check_ifconf(fd, hidden):
    class Ifconf(ctypes.Structure):
        _fields_ = [("length", ctypes.c_int), ("buf", ctypes.c_void_p)]

    libc = ctypes.CDLL(None, use_errno=True)
    query = Ifconf(0, None)
    if libc.ioctl(fd, SIOCGIFCONF, ctypes.byref(query)) != 0:
        raise AssertionError(f"ifconf size query: errno={ctypes.get_errno()}")
    capacity = 4096
    buf = (ctypes.c_ubyte * capacity)(*([0xA5] * capacity))
    output = Ifconf(capacity, ctypes.addressof(buf))
    if libc.ioctl(fd, SIOCGIFCONF, ctypes.byref(output)) != 0:
        raise AssertionError(f"ifconf list: errno={ctypes.get_errno()}")
    raw = bytes(buf)
    if output.length != query.length or output.length % 40:
        raise AssertionError(f"ifconf count={query.length} list={output.length}")
    names = [raw[i : i + 16].split(b"\0", 1)[0] for i in range(0, output.length, 40)]
    if (b"vpn0" in names) == hidden or b"eth0" not in names:
        raise AssertionError(f"ifconf hidden={hidden} names={names}")
    if raw[output.length :] != bytes([0xA5]) * (capacity - output.length):
        raise AssertionError("ifconf overwrote memory beyond returned entries")

    # A short buffer must preserve its unused portion and bytes past capacity.
    small = (ctypes.c_ubyte * 160)(*([0xA5] * 160))
    limited = Ifconf(80, ctypes.addressof(small))
    if libc.ioctl(fd, SIOCGIFCONF, ctypes.byref(limited)) != 0:
        raise AssertionError(f"short ifconf: errno={ctypes.get_errno()}")
    if limited.length < 0 or limited.length > 80 or bytes(small)[limited.length :] != bytes([0xA5]) * (160 - limited.length):
        raise AssertionError(f"short ifconf modified tail: length={limited.length}")
    # The kernel must report EFAULT for an inaccessible output buffer, without
    # changing the caller's ifconf length or an adjacent sentinel mapping.
    page = mmap.mmap(-1, mmap.PAGESIZE, prot=mmap.PROT_READ | mmap.PROT_WRITE)
    ptr = ctypes.addressof(ctypes.c_char.from_buffer(page))
    libc.mprotect.argtypes = (ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int)
    blocked = Ifconf(mmap.PAGESIZE, ptr)
    if libc.mprotect(ptr, mmap.PAGESIZE, 0) != 0:
        raise OSError(ctypes.get_errno(), "ifconf mprotect")
    rc = libc.ioctl(fd, SIOCGIFCONF, ctypes.byref(blocked))
    err = ctypes.get_errno()
    if libc.mprotect(ptr, mmap.PAGESIZE, mmap.PROT_READ | mmap.PROT_WRITE) != 0:
        raise OSError(ctypes.get_errno(), "ifconf mprotect restore")
    page.close()
    if rc != -1 or err != errno.EFAULT or blocked.length != mmap.PAGESIZE:
        raise AssertionError(f"ifconf fault rc={rc} errno={err} length={blocked.length}")
    empty = Ifconf(0, ctypes.addressof(buf))
    if libc.ioctl(fd, SIOCGIFCONF, ctypes.byref(empty)) != 0 or empty.length != 0:
        raise AssertionError(f"zero-capacity ifconf rc/length={empty.length}")
    print(f"[ifconf] hidden={hidden} size={query.length} visible={names}; tails intact")


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
    try:
        check_ifconf(s.fileno(), hidden=False)
    except AssertionError as e:
        print(f"FAIL: non-target {e}")
        return False

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
            check_ifconf(s.fileno(), hidden=True)
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

            # Use libc ioctl directly: Python's fcntl.ioctl may use an
            # intermediate buffer and hide writes made before an error.
            libc = ctypes.CDLL(None, use_errno=True)
            for cmd in (SIOCGIFADDR, SIOCGIFDSTADDR, SIOCGIFBRDADDR, SIOCGIFNETMASK):
                for name in (b"vpn0", b"no_vpn_device"):
                    before = name.ljust(16, b"\0") + bytes([0xA5]) * 24
                    buf = ctypes.create_string_buffer(before, len(before))
                    rc = libc.ioctl(s.fileno(), cmd, ctypes.byref(buf))
                    err = ctypes.get_errno()
                    if rc != -1 or err != errno.ENODEV or buf.raw != before:
                        print(f"FAIL: ioctl 0x{cmd:x} {name!r}: rc={rc} errno={err} buffer_changed={buf.raw != before}")
                        sys.exit(1)
            # Visible interfaces must still return their real IPv4 address.
            before = b"eth0".ljust(16, b"\0") + bytes([0xA5]) * 24
            buf = ctypes.create_string_buffer(before, len(before))
            if libc.ioctl(s.fileno(), SIOCGIFADDR, ctypes.byref(buf)) != 0:
                print(f"FAIL: visible eth0 SIOCGIFADDR: errno={ctypes.get_errno()}")
                sys.exit(1)
            if buf.raw[20:24] != socket.inet_aton("10.0.2.15"):
                print(f"FAIL: visible eth0 address: {buf.raw[20:24].hex()}")
                sys.exit(1)
            print("[dev_ioctl] hidden and absent address ioctls leave buffers intact; eth0 remains visible")

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

            libc = ctypes.CDLL(None, use_errno=True)
            invalid_name = ctypes.create_string_buffer(b"vpn0")
            rc = libc.setsockopt(-1, socket.SOL_SOCKET, SO_BINDTODEVICE, invalid_name, len(invalid_name))
            if rc != -1 or ctypes.get_errno() != errno.EBADF:
                print(f"FAIL: invalid fd bind errno={ctypes.get_errno()} rc={rc}")
                sys.exit(1)
            visible = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            visible.setsockopt(socket.SOL_SOCKET, SO_BINDTODEVICE, b"eth0\0")
            if visible.getsockopt(socket.SOL_SOCKET, SO_BINDTODEVICE, 16).rstrip(b"\0") != b"eth0":
                print("FAIL: visible interface bind did not persist")
                sys.exit(1)
            visible.close()
            page = mmap.mmap(-1, mmap.PAGESIZE, prot=mmap.PROT_READ | mmap.PROT_WRITE)
            ptr = ctypes.addressof(ctypes.c_char.from_buffer(page))
            libc.mprotect.argtypes = (ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int)
            for option, value in ((SO_BINDTODEVICE, b"vpn0\0"), (SO_BINDTOIFINDEX, struct.pack("i", vpn0_idx))):
                for readonly in (False, True):
                    page.seek(0)
                    page.write(value)
                    if readonly and libc.mprotect(ptr, mmap.PAGESIZE, mmap.PROT_READ) != 0:
                        raise OSError(ctypes.get_errno(), "mprotect read-only")
                    rc = libc.setsockopt(s_tgt.fileno(), socket.SOL_SOCKET, option, ctypes.c_void_p(ptr), len(value))
                    err = ctypes.get_errno()
                    unchanged = page[:len(value)] == value
                    if readonly and libc.mprotect(ptr, mmap.PAGESIZE, mmap.PROT_READ | mmap.PROT_WRITE) != 0:
                        raise OSError(ctypes.get_errno(), "mprotect restore")
                    if rc != -1 or err != errno.ENODEV or not unchanged:
                        print(f"FAIL: bind option={option} readonly={readonly} rc={rc} errno={err} unchanged={unchanged}")
                        sys.exit(1)
            page.close()

            # A file-backed mapping that has not yet been read exercises the
            # kprobe's in-atomic user access when the page is not resident in
            # this process. The kernel must not accept the hidden bind.
            with tempfile.TemporaryFile() as backing:
                backing.write(b"vpn0\0" + b"\0" * (mmap.PAGESIZE - 5))
                backing.flush()
                libc.mmap.restype = ctypes.c_void_p
                libc.mmap.argtypes = (ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int,
                                      ctypes.c_int, ctypes.c_int, ctypes.c_longlong)
                libc.munmap.argtypes = (ctypes.c_void_p, ctypes.c_size_t)
                cold = libc.mmap(None, mmap.PAGESIZE, mmap.PROT_READ, mmap.MAP_PRIVATE,
                                 backing.fileno(), 0)
                if cold == ctypes.c_void_p(-1).value:
                    raise OSError(ctypes.get_errno(), "mmap cold input")
                rc = libc.setsockopt(s_tgt.fileno(), socket.SOL_SOCKET, SO_BINDTODEVICE,
                                     ctypes.c_void_p(cold), 5)
                err = ctypes.get_errno()
                libc.munmap(cold, mmap.PAGESIZE)
                if rc != -1 or err != errno.ENODEV:
                    print(f"FAIL: cold-page bind rc={rc} errno={err}")
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

    try:
        phys4 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        phys4.bind(("10.0.2.15", 0))
        phys6 = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        phys6.bind(("fd00:2::1", 0))
        mapped = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        mapped.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        mapped.bind(("::ffff:10.9.0.1", 0))
    except OSError as e:
        print(f"FAIL: getsockname physical/mapped bind: {e}")
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

            if phys4.getsockname()[0] != "10.0.2.15":
                print(f"FAIL: physical IPv4 changed: {phys4.getsockname()}")
                sys.exit(1)
            if ipaddress.IPv6Address(phys6.getsockname()[0]) != ipaddress.IPv6Address("fd00:2::1"):
                print(f"FAIL: physical IPv6 changed: {phys6.getsockname()}")
                sys.exit(1)
            mapped_ip = ipaddress.IPv6Address(mapped.getsockname()[0])
            if mapped_ip.ipv4_mapped is None or str(mapped_ip.ipv4_mapped) == "10.9.0.1":
                print(f"FAIL: mapped VPN IPv4 not hidden or family changed: {mapped_ip}")
                sys.exit(1)

            # A truncated sockaddr can still contain the complete address;
            # it must agree with the same socket's full-length result.
            libc = ctypes.CDLL(None, use_errno=True)
            for sock, length, offset, family, expected in (
                (s_v4, 8, 4, socket.AF_INET, ip4),
                (s_v6, 24, 8, socket.AF_INET6, ip6),
                (mapped, 24, 8, socket.AF_INET6, str(mapped_ip)),
            ):
                buf = ctypes.create_string_buffer(length)
                size = ctypes.c_uint(length)
                if libc.getsockname(sock.fileno(), buf, ctypes.byref(size)) != 0:
                    print(f"FAIL: short getsockname errno={ctypes.get_errno()}")
                    sys.exit(1)
                address_len = 4 if family == socket.AF_INET else 16
                short_addr = socket.inet_ntop(family, buf.raw[offset:offset + address_len])
                if ipaddress.ip_address(short_addr) != ipaddress.ip_address(expected):
                    print(f"FAIL: short getsockname address {short_addr} != {expected}")
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
        sender.setsockopt(
            socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton("10.9.0.1")
        )
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
            print(
                f"FAIL: pktinfo non-target got ifindex={root_ifindex}, dst={root_dst}"
            )
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
BPF_MAP_LOOKUP_BATCH = 24
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


def create_stats_map(max_entries=1000):
    attr = BpfAttr()
    attr.create.map_type = BPF_MAP_TYPE_HASH
    attr.create.key_size = 4
    attr.create.value_size = 32
    attr.create.max_entries = max_entries
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


def lookup_map_batch(map_fd, capacity=2):
    keys = (ctypes.c_uint32 * capacity)()
    vals = (VhStatsValue * capacity)()
    out_batch = ctypes.c_uint64()
    attr = BpfAttr()
    attr.batch.out_batch = ctypes.addressof(out_batch)
    attr.batch.keys = ctypes.addressof(keys)
    attr.batch.values = ctypes.addressof(vals)
    attr.batch.count = capacity
    attr.batch.map_fd = map_fd
    bpf_syscall(BPF_MAP_LOOKUP_BATCH, attr, ctypes.sizeof(attr))
    return {keys[i]: vals[i] for i in range(attr.batch.count)}


def test_bpf_laundering(vpn0_idx):
    print("\n--- BPF map laundering checks ---")

    try:
        eth0_idx = socket.if_nametoindex("eth0")
        vpn1_idx = socket.if_nametoindex("vpn1")
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
        update_map_elem(map_fd, vpn1_idx, 3000, 4000)
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
        vpn1_val = lookup_map_elem(map_fd, vpn1_idx)
        print(f"[BPF Non-Target] vpn1: rx={vpn1_val.rxBytes}, tx={vpn1_val.txBytes}")
        assert vpn1_val.rxBytes == 0 and vpn1_val.txBytes == 0, "Second VPN stats not zeroed!"

        # Check cover: statistics must absorb VPN traffic
        eth_val = lookup_map_elem(map_fd, eth0_idx)
        print(f"[BPF Non-Target] eth0: rx={eth_val.rxBytes}, tx={eth_val.txBytes}")
        assert eth_val.rxBytes == 9000 and eth_val.txBytes == 12000, (
            "Cover interface stats not laundered!"
        )
        print("[BPF Non-Target] Single lookup checks passed")
        batch = lookup_map_batch(map_fd)
        assert len(batch) == 2
        for ifindex, value in batch.items():
            if ifindex in (vpn0_idx, vpn1_idx):
                assert value.rxBytes == 0 and value.txBytes == 0
            elif ifindex == eth0_idx:
                assert value.rxBytes == 9000 and value.txBytes == 12000
        print("[BPF Non-Target] Multi-interface batch laundering checks passed")
    except Exception as e:
        print(f"FAIL: BPF non-target lookup verification failed: {e}")
        return False

    # 4. Check under Target UID (115555): hook should be bypassed (raw stats visible)
    pid = safe_fork()
    if pid == 0:
        try:
            os.setuid(115555)
            vpn_val = lookup_map_elem(map_fd, vpn0_idx)
            vpn1_val = lookup_map_elem(map_fd, vpn1_idx)
            eth_val = lookup_map_elem(map_fd, eth0_idx)
            print(f"[BPF Target] vpn0: rx={vpn_val.rxBytes}, tx={vpn_val.txBytes}")
            print(f"[BPF Target] eth0: rx={eth_val.rxBytes}, tx={eth_val.txBytes}")

            if (vpn_val.rxBytes != 1000 or vpn1_val.rxBytes != 3000 or
                    eth_val.rxBytes != 5000):
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

        # SUSFS owns filesystem path hiding.  The QEMU kmod test image does
        # not include SUSFS, so sysfs/proc-sysctl directories remain visible.
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


def route_lookup(address, fib_match=False, oif=0, detailed=False):
    request = struct.pack("=IHHII", 36 + (8 if oif else 0), 26, 1, 91, 0)
    request += struct.pack("=BBBBBBBBI", socket.AF_INET, 32, 0, 0, 0, 0, 0, 0, 0x2000 if fib_match else 0)
    request += struct.pack("=HH4s", 8, 1, socket.inet_aton(address))
    if oif:
        request += struct.pack("=HHI", 8, 4, oif)
    with socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, socket.NETLINK_ROUTE) as nl:
        nl.settimeout(3)
        nl.send(request)
        data = nl.recv(8192)
    if len(data) < 20:
        raise AssertionError(f"short route reply length={len(data)}")
    length, msg_type, flags, seq, pid = struct.unpack_from("=IHHII", data)
    if seq != 91 or length > len(data):
        raise AssertionError(f"invalid route reply length={length} seq={seq}")
    if msg_type == 2:
        return ("error", -struct.unpack_from("=i", data, 16)[0])
    if msg_type != 24 or length < 28:
        raise AssertionError(f"unexpected route message type={msg_type} length={length}")
    pos = 28
    index = 0
    attrs = {}
    while pos + 4 <= length:
        alen, atype = struct.unpack_from("=HH", data, pos)
        if alen < 4 or pos + alen > length:
            raise AssertionError("invalid route attribute")
        # Cache counters vary, and RTA_UID reflects the requesting UID.
        if atype & 0x3fff not in (12, 25):  # RTA_CACHEINFO, RTA_UID
            attrs[atype & 0x3fff] = data[pos + 4:pos + alen]
        if atype & 0x3fff == 4 and alen >= 8:
            index = struct.unpack_from("=I", data, pos + 4)[0]
        pos += (alen + 3) & ~3
    if detailed:
        return ("route", index, data[16:28], tuple(sorted(attrs.items())))
    return ("route", index)


def test_point_route(vpn0_idx):
    try:
        hidden = route_lookup("10.9.9.1")
        visible = route_lookup("10.0.2.2")
        fib_root = route_lookup("10.9.9.1", True)
        fib_visible = route_lookup("10.0.2.2", True)
        cover_index = socket.if_nametoindex("eth0")
        cover = route_lookup("10.9.9.1", oif=cover_index, detailed=True)
        fib_cover = route_lookup("10.9.9.1", True, oif=cover_index, detailed=True)
        if hidden != ("route", vpn0_idx) or visible[0] != "route" or fib_root != ("route", vpn0_idx) or fib_visible[0] != "route":
            raise AssertionError(f"root hidden={hidden} visible={visible} fib_hidden={fib_root} fib_visible={fib_visible}")
        pid = safe_fork()
        if pid == 0:
            try:
                os.setuid(115555)
                got_hidden = route_lookup("10.9.9.1", detailed=True)
                got_visible = route_lookup("10.0.2.2")
                if got_hidden != cover or got_visible != visible:
                    raise AssertionError(f"target hidden={got_hidden} visible={got_visible} root_visible={visible} cover={cover}")
                fib_hidden = route_lookup("10.9.9.1", True, detailed=True)
                fib_got_visible = route_lookup("10.0.2.2", True)
                if fib_hidden != fib_cover or fib_got_visible != fib_visible:
                    raise AssertionError(f"target FIB_MATCH hidden={fib_hidden} visible={fib_got_visible} root_visible={fib_visible} cover={fib_cover}")
                print(f"[point route] hidden={got_hidden} visible={got_visible}")
                sys.exit(0)
            except Exception as e:
                print(f"FAIL: point route child: {e}")
                sys.exit(1)
        return os.waitpid(pid, 0)[1] == 0
    except Exception as e:
        print(f"FAIL: point route fixture: {e}")
        return False


def test_tcp_cover_mss(requested=0):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(4)
        if requested:
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_MAXSEG, requested)
        s.connect(("10.77.0.2", 45678))
        root_info = s.getsockopt(socket.IPPROTO_TCP, socket.TCP_INFO, 104)
        root_mss = struct.unpack_from("I", root_info, 16)[0]
        root_mtu = s.getsockopt(socket.IPPROTO_IP, 14)
        pid = safe_fork()
        if pid == 0:
            try:
                os.setuid(115555)
                info = s.getsockopt(socket.IPPROTO_TCP, socket.TCP_INFO, 104)
                shorts = [s.getsockopt(socket.IPPROTO_TCP, socket.TCP_INFO, n) for n in (17, 18, 19, 20)]
                mss = s.getsockopt(socket.IPPROTO_TCP, socket.TCP_MAXSEG)
                mtu = s.getsockopt(socket.IPPROTO_IP, 14)
                snd = struct.unpack_from("I", info, 16)[0]
                pmtu = struct.unpack_from("I", info, 60)[0]
                if mtu != 1500 or pmtu != mtu or snd != mss or (any(short[16:] != info[16:len(short)] for short in shorts)) or (not requested and snd <= root_mss) or (requested and snd != root_mss) or root_mtu != 1200:
                    print(f"FAIL: cover TCP root_mtu={root_mtu} root_mss={root_mss} mtu={mtu} pmtu={pmtu} snd={snd} maxseg={mss} shorts={[v[16:].hex() for v in shorts]} requested={requested}")
                    sys.exit(1)
                print(f"[tcp cover] root_mtu={root_mtu} root_mss={root_mss} target_mtu={mtu} target_mss={snd}")
                sys.exit(0)
            except Exception as e:
                print(f"FAIL: cover TCP child: {e}")
                sys.exit(1)
        _, status = os.waitpid(pid, 0)
        s.send(b"x")
        s.close()
        return status == 0
    except Exception as e:
        print(f"FAIL: cover TCP fixture: {e}")
        return False


def test_tc_qdisc(vpn0_idx):
    """A complete qdisc dump hides vpn0 only for the target UID."""
    def dump():
        sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, socket.NETLINK_ROUTE)
        sock.settimeout(5)
        try:
            sock.bind((0, 0))
            tcmsg = struct.pack("=BxxxiIII", socket.AF_UNSPEC, 0, 0, 0, 0)
            sock.send(struct.pack("=IHHII", 16 + len(tcmsg), 38, 0x301, 1, 0) + tcmsg)
            indexes = set()
            while True:
                data, _, flags, _ = sock.recvmsg(65536)
                if flags & socket.MSG_TRUNC:
                    raise AssertionError("truncated qdisc dump")
                offset = 0
                while offset + 16 <= len(data):
                    length, kind, nlflags, seq, _ = struct.unpack_from("=IHHII", data, offset)
                    if length < 16 or offset + length > len(data):
                        raise AssertionError("invalid netlink message")
                    if seq == 1 and kind == 3:
                        if nlflags & 0x10:
                            raise AssertionError("interrupted qdisc dump")
                        return indexes
                    if seq == 1 and kind == 2:
                        raise AssertionError("netlink error: " + str(struct.unpack_from("=i", data, offset + 16)[0]))
                    if seq == 1 and kind == 36 and length >= 32:
                        indexes.add(struct.unpack_from("=i", data, offset + 20)[0])
                    offset += (length + 3) & ~3
        finally:
            sock.close()
    try:
        visible = dump()
        if vpn0_idx not in visible:
            raise AssertionError("vpn0 qdisc fixture missing: " + str(visible))
        pid = safe_fork()
        if pid == 0:
            try:
                os.setuid(115555)
                target = dump()
                if vpn0_idx in target:
                    raise AssertionError("hidden index in qdisc dump: " + str(target))
                if not (target & (visible - {vpn0_idx})):
                    raise AssertionError("visible qdiscs missing: " + str(target))
                print("[tc_qdisc] target indexes:", sorted(target))
                sys.exit(0)
            except Exception as e:
                print("FAIL: tc_qdisc target:", e)
                sys.exit(1)
        _, status = os.waitpid(pid, 0)
        return status == 0
    except Exception as e:
        print("FAIL: tc_qdisc:", e)
        return False


def main():
    try:
        vpn0_idx = socket.if_nametoindex("vpn0")
    except Exception as e:
        print(f"FAIL: cannot find interface vpn0: {e}")
        sys.exit(1)

    success = True

    if not test_tc_qdisc(vpn0_idx):
        print("RESULT tc_qdisc=FAIL")
        success = False
    else:
        print("RESULT tc_qdisc=PASS")

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

    if tuple(int(x) for x in platform.release().split("-")[0].split(".")[:2]) >= (5, 10):
        if not (test_tcp_cover_mss() and test_tcp_cover_mss(1000)):
            print("RESULT tcp_cover_mss=FAIL")
            success = False
        else:
            print("RESULT tcp_cover_mss=PASS")
    else:
        print("tcp_cover_mss skipped: unsupported kernel")

    if not test_point_route(vpn0_idx):
        print("RESULT point_route=FAIL")
        success = False
    else:
        print("RESULT point_route=PASS")

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

    print("\n--- Verification Summary ---")
    if not success:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
