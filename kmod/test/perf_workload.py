#!/usr/bin/env python3
"""Deterministic in-guest workload for baseline/optimized comparisons."""

import os
import resource
import socket
import sys
import time
import ctypes

UID = 115555
ITERATIONS = int(os.environ.get("VPNHIDE_PERF_ITERATIONS", "20000"))
REPEATS = int(os.environ.get("VPNHIDE_PERF_REPEATS", "5"))
libc = ctypes.CDLL(None, use_errno=True)
__NR_bpf = 280 if os.uname().machine in ("aarch64", "arm64") else 321
BPF_MAP_CREATE = 0
BPF_MAP_LOOKUP_ELEM = 1
BPF_MAP_UPDATE_ELEM = 2
BPF_MAP_LOOKUP_BATCH = 24
BPF_BATCH_COUNT = 2


class BpfAttrCreate(ctypes.Structure):
    _fields_ = [("map_type", ctypes.c_uint32), ("key_size", ctypes.c_uint32),
                ("value_size", ctypes.c_uint32), ("max_entries", ctypes.c_uint32),
                ("map_flags", ctypes.c_uint32), ("inner_map_fd", ctypes.c_uint32),
                ("numa_node", ctypes.c_uint32), ("map_name", ctypes.c_char * 16),
                ("map_ifindex", ctypes.c_uint32), ("btf_fd", ctypes.c_uint32),
                ("btf_key_type_id", ctypes.c_uint32), ("btf_value_type_id", ctypes.c_uint32),
                ("btf_vmlinux_value_type_id", ctypes.c_uint32), ("map_extra", ctypes.c_uint64)]


class BpfAttrElem(ctypes.Structure):
    _fields_ = [("map_fd", ctypes.c_uint32), ("key", ctypes.c_uint64),
                ("value", ctypes.c_uint64), ("flags", ctypes.c_uint64)]


class BpfAttrBatch(ctypes.Structure):
    _fields_ = [("in_batch", ctypes.c_uint64), ("out_batch", ctypes.c_uint64),
                ("keys", ctypes.c_uint64), ("values", ctypes.c_uint64),
                ("count", ctypes.c_uint32), ("map_fd", ctypes.c_uint32),
                ("elem_flags", ctypes.c_uint64), ("flags", ctypes.c_uint64)]


class BpfAttr(ctypes.Union):
    _fields_ = [("create", BpfAttrCreate), ("elem", BpfAttrElem),
                ("batch", BpfAttrBatch), ("raw", ctypes.c_ubyte * 128)]


class StatsValue(ctypes.Structure):
    _fields_ = [("rx_bytes", ctypes.c_uint64), ("rx_packets", ctypes.c_uint64),
                ("tx_bytes", ctypes.c_uint64), ("tx_packets", ctypes.c_uint64)]


def bpf_call(cmd, attr):
    ret = libc.syscall(__NR_bpf, cmd, ctypes.byref(attr), ctypes.sizeof(attr))
    if ret < 0:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err))
    return ret


def prepare_bpf_map():
    attr = BpfAttr()
    attr.create.map_type = 2
    attr.create.key_size = 4
    attr.create.value_size = ctypes.sizeof(StatsValue)
    attr.create.max_entries = 16
    attr.create.map_name = b"iface_stats"
    fd = bpf_call(BPF_MAP_CREATE, attr)
    for ifindex in range(1, BPF_BATCH_COUNT + 1):
        key = ctypes.c_uint32(ifindex)
        val = StatsValue(ifindex * 1000, ifindex * 10,
                         ifindex * 2000, ifindex * 20)
        update = BpfAttr()
        update.elem.map_fd = fd
        update.elem.key = ctypes.addressof(key)
        update.elem.value = ctypes.addressof(val)
        bpf_call(BPF_MAP_UPDATE_ELEM, update)
    return fd


def bpf_single_lookup(fd):
    key = ctypes.c_uint32(1)
    val = StatsValue()
    attr = BpfAttr()
    attr.elem.map_fd = fd
    attr.elem.key = ctypes.addressof(key)
    attr.elem.value = ctypes.addressof(val)
    bpf_call(BPF_MAP_LOOKUP_ELEM, attr)


def bpf_batch_lookup(fd):
    keys = (ctypes.c_uint32 * BPF_BATCH_COUNT)(*range(1, BPF_BATCH_COUNT + 1))
    vals = (StatsValue * BPF_BATCH_COUNT)()
    out_batch = ctypes.c_uint64(0)
    attr = BpfAttr()
    attr.batch.out_batch = ctypes.addressof(out_batch)
    attr.batch.keys = ctypes.addressof(keys)
    attr.batch.values = ctypes.addressof(vals)
    attr.batch.count = BPF_BATCH_COUNT
    attr.batch.map_fd = fd
    bpf_call(BPF_MAP_LOOKUP_BATCH, attr)


def measure(name, fn):
    walls = []
    cpus = []
    for _ in range(REPEATS):
        before = resource.getrusage(resource.RUSAGE_SELF)
        start = time.monotonic_ns()
        fn()
        end = time.monotonic_ns()
        after = resource.getrusage(resource.RUSAGE_SELF)
        cpu_ns = int(((after.ru_utime - before.ru_utime) +
                      (after.ru_stime - before.ru_stime)) * 1_000_000_000)
        walls.append(end - start)
        cpus.append(cpu_ns)
    walls.sort()
    cpus.sort()
    print("PERF metric=%s iterations=%d repeats=%d wall_ns=%d cpu_ns=%d" %
          (name, ITERATIONS, REPEATS, walls[len(walls) // 2],
           cpus[len(cpus) // 2]))


def proc_readdir():
    for _ in range(ITERATIONS):
        for entry in os.scandir("/proc/sys/net/ipv4/conf"):
            entry.name


def unrelated_readdir():
    for _ in range(ITERATIONS):
        for entry in os.scandir("/tmp"):
            entry.name


def proc_read():
    for _ in range(ITERATIONS):
        with open("/proc/net/dev", "rb") as stream:
            stream.read()


def getsockopt_path():
    for _ in range(ITERATIONS):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.getsockopt(socket.SOL_SOCKET, socket.SO_MARK)
        sock.close()


def connect_path():
    for _ in range(ITERATIONS):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.connect(("127.0.0.1", 18080))
        except OSError:
            pass
        sock.close()


def main():
    if os.geteuid() != 0:
        print("PERF_ERROR=workload-must-start-as-root", file=sys.stderr)
        return 2
    try:
        bpf_fd = prepare_bpf_map()
        measure("bpf_single_lookup", lambda: [bpf_single_lookup(bpf_fd) for _ in range(ITERATIONS)])
        measure("bpf_lookup_batch", lambda: [bpf_batch_lookup(bpf_fd) for _ in range(ITERATIONS)])
    except OSError as error:
        print("PERF_ERROR=bpf: %s" % error, file=sys.stderr)
        return 3
    os.setuid(UID)
    measure("proc_readdir", proc_readdir)
    measure("unrelated_readdir", unrelated_readdir)
    measure("proc_read", proc_read)
    measure("getsockopt", getsockopt_path)
    measure("connect_port_policy", connect_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
