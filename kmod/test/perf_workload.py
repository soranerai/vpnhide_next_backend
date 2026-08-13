#!/usr/bin/env python3
"""Deterministic in-guest workload for baseline/optimized comparisons."""

import os
import resource
import socket
import sys
import time

UID = 115555
ITERATIONS = int(os.environ.get("VPNHIDE_PERF_ITERATIONS", "20000"))
REPEATS = int(os.environ.get("VPNHIDE_PERF_REPEATS", "5"))


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
    os.setuid(UID)
    measure("proc_readdir", proc_readdir)
    measure("proc_read", proc_read)
    measure("getsockopt", getsockopt_path)
    measure("connect_port_policy", connect_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
