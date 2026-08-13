# QEMU performance comparison

`run-perf.sh` boots the same QEMU configuration twice: once with a baseline
artifact and once with an optimized artifact. The guest runs the same policy
and the same workload in both cases. It prints median wall-clock and process
CPU time for:

- `/proc` directory enumeration;
- `/proc/net/dev` reads;
- `getsockopt` path;
- loopback connect/port-policy path.

The final `DELTA` lines are `optimized - baseline`. Negative values mean an
improvement. Percentages use the baseline as the denominator.

## kmod

Build the baseline from the parent commit in a separate worktree, then build
the current branch normally. Place the resulting artifacts at the paths below
or set the corresponding environment variables:

```sh
git worktree add /tmp/vpnhide-baseline HEAD
# build /tmp/vpnhide-baseline/kmod for the selected KMI
# build the current worktree for the same KMI

VPNHIDE_PERF_BASELINE_IMAGE=/path/Image \
VPNHIDE_PERF_OPTIMIZED_IMAGE=/path/Image \
VPNHIDE_PERF_BASELINE_KO=/path/vpnhide_kmod.ko \
VPNHIDE_PERF_OPTIMIZED_KO=/path/vpnhide_kmod.ko \
VPNHIDE_PERF_ITERATIONS=20000 \
VPNHIDE_PERF_REPEATS=5 \
./kmod/test/run-perf.sh android14-6.1
```

For a module-only comparison, the images must still be identical; only the
`.ko` files should differ.

## kpatch

For built-in kpatch, compare two kernel Images and use the wrapper:

```sh
VPNHIDE_PERF_BASELINE_IMAGE=/path/Image-baseline \
VPNHIDE_PERF_OPTIMIZED_IMAGE=/path/Image-optimized \
VPNHIDE_PERF_ITERATIONS=20000 \
VPNHIDE_PERF_REPEATS=5 \
./kpatch/test/run-perf.sh android14-6.1
```

Run the ordinary correctness harness separately for both artifacts:

```sh
./kmod/test/run.sh android14-6.1
./kpatch/test/run.sh android14-6.1
```

The performance test is not a substitute for the correctness test. QEMU uses
TCG, so absolute timings are not device timings; the useful result is the
baseline/optimized delta under identical VM conditions.
