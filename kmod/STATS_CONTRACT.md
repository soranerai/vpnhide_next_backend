# Intercept statistics contract

The statistics API is session-scoped. It is not persisted across reboot and
does not contain kernel-side time buckets.

## Kernel ABI

`VH_GET_STATS` receives and returns `struct vpnhide_stats_snapshot`:

- `capacity` is the number of entries allocated by userspace;
- `entries_ptr` points to that userspace array;
- `count` is the number of entries currently available;
- `sequence` is a monotonically increasing snapshot sequence;
- `monotonic_ns` is the snapshot timestamp from `ktime_get_ns()`.

The entry array contains one `struct vpnhide_uid_stats` per UID. All seven
counters are cumulative `u64` values for the current kernel session. There is
no fixed UID capacity. Userspace first calls the ioctl with capacity zero,
allocates the returned `count`, and retries. If the target set grows between
calls, the ioctl returns `-ENOSPC` with the new required count and the caller
retries again.

`VH_CLEAR_STATS` clears all kernel counters and resets the snapshot sequence.
It is an explicit destructive operation; reading statistics never clears
anything.

Each kernel-module load creates a new opaque session token, available through
`VH_GET_STATS_SESSION`. The daemon combines this token with Android's boot ID
as `sessionId` (for example, `boot-id-0123456789abcdef`).

The kernel retains only counters for UIDs in the current kmod target policy.
When the policy changes, removed UIDs are pruned so new target UIDs cannot be
blocked by stale table entries.

## Userspace session ring

The frontend or its daemon owns history. It periodically obtains cumulative
snapshots and computes per-UID deltas against the previous snapshot:

```text
delta = current_snapshot - previous_snapshot
```

The history is an in-memory ring of interval points. Recommended defaults are
60-second points and a 24-hour retention (`1440` points). No point is written
to disk.

The bundled daemon implements this ring with the following defaults. It takes
one baseline snapshot when it starts, then samples every 60 seconds. The first
point is always marked `gap: true` and contains no deltas, because counters may
include activity from before the daemon started. Later points contain only
non-zero per-UID deltas. A kernel sequence reset (for example after
`VH_CLEAR_STATS`) also produces a gap point and establishes a new baseline.

The daemon keeps the ring in memory only. Restarting the daemon loses the ring,
but does not clear kernel counters.

Each frontend response must include:

```json
{
  "sessionId": "boot-id",
  "sequence": 1234,
  "resolutionSec": 60,
  "retentionSec": 86400,
  "dropped": false,
  "droppedIntervals": 0,
  "oldestTimestampMs": 0,
  "newestTimestampMs": 0,
  "points": []
}
```

`sequence` is the kernel snapshot sequence of the newest point (or `0` when
there is no point). `oldestTimestampMs` and `newestTimestampMs` are Unix epoch
milliseconds. Each point has this shape:

```json
{
  "timestampMs": 1710000000000,
  "gap": false,
  "uids": [
    {
      "uid": 12345,
      "ioctl": 1,
      "netlink": 2,
      "proc": 0,
      "sockopt": 3,
      "connect": 0,
      "getname": 0,
      "port": 0
    }
  ]
}
```

`uids` contains interval deltas, not cumulative kernel counters. A missing UID
means that all seven deltas for that UID are zero for the interval.

When the ring evicts old points, `dropped` is `true` and
`droppedIntervals` is incremented. This describes history loss only; kernel
counters remain cumulative and are not affected. A frontend clear operation
must clear its ring and reset its userspace baseline; it should not call
`VH_CLEAR_STATS` unless a full kernel-session reset is explicitly requested.

If the daemon restarts, it starts a new userspace sampling segment and marks
the first point as a gap. If the kernel session also changed, `sessionId`
changes and the frontend must discard the previous in-memory ring.

## Daemon frontend API

The daemon exposes the frontend API through an abstract Unix domain stream
socket named `vpnhide.stats.v1`. It is deliberately not a TCP/UDP port: the
socket is local-only, does not create a network listener, and avoids exposing
statistics to arbitrary applications. The daemon accepts a connection only
when `SO_PEERCRED.uid` equals the manager application's UID passed by the
module service at startup.

The root-side `vpnhide-ctl` sends one UTF-8 command followed by `\n` and reads
one UTF-8 JSON response until EOF:

- `GET_STATS` returns the complete current response;
- `CLEAR_HISTORY` clears only the daemon ring and userspace baseline, then
  returns the now-empty response. It never calls `VH_CLEAR_STATS`.

The Android frontend does not connect to the abstract socket directly. It
invokes `su -c '<module>/vpnhide-ctl stats_history'` (or `... stats_history
clear`) and parses stdout as JSON. Root is accepted as a trusted peer by the
daemon; the manager UID remains accepted for diagnostics and compatibility.
No `untrusted_app -> su` SELinux socket rule is required.
