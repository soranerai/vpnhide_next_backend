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
counters are cumulative `u64` values for the current kernel session. A
snapshot must be taken with capacity `MAX_TARGET_UIDS`. If the capacity is too
small, the ioctl returns `-ENOSPC` and returns the required `count`.

`VH_CLEAR_STATS` clears all kernel counters and resets the snapshot sequence.
It is an explicit destructive operation; reading statistics never clears
anything.

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

When the ring evicts old points, `dropped` is `true` and
`droppedIntervals` is incremented. This describes history loss only; kernel
counters remain cumulative and are not affected. A frontend clear operation
must clear its ring and reset its userspace baseline; it should not call
`VH_CLEAR_STATS` unless a full kernel-session reset is explicitly requested.

If the daemon restarts, it starts a new userspace sampling segment and marks
the first point as a gap. If the kernel session also changed, `sessionId`
changes and the frontend must discard the previous in-memory ring.
