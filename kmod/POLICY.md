# Policy ABI v4 contract

`vpnhide_config.json` is the sole source of policy truth. The Android
application owns package discovery, system-app defaults, current UID
reconciliation, and persistence. `vpnhide-ctl` only validates and serializes
that declarative configuration. The daemon never queries Package Manager and
never expands package names into effective UID sets.

The mode is selected by:

```json
{
  "globalConfig": {
    "listMode": "BLACKLIST"
  }
}
```

`BLACKLIST` is the default. ABI v4 publishes `VPNHIDE_MATCH_INCLUDE`, so a UID
matches a layer when it is present in that layer's list.

`ALLOWLIST` publishes `VPNHIDE_MATCH_EXCLUDE`. Lists contain exceptions, and
the kernel evaluates membership as:

```text
eligible(uid) && !listed(uid)
```

The rule is evaluated independently for kernel hooks, framework hooks, and
port policy. Empty allowlists therefore target every eligible UID; there is no
daemon-generated enumeration of installed applications.

Eligibility is a kernel safety invariant, not package classification. UID 0,
UID 1000, and every UID whose Android appId (`uid % 100000`) is below 10000
never matches either mode. `vpnhide-ctl` also rejects those entries while
packing a snapshot, but the kernel check remains authoritative if userspace is
buggy or compromised. System applications with an application-range appId are
not implicitly protected by the backend: the application must persist its
chosen defaults and explicit overrides in JSON.

Each `apps[]` object carries a full current UID. Its `kmod`, `lsposed`, and
`portHiding` booleans control inclusion in the corresponding ABI list. Package
name, user ID, and `systemPolicyExplicit` are application metadata; the native
backend does not resolve or reinterpret them. The application refreshes stale
UIDs after package changes, reinstall, restore, and boot, then atomically
rewrites the JSON file.

Use the userspace validator without Package Manager access:

```sh
vpnhide-ctl validate /path/to/vpnhide_config.json
vpnhide-ctl preview /path/to/vpnhide_config.json
```

The preview reports `match_mode=INCLUDE` or `match_mode=EXCLUDE`. Its target
counts are serialized list counts; `lsposed_entries` is likewise an entry
count, not an expanded target count.

The framework status stream uses an explicit presentation contract:

```text
lsposed_list_mode: SHOW
lsposed_uids: 10001 10004
```

`SHOW` is emitted for allowlist policy, and `lsposed_uids` contains only UIDs
that may see VPN state. LSPosed hides VPN state from every other eligible UID.
`HIDE` is emitted for blacklist policy, and the same field contains only UIDs
from which VPN state must be hidden. The neutral `lsposed_uids` name avoids
misreporting allowlist exceptions as expanded targets.

ABI v4 stores three match modes plus UID sets, port targets, flattened port
rules, and per-app hook masks in variable-length sections. The complete
transaction is bounded by `VPNHIDE_POLICY_MAX_BYTES`. The kernel copies and
validates the payload, sorts and deduplicates UID-keyed sections, reconciles
statistics, and publishes one immutable RCU snapshot. Readers therefore see
either the previous complete generation or the next complete generation.
Malformed mode values, offsets, counts, ranges, duplicates, and reserved bits
reject the entire transaction. ABI v2 and v3 remain accepted as transitional
include-only inputs; v4 is the controller's emitted format.

Policy writes use one `VH_SET_POLICY` transaction. `expected_generation` can
reject a stale writer with `-EAGAIN`. The daemon watches only the JSON
directory and invokes the same `vpnhide-ctl load` operation after an atomic
application update. Its Package Manager lookup for the manager UID in module
startup scripts is used solely to authorize the statistics socket and migrate
legacy database ownership; that UID is not passed into policy construction.

Port policy follows the same modes. In blacklist mode, listed port targets
receive their compiled blocking rules. In allowlist mode, an eligible UID with
no explicit target receives the kernel's synthetic deny-all policy. A listed
exception overrides that default: no enabled matching rule means unrestricted;
otherwise app-specific rules plus enabled mass rules describe visible ports,
and userspace serializes their blocking complement. No full-range entries are
generated for every installed UID.

Per-app hook masks remain explicit UID-keyed overrides. In allowlist mode the
controller converts selected bits into removals from the global mask for that
exception. `CONNECT` and `BIND` remain mandatory because they enforce port
policy.

Allowlist statistics are created lazily on the first intercepted event because
the finite exception list cannot enumerate the inverted target population.
Current-session entries are retained across policy updates only while their UID
still matches the new policy, with a bounded capacity of 4096 UIDs.
