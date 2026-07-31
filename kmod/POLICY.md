# Target policy contract

`vpnhide_ctl` accepts a declarative policy in `vpnhide_config.json` and
translates it into the effective UID snapshots consumed by the kernel.

The optional field is:

```json
{
  "globalConfig": {
    "listMode": "BLACKLIST"
  }
}
```

`BLACKLIST` is the compatibility mode: `apps[].kmod` and
`apps[].lsposed` select UIDs that receive hiding. If the field is absent,
blacklist is used.

`ALLOWLIST` means that selected applications are exceptions. The resolver
queries Package Manager and targets every eligible application UID that is
not selected for the corresponding layer. It never targets:

- UID 0, UID 1000, or any UID below 10000;
- the manager application's UID in `BLACKLIST` mode (in `ALLOWLIST` it is
  eligible unless selected explicitly);
- packages whose APK is outside `/data/app/`.

The last rule is intentionally conservative and protects system, privileged,
APEX, vendor, product, and shared system UID groups. The resolver also asks
Package Manager for the authoritative system-package set, so updated system
APKs under `/data/app/` and every package sharing a protected UID are excluded.
UID protection uses the appId component (`uid % 100000`) for secondary users.
A selected system package is reported as ignored rather than being forced into
the target set.

Use the userspace preview before applying a policy:

```sh
vpnhide-ctl validate /path/to/vpnhide_config.json <manager_uid>
vpnhide-ctl preview /path/to/vpnhide_config.json <manager_uid>
```

The current kernel ABI still limits each effective UID snapshot to
`MAX_TARGET_UIDS` (512). Allowlist resolution fails rather than truncating a
larger result. Removing this limit requires a staged/committed kernel UAPI and
must be implemented consistently in kmod and kpatch.

The `load` path resolves and validates the complete policy, builds a versioned
`struct vpnhide_policy_payload`, and commits it with one `VH_SET_POLICY`
ioctl. The ioctl carries an explicit pointer and length because the complete
payload is larger than the size field available in the encoded ioctl command.
The kernel copies the payload, validates all counts/ranges, sorts target UIDs,
and publishes one immutable RCU snapshot. Readers therefore observe either
the previous generation or the complete new generation. `expected_generation`
may be used by a future controller to reject a stale commit with `-EAGAIN`.

Policy writes use only `VH_SET_POLICY`, which replaces the complete immutable
policy snapshot atomically. The former per-component policy setter ABI has
been removed. The corresponding GET ioctls remain read-only diagnostics.

Port hiding follows the same `listMode`. In `BLACKLIST`, apps with
`portHiding: true` are targeted. In `ALLOWLIST`, those apps are exceptions and
all other eligible third-party applications are targeted. System packages,
the manager UID in `BLACKLIST`, and isolated/system UIDs are never port
targets. Port rules are resolved independently from the application exception
set. In `ALLOWLIST`, a `portHiding: true` app with no enabled matching rules
sees all ports; when rules exist, its matching app-specific rules and enabled
`massPortRules` form its visible-port set, and the kernel receives the
complement to hide. An allowlist app with no `portHiding` exception is denied
all ports and receives full-range hiding, regardless of global rules. Thus
global rules affect only selected allowlist applications. In
`BLACKLIST`, matching app-specific rules and enabled `massPortRules` are
combined; a selected app receives full-range hiding only when no resulting
rule exists. Invalid ranges and rule-count overflow reject the configuration
instead of truncating it.

The daemon watches the JSON configuration directory and invokes the same
`vpnhide-ctl load` path after an atomic config update, so frontend writes do
not require a reboot or a separate privileged apply action. Package Manager
reconciliation is filesystem-free: the daemon periodically fingerprints the
authoritative `pm list packages -f -U --user all` output in memory and
re-resolves after install, uninstall, UID, or user changes. No Package Manager
state files are opened, watched, or created; persistent state remains in the
application configuration directory.

Per-app hook masks use the same exception semantics in `ALLOWLIST`: enabled
bits are removed from the effective global active mask for that application.
`CONNECT` (hook 13) and `BIND` (hook 16) are mandatory because they enforce
the port policy; requests to disable either bit are ignored in both global and
per-app masks. Port targets carry an explicit mode: unrestricted, rule-based
blocking, or deny-all. The kernel still receives effective active masks, so it
does not need to know which list mode produced them.
