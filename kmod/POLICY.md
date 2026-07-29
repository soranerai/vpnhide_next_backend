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
- the manager application's UID;
- packages whose APK is outside `/data/app/`.

The last rule is intentionally conservative and protects system, privileged,
APEX, vendor, product, and shared system UID groups. A selected system package
is reported as ignored rather than being forced into the target set.

Use the userspace preview before applying a policy:

```sh
vpnhide-ctl validate /path/to/vpnhide_config.json <manager_uid>
vpnhide-ctl preview /path/to/vpnhide_config.json <manager_uid>
```

The current kernel ABI still limits each effective UID snapshot to
`MAX_TARGET_UIDS` (512). Allowlist resolution fails rather than truncating a
larger result. Removing this limit requires a staged/committed kernel UAPI and
must be implemented consistently in kmod and kpatch.

The current `load` path validates the complete policy before issuing ioctls
and returns failure if any ioctl fails. It is not yet a cross-ioctl atomic
commit; that is the next backend ABI step.
