# Known limitations and non-goals

## This is a simulation-only prototype
- It performs **no** data destruction. There is no code that overwrites disks,
  issues sanitize/secure-erase commands, modifies bootloaders, or deletes
  partitions. The "disposal" workflow records a *plan* and a *verification
  plan*; it does not act.
- The 50-minute countdown **never executes anything**. On expiry it locks the
  request for a separate, interactive, two-person authorization.

## Deliberate non-goals
- **No universal destructive binary.** Assured erasure is platform- and
  firmware-specific; this tool orchestrates vendor-approved procedures instead.
- **No bypass of security controls.** The tool will not attempt to defeat locked
  bootloaders, device-admin restrictions, firmware protections, Secure Boot, or
  manufacturer controls. Devices that block the required procedure are reported
  as unsupported.
- **No hidden/discreet operation and no automatic destructive trigger.**
  Concealed timers that auto-wipe are an anti-forensic pattern and are out of
  scope. Every consequential step is explicit, logged, and human-confirmed.

## Technical limitations
- **Detection is best-effort and read-only.** Full inventory currently has a
  Linux (`lsblk`) adapter; other platforms warn and block until a human verifies
  the configuration. Windows/Android deep detection needs native adapters.
- **Compatibility assessment is advisory.** It cannot guarantee a controller
  honours a sanitize command; verification after a real operation is mandatory
  and is only *described* here, not performed.
- **Audit log is tamper-evident, not tamper-proof.** Strong assurance requires
  exporting the chain head to external append-only/WORM storage.
- **Clock/power anomaly detection is heuristic.** It flags likely manipulation or
  unexpected shutdown; it is not a secure time source.
- **No GUI in the prototype.** The spec's dashboard is described in
  `ARCHITECTURE.md`; the prototype exposes the same logic via a CLI so it is
  easy to audit and test. A production GUI (Tauri) would wrap the same modules.
- **MFA is TOTP only** (stdlib implementation). Production should prefer
  hardware-backed FIDO2.

## What would change for a production, destructive-capable build
See `ARCHITECTURE.md` and `THREAT_MODEL.md`: signed binaries, per-platform
native adapters, machine-readable verification evidence, crash-safe resumable
operations, external WORM audit anchoring, and a formal authorization policy
(e.g. hardware MFA + dual control + change-ticket reference).
