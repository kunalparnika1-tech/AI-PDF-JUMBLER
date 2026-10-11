# Threat model

Scope: a tool used by authorized administrators to plan and record device
retirement. The highest-consequence failure is **destroying the wrong data** or
**destroying data without authorization/backup**. Because the prototype performs
no destruction, several threats are mitigated by construction; the table notes
where a production (destructive) build would need additional controls.

| # | Threat | Mitigation in this design | Residual risk / production note |
|---|--------|---------------------------|---------------------------------|
| 1 | **Incorrect device identification** | Read-only inventory distinguishes physical drives from partitions; simulated/undetected inventories are `verified=False` and blocked until a human asserts `--verified` (audited); report echoes device identity. | Human verification is only as good as the operator; production should re-read device serials at authorization time and compare to the inventory. |
| 2 | **Accidental activation** | Countdown never executes; expiry only *locks*. Authorization is a separate interactive step with a full checklist. | None in prototype (no destructive path). |
| 3 | **Unauthorized users** | Password auth (scrypt), role-based authorization, two-person rule for final confirmation. | Add OS-level access control and signed binaries. |
| 4 | **Stolen credentials** | Optional TOTP MFA; per-account lockout after repeated failures; two-person rule means one stolen credential is insufficient to authorize. | Prefer hardware-backed MFA (FIDO2) in production; rotate on suspicion. |
| 5 | **Power interruptions** | Schedule state persisted atomically; on recovery a lapsed deadline **locks** (never executes); heartbeat gap flags unexpected shutdown (audited). | A destructive build must be crash-safe mid-operation and resumable with verification. |
| 6 | **OS incompatibility** | Per-platform detection; unknown platforms warn and block; compatibility assessment marks undetermined capability as UNSUPPORTED. | Real sanitize commands need native adapters per OS. |
| 7 | **Storage-controller limitations** | Compatibility notes that sanitize/secure-erase may be silently ignored by firmware; verification step is mandatory in the plan. | Production must sample-read and read sanitize-status; fall back to physical destruction. |
| 8 | **Incomplete sanitization** | Every method lists its limitations; verification plan is part of every report. | Capture machine-readable verification evidence; retain certificates. |
| 9 | **Unverified backups** | Checklist item `backup_status_checked` + `records_retained_confirmed`; all must be asserted before authorization. | Integrate with backup systems to assert programmatically, not just by attestation. |
| 10 | **Unexpected external storage** | External/removable/network drives are **refused** unless each is named via `--allow-external`; `is_external` flag on drives. | Keep the guard in any destructive build; default-deny. |
| 11 | **Malicious modification of the app** | No destructive payload to weaponize; audit log is hash-chained and verifiable; stdlib-only reduces supply-chain surface. | Code-sign binaries; verify signatures at launch; pin dependencies; reproducible builds. |
| 12 | **Clock manipulation** | Future-dated heartbeat flags backward clock changes (audited); anomalies surfaced, not silently trusted. | Cross-check with a trusted time source (monotonic clock + NTP attestation) for time-sensitive policies. |

## Trust boundaries

- **Audit log is tamper-evident, not tamper-proof.** An attacker able to rewrite
  the whole file can recompute the chain. Export the chain head periodically to
  external append-only/WORM storage for stronger guarantees.
- **The controller is trusted.** Compromise of the admin's machine undermines
  the tool; use a hardened, dedicated controller for retirement operations.
- **Vendor procedures are trusted** to do what their documentation claims; the
  tool records the plan and the verification but cannot independently guarantee
  firmware behaviour — hence mandatory post-operation verification.
