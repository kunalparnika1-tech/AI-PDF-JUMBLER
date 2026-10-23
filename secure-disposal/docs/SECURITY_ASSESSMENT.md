# Security assessment

Scope: the autonomous execution engine added on top of the simulation-only
prototype. This complements `THREAT_MODEL.md`; here the focus is the new
destructive-capable path and the autonomy model.

## Autonomy model (what runs unsupervised vs. not)

| Class of action | Supervision |
|---|---|
| Inventory, compatibility, scheduling, reporting, audit, logging, crash recovery | Fully autonomous. Reversible / read-only. |
| Dry-run execution (the default `execute`) | Autonomous. Issues **no** command to any device. |
| **Real destructive execution** | **Never autonomous.** Requires, together: `config.allow_real_execution=true`, env `DISPOSAL_ALLOW_REAL_EXECUTION=yes`, the `--real` flag, a valid two-person authorization, and a human typing the target's exact serial at the moment of action. |

The countdown expiring, operator silence, inactivity, or a missing response are
**never** treated as authorization to destroy data. This is enforced in
`engine.ExecutionEngine._may_execute_for_real` and tested in
`tests/test_execution.py`.

## The destructive-execution gate (defence in depth)

1. **Simulation by default.** `__init__.SIMULATION_ONLY` and the `DryRunRunner`
   default mean the out-of-the-box behaviour destroys nothing.
2. **Config opt-in.** `allow_real_execution` must be set in a config file.
3. **Environment opt-in.** `DISPOSAL_ALLOW_REAL_EXECUTION=yes` must be present
   — a deliberate, per-shell action that is not persisted in the repo.
4. **Explicit runner.** The caller must pass `RealCommandRunner`.
5. **Two-person authorization.** The confirming admin must differ from the
   scheduling admin; both authenticated (scrypt, lockout, optional MFA).
6. **Target identity.** `TargetGuard` pins the physical drive by name + size,
   refuses the live root/boot drive, refuses external/USB/network drives unless
   explicitly named, and refuses partitions as targets.
7. **Strong, matched identity.** The target must carry a serial/WWN that matches
   the authorized identity; weak (no serial) or ambiguous (duplicate) identities
   are refused.
8. **Adapter preflight.** Identity, hardware compatibility, method support,
   privileges, encryption prerequisite, and tool availability are checked; any
   failure stops the op with **no silent fallback** to another method.
9. **Immediate re-verification.** The device is re-detected and re-compared right
   before the irreversible step; a removed/replaced device aborts.
10. **Human serial confirmation.** At the moment of action a human must type the
   target's exact serial; anything else aborts.

### Verification levels (no false success)

A result is graded `none` → `command_accepted` → `operation_complete` →
`independently_verified`. An **erasure claim requires `independently_verified`**,
which is not yet implemented, so a real run is recorded as `executed_unverified`
and never as erased. Missing or inconclusive evidence never yields success.

If any gate fails for a real request, the engine **downgrades to a dry-run** and
records `execution.real_denied` in the audit log — it never silently proceeds
and never escalates privileges on its own.

## Privilege handling

- `privileges.detect()` only observes; it never calls sudo or changes OS
  security. Root/Administrator is necessary but never sufficient — authorization
  is separate.
- `privileges.missing_requirements()` reports exactly why a capability is
  unavailable (not elevated / tool missing) so the engine fails early and
  clearly instead of part-way.

## Reliability properties

- **Atomic, fsync'd state** (`state.StateStore`): survives power loss.
- **Crash recovery policy**: a destructive op interrupted mid-flight is
  recovered as `NEEDS_MANUAL_REVIEW` and **never auto-retried** (device state
  unknown). Non-destructive ops resume. Enforced in `state.recover`, tested in
  `tests/test_state.py`.
- **Idempotency**: operations carry a stable `idem_key`; already-terminal ops
  are skipped on resume.
- **No false success**: `data_erased_claim` is true only when a real command
  actually ran and returned success; a dry-run/simulation never claims erasure.

## Residual risks and recommendations

| Risk | Recommendation |
|---|---|
| Serial/WWN reading implemented (Linux/Windows/Android) but not validated on real hardware | Validate against real devices; handle empty serials on USB bridges and virtual disks. |
| Audit log is tamper-evident, not tamper-proof | Anchor the chain head to external WORM storage. |
| A real adapter's command assumes a correctly prepared device (e.g. ATA Secure Erase needs a password set first) | Add per-adapter preflight checks; treat preflight failure as a hard stop. |
| Verification is currently a read-back of device metadata | Add content sampling and vendor sanitize-status parsing before asserting success. |
| Compromise of the controller host | Run retirement from a hardened, dedicated, offline-capable controller; require hardware MFA. |

## Tooling

A `security-review` of the diff is recommended before enabling any real
execution in a production environment. The prototype itself ships with real
execution disabled at three independent layers.
