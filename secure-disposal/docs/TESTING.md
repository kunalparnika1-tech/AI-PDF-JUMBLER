# Test strategy

## Automated tests (in this repo)
Run with `python3 -m pytest -q`. Coverage of the safety-critical logic:

- **Authentication** (`test_auth.py`): bootstrap, no hardcoded second admin,
  short-password rejection, wrong-password lockout, generic error for unknown
  users, MFA enforcement, TOTP round-trip, persistence.
- **Audit** (`test_audit.py`): append+verify, tamper detection, deletion
  detection.
- **Scheduler** (`test_scheduler.py`): countdown, **timer locks but never
  executes**, cancel, reschedule, double-schedule rejection, power-loss recovery
  locks on lapsed deadline, backward-clock anomaly flag.
- **Workflow** (`test_workflow.py`): simulation-only outputs, blocks on
  unverified inventory / incomplete checklist, two-person rule, locked-state
  requirement, external-drive guard (and explicit allow), independent
  smart-board environments.
- **CLI** (`test_cli.py`): full end-to-end simulated flow with two admins;
  two-person rule enforced via the CLI.

## Manual / environment testing (recommended, not claimed as done)
Because we must **not** claim compatibility without real evidence, the following
are part of the strategy but require actual hardware/VMs and vendor docs:

- **Windows VM / Linux VM:** verify read-only detection depth and that unknown
  platforms block. Multi-boot VM: confirm per-physical-drive reasoning.
- **Android emulator / real board:** confirm factory-reset/EMM assumptions
  against vendor documentation; do **not** claim cryptographic purge without
  confirmation.
- **OPS module:** confirm independent inventory from the host panel.
- **Fault injection:** kill the controller mid-countdown (power loss), move the
  system clock, disconnect the target — confirm the tool locks/flags and never
  executes.
- **Incorrect authentication:** confirm lockout and audit entries.
- **Storage inventory errors:** simulate missing `lsblk` / permission denial —
  confirm the tool warns and blocks irreversible operations.

## Non-negotiable invariants to assert in any build
1. No code path leads from countdown expiry to a destructive action.
2. Simulated/undetected inventory cannot be authorized without an explicit,
   audited human-verification assertion.
3. The confirming admin differs from the scheduling admin.
4. External/removable/network drives are default-denied.
