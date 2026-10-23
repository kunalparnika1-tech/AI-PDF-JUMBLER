# Secure Device Disposal (simulation-only prototype)

A password-protected planning and orchestration tool for **authorized** device
retirement, oriented around **NIST SP 800-88 Rev. 2** data-sanitization
categories. It inventories hardware, assesses which sanitization methods are
plausibly supported, schedules a review with a 50-minute countdown, enforces a
pre-authorization checklist with a two-person rule, and produces timestamped,
tamper-evident reports.

> ## ⚠️ What this tool does NOT do
> This prototype runs in **simulation mode only**. It contains **no** code that
> wipes disks, overwrites sectors, modifies bootloaders, or deletes partitions.
> Its "disposal" step records what a documented, vendor-approved procedure
> *would* do and the verification a human would perform. It is a planning,
> authorization, and record-keeping tool — the actual sanitization is always a
> deliberate, human-run, out-of-band procedure.
>
> The 50-minute countdown **never executes anything**. On expiry it moves the
> request to `LOCKED_PENDING_CONFIRMATION`, which still requires an explicit,
> interactive second-admin confirmation. There is no timer-to-destruction path,
> by design. See [docs/LIMITATIONS.md](docs/LIMITATIONS.md).

## Why this scope

A single executable cannot safely and universally wipe Windows, Linux, Android
boards, and proprietary OPS/embedded devices. Assured erasure depends on the
storage controller's firmware, the device's encryption posture, and
vendor-specific procedures. This tool therefore **plans and records**
vendor-approved procedures under strong human authorization instead of shipping
a cross-platform destructive payload. See
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) and
[docs/COMPATIBILITY.md](docs/COMPATIBILITY.md).

## Technology stack

The prototype is **Python 3.10+ standard library only** (no third-party runtime
dependencies), chosen for portability and auditability of a reference
implementation. For a production build, see the stack comparison and
recommendation in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md#technology-stack-comparison)
(short version: a **Rust core** with **Tauri** for the GUI, with
platform-specific adapters — never one binary claiming universal reach).

## Install

```bash
cd secure-disposal
python3 -m pip install -e .          # installs the `disposal` command
# or run without installing:
export PYTHONPATH=src
python3 -m disposal.cli --help
```

Run the tests:

```bash
python3 -m pip install -e '.[test]'
python3 -m pytest -q
```

## Quick start (full simulated flow)

```bash
# 1. Create the first admin (no hardcoded credentials; you set the password).
disposal init-admin alice            # prompts for a password (min 12 chars)

# 2. Create a SECOND admin — the authorization step requires two people.
disposal add-user --as alice bob --role ADMIN

# 3. Inspect the device (read-only). Use --simulated-board to see the
#    dual-environment smart-board example (Android + Windows OPS).
disposal inventory --simulated-board
disposal compat   --simulated-board

# 4. Schedule a review (default 50 min; shortened here only to demonstrate).
disposal schedule --as alice SIM-SMARTBOARD-01 --seconds 3000

# 5. Watch the countdown.
disposal status

# 6. After expiry the request is LOCKED. A DIFFERENT admin authorizes the
#    SIMULATED workflow, asserting the checklist and human-verified inventory.
disposal authorize --as bob --simulated-board \
    --method vendor-secure-erase --confirm-all --verified \
    --allow-external android:emmc0 ops:/dev/nvme0n1

# 7. Verify the tamper-evident audit chain, and read the report.
disposal audit-verify
```

Passwords may be supplied non-interactively via `DISPOSAL_PASSWORD` /
`DISPOSAL_PASSWORD2` for automation; otherwise they are prompted without echo.

## Administrative user guide

| Role | Can do |
|------|--------|
| `ADMIN` | everything, including final authorization and user management |
| `OPERATOR` | inventory, compatibility, schedule/cancel/reschedule — **cannot** give final authorization |
| `AUDITOR` | read-only: inventory, compatibility, status, reports, audit log |

**Authorization requires two distinct admins** (the one who scheduled the
review cannot be the one who confirms it). Before a simulated run proceeds, all
seven pre-authorization checklist items must be asserted (`--confirm-all`) and
the inventory must be human-verified (`--verified`) — the tool never assumes a
simulated or undetected inventory is correct.

State (users, audit log, schedule, reports) lives under
`~/.local/share/secure-disposal` by default, or `$DISPOSAL_DATA_DIR`. The
password store and data directory are created with restrictive permissions on
POSIX systems.

## Autonomous execution and the real-execution gate

The engine runs everything non-destructive **without supervision**: inventory,
compatibility, scheduling, dry-run execution, reporting, audit, structured
logging, persistent state, and crash recovery. You can start an authorized
dry-run and come back to a complete report.

**Real destructive execution is never autonomous.** The `execute` command is a
dry-run by default (it issues no command to any device). A real sanitize command
runs only when *all* of these hold at once:

1. `allow_real_execution: true` in your `--config` file,
2. environment `DISPOSAL_ALLOW_REAL_EXECUTION=yes`,
3. the `--real` flag,
4. a valid two-person authorization (confirming admin ≠ scheduling admin),
5. the `TargetGuard` accepts the drive (right size, not the boot drive, not an
   unlisted external/network drive, not a partition), and
6. a human types the target drive's **exact serial** when prompted.

If any gate fails, the engine safely **downgrades to a dry-run** and records
`execution.real_denied` in the audit log. A completed countdown, silence, or
inactivity is **never** treated as authorization. See
[docs/SECURITY_ASSESSMENT.md](docs/SECURITY_ASSESSMENT.md).

```bash
# Dry-run execution over the locked review's targets (destroys nothing):
disposal execute --as bob --simulated-board --verified --adapter simulation \
    --allow-external android:emmc0 ops:/dev/nvme0n1

# Inspect privilege level:
disposal privileges

# Real execution (only on an authorized host, with a real config + env opt-in):
disposal --config my.json execute --as bob --adapter nvme-format --real \
    --verified --target-serial S1234 --boot-drive /dev/sda   # prompts for serial
```

Crash recovery is automatic: if the process dies mid-run, re-running `execute`
reloads the persisted state, resumes safe operations, and marks any destructive
operation that was interrupted as `NEEDS_MANUAL_REVIEW` (never auto-retried).

## Documentation

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — system architecture, stack comparison, scheduler behaviour across device power states.
- [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) — threats and mitigations.
- [docs/COMPATIBILITY.md](docs/COMPATIBILITY.md) — device/method compatibility matrix and what is cross-platform vs platform-specific.
- [docs/PLATFORM_PROCEDURES.md](docs/PLATFORM_PROCEDURES.md) — documented, vendor-approved disposal procedures per platform.
- [docs/LIMITATIONS.md](docs/LIMITATIONS.md) — known limitations and non-goals.
- [docs/SECURITY_ASSESSMENT.md](docs/SECURITY_ASSESSMENT.md) — autonomy model, destructive-execution gate, reliability properties, residual risks.
- [docs/VERIFICATION.md](docs/VERIFICATION.md) — verification state machine, evidence required per transition, and the limits of read-back sampling.
- [docs/UNRESOLVED_HARDWARE_TASKS.md](docs/UNRESOLVED_HARDWARE_TASKS.md) — precise list of hardware-dependent tasks not completed.
- [docs/ROADMAP.md](docs/ROADMAP.md) — future development.
- [docs/TESTING.md](docs/TESTING.md) — test strategy.

## License

MIT (see repository `LICENSE`).
