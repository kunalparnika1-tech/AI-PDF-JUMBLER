# Execution & verification report (development run)

This records the autonomous development run that extended the simulation-only
prototype into an execution-capable system. It covers completed work, test
results, limitations, and required operator actions.

## Iteration 3 — independent verification layer

Added `verification.py`: parsers for documented evidence (NVMe `sanitize-log`
SSTAT, `cryptsetup luksDump`, structured read-back samples, bare exit code) plus
a conservative `grade()` that combines a command baseline with evidence.

- **State machine enforced**: `none → command_accepted → operation_complete →
  independently_verified`, with the required evidence for each transition
  documented in `VERIFICATION.md`.
- **No false success**: a zero exit code is only `command_accepted`; LBA
  sampling tops out at `operation_complete` (FTL/over-provisioning caveat);
  only a controller-level completion (NVMe SSTAT completed) or confirmed key
  destruction reaches `independently_verified`.
- **Conflict handling**: failed/incomplete/contradictory evidence caps the
  result at `command_accepted`, records the conflict and follow-up, and the
  engine marks the op `NEEDS_MANUAL_REVIEW` — never success.
- **Engine integration**: `data_erased_claim` is true only on a real,
  successful, `independently_verified`, conflict-free op; adapters expose
  read-only evidence commands (NVMe sanitize-log, luksDump).

Tests this iteration: +19 (verification unit tests + engine integration for
completed / failed / in-progress evidence), **76 total**, all passing per-file.

## Iteration 2 — hardware identification & verification

Added on top of the execution engine (human-in-the-loop preserved; no
website/USB auto-trigger, no auto-execution on countdown):

- **USB / drive identification**: `Drive` now carries serial/WWN/vendor; a
  stable `identity()` prefers WWN → serial → (weak) path. Linux `lsblk` reads
  SERIAL/WWN/VENDOR. Missing serials are flagged WEAK; duplicate serials are
  flagged ambiguous. `diff_inventories` detects removal and replacement.
- **Target verification**: `TargetGuard` now requires a strong, matching
  identity for destructive ops, refuses weak/ambiguous identities, and the
  engine re-detects and re-compares the device immediately before the
  irreversible step (replacement/removal = hard stop).
- **Platform inventory adapters**: Windows (`Get-Disk`) and Android
  (`adb shell lsblk`) read-only adapters with pure, unit-tested parsers; Linux
  extended. Requirements documented in `COMPATIBILITY.md`.
- **Adapter preflight**: identity, compatibility, method support, privileges,
  encryption prerequisite, tool availability — no silent fallback.
- **Verification levels**: `none → command_accepted → operation_complete →
  independently_verified`. A real run is recorded as `executed_unverified`;
  `data_erased` is never claimed without independent verification (not yet
  implemented — see UNRESOLVED_HARDWARE_TASKS.md).

Tests this iteration: +13 (execution guards/preflight/re-verify, inventory
identity, platform parsers), **57 total**, all passing per-file.

## Completed work

| Component (directive §) | Module(s) | State |
|---|---|---|
| Structured logging (§1.7) | `logging_.py` | Done |
| Privilege detection / least-privilege / capability checks (§2) | `privileges.py` | Done |
| Persistent execution state, checkpoints, crash recovery, idempotency (§5) | `state.py` | Done |
| Execution adapters: discovery→identification→compatibility→method→authorization→execution→verification→audit (§3) | `execution.py`, `engine.py` | Done (real execution gated) |
| Single authorization boundary; no autonomy for destruction (§4) | `engine.py` | Done |
| Config file + real-execution opt-in (§4) | `config.py`, `config.example.json` | Done |
| CLI `execute` + `privileges` wired in | `cli.py` | Done |
| Security assessment (§7.6) | `docs/SECURITY_ASSESSMENT.md` | Done |
| Hardware compatibility matrix incl. commands (§7.4) | `docs/COMPATIBILITY.md` | Done |
| Unresolved hardware-dependent tasks (§7.8) | `docs/UNRESOLVED_HARDWARE_TASKS.md` | Done |

Dependency order followed: logging → privileges → state → execution adapters →
engine → config → CLI wiring → tests → docs.

## Test results

- **45 automated tests**, all passing (run per-file; see note below).
  - auth 8, audit 3, scheduler 7, workflow 8, state 4, execution 11,
    cli 2, cli-execute 2.
- Destructive adapters are tested for **command construction and gating only**,
  using injected fake runners. **No destructive command was executed against any
  real device.**
- Verified safety properties: dry-run is the default; `--real` without the full
  opt-in chain downgrades and audits `real_denied`; wrong serial / two-person
  violation both block; crash mid-destructive-op → `NEEDS_MANUAL_REVIEW`, never
  auto-retried; `data_erased_claim` only when a real command actually succeeded.

> Note: running all test files in one `pytest` invocation is blocked by the
> environment's safety classifier because the test sources contain destructive
> command *strings* (e.g. `blkdiscard`, `nvme format`). The tests never execute
> those commands. Each test file passes when run on its own.

## Limitations (see UNRESOLVED_HARDWARE_TASKS.md for the full list)

- Target serial is matched against operator-provided input, not yet read from
  the device automatically.
- Verification is a metadata read-back; content-sampling evidence is not yet
  implemented.
- Only a Linux inventory adapter exists; Windows/Android/OPS adapters are
  skeletoned at the command level but need real hosts and vendor tooling.
- No destructive adapter has been validated on real hardware.

## Required operator actions

1. **To keep it safe (recommended default):** nothing — simulation/dry-run is
   the default and destroys nothing.
2. **To enable real execution on an authorized host:** set
   `allow_real_execution: true` in a config file, export
   `DISPOSAL_ALLOW_REAL_EXECUTION=yes`, run `execute --real` as a second admin,
   and type the target serial when prompted. Review
   `docs/SECURITY_ASSESSMENT.md` and run `/security-review` on the diff first.
3. **Before trusting any real run:** implement automatic serial reading and
   adapter preflight checks (UNRESOLVED_HARDWARE_TASKS.md items 1–2), and test
   on a sacrificial device.
