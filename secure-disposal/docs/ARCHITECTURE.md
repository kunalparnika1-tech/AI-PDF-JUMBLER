# Architecture

## Goals and non-goals

**Goal:** a secure, auditable tool that plans, authorizes, and records
authorized device retirement across heterogeneous hardware, mapping to NIST
SP 800-88 Rev. 2 sanitization categories (Clear / Purge / Destroy).

**Non-goal:** a single binary that performs assured erasure everywhere. That is
not achievable safely — see [COMPATIBILITY.md](COMPATIBILITY.md). The tool
orchestrates documented, vendor-approved procedures under human control; it does
not ship a cross-platform destructive payload, and the prototype performs no
destruction at all.

## Module layout

```
src/disposal/
  config.py        on-disk paths, cost parameters, countdown default
  audit.py         append-only, hash-chained, tamper-evident audit log
  auth.py          scrypt password hashing, roles, lockout, optional TOTP MFA
  inventory.py     READ-ONLY device/storage detection (+ labelled simulation)
  compatibility.py maps storage to NIST method categories (advisory only)
  scheduler.py     50-min countdown, persistence, power-loss/clock recovery
  workflow.py      pre-auth checklist, two-person rule, SIMULATED disposal
  reporting.py     JSON + Markdown reports with audit-chain verdict
  cli.py           command-line front end tying it together
```

Each module is independently testable (see `tests/`). The GUI in a production
build would be a thin layer over `auth`, `inventory`, `compatibility`,
`scheduler`, `workflow`, and `reporting` — no business logic lives in the UI.

## Safety architecture (the important part)

1. **No destructive code path exists.** `SIMULATION_ONLY` is a module constant
   gating `workflow.run_simulation`; there is no "real" branch to flip in this
   build. Adding one would require a reviewed, deliberate change.
2. **The countdown never acts.** `scheduler.tick()` can only move a review to
   `LOCKED_PENDING_CONFIRMATION`. Authorization is a separate, interactive,
   human step.
3. **Defence in depth before even a simulated action:** verified inventory →
   complete 7-item checklist → two-person rule → scheduler locked →
   external/network-drive guard. Any failure blocks.
4. **Everything is audited** in a hash-chained log whose integrity is verifiable
   and reported.

## Scheduler behaviour across device power states

The scheduler runs on the **controller** (the admin's machine or the
USB-hosted app), not on the target device. Consequences:

| Target state | Behaviour |
|---|---|
| Powered off | Countdown continues on the controller. Nothing is sent to the target. At authorization, the tool re-checks that the correct device is present/reachable before proceeding; if not, it blocks. |
| Asleep | Same as powered off from the tool's perspective. No wake-on-LAN or remote trigger is attempted. |
| Disconnected (network/USB) | Countdown continues; authorization's device re-verification and the external-drive guard prevent acting on the wrong or absent device. |
| Running another OS (multi-boot) | The tool cannot see the "other" OS's live state. Inventory must be captured per-OS or from a neutral environment; the human-verification gate exists precisely because cross-OS detection is unreliable. |
| Controller crash / power loss | On restart, persisted schedule state is reloaded. A heartbeat gap flags an unexpected shutdown (audited); if the deadline passed while down, the review is **locked, not executed**. |
| Clock changed | A heartbeat timestamp in the future (relative to now) flags possible clock manipulation (audited). Deadlines are wall-clock; anomalies are surfaced to the operator rather than silently trusted. |

## Technology stack comparison

| Stack | Security | Portability | Maintainability | Device reach | Notes |
|---|---|---|---|---|---|
| **Rust** | Excellent (memory safety) | Excellent | Good | Good via FFI | Best for a trustworthy core that touches storage APIs. |
| **C#/.NET** | Good | Good (esp. Windows) | Good | Strong on Windows | Natural for Windows-heavy fleets; MAUI for UI. |
| **Python** | Fair (easy to audit, but packaging/runtime trust is harder) | Excellent | Excellent | Good | Ideal for a **reference prototype** — this repo. |
| **Tauri** (Rust + web UI) | Excellent | Excellent | Good | UI layer | Small, signed binaries; pairs with a Rust core. |
| **Native platform APIs** | Best for the specific platform | Poor (per-platform) | Lower | Deepest | Required for real sanitize commands (NVMe/ATA, Android EMM). |

**Recommendation for a production build:** a **Rust core** (inventory,
scheduling, audit, authorization logic) exposed to a **Tauri** GUI, with
**per-platform adapters** that call native APIs/vendor tooling. Explicitly
**not** one universal binary: ship a Windows build, a Linux build, and
treat Android boards / OPS modules as separate device adapters with their own
vendor-approved procedures. Sign all binaries; verify the audit log head to
external append-only storage.

The prototype here is intentionally Python-stdlib-only so it is easy to read,
run, and audit without a dependency supply chain.
