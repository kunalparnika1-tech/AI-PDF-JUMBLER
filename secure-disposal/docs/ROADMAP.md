# Future development roadmap

Ordered by value and dependency. None of this changes the core rule: assured
erasure stays platform-specific, human-authorized, and verified.

## Near term
- **Tauri + Rust GUI** over the existing module boundaries (dashboard,
  scheduling, review, reports) — no business logic in the UI.
- **Windows detection adapter** (WMI/Win32) and **BitLocker posture** read-only.
- **External WORM audit anchoring**: periodically export the audit-chain head to
  append-only storage; verify on launch.
- **FIDO2/WebAuthn MFA** alongside TOTP.

## Medium term
- **Verification-evidence capture**: structured post-operation sample-read and
  sanitize-status records attached to reports (for real, out-of-band runs).
- **Android/EMM adapter** (read-only posture + documented wipe invocation via
  enterprise management, never bootloader bypass).
- **Backup-system integration** so `backup_status_checked` can be asserted
  programmatically rather than by attestation.
- **Policy engine**: require change-ticket references, approval quorums per
  device class, and time-window constraints.

## Longer term / carefully gated
- **Opt-in destructive adapters**, per platform, behind: signed builds, dual
  control, mandatory verification, and a separate, reviewed enablement flag —
  never a universal binary, never an unattended trigger.
- **Fleet mode**: manage many devices with per-device audit trails and
  aggregated retirement reporting.
- **Formal compatibility testing program** with documented hardware results,
  replacing the advisory matrix with evidence-backed entries.
