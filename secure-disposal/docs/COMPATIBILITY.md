# Compatibility matrix

## What is genuinely cross-platform vs. platform-specific

**Cross-platform (works the same everywhere, implemented in the prototype):**
- Authentication, roles, lockout, MFA.
- Scheduling, the 50-minute countdown, cancel/reschedule, recovery.
- Audit logging and tamper-evidence.
- Reporting.
- The *authorization workflow* and all its safety gates.
- Read-only, best-effort inventory **collection** (the schema is uniform).

**Platform-specific (requires separate adapters; NOT one universal binary):**
- Actual storage **detection** depth (lsblk vs. WMI/Win32 vs. Android EMM APIs).
- Actual **sanitization** execution (ATA Secure Erase, NVMe Format, Android
  factory reset, vendor OPS tooling).
- **Verification** of erasure (sample reads, sanitize-status, vendor reports).
- Encryption posture detection (BitLocker vs. LUKS vs. Android FBE/FDE).

This split is the core design claim: plan/authorize/record is portable;
erase/verify is not, and must not pretend to be.

## Device × method suitability (advisory)

| Device class | Typical storage | Best-fit NIST method | Notes / limitations |
|---|---|---|---|
| Windows laptop/desktop | NVMe/SATA SSD, sometimes HDD | Crypto-erase if BitLocker from first use; else vendor secure-erase | SSD overwrite is unreliable (wear levelling). Verify. |
| Linux computer | NVMe/SATA SSD, HDD | Crypto-erase if LUKS; else secure-erase (SSD) / overwrite (HDD) | `blkdiscard`/`hdparm`/`nvme format` are vendor-dependent. Verify. |
| Dual/multi-boot | Multiple partitions, often one or more physical drives | Per *physical drive*, not per OS | Never reason per-partition for purge; a drive is the unit. Capture inventory per-OS or from a neutral boot. |
| Android interactive board | eMMC/UFS, FBE/FDE | Vendor factory reset (+ crypto-erase *if* encrypted from first boot) | Factory reset is **not guaranteed** to be a cryptographic purge. Confirm with vendor docs; may need EMM. |
| Windows interactive board | Internal SSD and/or OPS module | As Windows computer, **per environment** | Board firmware may restrict access; OPS is often a separate computer. |
| Linux smart board | eMMC/SSD | As Linux computer | Vendor lockdown may block native tools. |
| OPS module | NVMe/SATA SSD | Vendor secure-erase / crypto-erase | Inventory **independently** from the host panel. |
| Embedded compute module | eMMC/NAND | Vendor procedure or physical destruction | Often no standard sanitize command; destruction may be the only assured option. |

**A digital board may contain several independent computing environments**
(e.g. embedded Android **and** a pluggable Windows OPS). The tool inventories
each separately — see `inventory.sample_board()`.

## Hard rules

- Never assume a device has exactly one drive.
- Never treat a logical partition as the unit of purge; the physical drive is.
- If capability cannot be determined, it is **UNSUPPORTED**, not "probably fine".
- Do not bypass locked bootloaders, admin restrictions, firmware protections, or
  manufacturer security controls. If a device blocks the required procedure, it
  is **unsupported** and physical destruction by an accredited provider is the
  fallback.
- **No compatibility with specific physical boards is claimed** here; entries
  above are generic guidance pending hardware testing and vendor documentation.
