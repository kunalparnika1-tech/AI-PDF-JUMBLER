# Unresolved hardware-dependent tasks

These cannot be completed or validated without real hardware, elevated
privileges on a designated host, vendor tooling, or manufacturer documentation.
They are explicitly **out of scope for autonomous completion** and are listed so
an operator can schedule them deliberately. None of these are claimed as done.

## Status update (this iteration)
- **Serial/WWN reading — IMPLEMENTED (needs hardware validation).** Linux
  (`lsblk` SERIAL/WWN) and Windows (`Get-Disk` SerialNumber) parsers are in
  place and unit-tested on sample output; Android via `adb shell lsblk`. These
  have not been validated against real devices in this environment.
- **Adapter preflight — IMPLEMENTED.** Identity, compatibility, method support,
  privileges, encryption prerequisite, and tool availability are checked before
  any real op, with no silent fallback. Validated in unit tests.
- **Target re-verification — IMPLEMENTED.** Re-detect-and-compare immediately
  before the irreversible step; replacement/removal is a hard stop.

## Still requires real devices / privileges
1. **Validate serial/WWN reading on real Linux/Windows/Android hardware** and
   handle vendor quirks (empty serials on some USB bridges, virtual disks).
2. **Adapter preflight depth**: ATA Secure Erase also needs a user password set
   via `hdparm --security-set-pass` and a `not frozen` state; NVMe sanitize
   support must be read from the controller before a format. These device-state
   checks need real drives.
3. **Independent post-operation verification — IMPLEMENTED IN SOFTWARE, needs
   hardware validation.** `verification.py` parses NVMe `sanitize-log` (SSTAT),
   `cryptsetup luksDump`, and structured read-back samples, grades them into the
   four-state model, and the engine claims `data_erased` only on
   `independently_verified` with no conflict (else `NEEDS_MANUAL_REVIEW`). Still
   to do on real hardware:
   - Validate NVMe SSTAT parsing against drives from multiple vendors.
   - Validate LUKS keyslot interpretation on LUKS1 and LUKS2.
   - Confirm the all-zero-sampling limitation handling against real SSDs.
4. **ATA / Windows / Android completion parsers — NOT YET IMPLEMENTED.** These
   adapters currently top out at `command_accepted` (exit code only). Parsing
   `hdparm` security status, Windows vendor/`Get-Disk` completion, and Android
   EMM wipe attestation each needs the corresponding real environment.
4. **Windows execution adapter**: `cipher /w`, `manage-bde` crypto-erase,
   vendor toolkits — requires a Windows host and Administrator.
5. **Android / OPS adapters**: EMM/MDM enterprise-wipe invocation and OPS module
   enumeration — requires enrolled devices and vendor SDKs/docs.

## Requires manufacturer documentation
6. **Per-vendor smart-board procedures** and their guarantees (whether a factory
   reset is a cryptographic purge). The compatibility matrix entries stay
   advisory until confirmed against each vendor.
7. **Secure Boot / firmware-lock interactions** per board model.

## Requires external authorization
8. **Accredited physical-destruction** workflow integration and certificate
   capture.
9. **Enabling real execution** in any environment: a human decision plus the
   three-layer opt-in described in `SECURITY_ASSESSMENT.md`.

## Validated only in simulation so far
- Every destructive adapter's command string is constructed and unit-tested, but
  executed **only** against injected fake runners. No destructive command has
  been run against a real device by this codebase.
