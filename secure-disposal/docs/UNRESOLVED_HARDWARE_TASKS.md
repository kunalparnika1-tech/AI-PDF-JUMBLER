# Unresolved hardware-dependent tasks

These cannot be completed or validated without real hardware, elevated
privileges on a designated host, vendor tooling, or manufacturer documentation.
They are explicitly **out of scope for autonomous completion** and are listed so
an operator can schedule them deliberately. None of these are claimed as done.

## Requires real devices / privileges
1. **Automatic device-serial read** per platform (Linux `lsblk -o SERIAL` /
   `nvme id-ctrl`, Windows WMI `Win32_DiskDrive.SerialNumber`, Android build
   props). Needed so the typed-serial confirmation can be checked against the
   device, not just operator input.
2. **Adapter preflight checks**: e.g. ATA Secure Erase requires a user password
   set via `hdparm --security-set-pass` and a `not frozen` state; NVMe sanitize
   support must be read from the controller before `nvme format`.
3. **Real post-operation verification**: content sampling of representative
   LBAs and parsing of the drive's sanitize-status / NVMe sanitize log to
   produce machine-readable evidence.
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
