# Platform-specific disposal procedures (documented, vendor-approved)

These are **operator procedures**, run deliberately and out-of-band by a human
after the tool has authorized a review and produced a plan. The tool records
which procedure was chosen and the verification; it does not execute them. Follow
your organization's policy and the device vendor's current documentation —
treat the references below as pointers, and verify against the vendor before
acting.

Always: confirm backups and record retention, confirm the correct physical
drive(s), and perform post-operation verification. Keep the certificate or
verification evidence with the report.

## Windows computers
- **Crypto-erase (preferred if BitLocker was enabled from first use):** confirm
  the drive was always encrypted, then remove/rotate so the key is unrecoverable
  (e.g. reset via the drive's secure-erase, which discards the media key on SEDs).
- **Vendor secure-erase:** use the SSD vendor's toolkit or UEFI firmware's
  built-in secure-erase; for NVMe, a format with secure-erase setting.
- **Verification:** sample-read regions; check the drive's sanitize-status.
- Reference: NIST SP 800-88 Rev. 2; Microsoft BitLocker documentation; SSD
  vendor sanitize tooling.

## Linux computers
- **Crypto-erase (if LUKS from first use):** destroy the LUKS header/keyslots so
  the master key is unrecoverable (`cryptsetup luksErase` on the correct device).
- **SSD:** vendor secure-erase (`nvme format` with secure-erase, or ATA Secure
  Erase via `hdparm`) — effectiveness is firmware-dependent; verify.
- **HDD:** a single verified overwrite satisfies NIST Clear on modern drives;
  prefer the drive's own sanitize where available.
- **Verification:** sample-read; `nvme id-ctrl`/sanitize-log where supported.

## Dual-/multi-boot
- Reason per **physical drive**, not per OS or per partition.
- Capture the full physical-drive inventory from a neutral environment (e.g. a
  live USB) so no OS's live state hides a drive.
- Apply the per-drive method above to each physical drive selected.

## Android interactive boards
- **Factory reset** via the device's admin settings, and/or an EMM/MDM
  enterprise wipe if enrolled. Note: a factory reset is a cryptographic purge
  **only if** the device used file-based/full-disk encryption from first boot —
  confirm with the vendor.
- Do not attempt to unlock the bootloader or bypass device-admin restrictions.
- **Verification:** vendor attestation / EMM wipe confirmation.

## Windows OPS modules
- Treat as a Windows computer, inventoried **independently** of the host panel.
- Use the OPS SSD's secure-erase / crypto-erase as above.

## Linux smart boards / embedded compute modules
- If vendor tooling exposes a sanitize command, use it and verify.
- If the platform is locked down and exposes no assured sanitize path, it is
  **unsupported** for logical sanitization — use accredited physical
  destruction and file the certificate.

## Physical destruction (fallback for any class)
- Use an accredited destruction service; match the device/drive serial to the
  inventory; obtain and retain a certificate of destruction.
- Appropriate when logical sanitization is unsupported, unverifiable, or when
  policy requires Destroy-level assurance.
