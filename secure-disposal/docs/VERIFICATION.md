# Sanitization verification

The verification layer (`verification.py`) decides how far collected evidence is
allowed to advance the verification state. Its job is to **prevent false
success**: a command that exits zero has only been *accepted*; proving data is
unrecoverable needs more.

## States and the evidence required to advance

| State | Meaning | Evidence required to reach it |
|---|---|---|
| `none` | Nothing ran, or the command failed, or the device reports it was never sanitized. | — |
| `command_accepted` | The sanitize command returned success. | Exit code 0 from the erase command. **This is as far as an exit code alone can go.** |
| `operation_complete` | The operation finished on the device, but completion is not, by itself, proof of unrecoverability. | A device/OS completion signal that is necessary-but-not-sufficient, e.g. an all-zero read-back sample. |
| `independently_verified` | Evidence the applicable standard accepts as proof the data is unrecoverable. | A controller-level completion record (NVMe `sanitize-log` SSTAT = completed), or confirmed destruction of the encryption key for a volume encrypted from first use. |

Advancing requires a parser to return that level from *determined* evidence.
The engine additionally claims `data_erased` only when the op actually executed,
succeeded, reached `independently_verified`, **and** carries no conflicting
evidence.

## Inconclusive, conflicting, or error evidence

- **Unparseable / incomplete** evidence → `determined = False`; the state is not
  advanced; a follow-up action is recorded.
- **Device-reported error** (e.g. NVMe SSTAT = failed, a surviving LUKS keyslot,
  a non-zero read-back) → recorded as a **conflict**. `grade()` caps the result
  at `command_accepted` and never claims success; the engine marks the operation
  `NEEDS_MANUAL_REVIEW`.
- An unknown result is **never** converted into success.

## Hardware-specific verification interfaces

Each adapter collects only READ-ONLY evidence it actually supports; it does not
assume every device verifies the same way.

| Environment | Adapter evidence | Parser | Best reachable level | Key limitation |
|---|---|---|---|---|
| Linux NVMe SSD | `nvme sanitize-log` | `parse_nvme_sanitize_log` | `independently_verified` | Trusts the controller to implement SANITIZE conformantly. |
| Linux LUKS (crypto-erase) | `cryptsetup luksDump` | `parse_cryptsetup_luksdump` | `independently_verified` | Valid only if encrypted from first use. |
| Linux SATA SSD/HDD (blkdiscard / ATA) | exit code | `parse_exit_only` | `command_accepted` | No standard completion log parsed yet; needs device-state parsing. |
| Read-back sampling (any) | structured sample | `parse_lba_sample` | `operation_complete` | Cannot see over-provisioning, remapped sectors, or the FTL; never proves Purge alone. |
| Windows | *(exit code today)* | `parse_exit_only` | `command_accepted` | `Get-Disk`/vendor completion parsing not yet implemented. |
| Android / smart board | *(exit / attestation today)* | `parse_exit_only` | `command_accepted` | EMM/vendor attestation parsing not yet implemented. |

## Explicitly limited: LBA sampling

Ordinary read-back sampling is treated as **limited** evidence. All-zero samples
reach only `operation_complete` and always carry the limitation that they cannot
observe over-provisioned blocks, remapped sectors, or data hidden by the flash
translation layer. For Purge-level assurance the tool requires a device-level
sanitize status instead. This matches NIST SP 800-88 guidance that verification
of flash media should rely on the device's own sanitize operation, not surface
reads.

## What is software-implemented vs. hardware-validated

Every parser here is implemented and unit-tested against representative
documented output. **None has been validated against real hardware in this
environment.** See `UNRESOLVED_HARDWARE_TASKS.md`.
