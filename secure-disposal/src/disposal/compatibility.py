"""Compatibility assessment — maps detected storage to NIST SP 800-88 Rev. 2
sanitization *categories* and reports what is plausibly supported.

This is advisory only. It never claims a guarantee, and it flags anything it
cannot determine as UNSUPPORTED/UNKNOWN rather than assuming success. The actual
sanitization is always a documented, vendor-approved, human-run procedure — this
tool plans and records it; it does not perform it.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from .inventory import Drive, DeviceInventory


class Method(str, Enum):
    CRYPTO_ERASE = "cryptographic-erase"
    SECURE_ERASE = "vendor-secure-erase"          # ATA Secure Erase / NVMe Format
    FACTORY_RESET = "vendor-factory-reset"        # e.g. Android/board reset
    PHYSICAL = "physical-destruction"
    UNSUPPORTED = "unsupported"


class Confidence(str, Enum):
    DETECTED = "detected"       # we observed capability
    LIKELY = "likely"           # inferred from technology
    UNKNOWN = "unknown"         # cannot determine -> treat as unsupported


@dataclass
class MethodAssessment:
    method: Method
    confidence: Confidence
    rationale: str
    limitations: str


def assess_drive(drive: Drive) -> list[MethodAssessment]:
    out: list[MethodAssessment] = []

    # Cryptographic erase: only meaningful if the data was encrypted at rest.
    enc = any(p.encrypted for p in drive.partitions)
    if drive.supports_crypto_erase or enc:
        out.append(MethodAssessment(
            Method.CRYPTO_ERASE,
            Confidence.DETECTED if drive.supports_crypto_erase else Confidence.LIKELY,
            "Media encryption present or self-encrypting drive reported.",
            "Only sound if ALL data was encrypted from first use and the key is "
            "destroyed in hardware. Residual plaintext written before encryption "
            "is not covered. Verify the key-wrap is truly discarded.",
        ))

    if drive.technology in ("SSD-NVMe", "SSD-SATA"):
        out.append(MethodAssessment(
            Method.SECURE_ERASE,
            Confidence.LIKELY,
            f"{drive.technology} typically supports a vendor sanitize/format "
            "command (NVMe Format w/ secure-erase, ATA Secure Erase).",
            "Effectiveness depends on controller firmware honouring the command. "
            "Some drives silently no-op. Must be VERIFIED by sampling after the "
            "operation. Overwrite passes are NOT reliable on flash (wear "
            "levelling) and are not recommended by NIST for SSDs.",
        ))
    elif drive.technology == "HDD":
        out.append(MethodAssessment(
            Method.SECURE_ERASE,
            Confidence.LIKELY,
            "Magnetic HDD supports overwrite-based Clear/Purge.",
            "A single verified overwrite satisfies NIST Clear for modern drives. "
            "Remapped/reallocated sectors may retain data; use the drive's own "
            "sanitize command where available, and verify.",
        ))
    elif drive.technology == "eMMC":
        out.append(MethodAssessment(
            Method.FACTORY_RESET,
            Confidence.UNKNOWN,
            "Embedded eMMC (e.g. Android board). Sanitization is vendor-mediated.",
            "A factory reset is NOT guaranteed to be a cryptographic purge. "
            "Depends entirely on vendor implementation and whether the device "
            "used file-based/full-disk encryption. Confirm with vendor docs.",
        ))

    if not out:
        out.append(MethodAssessment(
            Method.UNSUPPORTED, Confidence.UNKNOWN,
            "No sanitization capability could be determined for this drive.",
            "Treat as UNSUPPORTED. Physical destruction by an accredited "
            "provider is the fallback for assured disposal.",
        ))

    # Physical destruction is always an option (out-of-band, human/service).
    out.append(MethodAssessment(
        Method.PHYSICAL, Confidence.LIKELY,
        "Physical destruction is media-agnostic.",
        "Requires an accredited destruction service and a certificate of "
        "destruction. Irreversible; removes any reuse/resale value.",
    ))
    return out


def assess_device(inv: DeviceInventory) -> dict:
    result = {
        "device": inv.hostname,
        "verified": inv.verified,
        "drives": [],
        "blocking_warnings": list(inv.warnings),
    }
    if not inv.verified:
        result["blocking_warnings"].append(
            "Inventory is not verified. All irreversible operations are BLOCKED "
            "until a human confirms the hardware configuration.")
    for d in inv.drives:
        result["drives"].append({
            "drive": d.name,
            "technology": d.technology,
            "external_or_network": d.is_external,
            "methods": [
                {"method": a.method.value, "confidence": a.confidence.value,
                 "rationale": a.rationale, "limitations": a.limitations}
                for a in assess_drive(d)
            ],
        })
    return result
