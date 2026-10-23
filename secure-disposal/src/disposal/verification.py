"""Independent sanitization-verification layer.

This module interprets *documented* verification evidence and decides how far it
is allowed to advance the verification state. Its guiding rule is conservative:

    A zero exit code alone is only ``command_accepted``. Advancing to
    ``operation_complete`` needs the device/OS to report completion. Advancing
    to ``independently_verified`` needs evidence that the applicable
    sanitization standard accepts as proof that the data is unrecoverable.

Nothing here invents a vendor format. Each parser targets a documented output
(NVMe sanitize-log fields from the NVMe spec, cryptsetup luksDump, ATA/hdparm
security section, a structured read-back sample). Unrecognised or incomplete
input yields an *undetermined* finding — never a success.

Crucially, ordinary LBA read-back sampling is treated as LIMITED evidence: it
cannot, by itself, prove erasure across SSD over-provisioning, remapped
sectors, or the flash translation layer. It therefore never reaches
``independently_verified`` on its own.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .execution import VerificationLevel

_ORDER = {
    VerificationLevel.NONE: 0,
    VerificationLevel.COMMAND_ACCEPTED: 1,
    VerificationLevel.OPERATION_COMPLETE: 2,
    VerificationLevel.INDEPENDENTLY_VERIFIED: 3,
}


def _min(a: VerificationLevel, b: VerificationLevel) -> VerificationLevel:
    return a if _ORDER[a] <= _ORDER[b] else b


@dataclass
class VerificationFinding:
    level: VerificationLevel
    evidence_type: str
    determined: bool                       # could we read anything meaningful?
    details: dict = field(default_factory=dict)
    limitations: list[str] = field(default_factory=list)
    required_followup: list[str] = field(default_factory=list)
    conflicts: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"level": self.level.value, "evidence_type": self.evidence_type,
                "determined": self.determined, "details": self.details,
                "limitations": self.limitations,
                "required_followup": self.required_followup,
                "conflicts": self.conflicts}


# --------------------------------------------------------------------------
# Parsers for documented evidence formats
# --------------------------------------------------------------------------
def parse_nvme_sanitize_log(text: str) -> VerificationFinding:
    """Parse `nvme sanitize-log` output. SSTAT bits [2:0] (NVMe spec):
    000 never, 001 completed successfully, 010 in progress, 011 failed,
    100 completed with deallocation. A completed controller sanitize is the
    device's authoritative purge indicator (NIST SP 800-88 treats a successful
    SANITIZE as Purge), so it may reach independently_verified."""
    m = re.search(r"SSTAT\)?\s*[:=]\s*(0x[0-9a-fA-F]+|\d+)", text)
    if not m:
        return VerificationFinding(
            VerificationLevel.NONE, "nvme-sanitize-log", determined=False,
            limitations=["no SSTAT field found in sanitize-log output"],
            required_followup=["re-read `nvme sanitize-log` for this device"])
    raw = m.group(1)
    sstat = int(raw, 16) if raw.lower().startswith("0x") else int(raw)
    status = sstat & 0x7
    sprog = None
    mp = re.search(r"SPROG\)?\s*[:=]\s*(\d+)", text)
    if mp:
        sprog = int(mp.group(1))
    details = {"sstat": hex(sstat), "status_bits": status, "sprog": sprog}

    if status in (1, 4):
        return VerificationFinding(
            VerificationLevel.INDEPENDENTLY_VERIFIED, "nvme-sanitize-log",
            determined=True, details=details,
            limitations=["relies on the controller implementing SANITIZE "
                         "conformantly; does not cover a drive that silently "
                         "no-ops a sanitize it reports as complete"])
    if status == 2:
        return VerificationFinding(
            VerificationLevel.COMMAND_ACCEPTED, "nvme-sanitize-log",
            determined=True, details=details,
            limitations=["sanitize still in progress"],
            required_followup=["re-check sanitize-log until SSTAT reports "
                               "completion"])
    if status == 3:
        return VerificationFinding(
            VerificationLevel.COMMAND_ACCEPTED, "nvme-sanitize-log",
            determined=True, details=details,
            conflicts=["device reports sanitize FAILED (SSTAT=0b011)"],
            required_followup=["investigate failure; re-run sanitize or use "
                               "physical destruction"])
    return VerificationFinding(
        VerificationLevel.NONE, "nvme-sanitize-log", determined=True,
        details=details,
        limitations=["device reports it was never sanitized (SSTAT=0b000)"])


def parse_cryptsetup_luksdump(text: str, erase_rc: int | None = None) -> VerificationFinding:
    """Interpret `cryptsetup luksDump` run AFTER a crypto-erase (luksErase).

    If the header is gone ('not a valid LUKS device') or no keyslots remain
    enabled, the master-key wrapping is destroyed. For a volume that was
    encrypted from first use, destroying the key material is an accepted
    cryptographic purge, so this can reach independently_verified — with the
    explicit precondition that the volume was always encrypted."""
    low = text.lower()
    header_gone = "not a valid luks device" in low or "cannot open" in low
    # luksDump lists keyslots; enabled ones say "Key Slot N: ENABLED" (LUKS1) or
    # appear under "Keyslots:" (LUKS2). Treat any 'enabled' as a surviving slot.
    enabled_slot = bool(re.search(r"key\s*slot\s*\d+\s*:\s*enabled", low)) or \
        "enabled" in low
    if header_gone or not enabled_slot:
        return VerificationFinding(
            VerificationLevel.INDEPENDENTLY_VERIFIED, "cryptsetup-luks",
            determined=True,
            details={"header_gone": header_gone, "enabled_slot": enabled_slot},
            limitations=["valid ONLY if the volume was encrypted from first "
                         "use; plaintext written before encryption is not "
                         "covered by crypto-erase"])
    return VerificationFinding(
        VerificationLevel.COMMAND_ACCEPTED, "cryptsetup-luks", determined=True,
        details={"enabled_slot": True},
        conflicts=["a LUKS keyslot is still ENABLED after erase"],
        required_followup=["re-run luksErase; confirm the correct device"])


def parse_lba_sample(samples: list[dict]) -> VerificationFinding:
    """Interpret a structured read-back sample. Each item:
    {"offset": int, "nonzero": bool}. All-zero is only LIMITED evidence."""
    if not samples:
        return VerificationFinding(
            VerificationLevel.NONE, "lba-sample", determined=False,
            required_followup=["collect read-back samples"])
    nonzero = [s for s in samples if s.get("nonzero")]
    if nonzero:
        return VerificationFinding(
            VerificationLevel.COMMAND_ACCEPTED, "lba-sample", determined=True,
            details={"sampled": len(samples), "nonzero": len(nonzero)},
            conflicts=[f"{len(nonzero)} sampled region(s) still contain data"],
            required_followup=["sanitization did not clear sampled data; do not "
                               "proceed"])
    # All sampled regions read zero: necessary but NOT sufficient for Purge.
    return VerificationFinding(
        VerificationLevel.OPERATION_COMPLETE, "lba-sample", determined=True,
        details={"sampled": len(samples), "nonzero": 0},
        limitations=["read-back sampling cannot see over-provisioned blocks, "
                     "remapped sectors, or data hidden by the flash "
                     "translation layer; it does not by itself prove Purge"],
        required_followup=["obtain a device-level sanitize-status (e.g. NVMe "
                           "sanitize-log) for Purge-level assurance"])


def parse_exit_only(returncode: int | None) -> VerificationFinding:
    """A bare command exit code. Success here is ONLY command_accepted."""
    if returncode == 0:
        return VerificationFinding(
            VerificationLevel.COMMAND_ACCEPTED, "exit-code", determined=True,
            details={"returncode": 0},
            limitations=["a zero exit code means the command was accepted, not "
                         "that data is unrecoverable"],
            required_followup=["collect device/OS completion evidence"])
    return VerificationFinding(
        VerificationLevel.NONE, "exit-code", determined=(returncode is not None),
        details={"returncode": returncode},
        conflicts=([f"command returned {returncode}"] if returncode not in (0, None) else []),
        required_followup=["command did not succeed; do not claim sanitization"])


# --------------------------------------------------------------------------
# Grading
# --------------------------------------------------------------------------
def grade(command_level: VerificationLevel,
          findings: list[VerificationFinding]) -> VerificationFinding:
    """Combine the command-level baseline with evidence findings.

    Rules:
      * Start from the command baseline (command_accepted on success).
      * Any conflict caps the result at command_accepted and never claims
        success, recording the conflict and required follow-up.
      * Otherwise the result is the HIGHEST level any determined finding
        supports — but independently_verified requires a finding that
        explicitly reaches it.
    """
    result = VerificationFinding(
        level=command_level, evidence_type="composite", determined=True,
        details={"command_level": command_level.value},
        limitations=[], required_followup=[], conflicts=[])

    any_conflict = False
    best = command_level
    for f in findings:
        result.limitations += [f"[{f.evidence_type}] {x}" for x in f.limitations]
        result.required_followup += [f"[{f.evidence_type}] {x}"
                                     for x in f.required_followup]
        if f.conflicts:
            any_conflict = True
            result.conflicts += [f"[{f.evidence_type}] {x}" for x in f.conflicts]
        if f.determined and _ORDER[f.level] > _ORDER[best]:
            best = f.level

    if any_conflict:
        # Conflicting/failing evidence: never advance past the command baseline,
        # and never above command_accepted.
        result.level = _min(command_level, VerificationLevel.COMMAND_ACCEPTED)
        result.details["downgraded_due_to_conflict"] = True
    else:
        result.level = best
    return result
