"""Pre-authorization safeguards and the SIMULATED disposal workflow.

Nothing in this module performs a destructive operation. ``run_simulation``
records, step by step, what a vendor-approved procedure *would* do and produces
verification evidence describing the checks a human would perform. It is gated
behind:

  1. A verified device inventory.
  2. A completed pre-authorization checklist (all seven items true).
  3. A second, distinct ADMIN confirmation (two-person rule).
  4. The scheduler being in LOCKED_PENDING_CONFIRMATION.
  5. A guard that refuses external / network / removable drives unless the
     operator explicitly, separately overrides per drive.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from . import SIMULATION_ONLY
from .audit import AuditLog
from .inventory import DeviceInventory, Drive


@dataclass
class PreAuthChecklist:
    device_identity_confirmed: bool = False
    drive_inventory_confirmed: bool = False
    backup_status_checked: bool = False
    records_retained_confirmed: bool = False
    device_not_in_use_confirmed: bool = False
    method_supported_confirmed: bool = False
    second_admin_confirmed: bool = False

    def outstanding(self) -> list[str]:
        return [k for k, v in self.__dict__.items() if not v]

    def complete(self) -> bool:
        return not self.outstanding()


class WorkflowError(Exception):
    pass


def _guard_external_drives(inv: DeviceInventory,
                           allow_external: set[str]) -> list[str]:
    """Return a list of blocking messages for external/network drives not
    explicitly allowed. This prevents accidentally selecting a USB stick or a
    network share."""
    blocks = []
    for d in inv.drives:
        if d.is_external and d.name not in allow_external:
            blocks.append(
                f"Drive {d.name} is external/removable/network and is NOT "
                "explicitly allowed. Refusing to include it.")
    return blocks


@dataclass
class SimulationResult:
    review_id: str
    device_id: str
    method: str
    steps: list[dict[str, Any]] = field(default_factory=list)
    verification: list[dict[str, Any]] = field(default_factory=list)
    status: str = "simulated-complete"
    simulated: bool = True
    generated_at: str = ""


def run_simulation(
    *,
    review_id: str,
    inventory: DeviceInventory,
    method: str,
    checklist: PreAuthChecklist,
    scheduler_locked: bool,
    confirming_admin: str,
    scheduling_admin: str,
    audit: AuditLog,
    allow_external: set[str] | None = None,
) -> SimulationResult:
    if not SIMULATION_ONLY:  # pragma: no cover - defensive; never flipped here
        raise WorkflowError("destructive mode is not implemented in this build")

    allow_external = allow_external or set()

    # --- gate 1: verified inventory ---
    if not inventory.verified:
        raise WorkflowError("device inventory is not verified; blocked")

    # --- gate 2: checklist complete ---
    if not checklist.complete():
        raise WorkflowError(
            "pre-authorization incomplete: " + ", ".join(checklist.outstanding()))

    # --- gate 3: two-person rule ---
    if confirming_admin == scheduling_admin:
        raise WorkflowError(
            "two-person rule: the confirming admin must differ from the admin "
            "who scheduled the review")

    # --- gate 4: scheduler locked ---
    if not scheduler_locked:
        raise WorkflowError(
            "review is not in LOCKED_PENDING_CONFIRMATION; cannot proceed")

    # --- gate 5: external-drive guard ---
    blocks = _guard_external_drives(inventory, allow_external)
    if blocks:
        raise WorkflowError(" / ".join(blocks))

    audit.append("workflow.authorized", confirming_admin, {
        "review_id": review_id, "method": method,
        "scheduled_by": scheduling_admin})

    result = SimulationResult(
        review_id=review_id,
        device_id=inventory.hostname,
        method=method,
        generated_at=datetime.now(timezone.utc).isoformat(),
    )

    for drive in inventory.drives:
        if drive.is_external and drive.name not in allow_external:
            continue  # already guarded, but be defensive
        result.steps.append({
            "drive": drive.name,
            "technology": drive.technology,
            "planned_action": _describe_action(method, drive),
            "performed": False,
            "note": "SIMULATION ONLY — no command was issued to the device.",
        })
        result.verification.append({
            "drive": drive.name,
            "verification_plan": _verification_plan(method, drive),
            "evidence": "n/a (simulation) — a real run would attach a sample "
                        "read-back and/or a vendor certificate here.",
        })

    audit.append("workflow.simulated_complete", confirming_admin, {
        "review_id": review_id, "drives": [d.name for d in inventory.drives]})
    return result


def _describe_action(method: str, drive: Drive) -> str:
    table = {
        "cryptographic-erase":
            f"[simulated] Instruct controller of {drive.name} to destroy the "
            "media-encryption key (crypto-erase), rendering ciphertext "
            "unrecoverable.",
        "vendor-secure-erase":
            f"[simulated] Issue the drive's native sanitize command to "
            f"{drive.name} (NVMe Format / ATA Secure Erase).",
        "vendor-factory-reset":
            f"[simulated] Invoke the vendor factory-reset procedure for "
            f"{drive.name} per the device's documented process.",
        "physical-destruction":
            f"[simulated] Route {drive.name} to an accredited physical-"
            "destruction service and record the certificate.",
    }
    return table.get(method, f"[simulated] UNSUPPORTED method for {drive.name}.")


def _verification_plan(method: str, drive: Drive) -> str:
    if method == "physical-destruction":
        return ("Obtain and file the certificate of destruction; confirm serial "
                "number matches the inventory.")
    return ("Sample-read representative LBAs/regions after the operation to "
            "confirm they no longer return prior data; record the drive's "
            "sanitize-status report where available.")
