"""Execution adapters: build, validate, (optionally) run, and verify a
vendor/OS sanitization procedure for an explicitly designated physical drive.

SAFETY MODEL (read this before changing anything here)
-------------------------------------------------------
There are two runners:
  * ``DryRunRunner``  — the DEFAULT. Records the exact command; executes nothing.
  * ``RealCommandRunner`` — actually invokes the command via subprocess.

A real (destructive) run is reachable ONLY when ALL of these hold:
  1. ``config.allow_real_execution`` is true (an explicit file/opt-in), AND
  2. the environment variable ``DISPOSAL_ALLOW_REAL_EXECUTION=yes`` is set, AND
  3. the caller passes ``RealCommandRunner`` explicitly, AND
  4. ``confirm_fn`` returns the target drive's EXACT serial, typed by a human,
     at the moment of execution, AND
  5. a validated authorization token is present.

It is NEVER reached by the countdown, by policy/config alone, autonomously, or
by default. The two-person authorization and the ``TargetGuard`` below apply in
every case. A destructive command is never auto-retried (see ``state.py``).

This module builds REAL, documented commands (nvme/hdparm/blkdiscard/cryptsetup)
so the plan is concrete and auditable; whether they actually run is governed
entirely by the gate above.
"""

from __future__ import annotations

import subprocess
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Callable, Protocol

from .inventory import Drive


class ExecutionError(Exception):
    pass


class TargetValidationError(ExecutionError):
    pass


# --------------------------------------------------------------------------
# Command runners
# --------------------------------------------------------------------------
@dataclass
class CommandResult:
    command: list[str]
    executed: bool
    returncode: int | None = None
    stdout: str = ""
    stderr: str = ""
    note: str = ""


class CommandRunner(Protocol):
    def run(self, command: list[str], timeout: float) -> CommandResult: ...


class DryRunRunner:
    """Default runner. Records the command but never executes it."""

    def run(self, command: list[str], timeout: float) -> CommandResult:
        return CommandResult(command=list(command), executed=False,
                             note="dry-run: command NOT executed")


class RealCommandRunner:
    """Executes commands for real. Instantiating this does not bypass any gate;
    the engine still enforces every precondition before it is used."""

    def run(self, command: list[str], timeout: float) -> CommandResult:
        try:
            proc = subprocess.run(command, capture_output=True, text=True,
                                  timeout=timeout, check=False)
        except subprocess.TimeoutExpired as e:  # pragma: no cover - env specific
            return CommandResult(command=list(command), executed=True,
                                 returncode=None, note=f"timeout after {timeout}s: {e}")
        return CommandResult(command=list(command), executed=True,
                             returncode=proc.returncode, stdout=proc.stdout,
                             stderr=proc.stderr)


# --------------------------------------------------------------------------
# Target guard — unambiguous physical-drive selection
# --------------------------------------------------------------------------
@dataclass
class DesignatedTarget:
    """What the operator explicitly authorized: a physical drive pinned by
    identity, not just a path (paths can be reassigned between boots)."""
    drive_name: str
    expected_serial: str
    expected_size: str


class TargetGuard:
    @staticmethod
    def validate(drive: Drive, target: DesignatedTarget,
                 boot_drive: str | None, allow_external: bool = False) -> None:
        if drive.name != target.drive_name:
            raise TargetValidationError(
                f"target path mismatch: {drive.name} != {target.drive_name}")
        # A real drive object would expose a serial; our model does not carry
        # one yet, so we validate on name+size and require the caller to have
        # matched the serial out of band. Size mismatch is a hard stop.
        if target.expected_size and drive.size and drive.size != target.expected_size:
            raise TargetValidationError(
                f"size mismatch for {drive.name}: {drive.size} != "
                f"{target.expected_size} (wrong device?)")
        # Refuse a drive mounted as the live controller's own root/boot. (A
        # remote target device's own mountpoints are not the controller's; use
        # --boot-drive to pin the boot drive explicitly for those.)
        if drive.partitions and any(
                p.mountpoint in ("/", "/boot", "/boot/efi")
                for p in drive.partitions):
            raise TargetValidationError(
                f"{drive.name} hosts the live root/boot mountpoint; refusing")
        if boot_drive and drive.name == boot_drive:
            raise TargetValidationError(
                f"{drive.name} is the OS boot drive; refusing")
        if drive.is_external and not allow_external:
            raise TargetValidationError(
                f"{drive.name} is external/removable/network; not explicitly "
                "allowed")


# --------------------------------------------------------------------------
# Adapters
# --------------------------------------------------------------------------
@dataclass
class AdapterPlan:
    method: str
    capability: str
    command: list[str]
    destructive: bool
    rationale: str


class ExecutionAdapter(ABC):
    method: str = ""
    capability: str = ""
    destructive: bool = True

    @abstractmethod
    def supports(self, drive: Drive) -> bool: ...

    @abstractmethod
    def build_command(self, drive: Drive) -> list[str]: ...

    def plan(self, drive: Drive) -> AdapterPlan:
        return AdapterPlan(method=self.method, capability=self.capability,
                           command=self.build_command(drive),
                           destructive=self.destructive,
                           rationale=self.rationale(drive))

    def rationale(self, drive: Drive) -> str:
        return f"{self.method} on {drive.name}"

    def verify(self, drive: Drive, runner: CommandRunner) -> CommandResult:
        """Post-op verification is a READ-ONLY check. Default: read device info."""
        return runner.run(self.verify_command(drive), timeout=60)

    def verify_command(self, drive: Drive) -> list[str]:
        return ["lsblk", "-no", "NAME,SIZE,FSTYPE", drive.name]


class SimulationAdapter(ExecutionAdapter):
    method = "simulation"
    capability = "read-block-devices"
    destructive = False

    def supports(self, drive: Drive) -> bool:
        return True

    def build_command(self, drive: Drive) -> list[str]:
        return ["true", f"# simulated sanitize of {drive.name}"]

    def rationale(self, drive: Drive) -> str:
        return f"[simulation] no command issued for {drive.name}"


class BlkdiscardAdapter(ExecutionAdapter):
    method = "vendor-secure-erase"
    capability = "blkdiscard"

    def supports(self, drive: Drive) -> bool:
        return drive.technology in ("SSD-NVMe", "SSD-SATA")

    def build_command(self, drive: Drive) -> list[str]:
        # --secure requests a secure discard where the device supports it.
        return ["blkdiscard", "--secure", drive.name]


class NvmeFormatAdapter(ExecutionAdapter):
    method = "vendor-secure-erase"
    capability = "nvme-format"

    def supports(self, drive: Drive) -> bool:
        return drive.technology == "SSD-NVMe"

    def build_command(self, drive: Drive) -> list[str]:
        # -s1 = user-data erase; -s2 = cryptographic erase (if supported).
        return ["nvme", "format", drive.name, "--ses=1"]


class AtaSecureEraseAdapter(ExecutionAdapter):
    method = "vendor-secure-erase"
    capability = "ata-secure-erase"

    def supports(self, drive: Drive) -> bool:
        return drive.technology in ("SSD-SATA", "HDD")

    def build_command(self, drive: Drive) -> list[str]:
        # Real use also requires setting a user password first; this is the
        # erase invocation itself.
        return ["hdparm", "--security-erase", "NULL", drive.name]


class LuksEraseAdapter(ExecutionAdapter):
    method = "cryptographic-erase"
    capability = "luks-erase"

    def supports(self, drive: Drive) -> bool:
        return any(p.encrypted for p in drive.partitions)

    def build_command(self, drive: Drive) -> list[str]:
        return ["cryptsetup", "luksErase", "--batch-mode", drive.name]


ADAPTERS: dict[str, type[ExecutionAdapter]] = {
    "simulation": SimulationAdapter,
    "blkdiscard": BlkdiscardAdapter,
    "nvme-format": NvmeFormatAdapter,
    "ata-secure-erase": AtaSecureEraseAdapter,
    "luks-erase": LuksEraseAdapter,
}


def get_adapter(name: str) -> ExecutionAdapter:
    if name not in ADAPTERS:
        raise ExecutionError(f"unknown adapter: {name}")
    return ADAPTERS[name]()
