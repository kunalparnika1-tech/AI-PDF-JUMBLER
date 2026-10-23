"""Privilege detection and capability checks.

This module only *observes* the current privilege level and reports it. It does
NOT escalate privileges, call sudo, modify OS security, or hide anything. The
principle is least privilege: an operation declares the capability it needs, and
this module reports whether the current context plausibly has it, so the engine
can refuse early and clearly rather than failing half-way.

Root/Administrator is necessary but never sufficient for a destructive
operation: authorization (two-person rule, verified target, explicit opt-in)
is enforced separately in the workflow/execution layers.
"""

from __future__ import annotations

import os
import platform
import shutil
from dataclasses import dataclass


@dataclass
class PrivilegeReport:
    platform: str
    is_elevated: bool          # root (POSIX) or Administrator (Windows)
    uid: int | None
    euid: int | None
    user: str
    notes: list[str]

    def summary(self) -> str:
        who = "elevated" if self.is_elevated else "unprivileged"
        return f"{self.user}@{self.platform}: {who}"


def detect() -> PrivilegeReport:
    system = platform.system()
    notes: list[str] = []
    user = os.environ.get("USER") or os.environ.get("USERNAME") or "unknown"
    uid = euid = None
    is_elevated = False

    if system in ("Linux", "Darwin"):
        uid = os.getuid()            # type: ignore[attr-defined]
        euid = os.geteuid()          # type: ignore[attr-defined]
        is_elevated = (euid == 0)
        if uid != euid:
            notes.append("running setuid; euid differs from uid")
    elif system == "Windows":
        try:
            import ctypes
            is_elevated = bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore
        except Exception:
            notes.append("could not determine Administrator status")
    else:
        notes.append(f"privilege detection not implemented for {system}")

    return PrivilegeReport(platform=system, is_elevated=is_elevated, uid=uid,
                           euid=euid, user=user, notes=notes)


# Capabilities an operation may require, mapped to a coarse check.
def has_capability(capability: str, report: PrivilegeReport | None = None) -> bool:
    report = report or detect()
    if capability == "read-block-devices":
        # Reading device metadata often works unprivileged; be optimistic but
        # callers should still handle permission errors.
        return True
    if capability in ("ata-secure-erase", "nvme-format", "blkdiscard",
                      "luks-erase"):
        # Issuing a controller sanitize/format command needs elevation and the
        # relevant tool present.
        tool = {
            "ata-secure-erase": "hdparm",
            "nvme-format": "nvme",
            "blkdiscard": "blkdiscard",
            "luks-erase": "cryptsetup",
        }[capability]
        return report.is_elevated and shutil.which(tool) is not None
    # Unknown capability => conservatively false.
    return False


def missing_requirements(capability: str,
                         report: PrivilegeReport | None = None) -> list[str]:
    """Human-readable reasons the capability is unavailable (empty => available)."""
    report = report or detect()
    reasons: list[str] = []
    tool_for = {
        "ata-secure-erase": "hdparm",
        "nvme-format": "nvme",
        "blkdiscard": "blkdiscard",
        "luks-erase": "cryptsetup",
    }
    if capability in tool_for:
        if not report.is_elevated:
            reasons.append("requires elevated privileges (root/Administrator)")
        if shutil.which(tool_for[capability]) is None:
            reasons.append(f"required tool not found: {tool_for[capability]}")
    elif capability != "read-block-devices":
        reasons.append(f"unknown capability: {capability}")
    return reasons
