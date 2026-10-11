"""Read-only device and storage inventory.

This module only *reads* system information. It never opens a block device for
writing. Where real detection is unavailable (e.g. inside a container, or on a
platform we cannot introspect without extra privileges), it falls back to a
clearly-labelled simulated inventory and sets ``verified=False`` so downstream
code will BLOCK any irreversible operation until a human verifies the config.

We deliberately distinguish *physical drives* from *logical partitions*, and we
never assume a device has exactly one drive.
"""

from __future__ import annotations

import json
import platform
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Any


@dataclass
class Partition:
    name: str
    size: str = ""
    fstype: str = ""
    mountpoint: str = ""
    encrypted: bool | None = None


@dataclass
class Drive:
    name: str
    model: str = ""
    size: str = ""
    # storage technology: "SSD-NVMe", "SSD-SATA", "HDD", "eMMC", "unknown"
    technology: str = "unknown"
    removable: bool = False
    bus: str = ""            # e.g. "usb", "nvme", "sata"
    is_network: bool = False
    partitions: list[Partition] = field(default_factory=list)
    # Sanitization capabilities we could *detect* (never assume). Informational.
    supports_crypto_erase: bool | None = None
    supports_secure_erase: bool | None = None

    @property
    def is_external(self) -> bool:
        return self.removable or self.bus == "usb" or self.is_network


@dataclass
class DeviceInventory:
    hostname: str
    manufacturer: str
    model: str
    os_name: str
    os_version: str
    cpu_arch: str
    device_type: str            # "computer", "android-board", "ops-module", ...
    drives: list[Drive] = field(default_factory=list)
    recovery_environment: str = "unknown"
    verified: bool = False       # False => block irreversible ops
    source: str = "simulated"    # "detected-linux" | "simulated" | ...
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        def enc(o: Any) -> Any:
            if hasattr(o, "__dict__"):
                return {k: enc(v) for k, v in o.__dict__.items()}
            if isinstance(o, list):
                return [enc(x) for x in o]
            return o
        return enc(self)


def _linux_lsblk() -> list[Drive] | None:
    """Read-only drive enumeration via lsblk JSON. Returns None if unavailable."""
    if not shutil.which("lsblk"):
        return None
    try:
        out = subprocess.run(
            ["lsblk", "-J", "-o",
             "NAME,MODEL,SIZE,TYPE,TRAN,RM,FSTYPE,MOUNTPOINT,ROTA"],
            capture_output=True, text=True, timeout=10, check=True,
        ).stdout
        data = json.loads(out)
    except (subprocess.SubprocessError, json.JSONDecodeError, OSError):
        return None

    drives: list[Drive] = []
    for node in data.get("blockdevices", []):
        if node.get("type") != "disk":
            continue
        tran = (node.get("tran") or "").lower()
        rota = node.get("rota")
        if tran == "nvme":
            tech = "SSD-NVMe"
        elif rota in (False, "0", 0):
            tech = "SSD-SATA"
        elif rota in (True, "1", 1):
            tech = "HDD"
        else:
            tech = "unknown"
        drive = Drive(
            name="/dev/" + node.get("name", "?"),
            model=(node.get("model") or "").strip(),
            size=node.get("size") or "",
            technology=tech,
            removable=bool(node.get("rm")),
            bus=tran,
        )
        for child in node.get("children", []) or []:
            drive.partitions.append(Partition(
                name="/dev/" + child.get("name", "?"),
                size=child.get("size") or "",
                fstype=child.get("fstype") or "",
                mountpoint=child.get("mountpoint") or "",
                encrypted=(child.get("fstype") == "crypto_LUKS"),
            ))
        drives.append(drive)
    return drives


def detect() -> DeviceInventory:
    """Best-effort, read-only detection of the *local* machine."""
    inv = DeviceInventory(
        hostname=platform.node() or "unknown",
        manufacturer="unknown",
        model="unknown",
        os_name=platform.system() or "unknown",
        os_version=platform.release() or "unknown",
        cpu_arch=platform.machine() or "unknown",
        device_type="computer",
    )

    if inv.os_name == "Linux":
        drives = _linux_lsblk()
        if drives is not None:
            inv.drives = drives
            inv.source = "detected-linux"
            inv.verified = True
        else:
            inv.warnings.append(
                "lsblk unavailable; storage not detected. Irreversible "
                "operations are blocked until configuration is verified.")
    else:
        inv.warnings.append(
            f"No read-only detector implemented for {inv.os_name}. "
            "Storage not detected; irreversible operations are blocked "
            "until configuration is verified.")

    if not inv.drives:
        inv.verified = False
    return inv


def sample_board() -> DeviceInventory:
    """A clearly-labelled *simulated* interactive smart board.

    Illustrates the key reality that one physical board can host several
    INDEPENDENT computing environments that must be inventoried separately:
    an embedded Android system AND a pluggable Windows OPS module. We do not
    claim this matches any specific vendor's hardware.
    """
    android = Drive(name="android:emmc0", model="Embedded eMMC",
                    size="32G", technology="eMMC", bus="embedded")
    android.partitions.append(Partition(name="userdata", size="24G",
                                         fstype="f2fs", encrypted=True))
    ops = Drive(name="ops:/dev/nvme0n1", model="OPS NVMe SSD",
                size="256G", technology="SSD-NVMe", bus="nvme",
                supports_crypto_erase=True)
    ops.partitions.append(Partition(name="ops:/dev/nvme0n1p1", size="256G",
                                     fstype="ntfs", mountpoint="C:",
                                     encrypted=False))
    inv = DeviceInventory(
        hostname="SIM-SMARTBOARD-01",
        manufacturer="(simulated vendor)",
        model="(simulated interactive flat panel)",
        os_name="Android + Windows OPS (dual environment)",
        os_version="Android 13 / Windows 11 OPS",
        cpu_arch="arm64 + x86_64",
        device_type="android-board+ops-module",
        drives=[android, ops],
        recovery_environment="vendor factory reset (Android) / WinRE (OPS)",
        verified=False,  # simulated => must be human-verified before any action
        source="simulated",
        warnings=["SIMULATED inventory — not real hardware detection. "
                  "Verify against the physical device and vendor docs."],
    )
    return inv
