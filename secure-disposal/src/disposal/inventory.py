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
    # Hardware identity. Read where supported; may be missing/empty.
    serial: str = ""
    wwn: str = ""            # World Wide Name (stable, globally unique when set)
    vendor: str = ""

    @property
    def is_external(self) -> bool:
        return self.removable or self.bus == "usb" or self.is_network

    def identity(self) -> str:
        """A stable identity for this physical drive, preferring the most
        trustworthy identifier available. Paths (``name``) are the LAST resort
        because they are reassigned between boots and across replug."""
        if self.wwn:
            return f"wwn:{self.wwn}"
        if self.serial:
            return f"serial:{self.serial}"
        # No stable hardware id: fall back to model+size+path, and callers must
        # treat this as weak (see has_strong_identity).
        return f"weak:{self.model}|{self.size}|{self.name}"

    def has_strong_identity(self) -> bool:
        return bool(self.wwn or self.serial)


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
             "NAME,MODEL,SIZE,TYPE,TRAN,RM,FSTYPE,MOUNTPOINT,ROTA,"
             "SERIAL,WWN,VENDOR"],
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
            serial=(node.get("serial") or "").strip(),
            wwn=(node.get("wwn") or "").strip(),
            vendor=(node.get("vendor") or "").strip(),
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


def _parse_windows_disks(json_text: str) -> list[Drive]:
    """Parse the JSON of a read-only ``Get-Disk`` / ``Get-PhysicalDisk`` query.

    Expected shape (array or single object):
      {"Number":0,"FriendlyName":"Samsung SSD","SerialNumber":"S1","Size":512...,
       "BusType":"NVMe","MediaType":"SSD"}
    """
    data = json.loads(json_text)
    if isinstance(data, dict):
        data = [data]
    drives: list[Drive] = []
    for d in data:
        bus = (d.get("BusType") or "").lower()
        media = (d.get("MediaType") or "").upper()
        if bus == "nvme":
            tech = "SSD-NVMe"
        elif media == "SSD":
            tech = "SSD-SATA"
        elif media == "HDD":
            tech = "HDD"
        else:
            tech = "unknown"
        size = d.get("Size")
        size_str = f"{round(int(size)/1e9)}G" if isinstance(size, (int, float)) else str(size or "")
        drives.append(Drive(
            name=f"\\\\.\\PhysicalDrive{d.get('Number', '?')}",
            model=(d.get("FriendlyName") or "").strip(),
            size=size_str,
            technology=tech,
            removable=bool(d.get("RemovableMedia") or bus == "usb"),
            bus=bus,
            serial=(d.get("SerialNumber") or "").strip(),
            vendor=(d.get("Manufacturer") or "").strip(),
        ))
    return drives


def _windows_powershell() -> list[Drive] | None:
    """Read-only disk enumeration on Windows via PowerShell. None if unavailable.

    Requires: Windows, PowerShell, and (for full identifiers) an elevated
    session. This issues only Get-* (read) cmdlets; it never writes.
    """
    if not shutil.which("powershell"):
        return None
    cmd = ["powershell", "-NoProfile", "-NonInteractive", "-Command",
           "Get-Disk | Select-Object Number,FriendlyName,SerialNumber,Size,"
           "BusType,Manufacturer | ConvertTo-Json -Compress"]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=20,
                             check=True).stdout
        return _parse_windows_disks(out) if out.strip() else []
    except (subprocess.SubprocessError, json.JSONDecodeError, OSError):
        return None


def _parse_android_disks(lsblk_json: str) -> list[Drive]:
    """Parse ``adb shell lsblk -J`` output from an Android device (read-only)."""
    data = json.loads(lsblk_json)
    drives: list[Drive] = []
    for node in data.get("blockdevices", []):
        if node.get("type") != "disk":
            continue
        drives.append(Drive(
            name="android:" + node.get("name", "?"),
            model=(node.get("model") or "").strip(),
            size=node.get("size") or "",
            technology="eMMC",
            bus="embedded",
            serial=(node.get("serial") or "").strip(),
        ))
    return drives


def _android_adb() -> list[Drive] | None:
    """Read-only Android storage enumeration via adb. None if unavailable.

    Requires: adb present, USB debugging/authorized device, and (for a managed
    device) the vendor's EMM/MDM for any actual sanitization. This reads only.
    """
    if not shutil.which("adb"):
        return None
    try:
        out = subprocess.run(["adb", "shell", "lsblk", "-J"],
                             capture_output=True, text=True, timeout=20,
                             check=True).stdout
        return _parse_android_disks(out) if out.strip() else []
    except (subprocess.SubprocessError, json.JSONDecodeError, OSError):
        return None


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
    elif inv.os_name == "Windows":
        drives = _windows_powershell()
        if drives is not None:
            inv.drives = drives
            inv.source = "detected-windows"
            inv.verified = True
        else:
            inv.warnings.append(
                "PowerShell disk query unavailable; storage not detected. "
                "Irreversible operations are blocked until verified.")
    else:
        inv.warnings.append(
            f"No read-only detector implemented for {inv.os_name}. "
            "Storage not detected; irreversible operations are blocked "
            "until configuration is verified.")

    if not inv.drives:
        inv.verified = False
    annotate_identity_warnings(inv)
    return inv


def annotate_identity_warnings(inv: DeviceInventory) -> None:
    """Flag drives with missing or duplicate serials. Duplicate/absent serials
    make a drive ambiguous; target verification must then rely on a stronger
    signal or refuse. We only warn here — we never erase on a weak identity."""
    seen: dict[str, list[str]] = {}
    for d in inv.drives:
        if not d.has_strong_identity():
            inv.warnings.append(
                f"{d.name}: no serial/WWN available; identity is WEAK. "
                "Destructive operations require a strong, verified identity.")
        key = d.serial or d.wwn
        if key:
            seen.setdefault(key, []).append(d.name)
    for key, names in seen.items():
        if len(names) > 1:
            inv.warnings.append(
                f"DUPLICATE identifier {key!r} on drives {names}; identity is "
                "ambiguous. Destructive operations are blocked for these.")


def duplicate_identifiers(inv: DeviceInventory) -> set[str]:
    """Return the set of serial/WWN values that appear on more than one drive."""
    seen: dict[str, int] = {}
    for d in inv.drives:
        key = d.serial or d.wwn
        if key:
            seen[key] = seen.get(key, 0) + 1
    return {k for k, n in seen.items() if n > 1}


@dataclass
class InventoryDelta:
    removed: list[str] = field(default_factory=list)      # identities gone
    added: list[str] = field(default_factory=list)        # new identities
    replaced: list[tuple[str, str]] = field(default_factory=list)  # path reused

    @property
    def changed(self) -> bool:
        return bool(self.removed or self.added or self.replaced)


def diff_inventories(before: DeviceInventory,
                     after: DeviceInventory) -> InventoryDelta:
    """Detect device removal and replacement between two snapshots.

    A *replacement* is the dangerous case: the same path (e.g. /dev/sdb) now
    carries a DIFFERENT strong identity than before. Callers must treat a
    replacement on an approved target as a hard stop.
    """
    delta = InventoryDelta()
    before_ids = {d.identity() for d in before.drives if d.has_strong_identity()}
    after_ids = {d.identity() for d in after.drives if d.has_strong_identity()}
    delta.removed = sorted(before_ids - after_ids)
    delta.added = sorted(after_ids - before_ids)

    before_by_path = {d.name: d for d in before.drives}
    for d in after.drives:
        prev = before_by_path.get(d.name)
        if prev and prev.has_strong_identity() and d.has_strong_identity():
            if prev.identity() != d.identity():
                delta.replaced.append((d.name, d.identity()))
    return delta


def sample_board() -> DeviceInventory:
    """A clearly-labelled *simulated* interactive smart board.

    Illustrates the key reality that one physical board can host several
    INDEPENDENT computing environments that must be inventoried separately:
    an embedded Android system AND a pluggable Windows OPS module. We do not
    claim this matches any specific vendor's hardware.
    """
    android = Drive(name="android:emmc0", model="Embedded eMMC",
                    size="32G", technology="eMMC", bus="embedded",
                    serial="SIM-EMMC-AND-0001", vendor="(sim)")
    android.partitions.append(Partition(name="userdata", size="24G",
                                         fstype="f2fs", encrypted=True))
    ops = Drive(name="ops:/dev/nvme0n1", model="OPS NVMe SSD",
                size="256G", technology="SSD-NVMe", bus="nvme",
                supports_crypto_erase=True,
                serial="SIM-NVME-OPS-0001", wwn="eui.sim0000000000001",
                vendor="(sim)")
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
