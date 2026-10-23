"""Tests for the platform inventory PARSERS. These exercise the parsing logic
on representative tool output; they do NOT run powershell/adb and make no claim
about real hardware (see UNRESOLVED_HARDWARE_TASKS.md)."""
import json

from disposal.inventory import _parse_android_disks, _parse_windows_disks


def test_parse_windows_nvme():
    sample = json.dumps([
        {"Number": 0, "FriendlyName": "Samsung SSD 980", "SerialNumber": "S1ABC",
         "Size": 512_000_000_000, "BusType": "NVMe", "Manufacturer": "Samsung"},
        {"Number": 1, "FriendlyName": "WDC HDD", "SerialNumber": "WD123",
         "Size": 2_000_000_000_000, "BusType": "SATA", "MediaType": "HDD"},
    ])
    drives = _parse_windows_disks(sample)
    assert drives[0].name == r"\\.\PhysicalDrive0"
    assert drives[0].technology == "SSD-NVMe"
    assert drives[0].serial == "S1ABC"
    assert drives[0].has_strong_identity()
    assert drives[1].technology == "HDD"


def test_parse_windows_single_object():
    sample = json.dumps({"Number": 0, "FriendlyName": "X", "SerialNumber": "Z",
                         "Size": 256_000_000_000, "BusType": "NVMe"})
    drives = _parse_windows_disks(sample)
    assert len(drives) == 1 and drives[0].serial == "Z"


def test_parse_android():
    sample = json.dumps({"blockdevices": [
        {"name": "mmcblk0", "type": "disk", "size": "32G", "serial": "EMMC1"},
        {"name": "mmcblk0p1", "type": "part", "size": "24G"},
    ]})
    drives = _parse_android_disks(sample)
    assert len(drives) == 1
    assert drives[0].name == "android:mmcblk0"
    assert drives[0].technology == "eMMC"
    assert drives[0].serial == "EMMC1"
