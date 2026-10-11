import pytest

from disposal.audit import AuditLog
from disposal.inventory import DeviceInventory, Drive, Partition, sample_board
from disposal.workflow import PreAuthChecklist, WorkflowError, run_simulation


def _verified_inventory():
    d = Drive(name="/dev/sda", technology="SSD-SATA", bus="sata")
    d.partitions.append(Partition(name="/dev/sda1", fstype="ext4"))
    return DeviceInventory(
        hostname="host", manufacturer="m", model="x",
        os_name="Linux", os_version="6", cpu_arch="x86_64",
        device_type="computer", drives=[d], verified=True, source="detected-linux")


def _full_checklist():
    return PreAuthChecklist(True, True, True, True, True, True, True)


def _run(**over):
    base = dict(
        review_id="REV-1", inventory=_verified_inventory(),
        method="vendor-secure-erase", checklist=_full_checklist(),
        scheduler_locked=True, confirming_admin="bob", scheduling_admin="alice",
        audit=over.pop("audit"),
    )
    base.update(over)
    return run_simulation(**base)


def test_happy_path_is_simulation_only(config):
    res = _run(audit=AuditLog(config.audit_file))
    assert res.simulated is True
    assert res.status == "simulated-complete"
    assert all(step["performed"] is False for step in res.steps)


def test_blocks_unverified_inventory(config):
    inv = _verified_inventory()
    inv.verified = False
    with pytest.raises(WorkflowError, match="not verified"):
        _run(audit=AuditLog(config.audit_file), inventory=inv)


def test_blocks_incomplete_checklist(config):
    cl = _full_checklist()
    cl.backup_status_checked = False
    with pytest.raises(WorkflowError, match="pre-authorization incomplete"):
        _run(audit=AuditLog(config.audit_file), checklist=cl)


def test_enforces_two_person_rule(config):
    with pytest.raises(WorkflowError, match="two-person"):
        _run(audit=AuditLog(config.audit_file),
             confirming_admin="alice", scheduling_admin="alice")


def test_requires_locked_state(config):
    with pytest.raises(WorkflowError, match="LOCKED"):
        _run(audit=AuditLog(config.audit_file), scheduler_locked=False)


def test_external_drive_guarded(config):
    inv = _verified_inventory()
    inv.drives.append(Drive(name="/dev/sdb", technology="SSD-SATA",
                            bus="usb", removable=True))
    with pytest.raises(WorkflowError, match="external"):
        _run(audit=AuditLog(config.audit_file), inventory=inv)


def test_external_drive_allowed_explicitly(config):
    inv = _verified_inventory()
    inv.drives.append(Drive(name="/dev/sdb", technology="SSD-SATA",
                            bus="usb", removable=True))
    res = _run(audit=AuditLog(config.audit_file), inventory=inv,
               allow_external={"/dev/sdb"})
    assert any(s["drive"] == "/dev/sdb" for s in res.steps)


def test_board_has_independent_environments():
    board = sample_board()
    names = {d.name for d in board.drives}
    assert "android:emmc0" in names and "ops:/dev/nvme0n1" in names
    assert board.verified is False  # simulated must be human-verified
