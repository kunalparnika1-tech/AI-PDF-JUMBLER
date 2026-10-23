from disposal.inventory import (DeviceInventory, Drive, Partition,
                                annotate_identity_warnings, diff_inventories,
                                duplicate_identifiers, sample_board)


def _inv(drives):
    return DeviceInventory(hostname="h", manufacturer="m", model="x",
                           os_name="Linux", os_version="6", cpu_arch="x86_64",
                           device_type="computer", drives=drives, verified=True)


def test_identity_prefers_wwn_then_serial_then_weak():
    assert Drive(name="/dev/sda", wwn="w1", serial="s1").identity() == "wwn:w1"
    assert Drive(name="/dev/sda", serial="s1").identity() == "serial:s1"
    d = Drive(name="/dev/sda", model="M", size="1T")
    assert d.identity().startswith("weak:")
    assert not d.has_strong_identity()


def test_missing_serial_warned():
    inv = _inv([Drive(name="/dev/sda")])
    annotate_identity_warnings(inv)
    assert any("WEAK" in w for w in inv.warnings)


def test_duplicate_serial_detected():
    inv = _inv([Drive(name="/dev/sda", serial="DUP"),
                Drive(name="/dev/sdb", serial="DUP")])
    assert duplicate_identifiers(inv) == {"DUP"}
    annotate_identity_warnings(inv)
    assert any("DUPLICATE" in w for w in inv.warnings)


def test_removal_detected():
    before = _inv([Drive(name="/dev/sda", serial="A"),
                   Drive(name="/dev/sdb", serial="B")])
    after = _inv([Drive(name="/dev/sda", serial="A")])
    delta = diff_inventories(before, after)
    assert "serial:B" in delta.removed
    assert delta.changed


def test_replacement_detected_same_path_new_identity():
    before = _inv([Drive(name="/dev/sdb", serial="B")])
    after = _inv([Drive(name="/dev/sdb", serial="C")])   # same path, new disk
    delta = diff_inventories(before, after)
    assert delta.replaced == [("/dev/sdb", "serial:C")]
    assert "serial:B" in delta.removed
    assert "serial:C" in delta.added


def test_sample_board_drives_have_identities():
    board = sample_board()
    by = {d.name: d for d in board.drives}
    assert by["ops:/dev/nvme0n1"].has_strong_identity()
    assert by["android:emmc0"].has_strong_identity()
