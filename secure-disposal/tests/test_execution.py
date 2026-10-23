import pytest

from disposal.audit import AuditLog
from disposal.engine import Authorization, ExecutionEngine
from disposal.execution import (BlkdiscardAdapter, DesignatedTarget,
                                DryRunRunner, NvmeFormatAdapter,
                                RealCommandRunner, SimulationAdapter,
                                TargetGuard, TargetValidationError, get_adapter)
from disposal.inventory import Drive, Partition
from disposal.logging_ import StructuredLogger
from disposal.state import OpState, Operation, StateStore


def _drive(name="/dev/sda", tech="SSD-NVMe", size="256G", **kw):
    return Drive(name=name, technology=tech, size=size, **kw)


def _engine(config):
    audit = AuditLog(config.audit_file)
    store = StateStore(config.exec_state_file)
    store.create("RUN-T", "REV-1")
    log = StructuredLogger(config.op_log_file, "RUN-T")
    return ExecutionEngine(config, audit, store, log), store


def _op(adapter, drive):
    return Operation(idem_key="k", target=drive.name, method=adapter.method,
                     destructive=adapter.destructive)


def _auth():
    return Authorization("REV-1", "alice", "bob", valid=True)


def _target(drive):
    return DesignatedTarget(drive.name, "SERIAL123", drive.size)


# -- target guard --------------------------------------------------------
def test_guard_rejects_boot_drive():
    d = _drive()
    with pytest.raises(TargetValidationError):
        TargetGuard.validate(d, _target(d), boot_drive="/dev/sda")


def test_guard_rejects_size_mismatch():
    d = _drive(size="256G")
    t = DesignatedTarget(d.name, "S", "512G")
    with pytest.raises(TargetValidationError):
        TargetGuard.validate(d, t, boot_drive=None)


def test_guard_rejects_system_mountpoint():
    d = _drive()
    d.partitions.append(Partition(name="/dev/sda1", mountpoint="/"))
    with pytest.raises(TargetValidationError):
        TargetGuard.validate(d, _target(d), boot_drive=None)


def test_guard_rejects_external_by_default():
    d = _drive(name="/dev/sdb", bus="usb", removable=True)
    with pytest.raises(TargetValidationError):
        TargetGuard.validate(d, _target(d), boot_drive=None)
    TargetGuard.validate(d, _target(d), boot_drive=None, allow_external=True)


# -- command construction ------------------------------------------------
def test_adapters_build_real_commands():
    d = _drive()
    assert BlkdiscardAdapter().build_command(d) == ["blkdiscard", "--secure", "/dev/sda"]
    assert NvmeFormatAdapter().build_command(d) == ["nvme", "format", "/dev/sda", "--ses=1"]


# -- the gate ------------------------------------------------------------
def test_default_is_dry_run_no_erasure(config):
    engine, store = _engine(config)
    d = _drive()
    op = _op(SimulationAdapter(), d)
    store.run.operations.append(op)
    engine.execute_operation(op, d, SimulationAdapter(), _auth(), _target(d))
    assert op.state == OpState.SUCCEEDED.value
    assert op.result["executed"] is False
    assert op.result["data_erased_claim"] is False


def test_real_runner_downgraded_without_optins(config):
    # config.allow_real_execution defaults False -> real must be denied.
    engine, store = _engine(config)
    d = _drive()
    adapter = BlkdiscardAdapter()
    op = _op(adapter, d)
    store.run.operations.append(op)
    engine.execute_operation(op, d, adapter, _auth(), _target(d),
                             runner=RealCommandRunner(),
                             confirm_fn=lambda prompt: "SERIAL123")
    # Downgraded to dry-run: nothing executed, no erasure claimed.
    assert op.result["executed"] is False
    assert op.result["data_erased_claim"] is False


def test_real_denied_on_wrong_serial(config, monkeypatch):
    config.allow_real_execution = True
    monkeypatch.setenv("DISPOSAL_ALLOW_REAL_EXECUTION", "yes")
    engine, store = _engine(config)
    d = _drive()
    adapter = BlkdiscardAdapter()
    op = _op(adapter, d)
    store.run.operations.append(op)
    engine.execute_operation(op, d, adapter, _auth(), _target(d),
                             runner=RealCommandRunner(),
                             confirm_fn=lambda prompt: "WRONG")
    assert op.result["executed"] is False  # serial mismatch -> downgraded


def test_real_denied_on_two_person_violation(config, monkeypatch):
    config.allow_real_execution = True
    monkeypatch.setenv("DISPOSAL_ALLOW_REAL_EXECUTION", "yes")
    engine, store = _engine(config)
    d = _drive()
    adapter = BlkdiscardAdapter()
    op = _op(adapter, d)
    store.run.operations.append(op)
    bad_auth = Authorization("REV-1", "alice", "alice", valid=True)
    engine.execute_operation(op, d, adapter, bad_auth, _target(d),
                             runner=RealCommandRunner(),
                             confirm_fn=lambda prompt: "SERIAL123")
    assert op.result["executed"] is False


def test_real_executes_with_all_gates_via_fake_runner(config, monkeypatch):
    """All gates pass -> the chosen runner IS used. We inject a fake runner so
    no real command touches the system."""
    config.allow_real_execution = True
    monkeypatch.setenv("DISPOSAL_ALLOW_REAL_EXECUTION", "yes")
    engine, store = _engine(config)
    d = _drive()
    adapter = BlkdiscardAdapter()
    op = _op(adapter, d)
    store.run.operations.append(op)

    calls = []

    class FakeReal(RealCommandRunner):
        def run(self, command, timeout):
            calls.append(command)
            from disposal.execution import CommandResult
            return CommandResult(command=command, executed=True, returncode=0,
                                 stdout="ok")

    engine.execute_operation(op, d, adapter, _auth(), _target(d),
                             runner=FakeReal(),
                             confirm_fn=lambda prompt: "SERIAL123")
    assert calls and calls[0] == ["blkdiscard", "--secure", "/dev/sda"]
    assert op.state == OpState.SUCCEEDED.value
    assert op.result["data_erased_claim"] is True


def test_target_rejection_skips_without_running(config):
    engine, store = _engine(config)
    d = _drive()
    adapter = BlkdiscardAdapter()
    op = _op(adapter, d)
    store.run.operations.append(op)
    engine.execute_operation(op, d, adapter, _auth(), _target(d),
                             runner=DryRunRunner(), boot_drive="/dev/sda")
    assert op.state == OpState.SKIPPED.value
