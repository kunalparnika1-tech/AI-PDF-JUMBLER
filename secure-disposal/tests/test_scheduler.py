import time

import pytest

from disposal.audit import AuditLog
from disposal.scheduler import Scheduler, ScheduleError, State


def _sched(config):
    return Scheduler(config, AuditLog(config.audit_file))


def test_schedule_and_countdown(config):
    s = _sched(config)
    r = s.schedule("device-1", "alice", duration_seconds=50 * 60)
    assert r.state == State.COUNTING.value
    assert 49 * 60 < r.remaining() <= 50 * 60


def test_timer_locks_but_never_executes(config):
    s = _sched(config)
    s.schedule("device-1", "alice", duration_seconds=1)
    time.sleep(1.1)
    r = s.tick()
    assert r.state == State.LOCKED_PENDING_CONFIRMATION.value
    # There is no state that means "executed" from the timer alone.
    assert r.state != State.COMPLETED.value


def test_cancel(config):
    s = _sched(config)
    s.schedule("device-1", "alice", duration_seconds=600)
    s.cancel("alice", reason="changed mind")
    assert s.current().state == State.CANCELLED.value


def test_reschedule_resets_deadline(config):
    s = _sched(config)
    s.schedule("device-1", "alice", duration_seconds=1)
    time.sleep(1.1)
    s.tick()
    r = s.reschedule("alice", duration_seconds=600)
    assert r.state == State.COUNTING.value
    assert r.remaining() > 500


def test_double_schedule_rejected(config):
    s = _sched(config)
    s.schedule("device-1", "alice", duration_seconds=600)
    with pytest.raises(ScheduleError):
        s.schedule("device-2", "alice", duration_seconds=600)


def test_recovery_locks_on_expired_deadline(config):
    s = _sched(config)
    r = s.schedule("device-1", "alice", duration_seconds=1)
    # Simulate power loss: deadline in the past, stale heartbeat.
    r.deadline_wall = time.time() - 10
    r.heartbeat_wall = time.time() - 500
    s._save()
    s2 = _sched(config)  # reload triggers recovery
    assert s2.current().state == State.LOCKED_PENDING_CONFIRMATION.value
    assert any("unexpected shutdown" in a for a in s2.anomalies)


def test_clock_moved_backwards_flagged(config):
    s = _sched(config)
    r = s.schedule("device-1", "alice", duration_seconds=600)
    r.heartbeat_wall = time.time() + 10_000  # future heartbeat => clock went back
    s._save()
    s2 = _sched(config)
    assert any("clock" in a.lower() for a in s2.anomalies)
