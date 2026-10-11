"""Scheduling and the 50-minute countdown.

CRITICAL SAFETY PROPERTY: the countdown NEVER executes anything. When it
expires, the request transitions to ``LOCKED_PENDING_CONFIRMATION`` — a state
that still requires an explicit, interactive second administrative confirmation
before any (simulated) irreversible step. There is no code path from "timer
expired" to "action performed".

State is persisted to disk so the schedule survives process exit, crash, or
power loss. On load we:
  * detect clock manipulation by comparing persisted wall-clock baselines, and
  * detect unexpected shutdown via a heartbeat that the running app updates.

Behaviour when the managed device is off / asleep / disconnected / booted into
another OS: this scheduler runs on the *controller* (the admin's machine / the
USB-hosted app), not on the target. It therefore keeps counting regardless of
target state. It makes NO attempt to reach across the network to a powered-off
or other-OS target; the final confirmation step explicitly re-verifies that the
correct device is present and reachable before anything proceeds. See
docs/ARCHITECTURE.md.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

from .audit import AuditLog
from .config import Config


class State(str, Enum):
    SCHEDULED = "scheduled"
    COUNTING = "counting"
    LOCKED_PENDING_CONFIRMATION = "locked_pending_confirmation"
    CANCELLED = "cancelled"
    COMPLETED = "completed"        # simulated workflow finished
    ABORTED = "aborted"


@dataclass
class Review:
    review_id: str
    device_id: str
    created_by: str
    created_at_wall: float
    duration_seconds: int
    deadline_wall: float
    state: str = State.COUNTING.value
    heartbeat_wall: float = 0.0
    notes: str = ""

    def remaining(self, now: float | None = None) -> float:
        now = now if now is not None else time.time()
        return max(0.0, self.deadline_wall - now)


class ScheduleError(Exception):
    pass


class Scheduler:
    def __init__(self, config: Config, audit: AuditLog):
        self.config = config
        self.audit = audit
        self._review: Review | None = None
        self._anomalies: list[str] = []
        self._load()

    # -- persistence & recovery --
    def _load(self) -> None:
        path = self.config.schedule_file
        if not path.exists():
            return
        data = json.loads(path.read_text(encoding="utf-8"))
        rev = data.get("review")
        if rev:
            self._review = Review(**rev)
            self._recover()

    def _recover(self) -> None:
        """Detect power-loss / unexpected shutdown and clock changes on load."""
        r = self._review
        if r is None:
            return
        now = time.time()

        if r.heartbeat_wall and r.heartbeat_wall > now + 5:
            msg = ("clock moved BACKWARDS since last heartbeat "
                   f"({r.heartbeat_wall - now:.0f}s). Possible clock manipulation.")
            self._anomalies.append(msg)
            self.audit.append("schedule.clock_anomaly", None, {"detail": msg})

        if r.state == State.COUNTING.value and r.heartbeat_wall:
            gap = now - r.heartbeat_wall
            # A gap much larger than our heartbeat cadence implies the app was
            # not running — treat as unexpected shutdown / power loss.
            if gap > 120:
                self._anomalies.append(
                    f"unexpected shutdown detected: {gap:.0f}s without heartbeat.")
                self.audit.append("schedule.unexpected_shutdown", None,
                                  {"gap_seconds": round(gap)})
            if now >= r.deadline_wall:
                # Deadline passed while we were down. Lock — never auto-execute.
                r.state = State.LOCKED_PENDING_CONFIRMATION.value
                self.audit.append("schedule.locked_on_recovery", None,
                                  {"review_id": r.review_id})
        self._save()

    def _save(self) -> None:
        self.config.ensure_dirs()
        payload = {"review": asdict(self._review) if self._review else None}
        tmp = self.config.schedule_file.with_suffix(".tmp")
        tmp.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        tmp.replace(self.config.schedule_file)

    # -- public API --
    @property
    def anomalies(self) -> list[str]:
        return list(self._anomalies)

    def current(self) -> Review | None:
        return self._review

    def schedule(self, device_id: str, actor: str,
                 duration_seconds: int | None = None) -> Review:
        if self._review and self._review.state in (
                State.COUNTING.value, State.LOCKED_PENDING_CONFIRMATION.value):
            raise ScheduleError("a review is already active; cancel it first")
        duration = duration_seconds or self.config.default_countdown_seconds
        now = time.time()
        review = Review(
            review_id=datetime.now(timezone.utc).strftime("REV-%Y%m%d-%H%M%S"),
            device_id=device_id,
            created_by=actor,
            created_at_wall=now,
            duration_seconds=duration,
            deadline_wall=now + duration,
            heartbeat_wall=now,
        )
        self._review = review
        self._save()
        self.audit.append("schedule.created", actor, {
            "review_id": review.review_id, "device_id": device_id,
            "duration_seconds": duration})
        return review

    def heartbeat(self) -> None:
        if self._review and self._review.state == State.COUNTING.value:
            self._review.heartbeat_wall = time.time()
            self._save()

    def tick(self) -> Review | None:
        """Advance state based on the clock. Locks on expiry; never executes."""
        r = self._review
        if r is None:
            return None
        if r.state == State.COUNTING.value and time.time() >= r.deadline_wall:
            r.state = State.LOCKED_PENDING_CONFIRMATION.value
            self.audit.append("schedule.locked", None, {"review_id": r.review_id})
            self._save()
        return r

    def cancel(self, actor: str, reason: str = "") -> None:
        if not self._review:
            raise ScheduleError("no active review")
        self._review.state = State.CANCELLED.value
        self._review.notes = reason
        self.audit.append("schedule.cancelled", actor,
                          {"review_id": self._review.review_id, "reason": reason})
        self._save()

    def reschedule(self, actor: str, duration_seconds: int | None = None) -> Review:
        if not self._review:
            raise ScheduleError("no active review")
        if self._review.state == State.COMPLETED.value:
            raise ScheduleError("review already completed")
        duration = duration_seconds or self.config.default_countdown_seconds
        now = time.time()
        self._review.duration_seconds = duration
        self._review.deadline_wall = now + duration
        self._review.state = State.COUNTING.value
        self._review.heartbeat_wall = now
        self.audit.append("schedule.rescheduled", actor, {
            "review_id": self._review.review_id, "duration_seconds": duration})
        self._save()
        return self._review
