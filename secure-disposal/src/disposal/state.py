"""Persistent execution state, checkpoints, crash recovery, and idempotency.

An execution run is a sequence of per-target operations. Each operation moves
through explicit states and is written to disk after every transition, so a
crash can be recovered without redoing completed work and — critically —
without re-issuing a destructive command whose outcome is unknown.

Idempotency: each operation has a stable ``idem_key``. Recovery uses the last
persisted state to decide what is safe to resume. The rule enforced here:

    If a destructive step was marked IN_PROGRESS and the process died before a
    terminal result, it is recovered as NEEDS_MANUAL_REVIEW, never auto-retried.
    Re-issuing a destructive command after a possible partial success, against a
    device in an unknown state, is forbidden.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any


class OpState(str, Enum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    VERIFYING = "verifying"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    SKIPPED = "skipped"
    NEEDS_MANUAL_REVIEW = "needs_manual_review"   # crashed mid-destructive-op


TERMINAL = {OpState.SUCCEEDED, OpState.FAILED, OpState.SKIPPED,
            OpState.NEEDS_MANUAL_REVIEW}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class Operation:
    idem_key: str
    target: str                 # physical drive identifier
    method: str
    destructive: bool
    state: str = OpState.PENDING.value
    attempts: int = 0
    history: list[dict[str, Any]] = field(default_factory=list)
    result: dict[str, Any] | None = None
    updated_at: str = ""

    def transition(self, new: OpState, note: str = "") -> None:
        self.history.append({"from": self.state, "to": new.value,
                             "note": note, "ts": _now()})
        self.state = new.value
        self.updated_at = _now()


@dataclass
class ExecutionRun:
    run_id: str
    review_id: str
    created_at: str = ""
    operations: list[Operation] = field(default_factory=list)

    def op(self, idem_key: str) -> Operation | None:
        return next((o for o in self.operations if o.idem_key == idem_key), None)


class StateStore:
    """Atomic, crash-safe persistence for a single execution run."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self.run: ExecutionRun | None = None

    def load(self) -> ExecutionRun | None:
        if not self.path.exists():
            return None
        data = json.loads(self.path.read_text(encoding="utf-8"))
        ops = [Operation(**o) for o in data.get("operations", [])]
        self.run = ExecutionRun(
            run_id=data["run_id"], review_id=data["review_id"],
            created_at=data.get("created_at", ""), operations=ops)
        return self.run

    def create(self, run_id: str, review_id: str) -> ExecutionRun:
        self.run = ExecutionRun(run_id=run_id, review_id=review_id,
                                created_at=_now())
        self.save()
        return self.run

    def save(self) -> None:
        assert self.run is not None
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "run_id": self.run.run_id,
            "review_id": self.run.review_id,
            "created_at": self.run.created_at,
            "operations": [asdict(o) for o in self.run.operations],
        }
        tmp = self.path.with_suffix(".tmp")
        with tmp.open("w", encoding="utf-8") as fh:
            fh.write(json.dumps(payload, indent=2))
            fh.flush()
            os.fsync(fh.fileno())      # durability: survive power loss
        tmp.replace(self.path)

    def checkpoint(self, op: Operation, new: OpState, note: str = "") -> None:
        op.transition(new, note)
        self.save()

    def recover(self) -> list[str]:
        """Apply the crash-recovery policy. Returns human-readable actions taken."""
        actions: list[str] = []
        if not self.run:
            return actions
        for op in self.run.operations:
            st = OpState(op.state)
            if st in (OpState.IN_PROGRESS, OpState.VERIFYING):
                if op.destructive:
                    # Unknown device state after a possible partial destructive
                    # op: do NOT auto-retry. Require a human to inspect.
                    op.transition(OpState.NEEDS_MANUAL_REVIEW,
                                  "recovered after crash during destructive op; "
                                  "device state unknown; manual review required")
                    actions.append(
                        f"{op.target}: destructive op interrupted -> "
                        "NEEDS_MANUAL_REVIEW (not auto-retried)")
                else:
                    op.transition(OpState.PENDING,
                                  "recovered after crash during non-destructive "
                                  "op; safe to resume")
                    actions.append(f"{op.target}: non-destructive op resumed")
        if actions:
            self.save()
        return actions

    def resumable(self) -> list[Operation]:
        """Operations still safe to run (never the manual-review ones)."""
        if not self.run:
            return []
        return [o for o in self.run.operations
                if OpState(o.state) in (OpState.PENDING,)]
