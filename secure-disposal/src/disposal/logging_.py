"""Structured, append-only operational logging (distinct from the audit log).

The audit log (``audit.py``) is the tamper-evident record of security-relevant
events. This module is the *operational* log: structured JSON lines describing
what the autonomous engine is doing, for debugging and post-mortem. Both can be
written for the same operation; they serve different purposes.

Design:
  * One JSON object per line (JSONL), easy to grep/ingest.
  * A monotonically increasing sequence number and an ISO-8601 UTC timestamp.
  * A ``run_id`` groups all lines for one engine invocation.
  * Never raises into the caller: a logging failure must not abort an operation.
"""

from __future__ import annotations

import json
import os
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class StructuredLogger:
    def __init__(self, path: Path | None, run_id: str, echo: bool = False):
        self.path = Path(path) if path else None
        self.run_id = run_id
        self.echo = echo
        self._seq = 0
        self._lock = threading.Lock()
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)

    def log(self, level: str, event: str, **fields: Any) -> dict[str, Any]:
        with self._lock:
            self._seq += 1
            seq = self._seq
        rec = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "run_id": self.run_id,
            "seq": seq,
            "level": level,
            "event": event,
            "fields": fields,
        }
        line = json.dumps(rec, sort_keys=True, default=str)
        try:
            if self.path:
                with self.path.open("a", encoding="utf-8") as fh:
                    fh.write(line + "\n")
            if self.echo:
                print(line, file=sys.stderr)
        except OSError:
            # Logging must never break the operation it is observing.
            pass
        return rec

    # convenience wrappers
    def info(self, event: str, **f: Any) -> dict[str, Any]:
        return self.log("INFO", event, **f)

    def warn(self, event: str, **f: Any) -> dict[str, Any]:
        return self.log("WARN", event, **f)

    def error(self, event: str, **f: Any) -> dict[str, Any]:
        return self.log("ERROR", event, **f)


def new_run_id() -> str:
    return datetime.now(timezone.utc).strftime("RUN-%Y%m%d-%H%M%S-") + \
        os.urandom(3).hex()
