"""Tamper-evident, append-only audit log.

Each record is a JSON object on its own line (JSONL). Records are hash-chained:
every entry carries the SHA-256 of the previous entry plus its own payload, so
any insertion, deletion, or edit of a historical record breaks the chain and is
detectable by ``verify``.

This is tamper-*evident*, not tamper-*proof*: an attacker who can rewrite the
whole file can recompute the chain. For stronger guarantees the chain head
should be periodically exported to append-only external storage (see
docs/THREAT_MODEL.md). We do not pretend otherwise.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

GENESIS = "0" * 64


def _canonical(obj: dict[str, Any]) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _entry_hash(prev_hash: str, payload: dict[str, Any]) -> str:
    h = hashlib.sha256()
    h.update(prev_hash.encode("ascii"))
    h.update(_canonical(payload))
    return h.hexdigest()


class AuditLog:
    def __init__(self, path: Path):
        self.path = Path(path)

    def _last_hash(self) -> str:
        last = GENESIS
        for rec in self.read_all():
            last = rec["hash"]
        return last

    def append(
        self,
        event: str,
        actor: str | None,
        detail: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Append one event. Returns the stored record (including its hash)."""
        payload = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "event": event,
            "actor": actor,
            "detail": detail or {},
        }
        prev = self._last_hash()
        record = {"payload": payload, "prev": prev, "hash": _entry_hash(prev, payload)}
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, sort_keys=True) + "\n")
        return record

    def read_all(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        out: list[dict[str, Any]] = []
        with self.path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    out.append(json.loads(line))
        return out

    def verify(self) -> tuple[bool, str]:
        """Return (ok, message). ok is False at the first broken link."""
        prev = GENESIS
        for i, rec in enumerate(self.read_all()):
            if rec.get("prev") != prev:
                return False, f"record {i}: prev-hash mismatch"
            expected = _entry_hash(prev, rec["payload"])
            if rec.get("hash") != expected:
                return False, f"record {i}: payload hash mismatch (tampered)"
            prev = rec["hash"]
        return True, "audit chain intact"

    def __iter__(self) -> Iterator[dict[str, Any]]:
        return iter(self.read_all())
