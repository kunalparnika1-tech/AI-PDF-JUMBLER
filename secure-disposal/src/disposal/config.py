"""Configuration and on-disk paths.

State is kept under a per-user data directory so the tool survives restarts
(needed for unexpected-shutdown recovery of scheduled reviews). Nothing here
touches block devices; these are plain application-state files.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


def _default_data_dir() -> Path:
    env = os.environ.get("DISPOSAL_DATA_DIR")
    if env:
        return Path(env).expanduser()
    # XDG-ish default, cross-platform-ish without extra deps.
    base = os.environ.get("XDG_DATA_HOME")
    if base:
        return Path(base) / "secure-disposal"
    return Path.home() / ".local" / "share" / "secure-disposal"


@dataclass
class Config:
    data_dir: Path = field(default_factory=_default_data_dir)

    # Countdown default is 50 minutes per spec. The countdown NEVER triggers a
    # destructive action: on expiry it only locks the request for final human
    # confirmation.
    default_countdown_seconds: int = 50 * 60

    # Authentication hardening.
    max_failed_attempts: int = 5
    lockout_seconds: int = 15 * 60
    # scrypt cost parameters (RFC 7914). These are deliberately expensive.
    scrypt_n: int = 2 ** 15
    scrypt_r: int = 8
    scrypt_p: int = 1

    @property
    def users_file(self) -> Path:
        return self.data_dir / "users.json"

    @property
    def audit_file(self) -> Path:
        return self.data_dir / "audit.log.jsonl"

    @property
    def schedule_file(self) -> Path:
        return self.data_dir / "schedule.json"

    @property
    def reports_dir(self) -> Path:
        return self.data_dir / "reports"

    def ensure_dirs(self) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        # Best-effort tighten permissions on POSIX; harmless elsewhere.
        try:
            os.chmod(self.data_dir, 0o700)
        except OSError:
            pass
