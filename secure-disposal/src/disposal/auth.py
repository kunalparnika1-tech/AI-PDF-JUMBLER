"""Authentication, roles, lockout, and optional TOTP MFA.

Design points:
  * Passwords are NEVER stored. We store a per-user random salt and an scrypt
    derivation. Verification is constant-time (``hmac.compare_digest``).
  * There are NO hardcoded passwords or recovery credentials. The first admin
    is created explicitly by the operator (see ``bootstrap_admin``); recovery
    is an operational procedure, not a backdoor.
  * Repeated wrong passwords trigger a time-based lockout per account.
  * Optional TOTP (RFC 6238) is implemented with the standard library only.
    Enabling MFA is per user.

Roles:
  ADMIN    - may authorize/confirm disposal requests and manage users.
  OPERATOR - may schedule and run compatibility checks, cannot give final
             authorization (needs an ADMIN second confirmation).
  AUDITOR  - read-only: may view inventory, schedules, reports, and audit log.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import struct
import time
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .config import Config

ROLES = ("ADMIN", "OPERATOR", "AUDITOR")


class AuthError(Exception):
    """Base class for authentication failures."""


class LockedOut(AuthError):
    pass


@dataclass
class User:
    username: str
    role: str
    salt_b64: str
    hash_b64: str
    scrypt_n: int
    scrypt_r: int
    scrypt_p: int
    mfa_secret_b32: str | None = None
    failed_attempts: int = 0
    locked_until: float = 0.0
    created_at: str = ""

    def public(self) -> dict[str, Any]:
        return {"username": self.username, "role": self.role,
                "mfa_enabled": bool(self.mfa_secret_b32)}


def _derive(password: str, salt: bytes, n: int, r: int, p: int) -> bytes:
    # scrypt needs roughly 128 * N * r bytes; OpenSSL's default cap (~32 MiB)
    # is too low for N=2**15, so size maxmem to the parameters plus headroom.
    maxmem = 128 * n * r * p + (16 * 1024 * 1024)
    return hashlib.scrypt(password.encode("utf-8"), salt=salt, n=n, r=r, p=p,
                          dklen=32, maxmem=maxmem)


# --- TOTP (RFC 6238) using the stdlib only --------------------------------

def generate_totp_secret() -> str:
    """Return a base32 secret suitable for authenticator apps."""
    return base64.b32encode(os.urandom(20)).decode("ascii").rstrip("=")


def totp_now(secret_b32: str, at: float | None = None, step: int = 30,
             digits: int = 6) -> str:
    if at is None:
        at = time.time()
    counter = int(at // step)
    key = base64.b32decode(secret_b32 + "=" * (-len(secret_b32) % 8))
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = (struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF)
    return str(code % (10 ** digits)).zfill(digits)


def totp_verify(secret_b32: str, code: str, at: float | None = None,
                window: int = 1) -> bool:
    if at is None:
        at = time.time()
    code = code.strip()
    for drift in range(-window, window + 1):
        if hmac.compare_digest(totp_now(secret_b32, at + drift * 30), code):
            return True
    return False


class UserStore:
    def __init__(self, config: Config):
        self.config = config
        self._users: dict[str, User] = {}
        self._load()

    # -- persistence --
    def _load(self) -> None:
        path = self.config.users_file
        if path.exists():
            data = json.loads(path.read_text(encoding="utf-8"))
            self._users = {u["username"]: User(**u) for u in data.get("users", [])}

    def _save(self) -> None:
        self.config.ensure_dirs()
        payload = {"users": [asdict(u) for u in self._users.values()]}
        tmp = self.config.users_file.with_suffix(".tmp")
        tmp.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        tmp.replace(self.config.users_file)
        try:
            os.chmod(self.config.users_file, 0o600)
        except OSError:
            pass

    # -- queries --
    def exists(self, username: str) -> bool:
        return username in self._users

    def get(self, username: str) -> User | None:
        return self._users.get(username)

    def list_users(self) -> list[dict[str, Any]]:
        return [u.public() for u in self._users.values()]

    def has_admin(self) -> bool:
        return any(u.role == "ADMIN" for u in self._users.values())

    # -- mutations --
    def create_user(self, username: str, password: str, role: str,
                    enable_mfa: bool = False) -> str | None:
        if role not in ROLES:
            raise AuthError(f"unknown role {role!r}")
        if username in self._users:
            raise AuthError("user already exists")
        if len(password) < 12:
            raise AuthError("password must be at least 12 characters")
        salt = os.urandom(16)
        c = self.config
        digest = _derive(password, salt, c.scrypt_n, c.scrypt_r, c.scrypt_p)
        mfa_secret = generate_totp_secret() if enable_mfa else None
        self._users[username] = User(
            username=username, role=role,
            salt_b64=base64.b64encode(salt).decode(),
            hash_b64=base64.b64encode(digest).decode(),
            scrypt_n=c.scrypt_n, scrypt_r=c.scrypt_r, scrypt_p=c.scrypt_p,
            mfa_secret_b32=mfa_secret,
            created_at=datetime.now(timezone.utc).isoformat(),
        )
        self._save()
        return mfa_secret  # returned once so the operator can enrol an app

    def bootstrap_admin(self, username: str, password: str,
                        enable_mfa: bool = False) -> str | None:
        """Create the first ADMIN. Refuses if any admin already exists."""
        if self.has_admin():
            raise AuthError("an administrator already exists; use create_user")
        return self.create_user(username, password, "ADMIN", enable_mfa)

    def authenticate(self, username: str, password: str,
                     mfa_code: str | None = None) -> User:
        user = self._users.get(username)
        if user is None:
            # Uniform work to reduce user-enumeration timing signal.
            _derive(password, b"0" * 16, self.config.scrypt_n,
                    self.config.scrypt_r, self.config.scrypt_p)
            raise AuthError("invalid credentials")

        now = time.time()
        if user.locked_until > now:
            remaining = int(user.locked_until - now)
            raise LockedOut(f"account locked for another {remaining}s")

        salt = base64.b64decode(user.salt_b64)
        expected = base64.b64decode(user.hash_b64)
        candidate = _derive(password, salt, user.scrypt_n, user.scrypt_r,
                             user.scrypt_p)
        if not hmac.compare_digest(candidate, expected):
            user.failed_attempts += 1
            if user.failed_attempts >= self.config.max_failed_attempts:
                user.locked_until = now + self.config.lockout_seconds
                user.failed_attempts = 0
            self._save()
            raise AuthError("invalid credentials")

        if user.mfa_secret_b32:
            if not mfa_code or not totp_verify(user.mfa_secret_b32, mfa_code):
                user.failed_attempts += 1
                self._save()
                raise AuthError("invalid or missing MFA code")

        user.failed_attempts = 0
        user.locked_until = 0.0
        self._save()
        return user
