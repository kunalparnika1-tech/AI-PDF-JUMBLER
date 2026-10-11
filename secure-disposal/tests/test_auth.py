import time

import pytest

from disposal.auth import AuthError, LockedOut, UserStore, totp_now, totp_verify


def test_bootstrap_and_authenticate(config):
    users = UserStore(config)
    assert not users.has_admin()
    users.bootstrap_admin("alice", "correct horse battery")
    assert users.has_admin()
    u = users.authenticate("alice", "correct horse battery")
    assert u.role == "ADMIN"


def test_no_hardcoded_second_admin(config):
    users = UserStore(config)
    users.bootstrap_admin("alice", "correct horse battery")
    with pytest.raises(AuthError):
        users.bootstrap_admin("mallory", "another good password")


def test_short_password_rejected(config):
    users = UserStore(config)
    with pytest.raises(AuthError):
        users.bootstrap_admin("bob", "short")


def test_wrong_password_and_lockout(config):
    config.max_failed_attempts = 3
    config.lockout_seconds = 100
    users = UserStore(config)
    users.bootstrap_admin("alice", "correct horse battery")
    for _ in range(3):
        with pytest.raises(AuthError):
            users.authenticate("alice", "wrong-password-xx")
    with pytest.raises(LockedOut):
        users.authenticate("alice", "correct horse battery")


def test_unknown_user_is_generic_error(config):
    users = UserStore(config)
    users.bootstrap_admin("alice", "correct horse battery")
    with pytest.raises(AuthError):
        users.authenticate("ghost", "whatever-password")


def test_mfa_required_when_enabled(config):
    users = UserStore(config)
    secret = users.bootstrap_admin("alice", "correct horse battery", enable_mfa=True)
    assert secret
    with pytest.raises(AuthError):
        users.authenticate("alice", "correct horse battery")  # no code
    code = totp_now(secret)
    u = users.authenticate("alice", "correct horse battery", mfa_code=code)
    assert u.username == "alice"


def test_totp_roundtrip():
    secret = "JBSWY3DPEHPK3PXP"
    now = time.time()
    assert totp_verify(secret, totp_now(secret, now), now)
    assert not totp_verify(secret, "000000", now)


def test_persistence_across_instances(config):
    UserStore(config).bootstrap_admin("alice", "correct horse battery")
    users2 = UserStore(config)
    assert users2.authenticate("alice", "correct horse battery").role == "ADMIN"
