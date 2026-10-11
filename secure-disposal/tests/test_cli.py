"""End-to-end CLI test exercising the full non-destructive flow."""
import time

from disposal import cli


def _run(args, env, monkeypatch, data_dir):
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    try:
        return cli.main(["--data-dir", str(data_dir)] + args)
    except SystemExit as e:  # some subcommands exit() with a status code
        return e.code if isinstance(e.code, int) else 1


def test_full_simulation_flow(tmp_path, monkeypatch, capsys):
    dd = tmp_path / "state"

    # Bootstrap two admins (two-person rule).
    assert _run(["init-admin", "alice"], {"DISPOSAL_PASSWORD": "correct horse battery"},
                monkeypatch, dd) == 0
    assert _run(["add-user", "--as", "alice", "bob", "--role", "ADMIN"],
                {"DISPOSAL_PASSWORD": "correct horse battery",
                 "DISPOSAL_PASSWORD2": "another good password"},
                monkeypatch, dd) == 0

    # Schedule a 1-second review as alice.
    assert _run(["schedule", "--as", "alice", "sim-board", "--seconds", "1"],
                {"DISPOSAL_PASSWORD": "correct horse battery"}, monkeypatch, dd) == 0

    time.sleep(1.1)
    assert _run(["status"], {}, monkeypatch, dd) == 0
    out = capsys.readouterr().out
    assert "locked_pending_confirmation" in out

    # bob (different admin) authorizes against the simulated board.
    rc = _run(["authorize", "--as", "bob", "--simulated-board",
               "--method", "vendor-secure-erase", "--confirm-all", "--verified",
               "--allow-external", "android:emmc0", "ops:/dev/nvme0n1"],
              {"DISPOSAL_PASSWORD": "another good password"}, monkeypatch, dd)
    out = capsys.readouterr().out
    assert rc == 0
    assert "Simulated workflow complete" in out

    # Audit chain must verify.
    assert _run(["audit-verify"], {}, monkeypatch, dd) == 0


def test_authorize_blocked_when_same_admin(tmp_path, monkeypatch, capsys):
    dd = tmp_path / "state"
    _run(["init-admin", "alice"], {"DISPOSAL_PASSWORD": "correct horse battery"},
         monkeypatch, dd)
    _run(["schedule", "--as", "alice", "dev", "--seconds", "1"],
         {"DISPOSAL_PASSWORD": "correct horse battery"}, monkeypatch, dd)
    time.sleep(1.1)
    _run(["status"], {}, monkeypatch, dd)
    capsys.readouterr()
    rc = _run(["authorize", "--as", "alice", "--simulated-board",
               "--method", "physical-destruction", "--confirm-all", "--verified",
               "--allow-external", "android:emmc0", "ops:/dev/nvme0n1"],
              {"DISPOSAL_PASSWORD": "correct horse battery"}, monkeypatch, dd)
    # alice scheduled AND tries to confirm -> two-person rule blocks (exit 3).
    assert rc == 3
