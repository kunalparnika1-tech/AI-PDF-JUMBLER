import time

from disposal import cli


def _run(args, env, monkeypatch, data_dir, stdin=None):
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    if stdin is not None:
        import builtins
        it = iter(stdin)
        monkeypatch.setattr(builtins, "input", lambda *a, **k: next(it, ""))
    try:
        return cli.main(["--data-dir", str(data_dir)] + args)
    except SystemExit as e:
        return e.code if isinstance(e.code, int) else 1


def _two_admins(dd, monkeypatch):
    _run(["init-admin", "alice"], {"DISPOSAL_PASSWORD": "correct horse battery"},
         monkeypatch, dd)
    _run(["add-user", "--as", "alice", "bob", "--role", "ADMIN"],
         {"DISPOSAL_PASSWORD": "correct horse battery",
          "DISPOSAL_PASSWORD2": "another good password"}, monkeypatch, dd)


def _lock(dd, monkeypatch):
    _run(["schedule", "--as", "alice", "SIM", "--seconds", "1"],
         {"DISPOSAL_PASSWORD": "correct horse battery"}, monkeypatch, dd)
    time.sleep(1.1)
    _run(["status"], {}, monkeypatch, dd)


def test_execute_dry_run_claims_no_erasure(tmp_path, monkeypatch, capsys):
    dd = tmp_path / "state"
    _two_admins(dd, monkeypatch)
    _lock(dd, monkeypatch)
    capsys.readouterr()
    rc = _run(["execute", "--as", "bob", "--simulated-board", "--verified",
               "--adapter", "simulation", "--allow-external",
               "android:emmc0", "ops:/dev/nvme0n1"],
              {"DISPOSAL_PASSWORD": "another good password"}, monkeypatch, dd)
    out = capsys.readouterr().out
    assert rc == 0
    assert "erased_claim=False" in out
    assert "Execution complete" in out
    assert _run(["audit-verify"], {}, monkeypatch, dd) == 0


def test_execute_real_downgrades_without_optins(tmp_path, monkeypatch, capsys):
    dd = tmp_path / "state"
    _two_admins(dd, monkeypatch)
    _lock(dd, monkeypatch)
    capsys.readouterr()
    # Even with --real and a correct typed serial, absence of config/env opt-ins
    # must downgrade to dry-run: nothing executed, nothing claimed erased.
    rc = _run(["execute", "--as", "bob", "--simulated-board", "--verified",
               "--adapter", "blkdiscard", "--real", "--allow-external",
               "android:emmc0", "ops:/dev/nvme0n1"],
              {"DISPOSAL_PASSWORD": "another good password"}, monkeypatch, dd,
              stdin=["SERIAL123", "SERIAL123"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "erased_claim=True" not in out
