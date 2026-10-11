import json

from disposal.audit import AuditLog


def test_append_and_verify(config):
    log = AuditLog(config.audit_file)
    log.append("test.event", "alice", {"x": 1})
    log.append("test.event2", "bob", {"y": 2})
    ok, msg = log.verify()
    assert ok, msg
    assert len(log.read_all()) == 2


def test_tamper_detected(config):
    log = AuditLog(config.audit_file)
    log.append("a", "alice")
    log.append("b", "alice")
    records = log.read_all()
    # Tamper with the first record's payload but keep its hash.
    records[0]["payload"]["event"] = "forged"
    config.audit_file.write_text(
        "\n".join(json.dumps(r, sort_keys=True) for r in records) + "\n")
    ok, msg = log.verify()
    assert not ok
    assert "tampered" in msg or "mismatch" in msg


def test_deletion_detected(config):
    log = AuditLog(config.audit_file)
    log.append("a", "alice")
    log.append("b", "alice")
    log.append("c", "alice")
    records = log.read_all()
    del records[1]  # remove middle record
    config.audit_file.write_text(
        "\n".join(json.dumps(r, sort_keys=True) for r in records) + "\n")
    ok, _ = log.verify()
    assert not ok
