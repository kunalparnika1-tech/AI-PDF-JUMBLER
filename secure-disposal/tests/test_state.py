from disposal.state import (ExecutionRun, Operation, OpState, StateStore)


def test_create_and_reload(tmp_path):
    store = StateStore(tmp_path / "exec.json")
    store.create("RUN-1", "REV-1")
    store.run.operations.append(
        Operation(idem_key="k1", target="/dev/sda", method="x", destructive=True))
    store.save()

    store2 = StateStore(tmp_path / "exec.json")
    run = store2.load()
    assert run.run_id == "RUN-1"
    assert run.op("k1").target == "/dev/sda"


def test_checkpoints_are_persisted(tmp_path):
    store = StateStore(tmp_path / "exec.json")
    store.create("RUN-1", "REV-1")
    op = Operation(idem_key="k1", target="/dev/sda", method="x", destructive=False)
    store.run.operations.append(op)
    store.checkpoint(op, OpState.IN_PROGRESS)
    store.checkpoint(op, OpState.SUCCEEDED)
    reloaded = StateStore(tmp_path / "exec.json").load()
    assert reloaded.op("k1").state == "succeeded"
    assert len(reloaded.op("k1").history) == 2


def test_recover_destructive_in_progress_needs_manual_review(tmp_path):
    store = StateStore(tmp_path / "exec.json")
    store.create("RUN-1", "REV-1")
    op = Operation(idem_key="k1", target="/dev/sda", method="nvme-format",
                   destructive=True, state=OpState.IN_PROGRESS.value)
    store.run.operations.append(op)
    store.save()

    store2 = StateStore(tmp_path / "exec.json")
    store2.load()
    actions = store2.recover()
    assert store2.run.op("k1").state == OpState.NEEDS_MANUAL_REVIEW.value
    assert any("NEEDS_MANUAL_REVIEW" in a for a in actions)
    # And it must NOT be resumable.
    assert store2.run.op("k1") not in store2.resumable()


def test_recover_nondestructive_in_progress_resumes(tmp_path):
    store = StateStore(tmp_path / "exec.json")
    store.create("RUN-1", "REV-1")
    op = Operation(idem_key="k1", target="/dev/sda", method="simulation",
                   destructive=False, state=OpState.IN_PROGRESS.value)
    store.run.operations.append(op)
    store.save()

    store2 = StateStore(tmp_path / "exec.json")
    store2.load()
    store2.recover()
    assert store2.run.op("k1").state == OpState.PENDING.value
    assert store2.run.op("k1") in store2.resumable()
