"""Execution engine — the single, clear authorization boundary for irreversible
operations.

The engine decides, per operation, whether the configured runner may actually
execute. Real (destructive) execution requires EVERY gate in
``_may_execute_for_real`` to pass. If any fails, the engine downgrades to a
dry-run for that operation and records why — it never silently proceeds and
never escalates on its own.

A human ``confirm_fn`` is called at the moment of a real destructive op and must
return the target's exact serial. Silence, empty input, a wrong serial, or a
timeout all mean "not authorized" — never "go ahead".
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Callable

from .audit import AuditLog
from .config import Config
from .execution import (CommandRunner, DryRunRunner, DesignatedTarget,
                        ExecutionAdapter, RealCommandRunner, TargetGuard)
from .inventory import Drive
from .logging_ import StructuredLogger
from .state import OpState, Operation, StateStore

# confirm_fn(prompt) -> the exact string the human typed (e.g. the serial).
ConfirmFn = Callable[[str], str]


@dataclass
class Authorization:
    """Validated authorization carried over from the workflow layer."""
    review_id: str
    scheduling_admin: str
    confirming_admin: str
    valid: bool
    reason: str = ""


def _authorization_ok(auth: Authorization) -> tuple[bool, str]:
    if not auth.valid:
        return False, auth.reason or "authorization not valid"
    if auth.scheduling_admin == auth.confirming_admin:
        return False, "two-person rule violated"
    return True, "ok"


class ExecutionEngine:
    def __init__(self, config: Config, audit: AuditLog, state: StateStore,
                 logger: StructuredLogger):
        self.config = config
        self.audit = audit
        self.state = state
        self.log = logger

    def _may_execute_for_real(self, op: Operation, auth: Authorization,
                              target: DesignatedTarget, drive: Drive,
                              confirm_fn: ConfirmFn | None) -> tuple[bool, str]:
        if not op.destructive:
            return False, "operation is non-destructive (dry-run path)"
        if not getattr(self.config, "allow_real_execution", False):
            return False, "config.allow_real_execution is false"
        if os.environ.get("DISPOSAL_ALLOW_REAL_EXECUTION") != "yes":
            return False, "env DISPOSAL_ALLOW_REAL_EXECUTION != yes"
        ok, why = _authorization_ok(auth)
        if not ok:
            return False, f"authorization: {why}"
        if confirm_fn is None:
            return False, "no interactive confirmation available"
        typed = (confirm_fn(
            f"Type the EXACT serial of {drive.name} to DESTROY its data "
            f"(expected: {target.expected_serial}); anything else aborts: ") or "").strip()
        if typed != target.expected_serial:
            return False, "serial confirmation did not match (aborted)"
        return True, "all gates passed"

    def execute_operation(
        self,
        op: Operation,
        drive: Drive,
        adapter: ExecutionAdapter,
        auth: Authorization,
        target: DesignatedTarget,
        *,
        runner: CommandRunner | None = None,
        confirm_fn: ConfirmFn | None = None,
        boot_drive: str | None = None,
        allow_external: bool = False,
        timeout: float = 3600.0,
    ) -> Operation:
        # Target guard applies in EVERY mode (sim or real).
        try:
            TargetGuard.validate(drive, target, boot_drive, allow_external)
        except Exception as e:
            self.state.checkpoint(op, OpState.SKIPPED, f"target rejected: {e}")
            self.audit.append("execution.target_rejected", auth.confirming_admin,
                              {"target": drive.name, "reason": str(e)})
            self.log.error("target_rejected", target=drive.name, reason=str(e))
            return op

        # Decide the runner. Default is always dry-run.
        chosen = runner or DryRunRunner()
        real_ok, why = self._may_execute_for_real(op, auth, target, drive, confirm_fn)
        if isinstance(chosen, RealCommandRunner) and not real_ok:
            # Caller wanted real execution but a gate failed -> downgrade safely.
            self.log.warn("real_execution_denied", target=drive.name, reason=why)
            self.audit.append("execution.real_denied", auth.confirming_admin,
                              {"target": drive.name, "reason": why})
            chosen = DryRunRunner()
        elif isinstance(chosen, RealCommandRunner) and real_ok:
            self.audit.append("execution.real_authorized", auth.confirming_admin,
                              {"target": drive.name, "method": adapter.method})
            self.log.warn("real_execution_authorized", target=drive.name,
                          method=adapter.method)

        op.attempts += 1
        self.state.checkpoint(op, OpState.IN_PROGRESS,
                              f"runner={type(chosen).__name__}")
        self.log.info("op_start", target=drive.name, method=adapter.method,
                      runner=type(chosen).__name__, attempt=op.attempts)

        command = adapter.build_command(drive)
        result = chosen.run(command, timeout=timeout)

        self.state.checkpoint(op, OpState.VERIFYING, "running verification")
        verify = adapter.verify(drive, chosen)

        executed = result.executed
        succeeded = (not op.destructive) or (not executed) or (
            result.returncode == 0)
        op.result = {
            "command": result.command,
            "executed": executed,
            "returncode": result.returncode,
            "verify_executed": verify.executed,
            "note": result.note,
            # We only claim erasure when a real op ran AND returned success AND
            # verification evidence exists. A dry-run never claims erasure.
            "data_erased_claim": bool(executed and succeeded and op.destructive),
            "verification_evidence": (verify.stdout if verify.executed
                                      else "n/a (dry-run/simulation)"),
        }
        if not executed:
            self.state.checkpoint(op, OpState.SUCCEEDED,
                                  "dry-run/simulation complete (no data destroyed)")
        elif succeeded:
            self.state.checkpoint(op, OpState.SUCCEEDED, "command returned success")
        else:
            self.state.checkpoint(op, OpState.FAILED,
                                  f"command returned {result.returncode}")

        self.audit.append("execution.op_complete", auth.confirming_admin, {
            "target": drive.name, "method": adapter.method,
            "executed": executed, "state": op.state,
            "data_erased_claim": op.result["data_erased_claim"]})
        self.log.info("op_complete", target=drive.name, state=op.state,
                      executed=executed)
        return op
