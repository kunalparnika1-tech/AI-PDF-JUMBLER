"""Command-line interface for the simulation-only disposal tool.

Commands:
  init-admin         Create the first ADMIN (interactive password prompt).
  add-user           Add a user (ADMIN only, via --as / password prompt).
  inventory          Show detected inventory, or a simulated smart board.
  compat             Show the NIST method compatibility assessment.
  schedule           Start a review with the 50-minute countdown.
  status             Show the current review and remaining time.
  cancel             Cancel the active review.
  reschedule         Restart the countdown for the active review.
  authorize          Run the gated, SIMULATED workflow and write a report.
  audit-verify       Verify the audit-chain integrity.

Passwords are read from the DISPOSAL_PASSWORD / DISPOSAL_PASSWORD2 environment
variables when set (useful for tests/automation), otherwise via getpass.
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
from typing import Any

from .audit import AuditLog
from .auth import AuthError, UserStore
from .config import Config
from . import compatibility, inventory as inv_mod
from .reporting import build_report, write_report
from .scheduler import Scheduler, ScheduleError, State
from .workflow import PreAuthChecklist, WorkflowError, run_simulation


def _pw(var: str, prompt: str) -> str:
    val = os.environ.get(var)
    return val if val is not None else getpass.getpass(prompt)


def _ctx(args: argparse.Namespace) -> tuple[Config, AuditLog, UserStore, Scheduler]:
    config = Config()
    if getattr(args, "data_dir", None):
        from pathlib import Path
        config.data_dir = Path(args.data_dir)
    config.ensure_dirs()
    audit = AuditLog(config.audit_file)
    return config, audit, UserStore(config), Scheduler(config, audit)


def _require(users: UserStore, username: str, password: str,
             mfa: str | None, roles: tuple[str, ...]):
    user = users.authenticate(username, password, mfa)
    if user.role not in roles:
        raise AuthError(f"role {user.role} not permitted (need one of {roles})")
    return user


def cmd_init_admin(args):
    _, audit, users, _ = _ctx(args)
    pw = _pw("DISPOSAL_PASSWORD", "New admin password: ")
    secret = users.bootstrap_admin(args.username, pw, enable_mfa=args.mfa)
    audit.append("auth.admin_bootstrapped", args.username, {})
    print(f"Admin '{args.username}' created.")
    if secret:
        print(f"MFA secret (enrol in an authenticator app now): {secret}")


def cmd_add_user(args):
    _, audit, users, _ = _ctx(args)
    admin_pw = _pw("DISPOSAL_PASSWORD", f"Password for admin '{args.as_user}': ")
    _require(users, args.as_user, admin_pw, args.mfa_code, ("ADMIN",))
    new_pw = _pw("DISPOSAL_PASSWORD2", f"Password for new user '{args.username}': ")
    secret = users.create_user(args.username, new_pw, args.role, enable_mfa=args.mfa)
    audit.append("auth.user_created", args.as_user,
                 {"new_user": args.username, "role": args.role})
    print(f"User '{args.username}' ({args.role}) created.")
    if secret:
        print(f"MFA secret: {secret}")


def _load_inventory(args):
    if args.simulated_board:
        return inv_mod.sample_board()
    return inv_mod.detect()


def cmd_inventory(args):
    inv = _load_inventory(args)
    print(json.dumps(inv.to_dict(), indent=2))
    for w in inv.warnings:
        print(f"WARNING: {w}", file=sys.stderr)


def cmd_compat(args):
    inv = _load_inventory(args)
    print(json.dumps(compatibility.assess_device(inv), indent=2))


def cmd_schedule(args):
    _, audit, users, sched = _ctx(args)
    pw = _pw("DISPOSAL_PASSWORD", f"Password for '{args.as_user}': ")
    _require(users, args.as_user, pw, args.mfa_code, ("ADMIN", "OPERATOR"))
    review = sched.schedule(args.device_id, args.as_user, args.seconds)
    mins = review.duration_seconds / 60
    print(f"Scheduled {review.review_id} for device '{args.device_id}'. "
          f"Countdown: {mins:.0f} min. The timer will LOCK the request on "
          "expiry; it will NOT execute anything.")


def cmd_status(args):
    _, _, _, sched = _ctx(args)
    r = sched.tick()
    if sched.anomalies:
        for a in sched.anomalies:
            print(f"ANOMALY: {a}", file=sys.stderr)
    if not r:
        print("No active review.")
        return
    print(json.dumps({
        "review_id": r.review_id, "device_id": r.device_id, "state": r.state,
        "remaining_seconds": round(r.remaining()),
        "created_by": r.created_by,
    }, indent=2))


def cmd_cancel(args):
    _, _, users, sched = _ctx(args)
    pw = _pw("DISPOSAL_PASSWORD", f"Password for '{args.as_user}': ")
    _require(users, args.as_user, pw, args.mfa_code, ("ADMIN", "OPERATOR"))
    sched.cancel(args.as_user, args.reason)
    print("Review cancelled.")


def cmd_reschedule(args):
    _, _, users, sched = _ctx(args)
    pw = _pw("DISPOSAL_PASSWORD", f"Password for '{args.as_user}': ")
    _require(users, args.as_user, pw, args.mfa_code, ("ADMIN", "OPERATOR"))
    r = sched.reschedule(args.as_user, args.seconds)
    print(f"Rescheduled {r.review_id}; {r.remaining():.0f}s remaining.")


def cmd_authorize(args):
    config, audit, users, sched = _ctx(args)
    pw = _pw("DISPOSAL_PASSWORD", f"Confirming admin '{args.as_user}' password: ")
    _require(users, args.as_user, pw, args.mfa_code, ("ADMIN",))

    r = sched.tick()
    if not r:
        print("No active review to authorize.", file=sys.stderr)
        sys.exit(2)
    if r.state != State.LOCKED_PENDING_CONFIRMATION.value:
        print(f"Review is '{r.state}', not locked-pending-confirmation. "
              "The countdown must expire (or be at its deadline) first.",
              file=sys.stderr)
        sys.exit(2)

    inv = _load_inventory(args)
    if args.verified and not inv.verified:
        # Explicit, audited human assertion that the hardware configuration was
        # checked. This is the gate that unblocks a simulated/undetected
        # inventory — the tool never assumes verification on its own.
        inv.verified = True
        inv.warnings.append(
            f"inventory marked human-verified by {args.as_user}")
        audit.append("inventory.human_verified", args.as_user,
                     {"review_id": r.review_id, "device": inv.hostname})
    checklist = PreAuthChecklist(
        device_identity_confirmed=args.confirm_all,
        drive_inventory_confirmed=args.confirm_all,
        backup_status_checked=args.confirm_all,
        records_retained_confirmed=args.confirm_all,
        device_not_in_use_confirmed=args.confirm_all,
        method_supported_confirmed=args.confirm_all,
        second_admin_confirmed=args.confirm_all,
    )
    try:
        result = run_simulation(
            review_id=r.review_id,
            inventory=inv,
            method=args.method,
            checklist=checklist,
            scheduler_locked=True,
            confirming_admin=args.as_user,
            scheduling_admin=r.created_by,
            audit=audit,
            allow_external=set(args.allow_external or []),
        )
    except WorkflowError as e:
        print(f"BLOCKED: {e}", file=sys.stderr)
        sys.exit(3)

    r.state = State.COMPLETED.value
    sched._save()  # persist terminal state
    report = build_report(config, audit, inv, result)
    jp, mp = write_report(config, report)
    print(f"Simulated workflow complete. Report written:\n  {jp}\n  {mp}")


def cmd_audit_verify(args):
    _, audit, _, _ = _ctx(args)
    ok, msg = audit.verify()
    print(("OK: " if ok else "FAIL: ") + msg)
    sys.exit(0 if ok else 1)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="disposal",
        description="Simulation-only secure device-disposal planner. "
                    "Performs NO destructive operations.")
    p.add_argument("--data-dir", help="override state directory")
    sub = p.add_subparsers(dest="cmd", required=True)

    def add_auth(sp):
        sp.add_argument("--as", dest="as_user", required=True)
        sp.add_argument("--mfa-code", dest="mfa_code")

    def add_inv(sp):
        sp.add_argument("--simulated-board", action="store_true",
                        help="use the labelled simulated smart-board inventory")

    s = sub.add_parser("init-admin"); s.add_argument("username"); \
        s.add_argument("--mfa", action="store_true"); s.set_defaults(func=cmd_init_admin)
    s = sub.add_parser("add-user"); add_auth(s); s.add_argument("username"); \
        s.add_argument("--role", choices=("ADMIN", "OPERATOR", "AUDITOR"), required=True); \
        s.add_argument("--mfa", action="store_true"); s.set_defaults(func=cmd_add_user)

    s = sub.add_parser("inventory"); add_inv(s); s.set_defaults(func=cmd_inventory)
    s = sub.add_parser("compat"); add_inv(s); s.set_defaults(func=cmd_compat)

    s = sub.add_parser("schedule"); add_auth(s); s.add_argument("device_id"); \
        s.add_argument("--seconds", type=int); s.set_defaults(func=cmd_schedule)
    s = sub.add_parser("status"); s.set_defaults(func=cmd_status)
    s = sub.add_parser("cancel"); add_auth(s); \
        s.add_argument("--reason", default=""); s.set_defaults(func=cmd_cancel)
    s = sub.add_parser("reschedule"); add_auth(s); \
        s.add_argument("--seconds", type=int); s.set_defaults(func=cmd_reschedule)

    s = sub.add_parser("authorize"); add_auth(s); add_inv(s)
    s.add_argument("--method", required=True,
                   choices=("cryptographic-erase", "vendor-secure-erase",
                            "vendor-factory-reset", "physical-destruction"))
    s.add_argument("--confirm-all", action="store_true",
                   help="assert every pre-authorization checklist item is true")
    s.add_argument("--verified", action="store_true",
                   help="assert (and audit) that the hardware configuration "
                        "was human-verified; required for simulated/undetected "
                        "inventories")
    s.add_argument("--allow-external", nargs="*",
                   help="explicitly permit these external/network drive names")
    s.set_defaults(func=cmd_authorize)

    s = sub.add_parser("audit-verify"); s.set_defaults(func=cmd_audit_verify)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        args.func(args)
    except (AuthError, ScheduleError, WorkflowError) as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
