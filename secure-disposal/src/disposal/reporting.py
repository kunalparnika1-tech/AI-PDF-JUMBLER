"""Reporting — produces a timestamped record of a (simulated) disposal review.

A report bundles: the device inventory, the method and its stated limitations,
the completion status, the verification plan/evidence, and the relevant audit
records (with a chain-integrity verdict). Reports are written as JSON and as a
human-readable Markdown summary.
"""

from __future__ import annotations

import json
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .audit import AuditLog
from .config import Config
from .inventory import DeviceInventory
from .workflow import SimulationResult


def build_report(
    config: Config,
    audit: AuditLog,
    inventory: DeviceInventory,
    result: SimulationResult,
) -> dict[str, Any]:
    ok, msg = audit.verify()
    records = [r for r in audit.read_all()
               if r["payload"].get("detail", {}).get("review_id") == result.review_id]
    return {
        "report_id": result.review_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "simulation_only": True,
        "device_inventory": inventory.to_dict(),
        "disposal": asdict(result),
        "audit_chain": {"intact": ok, "message": msg, "records": records},
    }


def write_report(config: Config, report: dict[str, Any]) -> tuple[Path, Path]:
    config.ensure_dirs()
    rid = report["report_id"]
    json_path = config.reports_dir / f"{rid}.json"
    md_path = config.reports_dir / f"{rid}.md"
    json_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    md_path.write_text(_render_markdown(report), encoding="utf-8")
    return json_path, md_path


def _render_markdown(report: dict[str, Any]) -> str:
    inv = report["device_inventory"]
    disp = report["disposal"]
    lines = [
        f"# Disposal Review Report — {report['report_id']}",
        "",
        "> **SIMULATION ONLY.** No data was destroyed. This report records a "
        "planned, human-authorized procedure.",
        "",
        f"- Generated: {report['generated_at']}",
        f"- Device: **{inv['hostname']}** ({inv['device_type']})",
        f"- OS: {inv['os_name']} {inv['os_version']} / {inv['cpu_arch']}",
        f"- Inventory source: `{inv['source']}` — verified: "
        f"**{inv['verified']}**",
        f"- Method: **{disp['method']}**",
        f"- Status: **{disp['status']}**",
        "",
        "## Drives",
    ]
    for d in inv["drives"]:
        lines.append(f"- `{d['name']}` — {d['technology']} "
                     f"({'external/network' if d['is_network'] or d['removable'] else 'internal'})")
    lines += ["", "## Planned actions (simulated)"]
    for s in disp["steps"]:
        lines.append(f"- `{s['drive']}`: {s['planned_action']}")
    lines += ["", "## Verification plan"]
    for v in disp["verification"]:
        lines.append(f"- `{v['drive']}`: {v['verification_plan']}")
    chain = report["audit_chain"]
    lines += ["", "## Audit",
              f"- Chain integrity: **{chain['intact']}** — {chain['message']}",
              f"- Relevant records: {len(chain['records'])}"]
    return "\n".join(lines) + "\n"
