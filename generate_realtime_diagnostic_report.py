"""CLI for a read-only AI_SCALPER realtime diagnostic performance report."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import sys
import tempfile
from typing import Mapping, Sequence

from live_runtime.diagnostic_report import (
    DiagnosticReportError,
    build_diagnostic_report,
)


REPO_ROOT = Path(__file__).resolve().parent
DEFAULT_DIAGNOSTIC_ROOT = REPO_ROOT / "runtime_state" / "diagnostic"


def _diagnostic_report_paths(
    candidate_id: str,
    *,
    root: Path = DEFAULT_DIAGNOSTIC_ROOT,
) -> tuple[Path, Path]:
    normalized = str(candidate_id or "").strip().lower()
    if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,31}", normalized):
        raise DiagnosticReportError("candidate id is invalid for artifact isolation")
    prefix = f"{normalized}-real-market"
    return root / f"{prefix}.sqlite3", root / f"{prefix}-performance.json"


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Build a read-only, non-promotional performance report from the "
            "realtime diagnostic journal"
        )
    )
    parser.add_argument("--candidate", default="xm")
    parser.add_argument("--database", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument(
        "--acknowledge-diagnostic-only",
        action="store_true",
        help="Confirm that this report cannot enable demo-auto or live trading",
    )
    return parser


def _write_report(report: Mapping[str, object], output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(report, indent=2, sort_keys=True) + "\n"
    temporary_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="\n",
            prefix=f".{output.name}.",
            suffix=".tmp",
            dir=output.parent,
            delete=False,
        ) as temporary:
            temporary_name = temporary.name
            temporary.write(payload)
            temporary.flush()
            os.fsync(temporary.fileno())
        os.replace(temporary_name, output)
        temporary_name = None
    finally:
        if temporary_name is not None:
            Path(temporary_name).unlink(missing_ok=True)


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if not args.acknowledge_diagnostic_only:
        raise DiagnosticReportError("--acknowledge-diagnostic-only is required")
    default_database, default_output = _diagnostic_report_paths(args.candidate)
    database = args.database or default_database
    output = args.output or default_output
    if database.resolve() == output.resolve():
        raise DiagnosticReportError("report output cannot replace the journal")
    report = build_diagnostic_report(database)
    _write_report(report, output)
    overall = report["overall"]
    if not isinstance(overall, Mapping):
        raise DiagnosticReportError("generated report metrics are unavailable")
    print(f"Diagnostic performance report written: {output}")
    print(f"Closed trades: {overall['closed_trades']}")
    print(f"Net R: {overall['net_r']}")
    print(f"Sample status: {report['sample_assessment']['status']}")
    print("Promotion evidence: DISABLED")
    print("Broker mutation capability: DISABLED")
    return 0


def cli_entrypoint(argv: Sequence[str] | None = None) -> int:
    try:
        return main(argv)
    except (DiagnosticReportError, OSError) as exc:
        print(f"DIAGNOSTIC_REPORT_REJECTED: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(cli_entrypoint())
