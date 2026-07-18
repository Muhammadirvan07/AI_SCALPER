"""Generate an isolated FBS broker BTC/ETH diagnostic report."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
import tempfile
from typing import Mapping, Sequence

from live_runtime.diagnostic_report import (
    DiagnosticReportError,
    build_fbs_crypto_broker_report,
)


ROOT = Path(__file__).resolve().parent / "runtime_state" / "diagnostic"


def _paths(timeframe: str) -> tuple[Path, Path]:
    normalized = str(timeframe or "").strip().lower()
    if normalized not in {"m5", "m15"}:
        raise DiagnosticReportError("timeframe must be M5 or M15")
    prefix = f"fbs-broker-crypto-{normalized}"
    return ROOT / f"{prefix}.sqlite3", ROOT / f"{prefix}-performance.json"


def _write(report: Mapping[str, object], output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
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
            temporary.write(json.dumps(report, indent=2, sort_keys=True) + "\n")
            temporary.flush()
            os.fsync(temporary.fileno())
        os.replace(temporary_name, output)
        temporary_name = None
    finally:
        if temporary_name is not None:
            Path(temporary_name).unlink(missing_ok=True)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="FBS broker BTC/ETH diagnostic report")
    parser.add_argument("--timeframe", choices=("M5", "M15"), required=True)
    parser.add_argument("--database", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--acknowledge-diagnostic-only", action="store_true")
    args = parser.parse_args(argv)
    if not args.acknowledge_diagnostic_only:
        raise DiagnosticReportError("--acknowledge-diagnostic-only is required")
    default_database, default_output = _paths(args.timeframe)
    database = args.database or default_database
    output = args.output or default_output
    if database.resolve() == output.resolve():
        raise DiagnosticReportError("report output cannot replace the journal")
    report = build_fbs_crypto_broker_report(database, timeframe=args.timeframe)
    _write(report, output)
    overall = report["overall"]
    if not isinstance(overall, Mapping):
        raise DiagnosticReportError("generated report metrics are unavailable")
    print(f"FBS crypto {args.timeframe} report written: {output}")
    print(f"Closed trades: {overall['closed_trades']}")
    print(f"Net R: {overall['net_r']}")
    print("Promotion evidence: DISABLED")
    print("Order capability: DISABLED")
    return 0


def cli_entrypoint(argv: Sequence[str] | None = None) -> int:
    try:
        return main(argv)
    except (DiagnosticReportError, OSError) as exc:
        print(f"FBS_CRYPTO_REPORT_REJECTED: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(cli_entrypoint())
