"""Generate the verified read-only BTC/ETH M5 challenger report."""

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
    build_crypto_m5_challenger_report,
)


REPO_ROOT = Path(__file__).resolve().parent
DEFAULT_DATABASE = (
    REPO_ROOT / "runtime_state" / "diagnostic" / "crypto-m5-challenger.sqlite3"
)
DEFAULT_OUTPUT = (
    REPO_ROOT
    / "runtime_state"
    / "diagnostic"
    / "crypto-m5-challenger-performance.json"
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Build the isolated read-only BTC/ETH M5 challenger report"
    )
    parser.add_argument("--database", type=Path, default=DEFAULT_DATABASE)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--acknowledge-diagnostic-only", action="store_true")
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
    if args.database.resolve() == args.output.resolve():
        raise DiagnosticReportError("report output cannot replace the journal")
    report = build_crypto_m5_challenger_report(args.database)
    _write_report(report, args.output)
    overall = report["overall"]
    if not isinstance(overall, Mapping):
        raise DiagnosticReportError("generated report metrics are unavailable")
    print(f"Crypto M5 challenger report written: {args.output}")
    print(f"Closed trades: {overall['closed_trades']}")
    print(f"Net R: {overall['net_r']}")
    print(f"Sample status: {report['sample_assessment']['status']}")
    print("Promotion evidence: DISABLED")
    print("Order capability: DISABLED")
    return 0


def cli_entrypoint(argv: Sequence[str] | None = None) -> int:
    try:
        return main(argv)
    except (DiagnosticReportError, OSError) as exc:
        print(f"CRYPTO_M5_REPORT_REJECTED: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(cli_entrypoint())
