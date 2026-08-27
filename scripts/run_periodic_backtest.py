"""Run a one-year H1 research diagnostic; never produce promotion evidence."""

from __future__ import annotations

import argparse
import json
from datetime import UTC, datetime
from pathlib import Path
import sys
import tempfile

import pandas as pd
import yfinance as yf

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from data_collector import YFINANCE_TICKERS  # noqa: E402
from strategy.replay_validator import validate_symbol_dataframe  # noqa: E402


def download_one_year(symbol: str) -> pd.DataFrame:
    ticker = YFINANCE_TICKERS[symbol.upper()]
    frame = yf.download(
        ticker, period="1y", interval="1h", auto_adjust=False, progress=False, threads=False
    )
    if frame.empty:
        raise RuntimeError(f"No one-year data returned for {symbol}")
    if isinstance(frame.columns, pd.MultiIndex):
        frame.columns = frame.columns.get_level_values(0)
    frame = frame.reset_index()
    if "Date" in frame.columns and "Datetime" not in frame.columns:
        frame = frame.rename(columns={"Date": "Datetime"})
    return frame


def build_report(symbols: list[str], *, verify_selector_parity: bool = False) -> dict:
    generated_at = datetime.now(UTC).isoformat()
    reports, failures = [], []
    for symbol in symbols:
        normalized = symbol.upper()
        try:
            frame = download_one_year(normalized)
            source = {
                "provider": "Yahoo Finance via yfinance", "ticker": YFINANCE_TICKERS[normalized],
                "period": "1y", "interval": "1h", "rows": len(frame),
                "downloaded_at": generated_at,
            }
            report = validate_symbol_dataframe(
                normalized,
                frame,
                source_metadata=source,
                verify_selector_parity=verify_selector_parity,
                timeframe="1h",
            )
            report["timeframe_assumption"] = "1h"
            report["evidence_scope"] = "H1_RESEARCH_ONLY_NOT_SCALPING_PROMOTION"
            report["promotion_eligible"] = False
            report["live_allowed"] = False
            report["safe_to_demo_auto_order"] = False
            report["downloaded_rows"] = len(frame)
            reports.append(report)
        except (KeyError, RuntimeError, ValueError) as exc:
            failures.append({"symbol": normalized.upper(), "error": str(exc)})
    return {
        "schema_version": "periodic-backtest-1.1", "generated_at": generated_at,
        "period": "1y", "interval": "1h", "method": "H1_COST_AWARE_PURGED_ROLLING_RESEARCH",
        "evidence_scope": "RESEARCH_ONLY_NOT_SCALPING_OR_PROMOTION_EVIDENCE",
        "requested_symbols": [symbol.upper() for symbol in symbols],
        "completed_symbols": [report["symbol"] for report in reports],
        "selector_parity_requested": verify_selector_parity,
        "status": "COMPLETE" if reports and not failures else "PARTIAL_OR_FAILED",
        "live_allowed": False, "execution_scope": "PAPER_ONLY",
        "openai_historical_replay": {
            "status": "NOT_EVALUATED_NO_POINT_IN_TIME_NEWS_ARCHIVE",
            "reason": (
                "Current news storage is not a complete one-year point-in-time archive. "
                "Using present-day LLM/news output on historical candles would introduce look-ahead bias."
            ),
            "future_source": "openai_advisory_audit.jsonl",
        },
        "symbol_reports": reports, "failures": failures,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--symbols", nargs="+", default=["eurusd", "gbpusd", "usdjpy", "xauusd", "btcusd"])
    parser.add_argument("--output", default="periodic_backtest_1y_report.json")
    parser.add_argument("--verify-selector-parity", action="store_true")
    return parser.parse_args()


def report_exit_code(report: dict) -> int:
    requested = set(report.get("requested_symbols", []))
    completed = set(report.get("completed_symbols", []))
    if report.get("failures") or not requested or completed != requested:
        return 1
    if report.get("selector_parity_requested"):
        if any(
            item.get("selector_signal_parity_verified") is not True
            for item in report.get("symbol_reports", [])
        ):
            return 1
    return 0


def write_json_atomic(path: Path, payload: dict) -> None:
    path = path.resolve()
    fd, temporary_path = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        with open(fd, "w", encoding="utf-8", closefd=True) as handle:
            json.dump(payload, handle, indent=2)
            handle.flush()
        Path(temporary_path).replace(path)
    finally:
        temporary = Path(temporary_path)
        if temporary.exists():
            temporary.unlink()


def main() -> int:
    args = parse_args()
    report = build_report(
        args.symbols,
        verify_selector_parity=args.verify_selector_parity,
    )
    output = Path(args.output)
    write_json_atomic(output, report)
    print(f"Saved one-year walk-forward report: {output}")
    print(f"Completed symbols: {len(report['symbol_reports'])}; failures: {len(report['failures'])}")
    return report_exit_code(report)


if __name__ == "__main__":
    raise SystemExit(main())
