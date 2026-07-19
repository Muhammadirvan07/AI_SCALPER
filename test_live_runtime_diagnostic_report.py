from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest

from live_runtime.diagnostic_report import (
    DiagnosticReportError,
    build_diagnostic_report,
)
from live_runtime.realtime_diagnostic import DiagnosticJournal
import generate_realtime_diagnostic_report as cli


UTC = timezone.utc
BASE = datetime(2026, 7, 17, 12, 0, tzinfo=UTC)


def _open_payload(
    *,
    decision_id: str,
    symbol: str,
    side: str,
    strategy: str,
    score: int,
    bar_closed_at: datetime,
) -> dict[str, object]:
    entry = {
        "EURUSD": 1.1000,
        "USDJPY": 150.000,
        "AUDUSD": 0.7000,
        "XAUUSD": 3300.0,
    }[symbol]
    direction = 1 if side == "BUY" else -1
    return {
        "decision_id": decision_id,
        "canonical_symbol": symbol,
        "broker_symbol": f"{symbol}.",
        "bar_closed_at_utc": bar_closed_at,
        "status": "PAPER_OPENED",
        "paper_opened": True,
        "reason_codes": (),
        "snapshot": {
            "symbol": symbol,
            "side": side,
            "strategy": strategy,
            "score": score,
            "entry_reference": entry,
            "stop_loss": entry - direction * entry * 0.001,
            "take_profit": entry + direction * entry * 0.002,
            "bar_closed_at": bar_closed_at,
            "created_at": bar_closed_at + timedelta(milliseconds=200),
        },
        "snapshot_sha256": "a" * 64,
        "decision_explanation": None,
        "max_holding_bars": 32,
        "outcome_quality": "BROKER_TICK_DIAGNOSTIC_NOT_PROMOTION_EVIDENCE",
    }


def _close_payload(
    *,
    decision_id: str,
    side: str,
    opened_at: datetime,
    closed_at: datetime,
    outcome: str,
    r_multiple: float,
    exit_reason: str | None,
) -> dict[str, object]:
    payload: dict[str, object] = {
        "decision_id": decision_id,
        "broker_symbol": "TEST.",
        "side": side,
        "entry_price": 1.0,
        "stop_loss": 0.9 if side == "BUY" else 1.1,
        "take_profit": 1.2 if side == "BUY" else 0.8,
        "opened_at_utc": opened_at,
        "closed_at_utc": closed_at,
        "recorded_at_utc": closed_at,
        "exit_price": 1.1,
        "outcome": outcome,
        "r_multiple": r_multiple,
        "outcome_quality": "BROKER_TICK_DIAGNOSTIC_NOT_PROMOTION_EVIDENCE",
    }
    if exit_reason is not None:
        payload["exit_reason"] = exit_reason
    return payload


def _append_open(
    journal: DiagnosticJournal,
    *,
    decision_id: str,
    symbol: str,
    side: str,
    strategy: str,
    score: int,
    bar_closed_at: datetime,
    observed_at: datetime,
) -> None:
    payload = _open_payload(
        decision_id=decision_id,
        symbol=symbol,
        side=side,
        strategy=strategy,
        score=score,
        bar_closed_at=bar_closed_at,
    )
    journal._append(
        event_id=f"bar-{decision_id}",
        event_type="BAR_DECISION",
        observed_at=observed_at,
        payload=payload,
        decision_key=f"{symbol}:{bar_closed_at.isoformat()}",
        symbol=symbol,
    )


def _append_close(
    journal: DiagnosticJournal,
    *,
    decision_id: str,
    symbol: str,
    side: str,
    opened_at: datetime,
    closed_at: datetime,
    outcome: str,
    r_multiple: float,
    exit_reason: str | None,
    recorded_at: datetime,
) -> None:
    journal._append(
        event_id=f"close-{decision_id}",
        event_type="PAPER_CLOSE",
        observed_at=recorded_at,
        payload=_close_payload(
            decision_id=decision_id,
            side=side,
            opened_at=opened_at,
            closed_at=closed_at,
            outcome=outcome,
            r_multiple=r_multiple,
            exit_reason=exit_reason,
        ),
        symbol=symbol,
    )


def build_fixture(path: Path) -> None:
    opens = (
        ("usd-win", "USDJPY", "BUY", "BREAKOUT", 6, BASE),
        ("eur-loss", "EURUSD", "BUY", "BREAKOUT", 5, BASE + timedelta(minutes=15)),
        ("eur-timeout", "EURUSD", "SELL", "MOMENTUM_PULLBACK", 4, BASE + timedelta(minutes=30)),
        ("aud-open", "AUDUSD", "BUY", "BREAKOUT", 5, BASE + timedelta(minutes=45)),
    )
    with DiagnosticJournal(path) as journal:
        for index, values in enumerate(opens):
            decision_id, symbol, side, strategy, score, bar_closed_at = values
            _append_open(
                journal,
                decision_id=decision_id,
                symbol=symbol,
                side=side,
                strategy=strategy,
                score=score,
                bar_closed_at=bar_closed_at,
                observed_at=BASE + timedelta(hours=1, seconds=index),
            )

        _append_close(
            journal,
            decision_id="usd-win",
            symbol="USDJPY",
            side="BUY",
            opened_at=BASE + timedelta(milliseconds=200),
            closed_at=BASE + timedelta(hours=2),
            outcome="WIN",
            r_multiple=2.0,
            exit_reason=None,
            recorded_at=BASE + timedelta(hours=9),
        )
        _append_close(
            journal,
            decision_id="eur-loss",
            symbol="EURUSD",
            side="BUY",
            opened_at=BASE + timedelta(minutes=15, milliseconds=200),
            closed_at=BASE + timedelta(hours=3),
            outcome="LOSS",
            r_multiple=-1.0,
            exit_reason="STOP_LOSS",
            recorded_at=BASE + timedelta(hours=9, seconds=1),
        )
        _append_close(
            journal,
            decision_id="eur-timeout",
            symbol="EURUSD",
            side="SELL",
            opened_at=BASE + timedelta(minutes=30, milliseconds=200),
            closed_at=BASE + timedelta(hours=8, minutes=30),
            outcome="WIN",
            r_multiple=0.5,
            exit_reason="TIMEOUT",
            recorded_at=BASE + timedelta(hours=9, seconds=2),
        )


class DiagnosticReportTests(unittest.TestCase):
    def test_report_default_artifacts_are_isolated_per_candidate(self) -> None:
        root = Path("C:/AI_SCALPER/runtime_state/diagnostic")
        database, output = cli._diagnostic_report_paths("fbs", root=root)

        self.assertEqual(root / "fbs-real-market.sqlite3", database)
        self.assertEqual(root / "fbs-real-market-performance.json", output)
        self.assertEqual("fbs", cli._parser().parse_args([]).candidate)

    def test_report_calculates_trade_pair_and_sample_metrics(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "diagnostic.sqlite3"
            build_fixture(database)

            report = build_diagnostic_report(
                database,
                generated_at=BASE + timedelta(days=1),
            )

        self.assertEqual("REALTIME_DIAGNOSTIC_PERFORMANCE_V1", report["schema_version"])
        self.assertTrue(report["source"]["journal_sha256_chain_valid"])
        self.assertEqual(7, report["source"]["event_count"])
        self.assertEqual(3, report["overall"]["closed_trades"])
        self.assertEqual(2, report["overall"]["wins"])
        self.assertEqual(1, report["overall"]["losses"])
        self.assertEqual(1, report["overall"]["timeouts"])
        self.assertEqual(66.666667, report["overall"]["win_rate_percent"])
        self.assertEqual(2.5, report["overall"]["profit_factor_r"])
        self.assertEqual(1.5, report["overall"]["net_r"])
        self.assertEqual(0.5, report["overall"]["expectancy_r"])
        self.assertEqual(0.5, report["overall"]["median_r"])
        self.assertEqual(1.0, report["overall"]["max_drawdown_r"])
        self.assertEqual(1, report["overall"]["max_consecutive_losses"])
        self.assertEqual(
            {"LEGACY_UNSPECIFIED": 1, "STOP_LOSS": 1, "TIMEOUT": 1},
            report["overall"]["exit_reason_counts"],
        )
        self.assertEqual(1, report["open_positions"]["count"])
        self.assertEqual("AUDUSD", report["open_positions"]["positions"][0]["symbol"])

        eurusd = report["per_symbol"]["EURUSD"]
        self.assertEqual(2, eurusd["closed_trades"])
        self.assertEqual(1, eurusd["wins"])
        self.assertEqual(1, eurusd["losses"])
        self.assertEqual(1, eurusd["timeouts"])
        self.assertEqual(-0.5, eurusd["net_r"])
        self.assertEqual(0.5, eurusd["profit_factor_r"])

        breakout = report["per_strategy"]["BREAKOUT"]
        self.assertEqual(2, breakout["closed_trades"])
        self.assertEqual(1, breakout["wins"])
        self.assertEqual(1, breakout["losses"])
        self.assertEqual(1.0, breakout["net_r"])
        self.assertEqual(2.0, breakout["profit_factor_r"])

        pullback = report["per_strategy"]["MOMENTUM_PULLBACK"]
        self.assertEqual(1, pullback["closed_trades"])
        self.assertEqual(1, pullback["wins"])
        self.assertEqual(0.5, pullback["net_r"])

        buy = report["per_side"]["BUY"]
        self.assertEqual(2, buy["closed_trades"])
        self.assertEqual(1, buy["wins"])
        self.assertEqual(1, buy["losses"])
        self.assertEqual(1.0, buy["net_r"])

        sell = report["per_side"]["SELL"]
        self.assertEqual(1, sell["closed_trades"])
        self.assertEqual(1, sell["wins"])
        self.assertEqual(0.5, sell["net_r"])

        timeout = next(
            trade for trade in report["trades"] if trade["decision_id"] == "eur-timeout"
        )
        self.assertEqual(32.0, timeout["holding_horizon_m15_bars"])
        self.assertEqual(28_799.8, timeout["holding_seconds"])
        self.assertEqual("VERY_LOW_SAMPLE", report["sample_assessment"]["status"])
        self.assertFalse(report["sample_assessment"]["promotion_eligible"])
        self.assertIn("DIAGNOSTIC_ONLY", report["sample_assessment"]["warnings"])
        self.assertFalse(report["safety"]["live_allowed"])
        self.assertEqual("DISABLED", report["safety"]["order_capability"])

    def test_empty_journal_is_explicit_and_never_claims_performance(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "diagnostic.sqlite3"
            with DiagnosticJournal(database):
                pass
            report = build_diagnostic_report(database, generated_at=BASE)

        self.assertEqual(0, report["overall"]["closed_trades"])
        self.assertIsNone(report["overall"]["win_rate_percent"])
        self.assertIsNone(report["overall"]["profit_factor_r"])
        self.assertIsNone(report["overall"]["expectancy_r"])
        self.assertEqual({}, report["per_strategy"])
        self.assertEqual(0, report["per_side"]["BUY"]["closed_trades"])
        self.assertEqual(0, report["per_side"]["SELL"]["closed_trades"])
        self.assertEqual("NO_CLOSED_TRADES", report["sample_assessment"]["status"])
        self.assertIn("NO_CLOSED_TRADES", report["sample_assessment"]["warnings"])

    def test_tampered_chain_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "diagnostic.sqlite3"
            build_fixture(database)
            connection = sqlite3.connect(database)
            connection.execute("DROP TRIGGER diagnostic_events_no_update")
            connection.execute(
                "UPDATE diagnostic_events SET payload_sha256=? WHERE sequence=1",
                ("f" * 64,),
            )
            connection.commit()
            connection.close()

            with self.assertRaisesRegex(DiagnosticReportError, "hash chain"):
                build_diagnostic_report(database, generated_at=BASE + timedelta(days=1))

    def test_cli_writes_report_atomically_without_mutating_database(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            database = root / "diagnostic.sqlite3"
            output = root / "report.json"
            build_fixture(database)
            before = hashlib.sha256(database.read_bytes()).hexdigest()

            result = cli.main(
                [
                    "--acknowledge-diagnostic-only",
                    "--database",
                    str(database),
                    "--output",
                    str(output),
                ]
            )

            after = hashlib.sha256(database.read_bytes()).hexdigest()
            persisted = json.loads(output.read_text(encoding="utf-8"))

        self.assertEqual(0, result)
        self.assertEqual(before, after)
        self.assertEqual(3, persisted["overall"]["closed_trades"])
        self.assertFalse(persisted["safety"]["promotion_eligible"])
        self.assertFalse(output.with_suffix(".json.tmp").exists())

    def test_cli_requires_explicit_diagnostic_acknowledgement(self) -> None:
        with self.assertRaisesRegex(DiagnosticReportError, "acknowledge-diagnostic-only"):
            cli.main([])

    def test_missing_database_and_naive_clock_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            missing = Path(directory) / "missing.sqlite3"
            with self.assertRaisesRegex(DiagnosticReportError, "does not exist"):
                build_diagnostic_report(missing, generated_at=BASE)

            database = Path(directory) / "diagnostic.sqlite3"
            with DiagnosticJournal(database):
                pass
            with self.assertRaisesRegex(DiagnosticReportError, "timezone-aware UTC"):
                build_diagnostic_report(
                    database,
                    generated_at=datetime(2026, 7, 18),
                )


if __name__ == "__main__":
    unittest.main()
