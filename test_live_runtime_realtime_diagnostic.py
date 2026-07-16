from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest

import numpy as np

from live_runtime.account_fence import account_runtime_identity
from live_runtime.mt5_readonly import (
    MT5ReadOnlyAttestationError,
    MT5ReadOnlyCapabilityError,
    ReadOnlyMT5Facade,
    attest_mt5_read_only,
)
from live_runtime.realtime_diagnostic import (
    DiagnosticIdentity,
    DiagnosticJournal,
    REQUIRED_SYMBOLS,
    fetch_finalized_m15_bars,
    run_diagnostic_cycle,
)


UTC = timezone.utc
START = datetime(2026, 1, 1, tzinfo=UTC)
ROWS = 260
CASES = {
    "XAUUSD": {"base": 3300.0, "direction": 1, "spread": 0.02},
    "EURUSD": {"base": 1.2, "direction": 1, "spread": 0.00002},
    "USDJPY": {"base": 150.0, "direction": -1, "spread": 0.002},
    "AUDUSD": {"base": 0.7, "direction": -1, "spread": 0.00002},
}
BROKER_SYMBOLS = {
    "XAUUSD": "GOLD.",
    "EURUSD": "EURUSD.",
    "USDJPY": "USDJPY.",
    "AUDUSD": "AUDUSD.",
}
ACCOUNT_IDENTITY = account_runtime_identity(
    123456,
    "XMTrading-MT5 3",
    "DEMO",
)


def rate_rows(symbol: str) -> list[dict[str, object]]:
    case = CASES[symbol]
    index = np.arange(ROWS, dtype=float)
    base = case["base"]
    direction = case["direction"]
    close = base + direction * (
        base * 0.0002 * 0.2 * index
        + base * 0.005 * 0.2 * np.sin(index / 7.0)
    )
    candle_body = base * 0.0003
    open_price = close - direction * candle_body
    high = np.maximum(open_price, close) + candle_body * 0.2
    low = np.minimum(open_price, close) - candle_body * 0.2
    return [
        {
            "time": int((START + timedelta(minutes=15 * row)).timestamp()),
            "open": float(open_price[row]),
            "high": float(high[row]),
            "low": float(low[row]),
            "close": float(close[row]),
        }
        for row in range(ROWS)
    ]


class FakeMT5:
    COPY_TICKS_ALL = 15
    TIMEFRAME_M15 = 15
    ACCOUNT_TRADE_MODE_DEMO = 0
    ACCOUNT_TRADE_MODE_REAL = 2
    ACCOUNT_MARGIN_MODE_RETAIL_NETTING = 0
    ACCOUNT_MARGIN_MODE_EXCHANGE = 1
    ACCOUNT_MARGIN_MODE_RETAIL_HEDGING = 2

    def __init__(self) -> None:
        self.rates = {
            BROKER_SYMBOLS[symbol]: rate_rows(symbol)
            for symbol in REQUIRED_SYMBOLS
        }
        self.ticks: dict[str, list[dict[str, object]]] = {}
        for symbol in REQUIRED_SYMBOLS:
            broker_symbol = BROKER_SYMBOLS[symbol]
            closed_at = START + timedelta(minutes=15 * ROWS)
            price = float(self.rates[broker_symbol][-1]["close"])
            half_spread = CASES[symbol]["spread"] / 2.0
            tick_at = closed_at + timedelta(seconds=1)
            self.ticks[broker_symbol] = [
                {
                    "time_msc": int(tick_at.timestamp() * 1000),
                    "bid": price - half_spread,
                    "ask": price + half_spread,
                }
            ]

    def account_info(self):
        return {
            "login": 123456,
            "server": "XMTrading-MT5 3",
            "trade_mode": self.ACCOUNT_TRADE_MODE_DEMO,
            "trade_allowed": False,
            "trade_expert": False,
        }

    def terminal_info(self):
        return {
            "trade_allowed": False,
            "tradeapi_disabled": True,
        }

    def symbol_info(self, symbol):
        return {"name": symbol}

    def copy_rates_from_pos(self, symbol, timeframe, start_pos, count):
        if timeframe != self.TIMEFRAME_M15 or start_pos != 0:
            raise AssertionError("diagnostic must request M15 bars from current")
        return self.rates[symbol][-count:]

    def copy_ticks_range(self, symbol, start, end, flags):
        if flags != self.COPY_TICKS_ALL:
            raise AssertionError("diagnostic must request complete ticks")
        return [
            row
            for row in self.ticks[symbol]
            if start.timestamp() * 1000
            <= int(row["time_msc"])
            <= end.timestamp() * 1000
        ]

    def order_send(self, request):
        raise AssertionError("mutation API must never be exposed")


def identity() -> DiagnosticIdentity:
    return DiagnosticIdentity(
        commit_sha="a" * 40,
        model_version="test-locked-v1",
        model_artifact_sha256="b" * 64,
        config_sha256="c" * 64,
    )


class RealtimeDiagnosticTests(unittest.TestCase):
    def test_facade_adds_rates_without_exposing_broker_mutation(self) -> None:
        facade = ReadOnlyMT5Facade(FakeMT5())
        self.assertFalse(hasattr(facade, "order_send"))
        self.assertEqual(
            ROWS,
            len(facade.copy_rates_from_pos("GOLD.", facade.TIMEFRAME_M15, 0, ROWS)),
        )

        fake = FakeMT5()
        fake.copy_rates_from_pos = None
        no_rates = ReadOnlyMT5Facade(fake)
        with self.assertRaisesRegex(
            MT5ReadOnlyCapabilityError,
            "copy_rates_from_pos",
        ):
            no_rates.copy_rates_from_pos("GOLD.", no_rates.TIMEFRAME_M15, 0, ROWS)

    def test_attestation_reports_exact_safe_boolean_mismatches(self) -> None:
        fake = FakeMT5()
        fake.account_info = lambda: {
            "login": 123456,
            "server": "XMTrading-MT5 3",
            "trade_mode": fake.ACCOUNT_TRADE_MODE_DEMO,
            "trade_allowed": True,
            "trade_expert": True,
        }
        fake.terminal_info = lambda: {
            "trade_allowed": False,
            "tradeapi_disabled": False,
        }
        with self.assertRaises(MT5ReadOnlyAttestationError) as caught:
            attest_mt5_read_only(ReadOnlyMT5Facade(fake))
        self.assertEqual(
            {
                "account_trade_allowed": (True, False),
                "account_trade_expert": (True, False),
                "terminal_tradeapi_disabled": (False, True),
            },
            dict(caught.exception.mismatches),
        )
        message = str(caught.exception)
        self.assertIn("MT5_READ_ONLY_ATTESTATION_FAILED", message)
        self.assertIn("account_trade_allowed=True (expected False)", message)
        self.assertIn(
            "terminal_tradeapi_disabled=False (expected True)",
            message,
        )

    def test_investor_diagnostic_allows_expert_analysis_but_not_trading(self) -> None:
        fake = FakeMT5()
        fake.account_info = lambda: {
            "login": 123456,
            "server": "XMTrading-MT5 3",
            "trade_mode": fake.ACCOUNT_TRADE_MODE_DEMO,
            "trade_allowed": False,
            "trade_expert": True,
        }
        attested = attest_mt5_read_only(
            ReadOnlyMT5Facade(fake),
            require_account_expert_disabled=False,
        )
        self.assertFalse(attested["account_trade_allowed"])
        self.assertTrue(attested["account_trade_expert"])
        self.assertFalse(attested["terminal_trade_allowed"])
        self.assertTrue(attested["terminal_tradeapi_disabled"])

        with self.assertRaisesRegex(
            MT5ReadOnlyAttestationError,
            "account_trade_expert=True",
        ):
            attest_mt5_read_only(ReadOnlyMT5Facade(fake))

    def test_cycle_opens_and_closes_four_tick_semantic_paper_positions(self) -> None:
        fake = FakeMT5()
        facade = ReadOnlyMT5Facade(fake)
        closed_at = START + timedelta(minutes=15 * ROWS)
        with tempfile.TemporaryDirectory() as directory:
            with DiagnosticJournal(Path(directory) / "diagnostic.sqlite3") as journal:
                first = run_diagnostic_cycle(
                    facade,
                    journal,
                    cycle_id="cycle-1",
                    expected_server="XMTrading-MT5 3",
                    expected_account_identity_sha256=ACCOUNT_IDENTITY,
                    broker_symbols=BROKER_SYMBOLS,
                    identity=identity(),
                    observed_at=closed_at + timedelta(seconds=5),
                )
                self.assertEqual("OBSERVED", first.status)
                positions = journal.open_positions()
                self.assertEqual(set(REQUIRED_SYMBOLS), {item.symbol for item in positions})
                self.assertEqual({"BUY", "SELL"}, {item.side for item in positions})

                for position in positions:
                    spread = CASES[position.symbol]["spread"]
                    tick_at = position.opened_at + timedelta(seconds=2)
                    if position.side == "BUY":
                        bid = position.take_profit + spread
                        ask = bid + spread
                    else:
                        ask = position.take_profit - spread
                        bid = ask - spread
                    fake.ticks[position.broker_symbol].append(
                        {
                            "time_msc": int(tick_at.timestamp() * 1000),
                            "bid": bid,
                            "ask": ask,
                        }
                    )

                second = run_diagnostic_cycle(
                    facade,
                    journal,
                    cycle_id="cycle-2",
                    expected_server="XMTrading-MT5 3",
                    expected_account_identity_sha256=ACCOUNT_IDENTITY,
                    broker_symbols=BROKER_SYMBOLS,
                    identity=identity(),
                    observed_at=closed_at + timedelta(seconds=6),
                )
                self.assertEqual(4, len(second.closed_positions))
                self.assertEqual((), journal.open_positions())
                summary = journal.summary()
                self.assertEqual(4, summary["paper_opened"])
                self.assertEqual(4, summary["paper_closed"])
                self.assertEqual(4, summary["wins"])
                self.assertEqual(100.0, summary["win_rate_percent"])
                self.assertTrue(summary["journal_sha256_chain_valid"])

    def test_active_bar_is_filtered_and_registered_broker_offset_is_bounded(
        self,
    ) -> None:
        fake = FakeMT5()
        broker_symbol = BROKER_SYMBOLS["XAUUSD"]
        closed_at = START + timedelta(minutes=15 * ROWS)
        current = dict(fake.rates[broker_symbol][-1])
        current["time"] = int(closed_at.timestamp())
        fake.rates[broker_symbol].append(current)
        frame, latest_close = fetch_finalized_m15_bars(
            ReadOnlyMT5Facade(fake),
            broker_symbol=broker_symbol,
            count=ROWS,
            observed_at=closed_at + timedelta(seconds=5),
        )
        self.assertEqual(ROWS, len(frame))
        self.assertEqual(closed_at, latest_close)

        for rows in fake.rates.values():
            for row in rows:
                row["time"] = int(row["time"]) + 3 * 60 * 60
        shifted_frame, shifted_close = fetch_finalized_m15_bars(
            ReadOnlyMT5Facade(fake),
            broker_symbol=broker_symbol,
            count=ROWS,
            observed_at=closed_at + timedelta(seconds=5),
            broker_time_offset_seconds=3 * 60 * 60,
        )
        self.assertEqual(ROWS, len(shifted_frame))
        self.assertEqual(closed_at, shifted_close)

    def test_next_slot_prepublished_before_boundary_is_filtered_not_held(
        self,
    ) -> None:
        fake = FakeMT5()
        broker_symbol = BROKER_SYMBOLS["XAUUSD"]
        closed_at = START + timedelta(minutes=15 * ROWS)
        prepublished = dict(fake.rates[broker_symbol][-1])
        prepublished["time"] = int(
            (closed_at + timedelta(minutes=15, hours=3)).timestamp()
        )
        fake.rates[broker_symbol].append(prepublished)
        for row in fake.rates[broker_symbol][:-1]:
            row["time"] = int(row["time"]) + 3 * 60 * 60

        frame, latest_close = fetch_finalized_m15_bars(
            ReadOnlyMT5Facade(fake),
            broker_symbol=broker_symbol,
            count=ROWS,
            observed_at=closed_at + timedelta(minutes=14, seconds=58),
            broker_time_offset_seconds=3 * 60 * 60,
        )
        self.assertEqual(ROWS, len(frame))
        self.assertEqual(closed_at, latest_close)

    def test_journal_is_append_only_and_chain_detects_tampering(self) -> None:
        fake = FakeMT5()
        closed_at = START + timedelta(minutes=15 * ROWS)
        with tempfile.TemporaryDirectory() as directory:
            journal = DiagnosticJournal(Path(directory) / "diagnostic.sqlite3")
            run_diagnostic_cycle(
                ReadOnlyMT5Facade(fake),
                journal,
                cycle_id="cycle-1",
                expected_server="XMTrading-MT5 3",
                expected_account_identity_sha256=ACCOUNT_IDENTITY,
                broker_symbols=BROKER_SYMBOLS,
                identity=identity(),
                observed_at=closed_at + timedelta(seconds=5),
            )
            self.assertTrue(journal.verify_chain())
            with self.assertRaisesRegex(sqlite3.IntegrityError, "append-only"):
                journal.connection.execute(
                    "UPDATE diagnostic_events SET payload_sha256=? WHERE sequence=1",
                    ("f" * 64,),
                )
            with self.assertRaisesRegex(sqlite3.IntegrityError, "append-only"):
                journal.connection.execute(
                    "DELETE FROM diagnostic_events WHERE sequence=1"
                )
            journal.connection.execute("DROP TRIGGER diagnostic_events_no_update")
            journal.connection.execute(
                "UPDATE diagnostic_events SET payload_sha256=? WHERE sequence=1",
                ("f" * 64,),
            )
            self.assertFalse(journal.verify_chain())
            journal.close()

    def test_summary_is_explicitly_non_promotional(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with DiagnosticJournal(Path(directory) / "diagnostic.sqlite3") as journal:
                summary = journal.summary()
                self.assertFalse(summary["safety"]["live_allowed"])
                self.assertFalse(summary["safety"]["safe_to_demo_auto_order"])
                self.assertFalse(summary["safety"]["promotion_eligible"])
                self.assertFalse(summary["safety"]["validation_evidence"])
                self.assertFalse(summary["safety"]["legal_gate_bypassed"])
                self.assertEqual("DISABLED", summary["safety"]["order_capability"])

    def test_account_switch_is_rejected_before_market_reads(self) -> None:
        fake = FakeMT5()
        facade = ReadOnlyMT5Facade(fake)
        closed_at = START + timedelta(minutes=15 * ROWS)
        with tempfile.TemporaryDirectory() as directory:
            with DiagnosticJournal(Path(directory) / "diagnostic.sqlite3") as journal:
                with self.assertRaisesRegex(
                    RuntimeError,
                    "account identity changed",
                ):
                    run_diagnostic_cycle(
                        facade,
                        journal,
                        cycle_id="cycle-account-drift",
                        expected_server="XMTrading-MT5 3",
                        expected_account_identity_sha256="f" * 64,
                        broker_symbols=BROKER_SYMBOLS,
                        identity=identity(),
                        observed_at=closed_at + timedelta(seconds=5),
                    )
                count = journal.connection.execute(
                    "SELECT COUNT(*) FROM diagnostic_events"
                ).fetchone()[0]
                self.assertEqual(0, count)


if __name__ == "__main__":
    unittest.main()
