from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import tempfile
import unittest

import numpy as np

from live_runtime.account_fence import account_runtime_identity
from live_runtime.fbs_crypto_diagnostic import (
    FBS_CRYPTO_M15_PROFILE,
    FBS_CRYPTO_M5_PROFILE,
    fbs_crypto_m15_journal,
    fbs_crypto_m5_journal,
)
from live_runtime.mt5_readonly import ReadOnlyMT5Facade
from live_runtime.diagnostic_report import build_fbs_crypto_broker_report
from live_runtime.realtime_diagnostic import (
    DiagnosticIdentity,
    run_diagnostic_cycle,
)
from run_realtime_diagnostic_shadow import (
    FBS_CRYPTO_M15_RUNNER_DOMAIN,
    FBS_CRYPTO_M5_RUNNER_DOMAIN,
    _diagnostic_artifact_paths,
)


UTC = timezone.utc
START = datetime(2026, 1, 1, tzinfo=UTC)
SYMBOLS = {"BTCUSD": "BTCUSD", "ETHUSD": "ETHUSD"}
IDENTITY = account_runtime_identity(778899, "FBS-Demo", "DEMO")


def _rates(base: float, minutes: int) -> list[dict[str, float | int]]:
    index = np.arange(300, dtype=float)
    close = base + base * 0.00005 * index + base * 0.002 * np.sin(index / 8.0)
    body = base * 0.0002
    opened = close - body
    return [
        {
            "time": int((START + timedelta(minutes=minutes * row)).timestamp()),
            "open": float(opened[row]),
            "high": float(max(opened[row], close[row]) + body * 0.2),
            "low": float(min(opened[row], close[row]) - body * 0.2),
            "close": float(close[row]),
        }
        for row in range(300)
    ]


class FakeFBSMT5:
    COPY_TICKS_ALL = 15
    TIMEFRAME_M5 = 5
    TIMEFRAME_M15 = 15
    ACCOUNT_TRADE_MODE_DEMO = 0

    def __init__(self, *, minutes: int) -> None:
        self.timeframe = self.TIMEFRAME_M5 if minutes == 5 else self.TIMEFRAME_M15
        self.rows = {
            "BTCUSD": _rates(60_000.0, minutes),
            "ETHUSD": _rates(3_000.0, minutes),
        }
        closed_at = START + timedelta(minutes=minutes * 300)
        self.ticks = {}
        for symbol, rows in self.rows.items():
            price = float(rows[-1]["close"])
            self.ticks[symbol] = [
                {
                    "time_msc": int((closed_at + timedelta(seconds=1)).timestamp() * 1000),
                    "bid": price - price * 0.00005,
                    "ask": price + price * 0.00005,
                }
            ]

    def account_info(self):
        return {
            "login": 778899,
            "server": "FBS-Demo",
            "trade_mode": 0,
            "trade_allowed": False,
            "trade_expert": True,
        }

    def terminal_info(self):
        return {"trade_allowed": False, "tradeapi_disabled": True}

    def symbol_info(self, symbol):
        return {"name": symbol}

    def copy_rates_from_pos(self, symbol, timeframe, start_pos, count):
        if timeframe != self.timeframe or start_pos != 0:
            raise AssertionError("wrong broker timeframe request")
        return self.rows[symbol][-count:]

    def copy_ticks_range(self, symbol, start, end, flags):
        return [
            row
            for row in self.ticks[symbol]
            if start.timestamp() * 1000 <= row["time_msc"] <= end.timestamp() * 1000
        ]

    def order_send(self, _request):
        raise AssertionError("broker mutation must never be exposed")


def _identity() -> DiagnosticIdentity:
    return DiagnosticIdentity(
        commit_sha="a" * 40,
        model_version="fbs-crypto-test-v1",
        model_artifact_sha256="b" * 64,
        config_sha256="c" * 64,
    )


class FBSCryptoDiagnosticTests(unittest.TestCase):
    def test_config_binds_exact_optional_crypto_symbols(self) -> None:
        plan = json.loads(
            (Path(__file__).parent / "config" / "broker_candidates.phase3.json").read_text(
                encoding="utf-8"
            )
        )
        fbs = next(item for item in plan["candidates"] if item["candidate_id"] == "fbs")
        self.assertEqual(SYMBOLS, fbs["broker_crypto_symbols_observed"])

    def test_m15_and_m5_use_separate_broker_domains(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with fbs_crypto_m15_journal(root / "m15.sqlite3") as m15:
                self.assertEqual(FBS_CRYPTO_M15_PROFILE, m15.profile)
                self.assertEqual("M15", m15.timeframe)
            with fbs_crypto_m5_journal(root / "m5.sqlite3") as m5:
                self.assertEqual(FBS_CRYPTO_M5_PROFILE, m5.profile)
                self.assertEqual("M5", m5.timeframe)

    def test_runner_artifacts_and_reports_are_isolated_by_timeframe(self) -> None:
        root = Path("C:/AI_SCALPER/runtime_state/diagnostic")
        m15_database, m15_summary = _diagnostic_artifact_paths(
            "fbs",
            root=root,
            artifact_tag=FBS_CRYPTO_M15_RUNNER_DOMAIN.artifact_tag,
        )
        m5_database, m5_summary = _diagnostic_artifact_paths(
            "fbs",
            root=root,
            artifact_tag=FBS_CRYPTO_M5_RUNNER_DOMAIN.artifact_tag,
        )
        self.assertEqual(root / "fbs-broker-crypto-m15.sqlite3", m15_database)
        self.assertEqual(root / "fbs-broker-crypto-m15-summary.json", m15_summary)
        self.assertEqual(root / "fbs-broker-crypto-m5.sqlite3", m5_database)
        self.assertEqual(root / "fbs-broker-crypto-m5-summary.json", m5_summary)

        with tempfile.TemporaryDirectory() as directory:
            temp = Path(directory)
            with fbs_crypto_m15_journal(temp / "m15.sqlite3"):
                pass
            with fbs_crypto_m5_journal(temp / "m5.sqlite3"):
                pass
            m15_report = build_fbs_crypto_broker_report(
                temp / "m15.sqlite3",
                timeframe="M15",
                generated_at=START,
            )
            m5_report = build_fbs_crypto_broker_report(
                temp / "m5.sqlite3",
                timeframe="M5",
                generated_at=START,
            )
        self.assertEqual("M15", m15_report["timeframe"])
        self.assertEqual("M5", m5_report["timeframe"])
        self.assertNotEqual(m15_report["schema_version"], m5_report["schema_version"])

    def test_m5_cycle_reads_mt5_and_never_exposes_order_api(self) -> None:
        fake = FakeFBSMT5(minutes=5)
        facade = ReadOnlyMT5Facade(fake)
        self.assertFalse(hasattr(facade, "order_send"))
        observed_at = START + timedelta(minutes=5 * 300, seconds=2)
        with tempfile.TemporaryDirectory() as directory:
            with fbs_crypto_m5_journal(Path(directory) / "m5.sqlite3") as journal:
                receipt = run_diagnostic_cycle(
                    facade,
                    journal,
                    cycle_id="fbs-crypto-m5-1",
                    expected_server="FBS-Demo",
                    expected_account_identity_sha256=IDENTITY,
                    broker_symbols=SYMBOLS,
                    identity=_identity(),
                    observed_at=observed_at,
                )
                summary = journal.summary()

        self.assertEqual("OBSERVED", receipt.status)
        self.assertEqual({"BTCUSD", "ETHUSD"}, set(receipt.symbol_status))
        self.assertEqual(2, summary["decisions"])
        self.assertEqual("M5", summary["timeframe"])


if __name__ == "__main__":
    unittest.main()
