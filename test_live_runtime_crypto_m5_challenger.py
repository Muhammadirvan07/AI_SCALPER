from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import numpy as np

from live_runtime.contracts import TradeIntent
from live_runtime.crypto_diagnostic import (
    CRYPTO_M5_DIAGNOSTIC_PROFILE,
    CRYPTO_M5_SOURCE_BINDING_SHA256,
    CRYPTO_SOURCE_BINDING_SHA256,
    crypto_diagnostic_journal,
    crypto_m5_diagnostic_journal,
    run_crypto_m5_diagnostic_cycle,
)
from live_runtime.crypto_shadow import (
    CryptoMarketDataError,
    CryptoPublicMarketClient,
    build_crypto_market_snapshot,
)
from live_runtime.decision_core import (
    DecisionCoreResult,
    DecisionProvenance,
    build_runtime_decision_snapshot,
)
from live_runtime.diagnostic_report import (
    DiagnosticReportError,
    build_crypto_diagnostic_report,
    build_crypto_m5_challenger_report,
)
from live_runtime.realtime_diagnostic import (
    DiagnosticIdentity,
    RealtimeDiagnosticError,
)
from strategy.strategy_profiles import get_strategy_profile
import generate_crypto_m5_challenger_report as m5_report_cli
import run_crypto_m5_challenger as m5_cli


UTC = timezone.utc
BOUNDARY = datetime(2026, 7, 18, 12, 5, tzinfo=UTC)


def _klines(base: float, *, minutes: int, count: int = 301) -> list[list[object]]:
    start = BOUNDARY - timedelta(minutes=minutes * count)
    rows: list[list[object]] = []
    for index in range(count):
        opened = start + timedelta(minutes=minutes * index)
        close = base * (1.0 + index * 0.00002 + 0.001 * np.sin(index / 7.0))
        open_price = close * 0.9999
        high = max(open_price, close) * 1.0002
        low = min(open_price, close) * 0.9998
        rows.append(
            [
                int(opened.timestamp() * 1000),
                str(open_price),
                str(high),
                str(low),
                str(close),
                "10",
                int((opened + timedelta(minutes=minutes)).timestamp() * 1000) - 1,
                "100",
                10,
                "5",
                "50",
                "0",
            ]
        )
    return rows


class M5Transport:
    def __init__(self, *, bar_minutes: int = 5):
        self.bar_minutes = bar_minutes
        self.urls: list[str] = []

    def get_json(self, url: str) -> object:
        self.urls.append(url)
        if "klines" in url:
            base = 60_000.0 if "BTCUSDT" in url else 3_000.0
            return _klines(base, minutes=self.bar_minutes)
        if "bookTicker" in url:
            base = 60_360.0 if "BTCUSDT" in url else 3_018.0
            return {
                "symbol": "BTCUSDT" if "BTCUSDT" in url else "ETHUSDT",
                "bidPrice": str(base - 1.0),
                "askPrice": str(base + 1.0),
            }
        if "api/v3/time" in url:
            return {
                "serverTime": int(
                    (BOUNDARY + timedelta(seconds=1)).timestamp() * 1000
                )
            }
        if "coinbase.com" in url:
            base = 60_360.0 if "BTC-USD" in url else 3_018.0
            return {
                "price": str(base),
                "bid": str(base - 1.0),
                "ask": str(base + 1.0),
                "time": (BOUNDARY + timedelta(seconds=1))
                .isoformat()
                .replace("+00:00", "Z"),
            }
        raise AssertionError(url)


def _client(transport: M5Transport | None = None) -> CryptoPublicMarketClient:
    return CryptoPublicMarketClient(
        transport=transport or M5Transport(),
        clock_provider=lambda: BOUNDARY + timedelta(seconds=2),
    )


def _identity() -> DiagnosticIdentity:
    return DiagnosticIdentity(
        commit_sha="a" * 40,
        model_version="rule-core-crypto-m5-challenger-locked-v1",
        model_artifact_sha256="b" * 64,
        config_sha256="c" * 64,
        source_name="binance-primary-coinbase-validator-m5-challenger-only",
    )


class CryptoM5ChallengerTests(unittest.TestCase):
    def test_m5_snapshot_requires_finalized_contiguous_five_minute_bars(self) -> None:
        snapshot = build_crypto_market_snapshot(
            _client(),
            symbol="BTCUSD",
            observed_at=BOUNDARY + timedelta(seconds=2),
            bar_count=300,
            timeframe="M5",
        )

        self.assertEqual("M5", snapshot.timeframe)
        self.assertEqual(300, snapshot.bar_seconds)
        self.assertEqual(BOUNDARY, snapshot.bar_closed_at)
        self.assertEqual(300, len(snapshot.frame))
        with self.assertRaisesRegex(CryptoMarketDataError, "contiguous"):
            build_crypto_market_snapshot(
                _client(M5Transport(bar_minutes=15)),
                symbol="BTCUSD",
                observed_at=BOUNDARY + timedelta(seconds=2),
                bar_count=300,
                timeframe="M5",
            )

    def test_m5_profile_preserves_six_hour_horizon_without_changing_m15(self) -> None:
        self.assertEqual(24, get_strategy_profile("BTCUSD", timeframe="M15").max_holding_bars)
        self.assertEqual(72, get_strategy_profile("BTCUSD", timeframe="M5").max_holding_bars)
        self.assertEqual(
            get_strategy_profile("BTCUSD", timeframe="M15").stop_atr,
            get_strategy_profile("BTCUSD", timeframe="M5").stop_atr,
        )

    def test_m5_snapshot_is_explicit_and_cannot_create_trade_intent(self) -> None:
        market = build_crypto_market_snapshot(
            _client(),
            symbol="BTCUSD",
            observed_at=BOUNDARY + timedelta(seconds=2),
            timeframe="M5",
        )
        provenance = DecisionProvenance(
            decision_run_id="crypto-m5-contract-test",
            model_version="rule-core-crypto-m5-challenger-locked-v1",
            model_artifact_sha256="b" * 64,
            commit_sha="a" * 40,
            config_sha256="c" * 64,
            data_sha256="d" * 64,
            source_name="binance-primary-coinbase-validator-m5-challenger-only",
            source_aligned=True,
            data_fresh=True,
            bar_closed_at=market.bar_closed_at,
            created_at=market.primary_quote.observed_at,
            timeframe="M5",
        )
        forced_buy = DecisionCoreResult(
            symbol="BTCUSD",
            selector_signal="BUY",
            action="BUY",
            strategy="BREAKOUT",
            score=5,
            score_components=(("test", 5),),
            market_regime="BREAKOUT",
            market_status="NORMAL",
            volatility_percent=0.2,
            decision_price=60_000.0,
            atr=100.0,
            reasons=("test fixture",),
        )
        with patch(
            "live_runtime.decision_core.evaluate_decision_core",
            return_value=forced_buy,
        ):
            decision = build_runtime_decision_snapshot(
                market.frame,
                symbol="BTCUSD",
                first_eligible_bid=market.primary_quote.bid,
                first_eligible_ask=market.primary_quote.ask,
                first_eligible_tick_at=market.primary_quote.observed_at,
                provenance=provenance,
            )

        self.assertEqual("M5", decision.timeframe)
        with self.assertRaisesRegex(ValueError, "M15 decision snapshots"):
            TradeIntent(
                mode="PAPER",
                account_id="diagnostic-account",
                server="diagnostic-server",
                symbol="BTCUSD",
                side="BUY",
                requested_lot=0.01,
                entry_reference=decision.entry_reference,
                stop_loss=decision.stop_loss,
                take_profit=decision.take_profit,
                created_at=decision.created_at,
                expires_at=decision.created_at + timedelta(seconds=1),
                decision=decision,
                permit_id="diagnostic-permit",
            )

    def test_m5_journal_domain_and_source_binding_are_isolated_from_m15(self) -> None:
        self.assertNotEqual(
            CRYPTO_SOURCE_BINDING_SHA256,
            CRYPTO_M5_SOURCE_BINDING_SHA256,
        )
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "m5.sqlite3"
            with crypto_m5_diagnostic_journal(database) as journal:
                receipt = run_crypto_m5_diagnostic_cycle(
                    _client(),
                    journal,
                    cycle_id="crypto-m5-cycle-1",
                    identity=_identity(),
                    observed_at=BOUNDARY + timedelta(seconds=2),
                )
                summary = journal.summary()

            self.assertEqual("OBSERVED", receipt.status)
            self.assertEqual(CRYPTO_M5_DIAGNOSTIC_PROFILE, summary["profile"])
            self.assertEqual("M5", summary["timeframe"])
            self.assertEqual(2, summary["decisions"])
            with self.assertRaisesRegex(RealtimeDiagnosticError, "domain"):
                crypto_diagnostic_journal(database)

    def test_m5_report_is_read_only_isolated_and_uses_m5_horizon_metrics(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "m5.sqlite3"
            with crypto_m5_diagnostic_journal(database) as journal:
                run_crypto_m5_diagnostic_cycle(
                    _client(),
                    journal,
                    cycle_id="crypto-m5-cycle-report",
                    identity=_identity(),
                    observed_at=BOUNDARY + timedelta(seconds=2),
                )
            report = build_crypto_m5_challenger_report(
                database,
                generated_at=BOUNDARY + timedelta(hours=1),
            )
            output = Path(directory) / "m5-report.json"
            self.assertEqual(
                0,
                m5_report_cli.main(
                    [
                        "--acknowledge-diagnostic-only",
                        "--database",
                        str(database),
                        "--output",
                        str(output),
                    ]
                ),
            )
            generated = json.loads(output.read_text(encoding="utf-8"))
            with self.assertRaisesRegex(DiagnosticReportError, "profile or schema"):
                build_crypto_diagnostic_report(
                    database,
                    generated_at=BOUNDARY + timedelta(hours=1),
                )

        self.assertEqual("CRYPTO_M5_CHALLENGER_PERFORMANCE_V1", report["schema_version"])
        self.assertEqual("CRYPTO_M5_CHALLENGER_PERFORMANCE_V1", generated["schema_version"])
        self.assertEqual("M5", report["timeframe"])
        self.assertIn("average_holding_horizon_m5_bars", report["overall"])
        self.assertNotIn("average_holding_horizon_m15_bars", report["overall"])
        self.assertFalse(report["sample_assessment"]["promotion_eligible"])

    def test_m5_cli_uses_dedicated_artifacts_and_keeps_every_safety_lock(self) -> None:
        with self.assertRaisesRegex(
            RealtimeDiagnosticError,
            "--acknowledge-diagnostic-only",
        ):
            m5_cli.main([])

        with tempfile.TemporaryDirectory() as directory:
            journal = Path(directory) / "m5.sqlite3"
            summary = Path(directory) / "m5-summary.json"
            result = m5_cli.main(
                [
                    "--acknowledge-diagnostic-only",
                    "--journal",
                    str(journal),
                    "--summary",
                    str(summary),
                ],
                client=_client(),
                clock_provider=lambda: BOUNDARY + timedelta(seconds=2),
            )
            payload = json.loads(summary.read_text(encoding="utf-8"))

        self.assertEqual(0, result)
        self.assertEqual(CRYPTO_M5_DIAGNOSTIC_PROFILE, payload["profile"])
        self.assertEqual("M5", payload["timeframe"])
        self.assertFalse(payload["safety"]["live_allowed"])
        self.assertFalse(payload["safety"]["promotion_eligible"])
        self.assertEqual("DISABLED", payload["safety"]["order_capability"])

    def test_m5_cli_rejects_any_safety_unlock(self) -> None:
        source = json.loads(
            m5_cli.M5_RUNNER_PROFILE.default_config.read_text(encoding="utf-8")
        )
        source["safety"]["orders_allowed"] = True
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "unsafe-m5.json"
            config.write_text(json.dumps(source), encoding="utf-8")
            with self.assertRaisesRegex(RealtimeDiagnosticError, "safety lock"):
                m5_cli.main(
                    [
                        "--acknowledge-diagnostic-only",
                        "--config",
                        str(config),
                    ],
                    clock_provider=lambda: BOUNDARY,
                )


if __name__ == "__main__":
    unittest.main()
