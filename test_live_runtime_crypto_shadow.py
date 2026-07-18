from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import tempfile
import unittest

import numpy as np

from live_runtime.crypto_shadow import (
    CRYPTO_SYMBOLS,
    CryptoMarketDataError,
    CryptoPublicMarketClient,
    PublicJSONTransport,
    build_crypto_market_snapshot,
    crypto_weekend_focus_active,
)
from live_runtime.crypto_diagnostic import (
    CRYPTO_DIAGNOSTIC_PROFILE,
    crypto_diagnostic_journal,
    run_crypto_diagnostic_cycle,
)
from live_runtime.diagnostic_report import (
    DiagnosticReportError,
    build_crypto_diagnostic_report,
    build_diagnostic_report,
)
from live_runtime.realtime_diagnostic import (
    DiagnosticIdentity,
    RealtimeDiagnosticError,
)
import run_crypto_weekend_shadow as crypto_cli


UTC = timezone.utc
BOUNDARY = datetime(2026, 7, 18, 12, 0, tzinfo=UTC)


def _binance_klines(base: float, count: int = 301) -> list[list[object]]:
    start = BOUNDARY - timedelta(minutes=15 * count)
    rows: list[list[object]] = []
    for index in range(count):
        opened = start + timedelta(minutes=15 * index)
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
                int((opened + timedelta(minutes=15)).timestamp() * 1000) - 1,
                "100",
                10,
                "5",
                "50",
                "0",
            ]
        )
    return rows


class FakeTransport:
    def __init__(self, *, coinbase_age_seconds: float = 1.0, deviation_bps: float = 2.0):
        self.coinbase_age_seconds = coinbase_age_seconds
        self.deviation_bps = deviation_bps
        self.urls: list[str] = []

    def get_json(self, url: str) -> object:
        self.urls.append(url)
        if "klines" in url:
            base = 60_000.0 if "BTCUSDT" in url else 3_000.0
            return _binance_klines(base)
        if "bookTicker" in url:
            base = 60_360.0 if "BTCUSDT" in url else 3_018.0
            return {
                "symbol": "BTCUSDT" if "BTCUSDT" in url else "ETHUSDT",
                "bidPrice": str(base - 1.0),
                "askPrice": str(base + 1.0),
            }
        if "api/v3/time" in url:
            return {"serverTime": int((BOUNDARY + timedelta(seconds=2)).timestamp() * 1000)}
        if "coinbase.com" in url:
            base = 60_360.0 if "BTC-USD" in url else 3_018.0
            base *= 1.0 + self.deviation_bps / 10_000.0
            return {
                "price": str(base),
                "bid": str(base - 1.0),
                "ask": str(base + 1.0),
                "time": (BOUNDARY + timedelta(seconds=2 - self.coinbase_age_seconds))
                .isoformat()
                .replace("+00:00", "Z"),
            }
        raise AssertionError(url)


class CryptoShadowTests(unittest.TestCase):
    def test_weekend_focus_window_is_explicit_utc(self) -> None:
        self.assertTrue(crypto_weekend_focus_active(BOUNDARY))
        self.assertTrue(
            crypto_weekend_focus_active(datetime(2026, 7, 17, 22, tzinfo=UTC))
        )
        self.assertFalse(
            crypto_weekend_focus_active(datetime(2026, 7, 17, 20, tzinfo=UTC))
        )
        self.assertFalse(
            crypto_weekend_focus_active(datetime(2026, 7, 19, 23, tzinfo=UTC))
        )

    def test_public_client_has_only_market_reads_and_builds_finalized_snapshot(self) -> None:
        transport = FakeTransport()
        client = CryptoPublicMarketClient(
            transport=transport,
            clock_provider=lambda: BOUNDARY + timedelta(seconds=2),
        )
        snapshot = build_crypto_market_snapshot(
            client,
            symbol="BTCUSD",
            observed_at=BOUNDARY + timedelta(seconds=2),
            bar_count=300,
        )

        self.assertEqual(CRYPTO_SYMBOLS["BTCUSD"].primary_symbol, "BTCUSDT")
        self.assertEqual(300, len(snapshot.frame))
        self.assertTrue(snapshot.frame["is_final"].all())
        self.assertEqual(BOUNDARY, snapshot.bar_closed_at)
        self.assertLess(snapshot.cross_feed_deviation_bps, 5.0)
        self.assertGreater(snapshot.primary_quote.ask, snapshot.primary_quote.bid)
        self.assertFalse(hasattr(client, "order_send"))
        self.assertFalse(hasattr(client, "account_info"))
        self.assertTrue(all(url.startswith("https://") for url in transport.urls))

    def test_public_transport_rejects_credentials_hosts_and_unlisted_paths(self) -> None:
        transport = PublicJSONTransport()
        rejected = (
            "http://data-api.binance.vision/api/v3/time",
            "https://user:secret@data-api.binance.vision/api/v3/time",
            "https://example.com/api/v3/time",
            "https://data-api.binance.vision/api/v3/order",
            "https://api.exchange.coinbase.com/accounts",
        )
        for url in rejected:
            with self.subTest(url=url), self.assertRaisesRegex(
                CryptoMarketDataError,
                "allow-listed",
            ):
                transport.get_json(url)

    def test_cross_feed_deviation_and_staleness_fail_closed(self) -> None:
        with self.assertRaisesRegex(CryptoMarketDataError, "cross-feed deviation"):
            build_crypto_market_snapshot(
                CryptoPublicMarketClient(
                    transport=FakeTransport(deviation_bps=100.0),
                    clock_provider=lambda: BOUNDARY + timedelta(seconds=2),
                ),
                symbol="ETHUSD",
                observed_at=BOUNDARY + timedelta(seconds=2),
            )
        with self.assertRaisesRegex(CryptoMarketDataError, "Coinbase ticker is stale"):
            build_crypto_market_snapshot(
                CryptoPublicMarketClient(
                    transport=FakeTransport(coinbase_age_seconds=45.0),
                    clock_provider=lambda: BOUNDARY + timedelta(seconds=2),
                ),
                symbol="BTCUSD",
                observed_at=BOUNDARY + timedelta(seconds=2),
            )

    def test_bar_gaps_are_rejected(self) -> None:
        transport = FakeTransport()
        original = transport.get_json

        def with_gap(url: str) -> object:
            result = original(url)
            if "klines" in url:
                assert isinstance(result, list)
                del result[-3]
            return result

        transport.get_json = with_gap  # type: ignore[method-assign]
        with self.assertRaisesRegex(CryptoMarketDataError, "contiguous"):
            build_crypto_market_snapshot(
                CryptoPublicMarketClient(
                    transport=transport,
                    clock_provider=lambda: BOUNDARY + timedelta(seconds=2),
                ),
                symbol="BTCUSD",
                observed_at=BOUNDARY + timedelta(seconds=2),
            )

    def test_crypto_cycle_uses_separate_two_symbol_journal(self) -> None:
        transport = FakeTransport()
        client = CryptoPublicMarketClient(
            transport=transport,
            clock_provider=lambda: BOUNDARY + timedelta(seconds=2),
        )
        identity = DiagnosticIdentity(
            commit_sha="a" * 40,
            model_version="test-crypto-locked-v1",
            model_artifact_sha256="b" * 64,
            config_sha256="c" * 64,
            source_name="binance-primary-coinbase-validator-diagnostic-only",
        )
        with tempfile.TemporaryDirectory() as directory:
            with crypto_diagnostic_journal(
                Path(directory) / "crypto.sqlite3"
            ) as journal:
                receipt = run_crypto_diagnostic_cycle(
                    client,
                    journal,
                    cycle_id="crypto-cycle-1",
                    identity=identity,
                    observed_at=BOUNDARY + timedelta(seconds=2),
                )
                repeated = run_crypto_diagnostic_cycle(
                    client,
                    journal,
                    cycle_id="crypto-cycle-2",
                    identity=identity,
                    observed_at=BOUNDARY + timedelta(seconds=2),
                )
                summary = journal.summary()
            report = build_crypto_diagnostic_report(
                Path(directory) / "crypto.sqlite3",
                generated_at=BOUNDARY + timedelta(hours=1),
            )
            with self.assertRaisesRegex(
                DiagnosticReportError,
                "profile or schema",
            ):
                build_diagnostic_report(
                    Path(directory) / "crypto.sqlite3",
                    generated_at=BOUNDARY + timedelta(hours=1),
                )

        self.assertEqual("OBSERVED", receipt.status)
        self.assertEqual({"BTCUSD", "ETHUSD"}, set(receipt.symbol_status))
        self.assertEqual(CRYPTO_DIAGNOSTIC_PROFILE, summary["profile"])
        self.assertEqual(2, summary["decisions"])
        self.assertEqual(
            {"ALREADY_PROCESSED"},
            set(repeated.symbol_status.values()),
        )
        self.assertEqual({"BTCUSD", "ETHUSD"}, set(summary["per_symbol"]))
        self.assertTrue(summary["journal_sha256_chain_valid"])
        self.assertFalse(summary["safety"]["live_allowed"])
        self.assertEqual("DISABLED", summary["safety"]["order_capability"])
        self.assertEqual(
            "CRYPTO_WEEKEND_DIAGNOSTIC_PERFORMANCE_V1",
            report["schema_version"],
        )
        self.assertEqual({"BTCUSD", "ETHUSD"}, set(report["per_symbol"]))
        self.assertFalse(report["sample_assessment"]["promotion_eligible"])

    def test_cli_requires_acknowledgement_and_stays_inactive_on_weekday(self) -> None:
        with self.assertRaisesRegex(
            RealtimeDiagnosticError,
            "--acknowledge-diagnostic-only",
        ):
            crypto_cli.main([])
        transport = FakeTransport()
        client = CryptoPublicMarketClient(
            transport=transport,
            clock_provider=lambda: datetime(2026, 7, 20, 12, tzinfo=UTC),
        )
        result = crypto_cli.main(
            ["--acknowledge-diagnostic-only"],
            client=client,
            clock_provider=lambda: datetime(2026, 7, 20, 12, tzinfo=UTC),
        )
        self.assertEqual(0, result)
        self.assertEqual([], transport.urls)

    def test_cli_writes_isolated_weekend_summary(self) -> None:
        transport = FakeTransport()
        client = CryptoPublicMarketClient(
            transport=transport,
            clock_provider=lambda: BOUNDARY + timedelta(seconds=2),
        )
        with tempfile.TemporaryDirectory() as directory:
            journal = Path(directory) / "crypto.sqlite3"
            summary = Path(directory) / "summary.json"
            result = crypto_cli.main(
                [
                    "--acknowledge-diagnostic-only",
                    "--journal",
                    str(journal),
                    "--summary",
                    str(summary),
                ],
                client=client,
                clock_provider=lambda: BOUNDARY + timedelta(seconds=2),
            )
            payload = json.loads(summary.read_text(encoding="utf-8"))
        self.assertEqual(0, result)
        self.assertEqual(CRYPTO_DIAGNOSTIC_PROFILE, payload["profile"])
        self.assertEqual(2, payload["decisions"])
        self.assertEqual("DISABLED", payload["safety"]["order_capability"])

    def test_cli_rejects_any_safety_unlock_in_config(self) -> None:
        source = json.loads(
            crypto_cli.DEFAULT_CONFIG.read_text(encoding="utf-8")
        )
        source["safety"]["orders_allowed"] = True
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "unsafe.json"
            config.write_text(json.dumps(source), encoding="utf-8")
            with self.assertRaisesRegex(
                RealtimeDiagnosticError,
                "safety lock",
            ):
                crypto_cli.main(
                    [
                        "--acknowledge-diagnostic-only",
                        "--config",
                        str(config),
                    ],
                    clock_provider=lambda: BOUNDARY,
                )


if __name__ == "__main__":
    unittest.main()
