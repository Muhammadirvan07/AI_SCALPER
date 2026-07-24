from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import inspect
from pathlib import Path
import tempfile
import unittest

import numpy as np

from live_runtime.brokerless_decision_producer import (
    DecisionProducerLaneConfig,
    FinalizedM15DecisionInput,
    decision_producer_key_fingerprint,
    issue_signed_session_closure_receipt,
)
from live_runtime.decision_feed import (
    DecisionFeedBinding,
    DecisionFeedLaneBinding,
    SignedDecisionFeedDirectory,
    decision_feed_key_fingerprint,
)
from live_runtime.mt5_decision_feed_publisher import (
    LIVE_ALLOWED,
    MAX_LOT,
    ORDER_CAPABILITY,
    PROMOTION_ELIGIBLE,
    SAFE_TO_DEMO_AUTO_ORDER,
    VALIDATION_EVIDENCE,
    MT5DecisionFeedPublisherBinding,
    MT5DecisionFeedPublisherError,
    MT5DecisionFeedPublisherLane,
    MT5DecisionFeedPublisherService,
    make_read_only_account_identity_port,
    make_session_closure_receipt_source_port,
)
from live_runtime.mt5_readonly import ReadOnlyMT5Facade


UTC = timezone.utc
START = datetime(2026, 7, 20, tzinfo=UTC)
ROWS = 260
BAR_CLOSED_AT = START + timedelta(minutes=15 * ROWS)
ACCOUNT_IDENTITY = hashlib.sha256(b"keyed-demo-account").hexdigest()
DATA_CONTRACT = hashlib.sha256(b"publisher-data-contract").hexdigest()
CALENDAR = hashlib.sha256(b"publisher-calendar").hexdigest()
MODEL = hashlib.sha256(b"publisher-model").hexdigest()
CONFIG = hashlib.sha256(b"publisher-config").hexdigest()
FEED_KEY = b"publisher-feed-key-material-at-least-32-bytes"
CALENDAR_KEY = b"publisher-calendar-key-material-32-bytes"
SERVER = "PhillipSecuritiesJP-PROD"


def _rate_rows(base: float) -> list[dict[str, object]]:
    index = np.arange(ROWS, dtype=float)
    close = base + base * 0.00002 * index + base * 0.0003 * np.sin(index / 7.0)
    open_price = close - base * 0.00002
    high = np.maximum(open_price, close) + base * 0.00001
    low = np.minimum(open_price, close) - base * 0.00001
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


class FakeReadOnlyBroker:
    COPY_TICKS_ALL = 15
    TIMEFRAME_M5 = 5
    TIMEFRAME_M15 = 15
    ACCOUNT_TRADE_MODE_DEMO = 0
    ACCOUNT_TRADE_MODE_REAL = 2
    ACCOUNT_MARGIN_MODE_RETAIL_NETTING = 0
    ACCOUNT_MARGIN_MODE_EXCHANGE = 1
    ACCOUNT_MARGIN_MODE_RETAIL_HEDGING = 2

    def __init__(self) -> None:
        self.server = SERVER
        self.login = 123456789
        self.trade_allowed = False
        self.trade_expert = True
        self.terminal_trade_allowed = False
        self.tradeapi_disabled = True
        self.rate_calls = 0
        self.tick_calls = 0
        self.disable_read_only_after_rate = False
        self.rates = {
            "EURUSD.ps01": _rate_rows(1.1),
            "USDJPY.ps01": _rate_rows(150.0),
        }
        self.ticks: dict[str, list[dict[str, object]]] = {}
        for symbol, rows in self.rates.items():
            price = float(rows[-1]["close"])
            spread = 0.00002 if symbol.startswith("EUR") else 0.002
            tick_at = BAR_CLOSED_AT + timedelta(milliseconds=100)
            self.ticks[symbol] = [
                {
                    "time_msc": int(tick_at.timestamp() * 1000),
                    "bid": price - spread / 2.0,
                    "ask": price + spread / 2.0,
                }
            ]

    def account_info(self):
        return {
            "login": self.login,
            "server": self.server,
            "trade_mode": self.ACCOUNT_TRADE_MODE_DEMO,
            "trade_allowed": self.trade_allowed,
            "trade_expert": self.trade_expert,
        }

    def terminal_info(self):
        return {
            "trade_allowed": self.terminal_trade_allowed,
            "tradeapi_disabled": self.tradeapi_disabled,
        }

    def symbol_info(self, symbol):
        return {"name": symbol}

    def symbols_get(self):
        return tuple({"name": symbol} for symbol in self.rates)

    def copy_rates_from_pos(self, symbol, timeframe, start_pos, count):
        self.rate_calls += 1
        if timeframe != self.TIMEFRAME_M15 or start_pos != 0:
            raise AssertionError("publisher must request current M15 bars")
        result = self.rates[symbol][-count:]
        if self.disable_read_only_after_rate:
            self.tradeapi_disabled = False
        return result

    def copy_ticks_range(self, symbol, start, end, flags):
        self.tick_calls += 1
        if flags != self.COPY_TICKS_ALL:
            raise AssertionError("publisher must request all tick types")
        return [
            row
            for row in self.ticks[symbol]
            if start.timestamp() * 1000
            <= int(row["time_msc"])
            <= end.timestamp() * 1000
        ]

    def order_send(self, request):
        raise AssertionError("the original mutation method must never be exposed")


def feed_binding(*, two_lanes: bool = False) -> DecisionFeedBinding:
    lanes = [
        DecisionFeedLaneBinding(
            lane_id="eurusd-m15-primary",
            symbol="EURUSD",
            broker_symbol="EURUSD.ps01",
            source_name="phillip-read-only-m15",
            data_contract_sha256=DATA_CONTRACT,
            session_calendar_sha256=CALENDAR,
        )
    ]
    if two_lanes:
        lanes.append(
            DecisionFeedLaneBinding(
                lane_id="usdjpy-m15-secondary",
                symbol="USDJPY",
                broker_symbol="USDJPY.ps01",
                source_name="phillip-read-only-m15",
                data_contract_sha256=DATA_CONTRACT,
                session_calendar_sha256=CALENDAR,
            )
        )
    return DecisionFeedBinding(
        feed_id="phillip-demo-m15-feed-v1",
        broker_server=SERVER,
        broker_account_identity_sha256=ACCOUNT_IDENTITY,
        publisher_issuer_id="phillip-read-only-publisher",
        publisher_key_id="publisher-key-v1",
        publisher_key_fingerprint_sha256=decision_feed_key_fingerprint(FEED_KEY),
        lanes=tuple(lanes),
    )


def publisher_binding(
    *,
    two_lanes: bool = False,
    maximum_publish_lag_ms: int = 500,
) -> MT5DecisionFeedPublisherBinding:
    feed = feed_binding(two_lanes=two_lanes)
    return MT5DecisionFeedPublisherBinding(
        service_id="phillip-read-only-feed-publisher-v1",
        feed_binding=feed,
        lanes=tuple(
            MT5DecisionFeedPublisherLane(
                lane_id=lane.lane_id,
                broker_time_offset_seconds=0,
                bar_count=ROWS,
                maximum_publish_lag_ms=maximum_publish_lag_ms,
            )
            for lane in feed.lanes
        ),
    )


def producer_lane() -> DecisionProducerLaneConfig:
    return DecisionProducerLaneConfig(
        lane_id="eurusd-m15-primary",
        symbol="EURUSD",
        source_name="phillip-read-only-m15",
        data_contract_sha256=DATA_CONTRACT,
        model_version="champion-locked-v1",
        model_artifact_sha256=MODEL,
        commit_sha="a" * 40,
        config_sha256=CONFIG,
        session_calendar_sha256=CALENDAR,
        session_calendar_issuer_id="calendar-authority",
        session_calendar_key_id="calendar-key-v1",
        session_calendar_key_fingerprint_sha256=(
            decision_producer_key_fingerprint(CALENDAR_KEY)
        ),
        maximum_processing_lag_ms=1_000,
    )


class MT5DecisionFeedPublisherTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.broker = FakeReadOnlyBroker()
        self.facade = ReadOnlyMT5Facade(self.broker)
        self.now = BAR_CLOSED_AT + timedelta(milliseconds=200)
        self.binding = publisher_binding()
        self.feed = SignedDecisionFeedDirectory(
            self.root,
            binding=self.binding.feed_binding,
            key_provider=lambda key_id: FEED_KEY,
            clock_provider=lambda: self.now,
        )
        self.account_port = make_read_only_account_identity_port(
            lambda account, environment: ACCOUNT_IDENTITY
        )
        self.receipt_port = make_session_closure_receipt_source_port(
            lambda lane, gaps, observed_at: ()
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _service(
        self,
        *,
        binding: MT5DecisionFeedPublisherBinding | None = None,
        account_port=None,
        receipt_port=None,
    ) -> MT5DecisionFeedPublisherService:
        return MT5DecisionFeedPublisherService(
            facade=self.facade,
            binding=self.binding if binding is None else binding,
            feed_directory=self.feed,
            account_identity_port=(
                self.account_port if account_port is None else account_port
            ),
            session_receipt_port=(
                self.receipt_port if receipt_port is None else receipt_port
            ),
            clock_provider=lambda: self.now,
        )

    def test_ac1_exact_current_boundary_publication_round_trip(self) -> None:
        result = self._service().run_cycle()

        self.assertEqual("OBSERVED", result.status)
        self.assertEqual("PUBLISHED", result.lanes[0].status)
        self.assertEqual(BAR_CLOSED_AT, result.lanes[0].bar_closed_at)
        self.assertIsNotNone(result.lanes[0].packet_sha256)
        reconstructed = self.feed.fetch(producer_lane())
        self.assertIs(type(reconstructed), FinalizedM15DecisionInput)
        assert reconstructed is not None
        self.assertEqual(BAR_CLOSED_AT, reconstructed.bar_closed_at)
        self.assertEqual(
            BAR_CLOSED_AT + timedelta(milliseconds=100),
            reconstructed.first_eligible_at,
        )
        self.assertEqual(ROWS, len(reconstructed.finalized_bars))

    def test_ac2_read_only_attestation_fails_before_market_reads(self) -> None:
        self.broker.tradeapi_disabled = False

        with self.assertRaises(MT5DecisionFeedPublisherError) as caught:
            self._service().run_cycle()

        self.assertEqual(
            "PUBLISHER_READ_ONLY_ATTESTATION_FAILED",
            caught.exception.reason_code,
        )
        self.assertEqual(0, self.broker.rate_calls)
        self.assertEqual(0, self.broker.tick_calls)
        self.assertEqual((), tuple(self.root.iterdir()))

    def test_ac3_server_and_keyed_account_identity_mismatch_fail_globally(self) -> None:
        self.broker.server = "Wrong-Server"
        with self.assertRaises(MT5DecisionFeedPublisherError) as caught:
            self._service().run_cycle()
        self.assertEqual(
            "PUBLISHER_ACCOUNT_BINDING_MISMATCH",
            caught.exception.reason_code,
        )
        self.assertNotIn(str(self.broker.login), str(caught.exception))
        self.assertEqual(0, self.broker.rate_calls)

        self.broker.server = SERVER
        bad_port = make_read_only_account_identity_port(
            lambda account, environment: "f" * 64
        )
        with self.assertRaises(MT5DecisionFeedPublisherError) as caught:
            self._service(account_port=bad_port).run_cycle()
        self.assertEqual(
            "PUBLISHER_ACCOUNT_BINDING_MISMATCH",
            caught.exception.reason_code,
        )
        self.assertEqual(0, self.broker.rate_calls)

    def test_ac4_waiting_missed_and_stale_market_do_not_publish(self) -> None:
        self.broker.ticks["EURUSD.ps01"] = []
        waiting = self._service().run_cycle()
        self.assertEqual("WAITING_ENTRY_TICK", waiting.lanes[0].status)
        self.assertEqual((), tuple(self.root.iterdir()))

        self.now = BAR_CLOSED_AT + timedelta(seconds=11)
        missed = self._service().run_cycle()
        self.assertEqual("ENTRY_WINDOW_MISSED", missed.lanes[0].status)
        self.assertEqual((), tuple(self.root.iterdir()))

        self.now = BAR_CLOSED_AT + timedelta(minutes=15, milliseconds=200)
        stale = self._service().run_cycle()
        self.assertEqual("STALE_MARKET", stale.lanes[0].status)
        self.assertEqual((), tuple(self.root.iterdir()))

    def test_ac5_publish_lag_and_clock_regression_fail_closed(self) -> None:
        self.now = BAR_CLOSED_AT + timedelta(milliseconds=700)
        result = self._service().run_cycle()
        self.assertEqual("HOLD", result.status)
        self.assertEqual("HOLD", result.lanes[0].status)
        self.assertEqual(
            "PUBLISHER_LATENCY_BUDGET_EXCEEDED",
            result.lanes[0].reason_code,
        )
        self.assertEqual((), tuple(self.root.iterdir()))

        values = iter(
            (
                BAR_CLOSED_AT + timedelta(milliseconds=200),
                BAR_CLOSED_AT + timedelta(milliseconds=100),
            )
        )
        service = MT5DecisionFeedPublisherService(
            facade=self.facade,
            binding=self.binding,
            feed_directory=self.feed,
            account_identity_port=self.account_port,
            session_receipt_port=self.receipt_port,
            clock_provider=lambda: next(values),
        )
        with self.assertRaises(MT5DecisionFeedPublisherError) as caught:
            service.run_cycle()
        self.assertEqual("PUBLISHER_CLOCK_INVALID", caught.exception.reason_code)
        self.assertEqual((), tuple(self.root.iterdir()))

    def test_ac5_feed_rechecks_deadline_before_create_exclusive_write(self) -> None:
        feed_clock = BAR_CLOSED_AT + timedelta(milliseconds=601)
        self.feed = SignedDecisionFeedDirectory(
            self.root,
            binding=self.binding.feed_binding,
            key_provider=lambda key_id: FEED_KEY,
            clock_provider=lambda: feed_clock,
        )

        result = self._service().run_cycle()

        self.assertEqual("HOLD", result.status)
        self.assertEqual("HOLD", result.lanes[0].status)
        self.assertEqual(
            "PUBLISHER_FEED_REJECTED",
            result.lanes[0].reason_code,
        )
        self.assertEqual((), tuple(self.root.iterdir()))

    def test_ac6_gap_receipt_source_receives_exact_interval(self) -> None:
        removed_open = START + timedelta(minutes=15 * 100)
        self.broker.rates["EURUSD.ps01"] = [
            row
            for row in self.broker.rates["EURUSD.ps01"]
            if int(row["time"]) != int(removed_open.timestamp())
        ]
        observed: list[tuple] = []

        def receipt_source(lane, gaps, observed_at):
            observed.append(gaps)
            gap = gaps[0]
            return (
                issue_signed_session_closure_receipt(
                    lane_id=lane.lane_id,
                    symbol=lane.symbol,
                    session_calendar_sha256=lane.session_calendar_sha256,
                    closed_from_utc=gap.closed_from_utc,
                    closed_until_utc=gap.closed_until_utc,
                    issued_at_utc=START - timedelta(days=1),
                    issuer_id="calendar-authority",
                    key_id="calendar-key-v1",
                    verification_key=CALENDAR_KEY,
                ),
            )

        port = make_session_closure_receipt_source_port(receipt_source)
        result = self._service(receipt_port=port).run_cycle()
        self.assertEqual("PUBLISHED", result.lanes[0].status)
        self.assertEqual(1, len(observed))
        self.assertEqual(1, len(observed[0]))
        self.assertEqual(removed_open, observed[0][0].closed_from_utc)
        self.assertEqual(
            removed_open + timedelta(minutes=15),
            observed[0][0].closed_until_utc,
        )

        second_root = self.root / "missing-receipt"
        second_root.mkdir()
        self.feed = SignedDecisionFeedDirectory(
            second_root,
            binding=self.binding.feed_binding,
            key_provider=lambda key_id: FEED_KEY,
            clock_provider=lambda: self.now,
        )
        missing = self._service(
            receipt_port=make_session_closure_receipt_source_port(
                lambda lane, gaps, observed_at: ()
            )
        ).run_cycle()
        self.assertEqual("HOLD", missing.lanes[0].status)
        self.assertEqual(
            "PUBLISHER_SESSION_RECEIPTS_INVALID",
            missing.lanes[0].reason_code,
        )
        self.assertEqual((), tuple(second_root.iterdir()))

    def test_ac7_lane_failure_isolated(self) -> None:
        binding = publisher_binding(two_lanes=True)
        self.binding = binding
        self.feed = SignedDecisionFeedDirectory(
            self.root,
            binding=binding.feed_binding,
            key_provider=lambda key_id: FEED_KEY,
            clock_provider=lambda: self.now,
        )
        del self.broker.rates["USDJPY.ps01"]

        result = self._service(binding=binding).run_cycle()

        self.assertEqual("HOLD", result.status)
        by_lane = {item.lane_id: item for item in result.lanes}
        self.assertEqual("PUBLISHED", by_lane["eurusd-m15-primary"].status)
        self.assertEqual("HOLD", by_lane["usdjpy-m15-secondary"].status)
        self.assertEqual(
            "PUBLISHER_MARKET_DATA_FAILED",
            by_lane["usdjpy-m15-secondary"].reason_code,
        )

    def test_ac8_idempotent_replay_and_conflict_remain_feed_enforced(self) -> None:
        service = self._service()
        first = service.run_cycle()
        second = service.run_cycle()
        self.assertEqual(
            first.lanes[0].packet_sha256,
            second.lanes[0].packet_sha256,
        )
        self.assertEqual(1, len(tuple(self.root.iterdir())))

        tick = self.broker.ticks["EURUSD.ps01"][0]
        tick["bid"] = float(tick["bid"]) - 0.00001
        conflict = service.run_cycle()
        self.assertEqual("HOLD", conflict.lanes[0].status)
        self.assertEqual(
            "PUBLISHER_FEED_REJECTED",
            conflict.lanes[0].reason_code,
        )
        self.assertEqual(1, len(tuple(self.root.iterdir())))

    def test_ac9_capability_boundary_binding_validation_and_safety(self) -> None:
        import live_runtime.mt5_decision_feed_publisher as module

        source = inspect.getsource(module)
        for forbidden in (
            "order_send",
            "order_check",
            "TradeIntent",
            "MetaTrader5",
            "subprocess",
            "requests",
            "urllib",
            "socket",
            "keyring",
        ):
            self.assertNotIn(forbidden, source)
        self.assertFalse(hasattr(self.facade, "order_send"))
        self.assertEqual("DISABLED", ORDER_CAPABILITY)
        self.assertIs(LIVE_ALLOWED, False)
        self.assertIs(SAFE_TO_DEMO_AUTO_ORDER, False)
        self.assertEqual(0.01, MAX_LOT)
        self.assertIs(VALIDATION_EVIDENCE, False)
        self.assertIs(PROMOTION_ELIGIBLE, False)
        allowlist = (
            Path(__file__).resolve().parent
            / "config"
            / "windows_shadow_service_allowlist.v1.json"
        ).read_text(encoding="utf-8")
        self.assertIn(
            '"live_runtime/mt5_decision_feed_publisher.py"',
            allowlist,
        )
        self.assertIn('"live_runtime/decision_feed.py"', allowlist)
        self.assertNotIn('"live_runtime/executor.py"', allowlist)

        with self.assertRaises(ValueError):
            publisher_binding(maximum_publish_lag_ms=1_001)
        with self.assertRaises(ValueError):
            MT5DecisionFeedPublisherBinding(
                service_id="invalid-closed-set",
                feed_binding=feed_binding(two_lanes=True),
                lanes=(self.binding.lanes[0],),
            )
        with self.assertRaises(AttributeError):
            self.binding.service_id = "changed"

    def test_ec8_receipt_provider_error_and_wrong_type_are_redacted(self) -> None:
        self.broker.rates["EURUSD.ps01"].pop(100)
        failing = make_session_closure_receipt_source_port(
            lambda lane, gaps, observed_at: (_ for _ in ()).throw(
                RuntimeError("SECRET-CONTENT")
            )
        )
        result = self._service(receipt_port=failing).run_cycle()
        self.assertEqual("HOLD", result.lanes[0].status)
        self.assertEqual(
            "PUBLISHER_SESSION_RECEIPTS_UNAVAILABLE",
            result.lanes[0].reason_code,
        )
        self.assertNotIn("SECRET-CONTENT", str(result))

        wrong = make_session_closure_receipt_source_port(
            lambda lane, gaps, observed_at: []
        )
        result = self._service(receipt_port=wrong).run_cycle()
        self.assertEqual(
            "PUBLISHER_SESSION_RECEIPTS_INVALID",
            result.lanes[0].reason_code,
        )

    def test_ec1_ec2_ec3_binding_rejects_lane_and_offset_drift(self) -> None:
        for invalid in (-1, 14 * 60 * 60 + 1, True):
            with self.subTest(invalid=invalid):
                with self.assertRaises((TypeError, ValueError)):
                    MT5DecisionFeedPublisherLane(
                        lane_id="eurusd-m15-primary",
                        broker_time_offset_seconds=invalid,
                        bar_count=ROWS,
                        maximum_publish_lag_ms=500,
                    )

        duplicate_symbol_binding = DecisionFeedBinding(
            feed_id="duplicate-broker-symbol-feed",
            broker_server=SERVER,
            broker_account_identity_sha256=ACCOUNT_IDENTITY,
            publisher_issuer_id="phillip-read-only-publisher",
            publisher_key_id="publisher-key-v1",
            publisher_key_fingerprint_sha256=(
                decision_feed_key_fingerprint(FEED_KEY)
            ),
            lanes=(
                DecisionFeedLaneBinding(
                    lane_id="eurusd-m15-primary",
                    symbol="EURUSD",
                    broker_symbol="EURUSD.ps01",
                    source_name="phillip-read-only-m15",
                    data_contract_sha256=DATA_CONTRACT,
                    session_calendar_sha256=CALENDAR,
                ),
                DecisionFeedLaneBinding(
                    lane_id="usdjpy-m15-secondary",
                    symbol="USDJPY",
                    broker_symbol="eurusd.PS01",
                    source_name="phillip-read-only-m15",
                    data_contract_sha256=DATA_CONTRACT,
                    session_calendar_sha256=CALENDAR,
                ),
            ),
        )
        with self.assertRaises(ValueError):
            MT5DecisionFeedPublisherBinding(
                service_id="duplicate-broker-symbol-publisher",
                feed_binding=duplicate_symbol_binding,
                lanes=tuple(
                    MT5DecisionFeedPublisherLane(
                        lane_id=lane.lane_id,
                        broker_time_offset_seconds=0,
                        bar_count=ROWS,
                        maximum_publish_lag_ms=500,
                    )
                    for lane in duplicate_symbol_binding.lanes
                ),
            )

    def test_ec4_ec5_ec6_active_bar_and_invalid_ticks_fail_closed(self) -> None:
        active = dict(self.broker.rates["EURUSD.ps01"][-1])
        active["time"] = int(BAR_CLOSED_AT.timestamp())
        self.broker.rates["EURUSD.ps01"].append(active)
        observed = self._service().run_cycle()
        self.assertEqual("PUBLISHED", observed.lanes[0].status)

        second_root = self.root / "future-tick"
        second_root.mkdir()
        self.feed = SignedDecisionFeedDirectory(
            second_root,
            binding=self.binding.feed_binding,
            key_provider=lambda key_id: FEED_KEY,
            clock_provider=lambda: self.now,
        )
        tick = self.broker.ticks["EURUSD.ps01"][0]
        tick["time_msc"] = int(
            (self.now + timedelta(milliseconds=100)).timestamp() * 1_000
        )
        future = self._service().run_cycle()
        self.assertEqual("HOLD", future.lanes[0].status)
        self.assertEqual(
            "PUBLISHER_TICK_TIME_INVALID",
            future.lanes[0].reason_code,
        )
        self.assertEqual((), tuple(second_root.iterdir()))

        tick["time_msc"] = int(
            (BAR_CLOSED_AT + timedelta(milliseconds=100)).timestamp() * 1_000
        )
        tick["ask"] = float(tick["bid"]) - 0.00001
        invalid = self._service().run_cycle()
        self.assertEqual("HOLD", invalid.lanes[0].status)
        self.assertEqual(
            "PUBLISHER_MARKET_DATA_FAILED",
            invalid.lanes[0].reason_code,
        )
        self.assertEqual((), tuple(second_root.iterdir()))

    def test_ec9_ec10_final_attestation_and_feed_key_fail_closed(self) -> None:
        self.broker.disable_read_only_after_rate = True
        with self.assertRaises(MT5DecisionFeedPublisherError) as caught:
            self._service().run_cycle()
        self.assertEqual(
            "PUBLISHER_READ_ONLY_ATTESTATION_FAILED",
            caught.exception.reason_code,
        )
        self.assertEqual((), tuple(self.root.iterdir()))

        self.broker.disable_read_only_after_rate = False
        self.broker.tradeapi_disabled = True
        bad_root = self.root / "bad-feed-key"
        bad_root.mkdir()
        self.feed = SignedDecisionFeedDirectory(
            bad_root,
            binding=self.binding.feed_binding,
            key_provider=lambda key_id: b"x" * 32,
            clock_provider=lambda: self.now,
        )
        result = self._service().run_cycle()
        self.assertEqual("HOLD", result.lanes[0].status)
        self.assertEqual(
            "PUBLISHER_FEED_REJECTED",
            result.lanes[0].reason_code,
        )
        self.assertEqual((), tuple(bad_root.iterdir()))


if __name__ == "__main__":
    unittest.main()
