from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import hashlib
import inspect
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import numpy as np
import pandas as pd

from live_runtime.brokerless_decision_producer import (
    DecisionProducerBinding,
    DecisionProducerInputError,
    DecisionProducerLaneConfig,
    FinalizedM15DecisionInput,
    ReadOnlyFinalizedM15ProviderPort,
    _normalize_and_hash_input,
    decision_producer_key_fingerprint,
    issue_signed_session_closure_receipt,
    make_verified_session_calendar_port,
)
from live_runtime.contracts import canonical_json
from live_runtime.decision_feed import (
    LIVE_ALLOWED,
    MAXIMUM_PACKET_BYTES,
    MAXIMUM_PACKETS_PER_LANE,
    MAX_LOT,
    ORDER_CAPABILITY,
    PROMOTION_ELIGIBLE,
    SAFE_TO_DEMO_AUTO_ORDER,
    VALIDATION_EVIDENCE,
    DecisionFeedBinding,
    DecisionFeedError,
    DecisionFeedLaneBinding,
    SignedDecisionFeedDirectory,
    decision_feed_key_fingerprint,
    make_signed_decision_feed_provider,
    validate_decision_feed_binding,
)


UTC = timezone.utc
START = datetime(2026, 7, 20, tzinfo=UTC)
ROWS = 260
BAR_CLOSED_AT = START + timedelta(minutes=15 * ROWS)
QUOTE_AT = BAR_CLOSED_AT + timedelta(milliseconds=100)
DATA_CONTRACT = hashlib.sha256(b"decision-feed-data-contract").hexdigest()
CALENDAR = hashlib.sha256(b"decision-feed-calendar").hexdigest()
MODEL = hashlib.sha256(b"decision-feed-model").hexdigest()
CONFIG = hashlib.sha256(b"decision-feed-config").hexdigest()
ACCOUNT = hashlib.sha256(b"demo-account-alias").hexdigest()
FEED_KEY = b"decision-feed-publisher-key-material-v1"
CALENDAR_KEY = b"decision-feed-calendar-key-material-v1"


def frame(*, shift_bars: int = 0) -> pd.DataFrame:
    index = np.arange(ROWS, dtype=float)
    close = 1.1 + 0.00002 * index + 0.0003 * np.sin(index / 7.0)
    open_price = close - 0.0001
    return pd.DataFrame(
        {
            "open_time_utc": pd.date_range(
                START + timedelta(minutes=15 * shift_bars),
                periods=ROWS,
                freq="15min",
                tz="UTC",
            ),
            "Open": open_price,
            "High": np.maximum(open_price, close) + 0.00003,
            "Low": np.minimum(open_price, close) - 0.00003,
            "Close": close,
            "is_final": [True] * ROWS,
        }
    )


def producer_lane(
    *,
    lane_id: str = "eurusd-m15-primary",
    symbol: str = "EURUSD",
    source_name: str = "phillip-read-only-m15",
) -> DecisionProducerLaneConfig:
    return DecisionProducerLaneConfig(
        lane_id=lane_id,
        symbol=symbol,
        source_name=source_name,
        data_contract_sha256=DATA_CONTRACT,
        model_version="champion-locked-v1",
        model_artifact_sha256=MODEL,
        commit_sha="a" * 40,
        config_sha256=CONFIG,
        session_calendar_sha256=CALENDAR,
        session_calendar_issuer_id="reviewed-calendar-authority",
        session_calendar_key_id="calendar-key-v1",
        session_calendar_key_fingerprint_sha256=(
            decision_producer_key_fingerprint(CALENDAR_KEY)
        ),
        maximum_processing_lag_ms=1_000,
    )


def feed_binding(*, include_second_lane: bool = False) -> DecisionFeedBinding:
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
    if include_second_lane:
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
        feed_id="phillip-demo-read-only-feed-v1",
        broker_server="PhillipSecuritiesJP-PROD",
        broker_account_identity_sha256=ACCOUNT,
        publisher_issuer_id="phillip-read-only-exporter",
        publisher_key_id="decision-feed-key-v1",
        publisher_key_fingerprint_sha256=decision_feed_key_fingerprint(FEED_KEY),
        lanes=tuple(lanes),
    )


def observation(
    *,
    shift_bars: int = 0,
    bid: float = 1.10500,
    ask: float = 1.10502,
    data_fresh: bool = True,
    receipts: tuple = (),
) -> FinalizedM15DecisionInput:
    boundary = BAR_CLOSED_AT + timedelta(minutes=15 * shift_bars)
    return FinalizedM15DecisionInput(
        lane_id="eurusd-m15-primary",
        symbol="EURUSD",
        source_name="phillip-read-only-m15",
        data_contract_sha256=DATA_CONTRACT,
        session_calendar_sha256=CALENDAR,
        source_aligned=True,
        data_fresh=data_fresh,
        bar_closed_at=boundary,
        first_eligible_bid=bid,
        first_eligible_ask=ask,
        first_eligible_at=boundary + timedelta(milliseconds=100),
        finalized_bars=frame(shift_bars=shift_bars),
        session_closure_receipts=receipts,
    )


class TestSignedDecisionFeedHandoff(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.binding = feed_binding()
        self.lane = producer_lane()
        self.feed_lane = self.binding.lane(self.lane.lane_id)
        self.clock = BAR_CLOSED_AT + timedelta(milliseconds=200)
        self.store = SignedDecisionFeedDirectory(
            self.root,
            binding=self.binding,
            key_provider=lambda key_id: FEED_KEY,
            clock_provider=lambda: self.clock,
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_ac1_exact_signed_round_trip_and_sealed_provider(self) -> None:
        original = observation()
        packet = self.store.publish(
            self.feed_lane,
            original,
            issued_at_utc=self.clock,
        )
        provider = make_signed_decision_feed_provider(
            self.root,
            binding=self.binding,
            key_provider=lambda key_id: FEED_KEY,
            clock_provider=lambda: self.clock,
        )

        self.assertIs(type(provider), ReadOnlyFinalizedM15ProviderPort)
        reconstructed = provider.fetch(self.lane)
        self.assertIs(type(reconstructed), FinalizedM15DecisionInput)
        assert reconstructed is not None
        self.assertEqual(1, packet.sequence)
        self.assertEqual("0" * 64, packet.previous_packet_sha256)
        self.assertEqual(original.lane_id, reconstructed.lane_id)
        self.assertEqual(original.bar_closed_at, reconstructed.bar_closed_at)
        self.assertEqual(original.first_eligible_at, reconstructed.first_eligible_at)
        pd.testing.assert_frame_equal(
            original.finalized_bars,
            reconstructed.finalized_bars,
        )
        changed = reconstructed.finalized_bars
        changed.loc[0, "Close"] = 999
        self.assertNotEqual(
            999,
            provider.fetch(self.lane).finalized_bars.loc[0, "Close"],
        )
        packet_file = next(self.root.iterdir())
        self.assertEqual(
            canonical_json(json.loads(packet_file.read_text(encoding="utf-8").rstrip("\n")))
            + "\n",
            packet_file.read_text(encoding="utf-8"),
        )
        self.assertEqual(
            self.binding,
            validate_decision_feed_binding(self.binding.to_canonical_dict()),
        )
        invalid_binding = self.binding.to_canonical_dict()
        invalid_binding["unknown"] = True
        with self.assertRaises(DecisionFeedError) as caught:
            validate_decision_feed_binding(invalid_binding)
        self.assertEqual("FEED_BINDING_INVALID", caught.exception.reason_code)

    def test_ac2_same_observation_is_idempotent_and_conflict_is_denied(self) -> None:
        first = self.store.publish(
            self.feed_lane, observation(), issued_at_utc=self.clock
        )
        replay = self.store.publish(
            self.feed_lane,
            observation(),
            issued_at_utc=self.clock + timedelta(milliseconds=1),
        )
        self.assertEqual(first, replay)
        self.assertEqual(1, len(tuple(self.root.iterdir())))

        with self.assertRaises(DecisionFeedError) as caught:
            self.store.publish(
                self.feed_lane,
                observation(bid=1.10499),
                issued_at_utc=self.clock,
            )
        self.assertEqual("FEED_CANDLE_CONFLICT", caught.exception.reason_code)
        self.assertEqual(1, len(tuple(self.root.iterdir())))

    def test_ac2_publication_deadline_is_rechecked_at_write_boundary(self) -> None:
        issued = self.clock
        deadline = self.clock + timedelta(milliseconds=50)
        self.clock = deadline + timedelta(microseconds=1)

        with self.assertRaises(DecisionFeedError) as caught:
            self.store.publish(
                self.feed_lane,
                observation(),
                issued_at_utc=issued,
                publication_deadline_utc=deadline,
            )

        self.assertEqual(
            "FEED_PUBLICATION_DEADLINE_EXCEEDED",
            caught.exception.reason_code,
        )
        self.assertEqual((), tuple(self.root.iterdir()))

        for invalid in (
            QUOTE_AT - timedelta(microseconds=1),
            BAR_CLOSED_AT + timedelta(seconds=10, microseconds=1),
        ):
            with self.subTest(invalid=invalid):
                with self.assertRaises(DecisionFeedError) as invalid_deadline:
                    self.store.publish(
                        self.feed_lane,
                        observation(),
                        issued_at_utc=issued,
                        publication_deadline_utc=invalid,
                    )
                self.assertEqual(
                    "FEED_PUBLICATION_DEADLINE_INVALID",
                    invalid_deadline.exception.reason_code,
                )
        self.assertEqual((), tuple(self.root.iterdir()))

    def test_ac3_newer_packet_links_verified_head_and_fetch_reads_two_bodies(self) -> None:
        first = self.store.publish(
            self.feed_lane, observation(), issued_at_utc=self.clock
        )
        self.clock += timedelta(minutes=15)
        second = self.store.publish(
            self.feed_lane,
            observation(shift_bars=1),
            issued_at_utc=self.clock,
        )
        self.assertEqual(2, second.sequence)
        self.assertEqual(first.content_sha256, second.previous_packet_sha256)

        with mock.patch(
            "live_runtime.decision_feed._stable_read",
            wraps=__import__(
                "live_runtime.decision_feed",
                fromlist=["_stable_read"],
            )._stable_read,
        ) as stable_read:
            latest = self.store.fetch(self.lane)
        self.assertEqual(second.bar_closed_at, latest.bar_closed_at)
        self.assertEqual(2, stable_read.call_count)

    def test_ac4_tamper_and_wrong_key_are_rejected(self) -> None:
        self.store.publish(
            self.feed_lane, observation(), issued_at_utc=self.clock
        )
        packet_file = next(self.root.iterdir())
        payload = json.loads(packet_file.read_text(encoding="utf-8"))
        payload["first_eligible_bid"] = 1.0
        packet_file.write_text(
            canonical_json(payload) + "\n",
            encoding="utf-8",
        )
        with self.assertRaises(DecisionFeedError) as caught:
            self.store.fetch(self.lane)
        self.assertIn(
            caught.exception.reason_code,
            {"FEED_OBSERVATION_HASH_MISMATCH", "FEED_SIGNATURE_INVALID"},
        )

        valid_root = self.root / "wrong-key"
        valid_root.mkdir()
        valid_store = SignedDecisionFeedDirectory(
            valid_root,
            binding=self.binding,
            key_provider=lambda key_id: FEED_KEY,
            clock_provider=lambda: self.clock,
        )
        valid_store.publish(
            self.feed_lane,
            observation(),
            issued_at_utc=self.clock,
        )
        other = SignedDecisionFeedDirectory(
            valid_root,
            binding=self.binding,
            key_provider=lambda key_id: b"x" * 32,
            clock_provider=lambda: self.clock,
        )
        with self.assertRaises(DecisionFeedError) as caught:
            other.fetch(self.lane)
        self.assertEqual(
            "FEED_KEY_FINGERPRINT_MISMATCH",
            caught.exception.reason_code,
        )

    def test_ac5_missing_root_and_symlink_packet_are_rejected(self) -> None:
        missing = self.root / "missing"
        with self.assertRaises(DecisionFeedError) as caught:
            SignedDecisionFeedDirectory(
                missing,
                binding=self.binding,
                key_provider=lambda key_id: FEED_KEY,
                clock_provider=lambda: self.clock,
            )
        self.assertEqual("FEED_DIRECTORY_INVALID", caught.exception.reason_code)

        self.store.publish(
            self.feed_lane, observation(), issued_at_utc=self.clock
        )
        packet_file = next(self.root.iterdir())
        target = self.root / "moved.json"
        packet_file.replace(target)
        try:
            os.symlink(target, packet_file)
        except OSError:
            self.skipTest("symlink creation is unavailable on this host")
        with self.assertRaises(DecisionFeedError) as caught:
            self.store.fetch(self.lane)
        self.assertEqual("FEED_PACKET_PATH_INVALID", caught.exception.reason_code)

    def test_ac6_duplicate_keys_and_capacity_fail_before_key_use(self) -> None:
        key_calls = 0

        def key_provider(key_id: str) -> bytes:
            nonlocal key_calls
            key_calls += 1
            return FEED_KEY

        store = SignedDecisionFeedDirectory(
            self.root,
            binding=self.binding,
            key_provider=key_provider,
            clock_provider=lambda: self.clock,
        )
        store.publish(self.feed_lane, observation(), issued_at_utc=self.clock)
        packet_file = next(self.root.iterdir())
        text = packet_file.read_text(encoding="utf-8")
        packet_file.write_text(
            '{"feed_id":"duplicate",' + text[1:],
            encoding="utf-8",
        )
        key_calls = 0
        with self.assertRaises(DecisionFeedError) as caught:
            store.fetch(self.lane)
        self.assertEqual("FEED_JSON_DUPLICATE_KEY", caught.exception.reason_code)
        self.assertEqual(0, key_calls)

        packet_file.unlink()
        token = hashlib.sha256(self.lane.lane_id.encode("utf-8")).hexdigest()
        with mock.patch(
            "live_runtime.decision_feed.MAXIMUM_PACKETS_PER_LANE",
            2,
        ):
            for sequence in range(1, 4):
                (self.root / f"{token}.{sequence:020d}.json").touch()
            with self.assertRaises(DecisionFeedError) as caught:
                store.fetch(self.lane)
        self.assertEqual("FEED_CAPACITY_EXCEEDED", caught.exception.reason_code)

    def test_ac7_empty_lane_returns_none_but_invalid_lane_packet_raises(self) -> None:
        provider = self.store.provider()
        self.assertIsNone(provider.fetch(self.lane))

        token = hashlib.sha256(self.lane.lane_id.encode("utf-8")).hexdigest()
        (self.root / f"{token}.{1:020d}.json").write_text(
            "{}\n",
            encoding="utf-8",
        )
        with self.assertRaises(DecisionFeedError):
            provider.fetch(self.lane)

    def test_ac8_freshness_false_is_reconstructed_for_producer_to_reject(self) -> None:
        self.store.publish(
            self.feed_lane,
            observation(data_fresh=False),
            issued_at_utc=self.clock,
        )
        reconstructed = self.store.fetch(self.lane)
        self.assertIsNotNone(reconstructed)
        assert reconstructed is not None
        self.assertFalse(reconstructed.data_fresh)
        producer_binding = DecisionProducerBinding(
            service_id="decision-producer-v1",
            lanes=(self.lane,),
            custody_issuer_id="offhost-cursor-custody",
            custody_key_id="cursor-custody-key-v1",
            custody_key_fingerprint_sha256=hashlib.sha256(
                b"cursor-custody-key-material-v1"
            ).hexdigest(),
        )
        calendar = make_verified_session_calendar_port(
            producer_binding,
            lambda key_id: CALENDAR_KEY,
        )
        with self.assertRaises(DecisionProducerInputError):
            _normalize_and_hash_input(
                reconstructed,
                self.lane,
                trusted_now=self.clock,
                calendar_port=calendar,
            )

    def test_ac9_capability_boundary_and_safety_constants(self) -> None:
        import live_runtime.decision_feed as module

        source = inspect.getsource(module)
        forbidden = (
            "MetaTrader5",
            "order_send",
            "order_check",
            "TradeIntent",
            "subprocess",
            "requests",
            "urllib",
            "socket",
            "keyring",
        )
        for token in forbidden:
            self.assertNotIn(token, source)
        self.assertEqual("DISABLED", ORDER_CAPABILITY)
        self.assertIs(LIVE_ALLOWED, False)
        self.assertIs(SAFE_TO_DEMO_AUTO_ORDER, False)
        self.assertEqual(0.01, MAX_LOT)
        self.assertIs(VALIDATION_EVIDENCE, False)
        self.assertIs(PROMOTION_ELIGIBLE, False)

    def test_ac10_existing_producer_types_are_not_changed(self) -> None:
        packet = self.store.publish(
            self.feed_lane,
            observation(),
            issued_at_utc=self.clock,
        )
        result = self.store.fetch(self.lane)
        self.assertIs(type(result), FinalizedM15DecisionInput)
        self.assertEqual(self.lane.lane_id, packet.lane_id)
        self.assertEqual(self.lane.symbol, packet.symbol)
        self.assertEqual(
            packet,
            self.store.publish(
                self.lane,
                observation(),
                issued_at_utc=self.clock,
            ),
        )
        with self.assertRaises(AttributeError):
            self.store.binding = feed_binding(include_second_lane=True)

    def test_ec1_key_provider_failure_is_redacted(self) -> None:
        store = SignedDecisionFeedDirectory(
            self.root,
            binding=self.binding,
            key_provider=lambda key_id: (_ for _ in ()).throw(
                RuntimeError("SECRET-CONTENT")
            ),
            clock_provider=lambda: self.clock,
        )
        with self.assertRaises(DecisionFeedError) as caught:
            store.publish(
                self.feed_lane, observation(), issued_at_utc=self.clock
            )
        self.assertEqual("FEED_KEY_UNAVAILABLE", caught.exception.reason_code)
        self.assertEqual("FEED_KEY_UNAVAILABLE", str(caught.exception))

    def test_ec2_non_utc_and_regressing_clock_are_rejected(self) -> None:
        naive = SignedDecisionFeedDirectory(
            self.root,
            binding=self.binding,
            key_provider=lambda key_id: FEED_KEY,
            clock_provider=lambda: self.clock.replace(tzinfo=None),
        )
        with self.assertRaises(DecisionFeedError) as caught:
            naive.fetch(self.lane)
        self.assertEqual("FEED_CLOCK_INVALID", caught.exception.reason_code)

        values = iter((self.clock, self.clock - timedelta(seconds=1)))
        regressing = SignedDecisionFeedDirectory(
            self.root,
            binding=self.binding,
            key_provider=lambda key_id: FEED_KEY,
            clock_provider=lambda: next(values),
        )
        with self.assertRaises(DecisionFeedError) as caught:
            regressing.fetch(self.lane)
        self.assertEqual("FEED_CLOCK_INVALID", caught.exception.reason_code)

    def test_ec4_and_ec5_sequence_race_is_idempotent_or_conflicting(self) -> None:
        import live_runtime.decision_feed as decision_feed

        peer = SignedDecisionFeedDirectory(
            self.root,
            binding=self.binding,
            key_provider=lambda key_id: FEED_KEY,
            clock_provider=lambda: self.clock,
        )
        first = self.store.publish(
            self.feed_lane, observation(), issued_at_utc=self.clock
        )
        self.assertEqual(
            first,
            peer.publish(
                self.feed_lane, observation(), issued_at_utc=self.clock
            ),
        )

        self.clock += timedelta(minutes=15)
        second = self.store.publish(
            self.feed_lane,
            observation(shift_bars=1),
            issued_at_utc=self.clock,
        )
        self.assertEqual(
            second,
            peer.publish(
                self.feed_lane,
                observation(shift_bars=1),
                issued_at_utc=self.clock,
            ),
        )

        race_root = self.root / "race"
        race_root.mkdir()
        race_store = SignedDecisionFeedDirectory(
            race_root,
            binding=self.binding,
            key_provider=lambda key_id: FEED_KEY,
            clock_provider=lambda: self.clock,
        )
        race_head = race_store.publish(
            self.feed_lane,
            observation(),
            issued_at_utc=self.clock,
        )
        desired = observation(shift_bars=2)
        winner = observation(shift_bars=1)
        original_write = decision_feed._write_exclusive

        def competing_write(path, payload, *, root):
            competing_packet = decision_feed._issue_packet(
                binding=self.binding,
                lane=self.feed_lane,
                observation=winner,
                sequence=2,
                previous_packet_sha256=race_head.content_sha256,
                issued_at_utc=self.clock,
                key=FEED_KEY,
            )
            original_write(
                path,
                decision_feed._packet_bytes(competing_packet),
                root=root,
            )
            raise FileExistsError(path)

        with self.assertRaises(DecisionFeedError) as caught:
            with mock.patch(
                "live_runtime.decision_feed._write_exclusive",
                side_effect=competing_write,
            ):
                race_store.publish(
                    self.feed_lane,
                    desired,
                    issued_at_utc=self.clock,
                )
        self.assertEqual("FEED_SEQUENCE_CONFLICT", caught.exception.reason_code)

    def test_ec8_missing_historical_sequence_is_rejected(self) -> None:
        self.store.publish(
            self.feed_lane, observation(), issued_at_utc=self.clock
        )
        self.clock += timedelta(minutes=15)
        self.store.publish(
            self.feed_lane,
            observation(shift_bars=1),
            issued_at_utc=self.clock,
        )
        first = sorted(self.root.iterdir())[0]
        first.unlink()
        with self.assertRaises(DecisionFeedError) as caught:
            self.store.fetch(self.lane)
        self.assertEqual("FEED_CHAIN_INVALID", caught.exception.reason_code)

    def test_ec9_future_issued_packet_is_rejected(self) -> None:
        with self.assertRaises(DecisionFeedError) as caught:
            self.store.publish(
                self.feed_lane,
                observation(),
                issued_at_utc=self.clock + timedelta(seconds=2),
            )
        self.assertEqual("FEED_CLOCK_INVALID", caught.exception.reason_code)

    def test_ec10_other_lane_files_are_ignored(self) -> None:
        binding = feed_binding(include_second_lane=True)
        store = SignedDecisionFeedDirectory(
            self.root,
            binding=binding,
            key_provider=lambda key_id: FEED_KEY,
            clock_provider=lambda: self.clock,
        )
        other = producer_lane(
            lane_id="usdjpy-m15-secondary",
            symbol="USDJPY",
        )
        other_token = hashlib.sha256(other.lane_id.encode("utf-8")).hexdigest()
        (self.root / f"{other_token}.{1:020d}.json").write_text(
            "not-this-lane\n",
            encoding="utf-8",
        )
        self.assertIsNone(store.fetch(self.lane))

    def test_ec11_unknown_lane_is_rejected(self) -> None:
        with self.assertRaises(DecisionFeedError) as caught:
            self.store.fetch(
                producer_lane(
                    lane_id="unknown-lane",
                    symbol="EURUSD",
                )
            )
        self.assertEqual("FEED_LANE_BINDING_MISMATCH", caught.exception.reason_code)

    def test_ec13_receipts_round_trip_and_empty_continuous_receipts_are_valid(self) -> None:
        receipt = issue_signed_session_closure_receipt(
            lane_id=self.lane.lane_id,
            symbol=self.lane.symbol,
            session_calendar_sha256=CALENDAR,
            closed_from_utc=START - timedelta(hours=2),
            closed_until_utc=START - timedelta(hours=1),
            issued_at_utc=START - timedelta(days=1),
            issuer_id="reviewed-calendar-authority",
            key_id="calendar-key-v1",
            verification_key=CALENDAR_KEY,
        )
        self.store.publish(
            self.feed_lane,
            observation(receipts=(receipt,)),
            issued_at_utc=self.clock,
        )
        reconstructed = self.store.fetch(self.lane)
        self.assertEqual((receipt,), reconstructed.session_closure_receipts)

        empty_root = self.root / "empty-receipts"
        empty_root.mkdir()
        empty = SignedDecisionFeedDirectory(
            empty_root,
            binding=self.binding,
            key_provider=lambda key_id: FEED_KEY,
            clock_provider=lambda: self.clock,
        )
        empty.publish(
            self.feed_lane, observation(), issued_at_utc=self.clock
        )
        self.assertEqual((), empty.fetch(self.lane).session_closure_receipts)

    def test_resource_constants_match_reviewed_bounds(self) -> None:
        self.assertEqual(4 * 1024 * 1024, MAXIMUM_PACKET_BYTES)
        self.assertEqual(10_000, MAXIMUM_PACKETS_PER_LANE)


if __name__ == "__main__":
    unittest.main()
