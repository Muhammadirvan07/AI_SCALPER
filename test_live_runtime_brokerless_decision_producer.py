from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import hashlib
import inspect
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest

import numpy as np
import pandas as pd

from live_runtime.brokerless_decision_producer import (
    BrokerlessDecisionProducerService,
    DecisionProducerBinding,
    DecisionProducerCursorStore,
    DecisionProducerIntegrityError,
    DecisionProducerLaneConfig,
    DecisionProducerReplayError,
    FinalizedM15DecisionInput,
    LIVE_ALLOWED,
    MAX_LOT,
    ORDER_CAPABILITY,
    SAFE_TO_DEMO_AUTO_ORDER,
    decision_producer_key_fingerprint,
    issue_decision_producer_cas_acknowledgement,
    issue_signed_session_closure_receipt,
    make_decision_producer_cas_verifier,
    make_decision_snapshot_publish_port,
    make_read_only_finalized_m15_provider,
    make_verified_session_calendar_port,
)
from live_runtime.decision_ipc import (
    ZERO_SHA256,
    DecisionIPCBinding,
    DecisionIPCEmpty,
    DecisionIPCProducer,
    DurableDecisionIPCQueue,
    decision_ipc_key_fingerprint,
    issue_decision_ipc_cas_acknowledgement,
)


UTC = timezone.utc
START = datetime(2026, 7, 20, tzinfo=UTC)
SIGNAL_INDEX = 259
BAR_CLOSED_AT = START + timedelta(minutes=15 * (SIGNAL_INDEX + 1))
QUOTE_AT = BAR_CLOSED_AT + timedelta(milliseconds=100)
MODEL = hashlib.sha256(b"decision-producer-model").hexdigest()
CONFIG = hashlib.sha256(b"decision-producer-config").hexdigest()
DATA_CONTRACT = hashlib.sha256(b"finalized-m15-contract").hexdigest()
COMMIT = "a" * 40
DECISION_KEY = b"decision-producer-ipc-key-material-v1"
IPC_CUSTODY_KEY = b"decision-producer-ipc-custody-key-v1"
CURSOR_CUSTODY_KEY = b"decision-producer-cursor-custody-key-v1"
CALENDAR_KEY = b"decision-producer-calendar-key-material-v1"
CALENDAR = hashlib.sha256(b"exact-reviewed-session-calendar-v1").hexdigest()


def decision_frame() -> pd.DataFrame:
    rows = SIGNAL_INDEX + 1
    index = np.arange(rows, dtype=float)
    close = 1.1 + 0.00002 * index + 0.0003 * np.sin(index / 7.0)
    open_price = close - 0.0001
    high = np.maximum(open_price, close) + 0.00003
    low = np.minimum(open_price, close) - 0.00003
    return pd.DataFrame(
        {
            "open_time_utc": pd.date_range(
                START, periods=rows, freq="15min", tz="UTC"
            ),
            "Open": open_price,
            "High": high,
            "Low": low,
            "Close": close,
            "is_final": [True] * rows,
        }
    )


def lane() -> DecisionProducerLaneConfig:
    return DecisionProducerLaneConfig(
        lane_id="eurusd-m15-primary",
        symbol="EURUSD",
        source_name="reviewed-finalized-m15",
        data_contract_sha256=DATA_CONTRACT,
        model_version="champion-locked-v1",
        model_artifact_sha256=MODEL,
        commit_sha=COMMIT,
        config_sha256=CONFIG,
        session_calendar_sha256=CALENDAR,
        session_calendar_issuer_id="reviewed-session-calendar",
        session_calendar_key_id="session-calendar-key-v1",
        session_calendar_key_fingerprint_sha256=(
            decision_producer_key_fingerprint(CALENDAR_KEY)
        ),
        maximum_processing_lag_ms=1_000,
    )


def decision_input(
    *,
    frame: pd.DataFrame | None = None,
    quote_at: datetime | None = None,
    bar_closed_at: datetime = BAR_CLOSED_AT,
    source_name: str = "reviewed-finalized-m15",
    source_aligned: bool = True,
    data_fresh: bool = True,
    session_calendar_sha256: str = CALENDAR,
    session_closure_receipts: tuple = (),
) -> FinalizedM15DecisionInput:
    effective_quote = (
        bar_closed_at + timedelta(milliseconds=100)
        if quote_at is None
        else quote_at
    )
    return FinalizedM15DecisionInput(
        lane_id="eurusd-m15-primary",
        symbol="EURUSD",
        source_name=source_name,
        data_contract_sha256=DATA_CONTRACT,
        session_calendar_sha256=session_calendar_sha256,
        source_aligned=source_aligned,
        data_fresh=data_fresh,
        bar_closed_at=bar_closed_at,
        first_eligible_bid=1.10500,
        first_eligible_ask=1.10502,
        first_eligible_at=effective_quote,
        finalized_bars=decision_frame() if frame is None else frame,
        session_closure_receipts=session_closure_receipts,
    )


def decision_input_with_closed_session(
    closed_from_utc: datetime,
    closed_until_utc: datetime,
) -> tuple[FinalizedM15DecisionInput, object]:
    frame = decision_frame()
    before_count = 100
    before_start = closed_from_utc - timedelta(minutes=15 * before_count)
    timestamps = list(
        pd.date_range(before_start, periods=before_count, freq="15min", tz="UTC")
    )
    timestamps.extend(
        pd.date_range(
            closed_until_utc,
            periods=len(frame) - before_count,
            freq="15min",
            tz="UTC",
        )
    )
    frame["open_time_utc"] = pd.DatetimeIndex(timestamps)
    boundary = timestamps[-1].to_pydatetime() + timedelta(minutes=15)
    receipt = issue_signed_session_closure_receipt(
        lane_id="eurusd-m15-primary",
        symbol="EURUSD",
        session_calendar_sha256=CALENDAR,
        closed_from_utc=closed_from_utc,
        closed_until_utc=closed_until_utc,
        issued_at_utc=closed_from_utc - timedelta(days=1),
        issuer_id="reviewed-session-calendar",
        key_id="session-calendar-key-v1",
        verification_key=CALENDAR_KEY,
    )
    return (
        decision_input(
            frame=frame,
            bar_closed_at=boundary,
            session_closure_receipts=(receipt,),
        ),
        receipt,
    )


def clone_decision_input(
    observation: FinalizedM15DecisionInput,
    *,
    session_calendar_sha256: str | None = None,
    session_closure_receipts: tuple | None = None,
) -> FinalizedM15DecisionInput:
    return FinalizedM15DecisionInput(
        lane_id=observation.lane_id,
        symbol=observation.symbol,
        source_name=observation.source_name,
        data_contract_sha256=observation.data_contract_sha256,
        session_calendar_sha256=(
            observation.session_calendar_sha256
            if session_calendar_sha256 is None
            else session_calendar_sha256
        ),
        source_aligned=observation.source_aligned,
        data_fresh=observation.data_fresh,
        bar_closed_at=observation.bar_closed_at,
        first_eligible_bid=observation.first_eligible_bid,
        first_eligible_ask=observation.first_eligible_ask,
        first_eligible_at=observation.first_eligible_at,
        finalized_bars=observation.finalized_bars,
        session_closure_receipts=(
            observation.session_closure_receipts
            if session_closure_receipts is None
            else session_closure_receipts
        ),
    )


class CursorCustody:
    def __init__(self) -> None:
        self.current = None
        self.reject = False
        self.reject_state = None
        self.forge_hmac = False

    def provider(self):
        return self.current

    def cas(self, expected_previous, checkpoint):
        observed = ZERO_SHA256 if self.current is None else self.current.content_sha256
        cursor_state = (
            checkpoint.lane_cursors[-1].state
            if checkpoint.lane_cursors
            else "GENESIS"
        )
        accepted = (
            not self.reject
            and self.reject_state != cursor_state
            and observed == expected_previous
        )
        if accepted:
            self.current = checkpoint
        acknowledgement = issue_decision_producer_cas_acknowledgement(
            service_id="decision-producer-v1",
            binding_sha256=checkpoint.binding_sha256,
            expected_previous_checkpoint_sha256=expected_previous,
            accepted_checkpoint_sha256=checkpoint.content_sha256,
            observed_previous_checkpoint_sha256=observed,
            accepted=accepted,
            issued_at_utc=checkpoint.issued_at_utc,
            custody_issuer_id="offhost-decision-cursor",
            custody_key_id="cursor-custody-key-v1",
            custody_key=CURSOR_CUSTODY_KEY,
        )
        if self.forge_hmac:
            acknowledgement = replace(
                acknowledgement,
                hmac_sha256=(
                    "0" * 63
                    + ("1" if acknowledgement.hmac_sha256[-1] != "1" else "2")
                ),
            )
        return acknowledgement


class IPCCustody:
    def __init__(self) -> None:
        self.current = None

    def provider(self):
        return self.current

    def exporter(self, expected_previous, checkpoint):
        observed = ZERO_SHA256 if self.current is None else self.current.content_sha256
        accepted = observed == expected_previous
        if accepted:
            self.current = checkpoint
        return issue_decision_ipc_cas_acknowledgement(
            queue_id="producer-test-queue",
            expected_previous_checkpoint_sha256=expected_previous,
            accepted_checkpoint_sha256=checkpoint.content_sha256,
            observed_previous_checkpoint_sha256=observed,
            accepted=accepted,
            issued_at_utc=checkpoint.issued_at_utc,
            custody_issuer_id="ipc-custody",
            custody_key_id="ipc-custody-key-v1",
            custody_key=IPC_CUSTODY_KEY,
        )


class Fixture:
    def __init__(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.clock = QUOTE_AT
        self.cursor_custody = CursorCustody()
        self.ipc_custody = IPCCustody()
        self.lane = lane()
        self.binding = DecisionProducerBinding(
            service_id="decision-producer-v1",
            lanes=(self.lane,),
            custody_issuer_id="offhost-decision-cursor",
            custody_key_id="cursor-custody-key-v1",
            custody_key_fingerprint_sha256=(
                decision_producer_key_fingerprint(CURSOR_CUSTODY_KEY)
            ),
        )
        self.cursor_verifier = make_decision_producer_cas_verifier(
            self.binding,
            lambda _: CURSOR_CUSTODY_KEY,
        )
        self.calendar_port = make_verified_session_calendar_port(
            self.binding,
            lambda _: CALENDAR_KEY,
        )
        self.queue_binding = DecisionIPCBinding(
            queue_id="producer-test-queue",
            account_id_sha256=hashlib.sha256(b"demo-account-alias").hexdigest(),
            server="Reviewed-Demo-Server",
            environment="DEMO",
            journal_sha256=hashlib.sha256(b"journal-binding").hexdigest(),
            commit_sha=COMMIT,
            config_sha256=CONFIG,
            model_artifact_sha256=MODEL,
            data_contract_sha256=DATA_CONTRACT,
            decision_issuer_id="decision-producer-v1",
            decision_key_id="decision-key-v1",
            decision_key_fingerprint_sha256=decision_ipc_key_fingerprint(
                DECISION_KEY
            ),
            custody_issuer_id="ipc-custody",
            custody_key_id="ipc-custody-key-v1",
            custody_key_fingerprint_sha256=decision_ipc_key_fingerprint(
                IPC_CUSTODY_KEY
            ),
            permit_key_id="downstream-permit-key-v1",
            permit_key_fingerprint_sha256=hashlib.sha256(
                b"downstream-public-fingerprint"
            ).hexdigest(),
        )
        self.queue = DurableDecisionIPCQueue.provision(
            self.root / "decision-ipc.sqlite3",
            binding=self.queue_binding,
            decision_key_provider=lambda _: DECISION_KEY,
            custody_key_provider=lambda _: IPC_CUSTODY_KEY,
            external_checkpoint_provider=self.ipc_custody.provider,
            checkpoint_exporter=self.ipc_custody.exporter,
            clock_provider=lambda: self.clock,
        )
        self.store = DecisionProducerCursorStore.provision(
            self.root / "decision-producer.sqlite3",
            binding=self.binding,
            external_checkpoint_provider=self.cursor_custody.provider,
            checkpoint_cas=self.cursor_custody.cas,
            acknowledgement_verifier=self.cursor_verifier,
            clock_provider=lambda: self.clock,
        )
        self.current_input = decision_input()

    def service(self) -> BrokerlessDecisionProducerService:
        input_port = make_read_only_finalized_m15_provider(
            lambda selected_lane: self.current_input
        )
        publish_port = make_decision_snapshot_publish_port(
            DecisionIPCProducer(self.queue)
        )
        return BrokerlessDecisionProducerService(
            binding=self.binding,
            input_port=input_port,
            calendar_port=self.calendar_port,
            publish_port=publish_port,
            cursor_store=self.store,
            clock_provider=lambda: self.clock,
        )

    def close(self) -> None:
        self.temp.cleanup()


class BrokerlessDecisionProducerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = Fixture()

    def tearDown(self) -> None:
        self.fixture.close()

    def test_valid_input_publishes_exact_snapshot_once_and_survives_restart(self):
        service = self.fixture.service()
        first = service.run_cycle()
        self.assertEqual("PUBLISHED", first.lanes[0].status)
        self.assertEqual(1, self.fixture.queue.current_checkpoint().published_count)

        verified = self.fixture.queue.consume_next(
            consumed_at_utc=self.fixture.clock + timedelta(milliseconds=1)
        )
        snapshot = verified.envelope.decision
        self.assertEqual("EURUSD", snapshot.symbol)
        self.assertEqual("M15", snapshot.timeframe)
        self.assertEqual(first.lanes[0].decision_snapshot_sha256, snapshot.content_sha256)

        reopened = DecisionProducerCursorStore(
            self.fixture.root / "decision-producer.sqlite3",
            binding=self.fixture.binding,
            external_checkpoint_provider=self.fixture.cursor_custody.provider,
            checkpoint_cas=self.fixture.cursor_custody.cas,
            acknowledgement_verifier=self.fixture.cursor_verifier,
            clock_provider=lambda: self.fixture.clock,
        )
        self.fixture.store = reopened
        second = self.fixture.service().run_cycle()
        self.assertEqual("ALREADY_PROCESSED", second.lanes[0].status)
        self.assertEqual(1, self.fixture.queue.current_checkpoint().published_count)

    def test_ports_are_slot_only_immutable_and_expose_no_mutation_capability(self):
        read_port = make_read_only_finalized_m15_provider(lambda _: None)
        calendar_port = self.fixture.calendar_port
        cursor_verifier = self.fixture.cursor_verifier
        publish_port = make_decision_snapshot_publish_port(
            DecisionIPCProducer(self.fixture.queue)
        )
        for port in (read_port, publish_port, calendar_port, cursor_verifier):
            self.assertFalse(hasattr(port, "__dict__"))
            for forbidden in (
                "execute",
                "adapter",
                "permit",
                "order_send",
                "account",
                "queue",
                "producer",
            ):
                self.assertFalse(hasattr(port, forbidden), forbidden)
            with self.assertRaises(AttributeError):
                port.extra = object()

        source = inspect.getsource(
            __import__("live_runtime.brokerless_decision_producer", fromlist=["*"])
        )
        self.assertNotIn("MetaTrader5", source)
        self.assertNotIn("order_send", source)
        self.assertNotIn("order_check", source)
        self.assertNotIn("initialize(", source)
        self.assertEqual("DISABLED", ORDER_CAPABILITY)
        self.assertIs(False, LIVE_ALLOWED)
        self.assertIs(False, SAFE_TO_DEMO_AUTO_ORDER)
        self.assertEqual(0.01, MAX_LOT)

    def test_lane_requires_an_exact_full_commit_hash(self):
        values = {
            "lane_id": "eurusd-m15-primary",
            "symbol": "EURUSD",
            "source_name": "reviewed-finalized-m15",
            "data_contract_sha256": DATA_CONTRACT,
            "model_version": "champion-locked-v1",
            "model_artifact_sha256": MODEL,
            "config_sha256": CONFIG,
            "session_calendar_sha256": CALENDAR,
            "session_calendar_issuer_id": "reviewed-session-calendar",
            "session_calendar_key_id": "session-calendar-key-v1",
            "session_calendar_key_fingerprint_sha256": (
                decision_producer_key_fingerprint(CALENDAR_KEY)
            ),
        }
        for invalid in ("a" * 7, "a" * 39, "a" * 41, "z" * 40):
            with self.subTest(invalid=invalid):
                with self.assertRaises(ValueError):
                    DecisionProducerLaneConfig(commit_sha=invalid, **values)

    def test_qc_source_and_time_drift_hold_without_publication(self):
        cases = []
        non_contiguous = decision_frame().drop(index=10).reset_index(drop=True)
        cases.append(decision_input(frame=non_contiguous))
        invalid_ohlc = decision_frame()
        invalid_ohlc.loc[20, "High"] = invalid_ohlc.loc[20, "Low"] - 1
        cases.append(decision_input(frame=invalid_ohlc))
        cases.append(decision_input(source_name="unexpected-source"))
        cases.append(decision_input(source_aligned=False))
        cases.append(decision_input(data_fresh=False))
        cases.append(
            decision_input(quote_at=BAR_CLOSED_AT + timedelta(seconds=11))
        )
        for observation in cases:
            with self.subTest(observation=observation.source_name):
                self.fixture.current_input = observation
                result = self.fixture.service().run_cycle()
                self.assertEqual("HOLD", result.lanes[0].status)
                self.assertEqual(
                    0, self.fixture.queue.current_checkpoint().published_count
                )

    def test_exact_signed_weekend_closure_keeps_260_market_bars_usable(self):
        observation, _ = decision_input_with_closed_session(
            datetime(2026, 7, 24, 21, 0, tzinfo=UTC),
            datetime(2026, 7, 26, 21, 0, tzinfo=UTC),
        )
        self.fixture.current_input = observation
        self.fixture.clock = observation.first_eligible_at
        result = self.fixture.service().run_cycle()
        self.assertEqual("PUBLISHED", result.lanes[0].status)
        self.assertEqual(1, self.fixture.queue.current_checkpoint().published_count)

    def test_exact_signed_holiday_closure_is_accepted_without_padding_bars(self):
        observation, _ = decision_input_with_closed_session(
            datetime(2026, 7, 22, 0, 0, tzinfo=UTC),
            datetime(2026, 7, 23, 0, 0, tzinfo=UTC),
        )
        self.fixture.current_input = observation
        self.fixture.clock = observation.first_eligible_at
        result = self.fixture.service().run_cycle()
        self.assertEqual("PUBLISHED", result.lanes[0].status)

    def test_dst_weekend_uses_exact_signed_utc_interval_not_a_weekend_heuristic(self):
        closed_from = datetime(2026, 10, 23, 21, 0, tzinfo=UTC)
        closed_until = datetime(2026, 10, 25, 22, 0, tzinfo=UTC)
        self.assertEqual(timedelta(hours=49), closed_until - closed_from)
        observation, _ = decision_input_with_closed_session(
            closed_from,
            closed_until,
        )
        self.fixture.current_input = observation
        self.fixture.clock = observation.first_eligible_at
        result = self.fixture.service().run_cycle()
        self.assertEqual("PUBLISHED", result.lanes[0].status)

    def test_missing_extra_tampered_or_cross_calendar_gap_proof_holds(self):
        observation, receipt = decision_input_with_closed_session(
            datetime(2026, 7, 24, 21, 0, tzinfo=UTC),
            datetime(2026, 7, 26, 21, 0, tzinfo=UTC),
        )
        cases = (
            clone_decision_input(observation, session_closure_receipts=()),
            clone_decision_input(
                observation,
                session_closure_receipts=(
                    replace(receipt, hmac_sha256="f" * 64),
                ),
            ),
            clone_decision_input(
                observation, session_calendar_sha256="e" * 64
            ),
            decision_input(session_closure_receipts=(receipt,)),
        )
        for candidate in cases:
            with self.subTest(candidate=id(candidate)):
                self.fixture.current_input = candidate
                self.fixture.clock = candidate.first_eligible_at
                result = self.fixture.service().run_cycle()
                self.assertEqual("HOLD", result.lanes[0].status)
                self.assertEqual(
                    0, self.fixture.queue.current_checkpoint().published_count
                )

    def test_same_bar_changed_data_is_a_fatal_fork(self):
        self.fixture.service().run_cycle()
        changed = decision_frame()
        changed.loc[40, "Close"] += 0.00001
        changed.loc[40, "High"] += 0.00001
        self.fixture.current_input = decision_input(frame=changed)
        with self.assertRaises(DecisionProducerReplayError):
            self.fixture.service().run_cycle()

    def test_restart_recovers_publish_before_cursor_advance(self):
        self.fixture.cursor_custody.reject_state = "PUBLISHED"
        with self.assertRaises(DecisionProducerIntegrityError):
            self.fixture.service().run_cycle()
        self.assertEqual(1, self.fixture.queue.current_checkpoint().published_count)
        self.assertEqual(1, self.fixture.store.current_checkpoint().sequence)
        self.assertEqual(
            "PREPARED",
            self.fixture.store.current_checkpoint().lane_cursors[0].state,
        )

        self.fixture.cursor_custody.reject_state = None
        result = self.fixture.service().run_cycle()
        self.assertEqual("PUBLISHED_RECOVERED", result.lanes[0].status)
        self.assertEqual(1, self.fixture.queue.current_checkpoint().published_count)
        self.assertEqual(2, self.fixture.store.current_checkpoint().sequence)
        self.assertEqual(
            "PUBLISHED",
            self.fixture.store.current_checkpoint().lane_cursors[0].state,
        )

    def test_external_successor_is_imported_after_local_append_interruption(self):
        self.fixture.cursor_custody.forge_hmac = True
        with self.assertRaises(DecisionProducerIntegrityError):
            self.fixture.service().run_cycle()
        self.assertEqual(0, self.fixture.store.local_checkpoint().sequence)
        self.assertEqual(1, self.fixture.cursor_custody.current.sequence)

        self.fixture.cursor_custody.forge_hmac = False
        reopened = DecisionProducerCursorStore(
            self.fixture.root / "decision-producer.sqlite3",
            binding=self.fixture.binding,
            external_checkpoint_provider=self.fixture.cursor_custody.provider,
            checkpoint_cas=self.fixture.cursor_custody.cas,
            acknowledgement_verifier=self.fixture.cursor_verifier,
            clock_provider=lambda: self.fixture.clock,
        )
        self.assertEqual(1, reopened.current_checkpoint().sequence)
        self.assertEqual(1, reopened.local_checkpoint().sequence)

        changed = decision_frame()
        changed.loc[40, "Close"] += 0.00001
        changed.loc[40, "High"] += 0.00001
        self.fixture.store = reopened
        self.fixture.current_input = decision_input(frame=changed)
        with self.assertRaises(DecisionProducerReplayError):
            self.fixture.service().run_cycle()

    def test_cas_rejection_and_local_tamper_fail_closed(self):
        self.fixture.cursor_custody.reject = True
        with self.assertRaises(DecisionProducerIntegrityError):
            self.fixture.service().run_cycle()
        self.assertEqual(0, self.fixture.store.local_checkpoint().sequence)

        database = self.fixture.root / "decision-producer.sqlite3"
        connection = sqlite3.connect(database)
        connection.execute(
            "UPDATE decision_producer_checkpoints SET checkpoint_sha256=? WHERE sequence=0",
            ("f" * 64,),
        )
        connection.commit()
        connection.close()
        with self.assertRaises(DecisionProducerIntegrityError):
            DecisionProducerCursorStore(
                database,
                binding=self.fixture.binding,
                external_checkpoint_provider=self.fixture.cursor_custody.provider,
                checkpoint_cas=self.fixture.cursor_custody.cas,
                acknowledgement_verifier=self.fixture.cursor_verifier,
                clock_provider=lambda: self.fixture.clock,
            )

    def test_arbitrary_true_verifier_forged_ack_and_external_rollback_are_denied(self):
        with self.assertRaisesRegex(TypeError, "sealed cursor CAS verifier"):
            DecisionProducerCursorStore(
                self.fixture.root / "decision-producer.sqlite3",
                binding=self.fixture.binding,
                external_checkpoint_provider=self.fixture.cursor_custody.provider,
                checkpoint_cas=self.fixture.cursor_custody.cas,
                acknowledgement_verifier=lambda _: True,
                clock_provider=lambda: self.fixture.clock,
            )

        genesis = self.fixture.store.local_checkpoint()
        self.fixture.cursor_custody.forge_hmac = True
        with self.assertRaisesRegex(
            DecisionProducerIntegrityError,
            "unauthenticated",
        ):
            self.fixture.service().run_cycle()
        self.assertEqual(0, self.fixture.store.local_checkpoint().sequence)

        self.fixture.cursor_custody.forge_hmac = False
        reopened = DecisionProducerCursorStore(
            self.fixture.root / "decision-producer.sqlite3",
            binding=self.fixture.binding,
            external_checkpoint_provider=self.fixture.cursor_custody.provider,
            checkpoint_cas=self.fixture.cursor_custody.cas,
            acknowledgement_verifier=self.fixture.cursor_verifier,
            clock_provider=lambda: self.fixture.clock,
        )
        self.fixture.store = reopened
        self.fixture.service().run_cycle()
        self.fixture.cursor_custody.current = genesis
        with self.assertRaises(DecisionProducerReplayError):
            self.fixture.store.current_checkpoint()

    def test_post_construction_truthy_verifier_replacement_is_also_denied(self):
        self.fixture.store.acknowledgement_verifier = lambda _: True
        with self.assertRaisesRegex(
            DecisionProducerIntegrityError,
            "verifier capability is invalid",
        ):
            self.fixture.service().run_cycle()
        self.assertEqual(0, self.fixture.store.local_checkpoint().sequence)

    def test_runner_is_bounded_or_requires_continuous_stop_predicate(self):
        self.fixture.current_input = None
        service = self.fixture.service()
        bounded = service.run(max_cycles=3, poll_seconds=0, sleeper=lambda _: None)
        self.assertEqual(3, len(bounded))
        self.assertTrue(all(item.lanes[0].status == "NO_INPUT" for item in bounded))
        with self.assertRaisesRegex(ValueError, "stop predicate"):
            service.run(max_cycles=None, stop_requested=None)

        calls = {"count": 0}

        def stop() -> bool:
            calls["count"] += 1
            return calls["count"] > 2

        continuous = service.run(
            max_cycles=None,
            stop_requested=stop,
            poll_seconds=0,
            sleeper=lambda _: None,
        )
        self.assertEqual(2, len(continuous))

    def test_cli_is_validate_only_and_requires_explicit_acknowledgement(self):
        script = Path(__file__).parent / "run_brokerless_decision_producer.py"
        rejected = subprocess.run(
            [sys.executable, "-B", str(script), "--validate-only"],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertNotEqual(0, rejected.returncode)
        accepted = subprocess.run(
            [
                sys.executable,
                "-B",
                str(script),
                "--validate-only",
                "--acknowledge-decision-only",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(0, accepted.returncode, accepted.stderr)
        self.assertIn("BROKERLESS_DECISION_PRODUCER_VALID", accepted.stdout)
        self.assertIn("Broker mutation capability: DISABLED", accepted.stdout)


if __name__ == "__main__":
    unittest.main()
