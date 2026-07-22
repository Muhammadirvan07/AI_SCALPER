import hashlib
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from live_runtime.contracts import (
    BrokerSpec,
    TradeIntent,
    _mint_decision_snapshot,
    _mint_execution_receipt,
    canonical_sha256,
)
from live_runtime.journal import (
    DuplicateIntentError,
    ExecutionJournal,
    ExecutorFenceError,
    InvalidTransitionError,
    KillSwitchLatchedError,
    SubmissionLimitError,
)
from live_runtime.mt5_adapter import (
    _mint_mt5_preflight,
    _mint_mt5_submission_guard,
)
from live_runtime.permit import (
    KillSwitchResetPermit,
    authorize_kill_switch_reset,
    reset_reason_sha256,
)
from live_runtime.risk import RiskContext, evaluate_risk
from live_runtime.reconciliation import reconcile_broker_state
from test_fixtures.execution_receipt import mint_submission_consumption_proof


UTC = timezone.utc
RESET_SECRET_A = "journal-reset-approver-a-secret-at-least-32-bytes"
RESET_SECRET_B = "journal-reset-approver-b-secret-at-least-32-bytes"
RESET_KEY_ID_A = "risk-reset-key-v1"
RESET_KEY_ID_B = "operations-reset-key-v1"
MAGIC = 260615


class ExecutionJournalTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.path = Path(self.tempdir.name) / "journal.sqlite"
        self.now = datetime(2026, 7, 15, 12, 0, 1, tzinfo=UTC)
        self.clock_now = self.now
        self.submission_evidence = {}
        self.submission_proofs = {}
        self.journal = ExecutionJournal(
            self.path,
            clock_provider=lambda: self.clock_now,
        )

    def create(self, intent_id="intent-1", *, decision_id=None):
        return self.journal.create_intent(
            intent_id=intent_id,
            decision_id=decision_id or f"decision-{intent_id}",
            symbol="xauusd",
            payload={
                "lot": 0.01,
                "mode": "SHADOW",
                "intent": {
                    "account_id": "account-alias",
                    "server": "Broker-Demo",
                    "symbol": "XAUUSD",
                    "requested_lot": 0.01,
                },
            },
            created_at=self.now,
        )

    def broker_spec(self, when: datetime) -> BrokerSpec:
        return BrokerSpec(
            account_id="account-alias",
            broker_legal_name="Example Broker Ltd",
            server="Broker-Demo",
            environment="DEMO",
            symbol="EURUSD",
            broker_symbol="EURUSD.a",
            account_currency="USD",
            digits=5,
            point=0.00001,
            tick_size=0.00001,
            tick_value=1.0,
            contract_size=100000.0,
            volume_min=0.01,
            volume_max=50.0,
            volume_step=0.01,
            stops_level_points=0,
            freeze_level_points=0,
            margin_per_lot=1.0,
            session_calendar_sha256="a" * 64,
            captured_at=when,
        )

    def typed_submission_evidence(self, intent_id: str, when: datetime):
        bar_closed = when.replace(second=0, microsecond=0)
        decision = _mint_decision_snapshot(
            decision_run_id=f"run-{intent_id}",
            symbol="EURUSD",
            side="BUY",
            strategy="TEST",
            score=1,
            score_components={"test": 1},
            entry_reference=1.1,
            stop_loss=1.09999,
            take_profit=1.10002,
            model_version="test-v1",
            model_artifact_sha256="b" * 64,
            commit_sha="c" * 40,
            config_sha256="d" * 64,
            data_sha256="e" * 64,
            source_name="BROKER_TEST",
            source_aligned=True,
            data_fresh=True,
            bar_closed_at=bar_closed,
            created_at=when,
        )
        intent = TradeIntent(
            mode="DEMO",
            account_id="account-alias",
            server="Broker-Demo",
            symbol="EURUSD",
            side="BUY",
            requested_lot=0.01,
            entry_reference=1.1,
            stop_loss=1.09999,
            take_profit=1.10002,
            created_at=when,
            expires_at=bar_closed + timedelta(seconds=10),
            decision=decision,
            permit_id="test-permit",
        )
        broker = self.broker_spec(when)
        risk = evaluate_risk(
            intent,
            broker,
            RiskContext(
                evaluated_at=when,
                mode="DEMO",
                account_id="account-alias",
                server="Broker-Demo",
                equity=100.0,
                daily_start_equity=100.0,
                weekly_start_equity=100.0,
                high_water_equity=100.0,
                daily_pnl_cash=0.0,
                weekly_pnl_cash=0.0,
                open_position_count=0,
                entries_today=0,
                consecutive_losses=0,
                loss_latch_active=False,
                reserved_symbols=(),
                current_spread_points=1.0,
                median_spread_points=1.0,
                p95_spread_points=2.0,
                estimated_slippage_points=0.0,
                p95_slippage_points=1.0,
                news_clear=True,
                rollover_clear=True,
                data_fresh=True,
                source_aligned=True,
                permit_valid=True,
            ),
        )
        self.assertTrue(risk.allowed, risk.reason_codes)
        request = {
            "symbol": "EURUSD.a",
            "volume": 0.01,
            "price": 1.1,
            "sl": 1.09999,
            "tp": 1.10002,
        }
        preflight = _mint_mt5_preflight(
            intent_id=intent_id,
            passed=True,
            reason="OK",
            broker_symbol="EURUSD.a",
            intent_sha256=intent.content_sha256,
            broker_spec_sha256=broker.content_sha256,
            request=request,
            request_sha256=canonical_sha256(request),
            broker_retcode="10009",
            checked_at_utc=when,
            valid_until_utc=when + timedelta(seconds=3),
            current_bid=1.09999,
            current_ask=1.1,
            tick_time_utc=when,
            allowed_deviation_points=1,
            estimated_stop_risk_cash=0.01,
            estimated_margin_cash=0.01,
        )
        guard = _mint_mt5_submission_guard(
            intent_id=intent_id,
            account_id="account-alias",
            server="Broker-Demo",
            symbol="EURUSD",
            account_equity=100.0,
            active_order_count=0,
            active_position_count=0,
            broker_spec_sha256=broker.content_sha256,
            checked_at_utc=when,
        )
        return intent, broker, risk, preflight, guard

    def execution_receipt(self, intent_id: str, state: str):
        record = self.journal.get_intent(intent_id)
        intent_payload = record.payload["intent"]
        proof = self.submission_proofs.get(intent_id)
        if proof is None:
            with self.journal._reader() as connection:
                executor = connection.execute(
                    "SELECT owner_id, fence_token FROM executor_lease WHERE singleton=1"
                ).fetchone()
            self.assertIsNotNone(executor)
            gate_hash = hashlib.sha256(f"gate:{intent_id}".encode()).hexdigest()
            authorization_hash = hashlib.sha256(
                f"authorization:{intent_id}".encode()
            ).hexdigest()
            request_hash = hashlib.sha256(f"request:{intent_id}".encode()).hexdigest()
            with self.journal.final_submission_guard(
                intent_id,
                owner_id=executor["owner_id"],
                fence_token=int(executor["fence_token"]),
                execution_gate_sha256=gate_hash,
                authorization_sha256=authorization_hash,
                broker_request_sha256=request_hash,
                occurred_at=self.clock_now,
            ) as submission_lease:
                proof = submission_lease.consume(
                    journal_sha256=self.journal.journal_sha256,
                    intent_id=intent_id,
                    execution_gate_sha256=gate_hash,
                    authorization_sha256=authorization_hash,
                    broker_request_sha256=request_hash,
                )
            self.submission_proofs[intent_id] = proof
        filled = (
            0.0
            if state in {"ACKNOWLEDGED", "REJECTED", "UNCERTAIN"}
            else 0.01
        )
        return _mint_execution_receipt(
            submission_proof=proof,
            intent_id=intent_id,
            state=state,
            account_id=intent_payload["account_id"],
            server=intent_payload["server"],
            symbol=intent_payload["symbol"],
            requested_volume=intent_payload["requested_lot"],
            filled_volume=filled,
            received_at=self.clock_now,
            broker_retcode="10006" if state == "REJECTED" else "10009",
            message=state.lower(),
            order_ticket=None if state == "REJECTED" else "42",
            deal_ticket="84" if filled else None,
            fill_price=1.1 if filled else None,
        )

    def test_intent_is_idempotent_but_payload_reuse_is_rejected(self):
        self.assertEqual(4, self.journal.schema_version())
        self.assertTrue(self.journal.integrity_check())
        first = self.create()
        second = self.create()
        self.assertEqual(first, second)
        self.assertEqual(first.symbol, "XAUUSD")
        with self.assertRaises(DuplicateIntentError):
            self.journal.create_intent(
                intent_id="intent-1",
                decision_id="decision-intent-1",
                symbol="XAUUSD",
                payload={"lot": 0.02},
                created_at=self.now,
            )

    def test_one_decision_can_create_only_one_durable_intent(self):
        first = self.create("intent-1", decision_id="decision-shared")
        second = self.journal.create_intent(
            intent_id="intent-2",
            decision_id="decision-shared",
            symbol="XAUUSD",
            payload={"lot": 0.01, "mode": "SHADOW", "retry": True},
            created_at=self.now,
        )
        self.assertEqual(first, second)
        self.assertIsNone(self.journal.get_intent("intent-2"))

    def test_replacing_database_at_same_path_rotates_journal_identity(self):
        original_identity = self.journal.journal_sha256
        self.create()
        backup_path = self.path.with_suffix(".replaced.sqlite")
        self.path.replace(backup_path)
        replacement = ExecutionJournal(
            self.path,
            clock_provider=lambda: self.clock_now,
        )
        self.assertNotEqual(original_identity, replacement.journal_sha256)
        self.assertIsNone(replacement.get_intent("intent-1"))

    def test_state_machine_rejects_skips_and_records_receipts(self):
        self.create("skip-intent")
        with self.assertRaises(InvalidTransitionError):
            self.journal.transition("skip-intent", "FILLED")

        token = self.journal.claim_executor(
            "executor-state-machine", now=self.now, lease_seconds=60
        )
        self._prepare_reservation("intent-1", token, self.now)
        self.journal.reserve_submission(
            "intent-1",
            owner_id="executor-state-machine",
            fence_token=token,
            submission_evidence=self.submission_evidence["intent-1"],
            occurred_at=self.now,
        )
        self.journal.record_execution_receipt(
            self.execution_receipt("intent-1", "FILLED"),
            occurred_at=self.now,
        )
        reconcile_broker_state(
            self.journal,
            broker_orders=[],
            broker_positions=[],
            broker_deals=[
                {
                    "ticket": 81,
                    "comment": "AIS:intent-1",
                    "magic": MAGIC,
                    "entry": 1,
                    "symbol": "EURUSD.a",
                    "type": 1,
                    "volume": 0.01,
                    "time_msc": int(self.now.timestamp() * 1000),
                }
            ],
            magic_number=MAGIC,
            occurred_at=self.now,
        )
        self.journal.append_receipt(
            "intent-1", "BROKER_RESULT", {"retcode": 10009}, self.now
        )
        record = self.journal.get_intent("intent-1")
        self.assertEqual(record.state, "CLOSED")
        self.assertEqual(
            [item["to_state"] for item in self.journal.transition_history("intent-1")],
            [
                "CREATED",
                "RISK_APPROVED",
                "PREFLIGHT_PASSED",
                "SUBMITTING",
                "FILLED",
                "CLOSED",
            ],
        )

    def test_sealed_execution_receipt_allows_short_persistence_delay(self):
        token = self.journal.claim_executor(
            "executor-receipt-delay", now=self.now, lease_seconds=60
        )
        self._prepare_reservation("intent-1", token, self.now)
        self.journal.reserve_submission(
            "intent-1",
            owner_id="executor-receipt-delay",
            fence_token=token,
            submission_evidence=self.submission_evidence["intent-1"],
            occurred_at=self.now,
        )
        receipt = self.execution_receipt("intent-1", "FILLED")
        self.clock_now = self.now + timedelta(seconds=1)

        record = self.journal.record_execution_receipt(receipt)

        self.assertEqual("FILLED", record.state)
        self.assertEqual(
            self.clock_now.isoformat(),
            self.journal.transition_history("intent-1")[-1]["occurred_at_utc"],
        )

    def test_execution_receipt_requires_consumption_in_the_same_journal(self):
        token = self.journal.claim_executor(
            "executor-cross-journal", now=self.now, lease_seconds=60
        )
        self._prepare_reservation("intent-1", token, self.now)
        self.journal.reserve_submission(
            "intent-1",
            owner_id="executor-cross-journal",
            fence_token=token,
            submission_evidence=self.submission_evidence["intent-1"],
            occurred_at=self.now,
        )
        # The proof is genuinely sealed and claims the same public journal
        # identity, but its authorization was consumed in a different SQLite
        # incarnation.  Hash assertions alone must not be sufficient.
        foreign_proof = mint_submission_consumption_proof(
            intent_id="intent-1",
            consumed_at=self.now,
            journal_sha256=self.journal.journal_sha256,
        )
        receipt = _mint_execution_receipt(
            submission_proof=foreign_proof,
            intent_id="intent-1",
            state="REJECTED",
            account_id="account-alias",
            server="Broker-Demo",
            symbol="EURUSD",
            requested_volume=0.01,
            filled_volume=0.0,
            received_at=self.now,
            broker_retcode="10006",
            message="forged local outcome",
        )
        with self.assertRaisesRegex(
            InvalidTransitionError,
            "matching authorization consumption",
        ):
            self.journal.record_execution_receipt(receipt, occurred_at=self.now)

    def test_sealed_execution_receipt_rejects_future_or_stale_time(self):
        token = self.journal.claim_executor(
            "executor-receipt-time", now=self.now, lease_seconds=60
        )
        self._prepare_reservation("intent-1", token, self.now)
        self.journal.reserve_submission(
            "intent-1",
            owner_id="executor-receipt-time",
            fence_token=token,
            submission_evidence=self.submission_evidence["intent-1"],
            occurred_at=self.now,
        )
        stale_receipt = self.execution_receipt("intent-1", "FILLED")
        self.clock_now = self.now + timedelta(seconds=6)
        with self.assertRaisesRegex(ValueError, "not journaled promptly"):
            self.journal.record_execution_receipt(stale_receipt)

        self.clock_now = self.now
        future_receipt = _mint_execution_receipt(
            submission_proof=self.submission_proofs["intent-1"],
            intent_id="intent-1",
            state="FILLED",
            account_id="account-alias",
            server="Broker-Demo",
            symbol="EURUSD",
            requested_volume=0.01,
            filled_volume=0.01,
            received_at=self.now + timedelta(seconds=1),
            broker_retcode="10009",
            message="filled",
            order_ticket="42",
            deal_ticket="84",
            fill_price=1.1,
        )
        with self.assertRaisesRegex(ValueError, "in the future"):
            self.journal.record_execution_receipt(future_receipt)

    def test_uncertain_state_can_only_be_resolved_by_reconciliation_states(self):
        token = self.journal.claim_executor(
            "executor-uncertain", now=self.now, lease_seconds=60
        )
        self._prepare_reservation("intent-1", token, self.now)
        self.journal.reserve_submission(
            "intent-1",
            owner_id="executor-uncertain",
            fence_token=token,
            submission_evidence=self.submission_evidence["intent-1"],
            occurred_at=self.now,
        )
        self.journal.transition("intent-1", "UNCERTAIN", occurred_at=self.now)
        with self.assertRaises(InvalidTransitionError):
            self.journal.transition("intent-1", "SUBMITTING")
        reconcile_broker_state(
            self.journal,
            broker_orders=[],
            broker_positions=[
                {
                    "ticket": 42,
                    "comment": "AIS:intent-1",
                    "magic": MAGIC,
                    "symbol": "EURUSD.a",
                    "type": 0,
                    "volume": 0.01,
                    "sl": 1.09999,
                    "tp": 1.10002,
                }
            ],
            broker_deals=[],
            magic_number=MAGIC,
            occurred_at=self.now,
        )
        resolved = self.journal.get_intent("intent-1")
        self.assertEqual(resolved.broker_position_ticket, "42")
        self.assertTrue(resolved.protective_sl_tp_confirmed)

    def test_single_executor_fence_survives_restart(self):
        token = self.journal.claim_executor("executor-a", now=self.now, lease_seconds=15)
        self.journal.assert_executor_fence("executor-a", token, now=self.now)
        restarted = ExecutionJournal(
            self.path,
            clock_provider=lambda: self.clock_now,
        )
        self.clock_now = self.now + timedelta(seconds=5)
        with self.assertRaises(ExecutorFenceError):
            restarted.claim_executor(
                "executor-b", now=self.now + timedelta(seconds=5), lease_seconds=15
            )
        self.clock_now = self.now + timedelta(seconds=16)
        next_token = restarted.claim_executor(
            "executor-b", now=self.now + timedelta(seconds=16), lease_seconds=15
        )
        self.assertGreater(next_token, token)
        with self.assertRaises(ExecutorFenceError):
            restarted.assert_executor_fence(
                "executor-a", token, now=self.now + timedelta(seconds=16)
            )

    def test_reclaim_by_same_owner_rotates_fence_and_atomic_reservation_checks_kill(self):
        token = self.journal.claim_executor(
            "executor-a", now=self.now, lease_seconds=30
        )
        self.clock_now = self.now + timedelta(seconds=1)
        replacement = self.journal.claim_executor(
            "executor-a", now=self.now + timedelta(seconds=1), lease_seconds=30
        )
        self.assertGreater(replacement, token)
        with self.assertRaises(ExecutorFenceError):
            self.journal.assert_executor_fence(
                "executor-a", token, now=self.now + timedelta(seconds=1)
            )
        current = self.now + timedelta(seconds=1)
        self._prepare_reservation("intent-1", replacement, current)
        self.journal.latch_kill_switch(
            "incident",
            source="TEST",
            occurred_at=current,
        )
        with self.assertRaises(KillSwitchLatchedError):
            self.journal.reserve_submission(
                "intent-1",
                owner_id="executor-a",
                fence_token=replacement,
                submission_evidence=self.submission_evidence["intent-1"],
                occurred_at=current,
            )
        self.assertEqual("PREFLIGHT_PASSED", self.journal.get_intent("intent-1").state)

    def test_same_state_reconciliation_evidence_updates_protection(self):
        token = self.journal.claim_executor(
            "executor-reconciliation", now=self.now, lease_seconds=60
        )
        self._prepare_reservation("intent-1", token, self.now)
        self.journal.reserve_submission(
            "intent-1",
            owner_id="executor-reconciliation",
            fence_token=token,
            submission_evidence=self.submission_evidence["intent-1"],
            occurred_at=self.now,
        )
        self.journal.record_execution_receipt(
            self.execution_receipt("intent-1", "FILLED"),
            occurred_at=self.now,
        )
        reconcile_broker_state(
            self.journal,
            broker_orders=[],
            broker_positions=[
                {
                    "ticket": 42,
                    "comment": "AIS:intent-1",
                    "magic": MAGIC,
                    "symbol": "EURUSD.a",
                    "type": 0,
                    "volume": 0.01,
                    "sl": 1.09999,
                    "tp": 1.10002,
                }
            ],
            broker_deals=[],
            magic_number=MAGIC,
            occurred_at=self.now,
        )
        updated = self.journal.get_intent("intent-1")
        self.assertEqual("42", updated.broker_position_ticket)
        self.assertTrue(updated.protective_sl_tp_confirmed)
        self.assertEqual(
            ["FILLED", "FILLED"],
            [item["to_state"] for item in self.journal.transition_history("intent-1")][-2:],
        )

    def test_submission_reservation_requires_bound_risk_preflight_and_guard_receipts(self):
        token = self.journal.claim_executor(
            "executor-a", now=self.now, lease_seconds=30
        )
        self.create()
        self.journal.transition("intent-1", "RISK_APPROVED", occurred_at=self.now)
        self.journal.transition("intent-1", "PREFLIGHT_PASSED", occurred_at=self.now)
        with self.assertRaises(TypeError):
            self.journal.reserve_submission(
                "intent-1",
                owner_id="executor-a",
                fence_token=token,
                submission_evidence=None,
                occurred_at=self.now,
            )
        for receipt_type in (
            "RISK_DECISION",
            "MT5_PREFLIGHT",
            "SUBMISSION_GUARD",
        ):
            with self.assertRaises(PermissionError):
                self.journal.append_receipt(
                    "intent-1",
                    receipt_type,
                    {"forged": True},
                    self.now,
                )
        self.assertEqual("PREFLIGHT_PASSED", self.journal.get_intent("intent-1").state)

    def test_generic_transition_cannot_bypass_submission_reservation_or_latched_kill(self):
        token = self.journal.claim_executor(
            "executor-reserve-only", now=self.now, lease_seconds=60
        )
        self._prepare_reservation("intent-direct", token, self.now)
        history_before = self.journal.transition_history("intent-direct")

        with self.assertRaisesRegex(
            InvalidTransitionError,
            r"SUBMITTING is reserve-only; use reserve_submission\(\)",
        ):
            self.journal.transition(
                "intent-direct",
                "SUBMITTING",
                expected_state="PREFLIGHT_PASSED",
                occurred_at=self.now,
            )
        self.assertEqual(
            "PREFLIGHT_PASSED",
            self.journal.get_intent("intent-direct").state,
        )
        self.assertEqual(
            history_before,
            self.journal.transition_history("intent-direct"),
        )

        self.journal.latch_kill_switch(
            "incident",
            source="TEST",
            occurred_at=self.now,
        )
        with self.assertRaisesRegex(InvalidTransitionError, "reserve-only"):
            self.journal.transition(
                "intent-direct",
                "SUBMITTING",
                occurred_at=self.now,
            )
        with self.assertRaises(KillSwitchLatchedError):
            self.journal.reserve_submission(
                "intent-direct",
                owner_id="executor-reserve-only",
                fence_token=token,
                submission_evidence=self.submission_evidence["intent-direct"],
                occurred_at=self.now,
            )
        self.assertEqual(
            "PREFLIGHT_PASSED",
            self.journal.get_intent("intent-direct").state,
        )

    def _prepare_reservation(self, intent_id: str, token: int, when: datetime) -> None:
        intent, broker, risk, preflight, guard = self.typed_submission_evidence(
            intent_id,
            when,
        )
        self.journal.create_intent(
            intent_id=intent_id,
            decision_id=intent.decision.snapshot_id,
            symbol=intent.symbol,
            payload={
                "intent": intent.to_canonical_dict(),
                "broker_spec": broker.to_canonical_dict(),
                "broker_spec_sha256": broker.content_sha256,
                "broker_comment": f"AIS:{intent_id}",
            },
            created_at=when,
        )
        self.journal.record_risk_decision(
            intent_id,
            risk,
            occurred_at=when,
        )
        self.journal.transition(intent_id, "RISK_APPROVED", occurred_at=when)
        self.journal.record_mt5_preflight(
            intent_id,
            preflight,
            occurred_at=when,
        )
        self.journal.transition(intent_id, "PREFLIGHT_PASSED", occurred_at=when)
        self.submission_evidence[intent_id] = (
            self.journal.authorize_submission_evidence(
                intent_id,
                risk_decision=risk,
                preflight=preflight,
                submission_guard=guard,
                broker_spec=broker,
                occurred_at=when,
            )
        )

    def test_atomic_reservation_blocks_second_global_exposure(self):
        token = self.journal.claim_executor("executor-a", now=self.now, lease_seconds=60)
        self._prepare_reservation("intent-1", token, self.now)
        self.journal.reserve_submission(
            "intent-1",
            owner_id="executor-a",
            fence_token=token,
            submission_evidence=self.submission_evidence["intent-1"],
            occurred_at=self.now,
        )
        self._prepare_reservation("intent-2", token, self.now)
        with self.assertRaisesRegex(
            SubmissionLimitError, "GLOBAL_ACTIVE_EXECUTION_EXISTS"
        ):
            self.journal.reserve_submission(
                "intent-2",
                owner_id="executor-a",
                fence_token=token,
                submission_evidence=self.submission_evidence["intent-2"],
                occurred_at=self.now,
            )
        self.assertEqual("PREFLIGHT_PASSED", self.journal.get_intent("intent-2").state)

    def test_untrusted_state_or_receipt_cannot_release_the_global_slot(self):
        token = self.journal.claim_executor(
            "executor-slot-integrity",
            now=self.now,
            lease_seconds=60,
        )
        self._prepare_reservation("intent-slot-1", token, self.now)
        self.journal.reserve_submission(
            "intent-slot-1",
            owner_id="executor-slot-integrity",
            fence_token=token,
            submission_evidence=self.submission_evidence["intent-slot-1"],
            occurred_at=self.now,
        )
        self.journal.append_receipt(
            "intent-slot-1",
            "BROKER_RESULT",
            {"state": "REJECTED", "forged": True},
            self.now,
        )
        with self.assertRaisesRegex(InvalidTransitionError, "broker.*evidence"):
            self.journal.transition(
                "intent-slot-1",
                "FILLED",
                occurred_at=self.now,
            )
        with self.assertRaisesRegex(InvalidTransitionError, "broker.*evidence"):
            self.journal.transition(
                "intent-slot-1",
                "REJECTED",
                occurred_at=self.now,
            )

        self._prepare_reservation("intent-slot-2", token, self.now)
        with self.assertRaisesRegex(
            SubmissionLimitError,
            "GLOBAL_ACTIVE_EXECUTION_EXISTS",
        ):
            self.journal.reserve_submission(
                "intent-slot-2",
                owner_id="executor-slot-integrity",
                fence_token=token,
                submission_evidence=self.submission_evidence["intent-slot-2"],
                occurred_at=self.now,
            )

        self.journal.record_execution_receipt(
            self.execution_receipt("intent-slot-1", "FILLED"),
            occurred_at=self.now,
        )
        with self.assertRaisesRegex(InvalidTransitionError, "broker.*evidence"):
            self.journal.transition(
                "intent-slot-1",
                "CLOSED",
                occurred_at=self.now,
            )
        with self.assertRaisesRegex(
            SubmissionLimitError,
            "GLOBAL_ACTIVE_EXECUTION_EXISTS",
        ):
            self.journal.reserve_submission(
                "intent-slot-2",
                owner_id="executor-slot-integrity",
                fence_token=token,
                submission_evidence=self.submission_evidence["intent-slot-2"],
                occurred_at=self.now,
            )

        reconcile_broker_state(
            self.journal,
            broker_orders=[],
            broker_positions=[],
            broker_deals=[
                {
                    "ticket": 91,
                    "comment": "AIS:intent-slot-1",
                    "magic": MAGIC,
                    "entry": 1,
                    "symbol": "EURUSD.a",
                    "type": 1,
                    "volume": 0.01,
                    "time_msc": int(self.now.timestamp() * 1000),
                }
            ],
            magic_number=MAGIC,
            occurred_at=self.now,
        )
        reserved = self.journal.reserve_submission(
            "intent-slot-2",
            owner_id="executor-slot-integrity",
            fence_token=token,
            submission_evidence=self.submission_evidence["intent-slot-2"],
            occurred_at=self.now,
        )
        self.assertEqual("SUBMITTING", reserved.state)

    def test_atomic_reservation_enforces_four_entry_daily_limit(self):
        token = self.journal.claim_executor("executor-a", now=self.now, lease_seconds=60)
        for index in range(4):
            intent_id = f"intent-{index}"
            self._prepare_reservation(intent_id, token, self.now)
            self.journal.reserve_submission(
                intent_id,
                owner_id="executor-a",
                fence_token=token,
                submission_evidence=self.submission_evidence[intent_id],
                occurred_at=self.now,
            )
            self.journal.record_execution_receipt(
                self.execution_receipt(intent_id, "REJECTED"),
                occurred_at=self.now,
            )
        self._prepare_reservation("intent-5", token, self.now)
        with self.assertRaisesRegex(SubmissionLimitError, "DAILY_ENTRY_LIMIT"):
            self.journal.reserve_submission(
                "intent-5",
                owner_id="executor-a",
                fence_token=token,
                submission_evidence=self.submission_evidence["intent-5"],
                occurred_at=self.now,
            )

        # UTC-day accounting resets at midnight; it does not silently inherit
        # yesterday's four attempts.
        tomorrow = self.now + timedelta(days=1)
        self.clock_now = tomorrow
        next_token = self.journal.claim_executor(
            "executor-a", now=tomorrow, lease_seconds=60
        )
        self._prepare_reservation("intent-next-day", next_token, tomorrow)
        reserved = self.journal.reserve_submission(
            "intent-next-day",
            owner_id="executor-a",
            fence_token=next_token,
            submission_evidence=self.submission_evidence["intent-next-day"],
            occurred_at=tomorrow,
        )
        self.assertEqual("SUBMITTING", reserved.state)

    def test_kill_switch_is_latched_across_restart_and_requires_dual_control_reset(self):
        self.journal.latch_kill_switch(
            "orphan position", source="RECONCILIATION", occurred_at=self.now
        )
        restarted = ExecutionJournal(
            self.path,
            clock_provider=lambda: self.clock_now,
        )
        self.assertTrue(restarted.kill_switch_status()["latched"])
        with self.assertRaises(PermissionError):
            restarted.reset_kill_switch(
                authorization=None,  # type: ignore[arg-type]
                reason="not reviewed",
                occurred_at=self.now,
            )
        reset_reason = "operator reconciled position"
        latched_at = datetime.fromisoformat(
            restarted.kill_switch_status()["latched_at_utc"]
        )
        unsigned = KillSwitchResetPermit(
            journal_sha256=restarted.journal_sha256,
            latched_at_utc=latched_at,
            reset_reason_sha256=reset_reason_sha256(reset_reason),
            approver_ids=("risk-officer", "operations-officer"),
            approver_key_ids=(
                ("risk-officer", RESET_KEY_ID_A),
                ("operations-officer", RESET_KEY_ID_B),
            ),
            issued_at=self.now,
            expires_at=self.now + timedelta(minutes=5),
            nonce="reset-1",
        )
        with self.assertRaises(PermissionError):
            authorize_kill_switch_reset(
                unsigned.sign("risk-officer", RESET_KEY_ID_A, RESET_SECRET_A),
                {
                    "risk-officer": (RESET_KEY_ID_A, RESET_SECRET_A),
                    "operations-officer": (RESET_KEY_ID_B, RESET_SECRET_B),
                },
                now=self.now,
                expected_journal_sha256=restarted.journal_sha256,
                expected_latched_at_utc=latched_at,
                expected_reason=reset_reason,
                clock_provider=lambda: self.clock_now,
            )
        signed = unsigned.sign(
            "risk-officer", RESET_KEY_ID_A, RESET_SECRET_A
        ).sign(
            "operations-officer", RESET_KEY_ID_B, RESET_SECRET_B
        )
        authorization = authorize_kill_switch_reset(
            signed,
            {
                "risk-officer": (RESET_KEY_ID_A, RESET_SECRET_A),
                "operations-officer": (RESET_KEY_ID_B, RESET_SECRET_B),
            },
            now=self.now,
            expected_journal_sha256=restarted.journal_sha256,
            expected_latched_at_utc=latched_at,
            expected_reason=reset_reason,
            clock_provider=lambda: self.clock_now,
        )
        restarted.reset_kill_switch(
            authorization=authorization,
            reason=reset_reason,
            occurred_at=self.now,
        )
        self.assertFalse(restarted.kill_switch_status()["latched"])
        self.assertEqual(
            ["LATCH", "RESET"],
            [item["action"] for item in restarted.kill_switch_history()],
        )
        self.assertTrue(
            restarted.kill_switch_history()[-1]["source"].startswith("DUAL_CONTROL:"),
        )
        restarted.latch_kill_switch(
            "second latch",
            source="RECONCILIATION",
            occurred_at=self.now,
        )
        with self.assertRaisesRegex(PermissionError, "replayed"):
            restarted.reset_kill_switch(
                authorization=authorization,
                reason=reset_reason,
                occurred_at=self.now,
            )

    def test_kill_switch_reset_rejects_backdating_and_trusted_clock_expiry(self):
        self.journal.latch_kill_switch(
            "orphan position",
            source="RECONCILIATION",
            occurred_at=self.now,
        )
        reset_reason = "operator reconciled position"
        latched_at = datetime.fromisoformat(
            self.journal.kill_switch_status()["latched_at_utc"]
        )
        permit = KillSwitchResetPermit(
            journal_sha256=self.journal.journal_sha256,
            latched_at_utc=latched_at,
            reset_reason_sha256=reset_reason_sha256(reset_reason),
            approver_ids=("risk-officer", "operations-officer"),
            approver_key_ids=(
                ("risk-officer", RESET_KEY_ID_A),
                ("operations-officer", RESET_KEY_ID_B),
            ),
            issued_at=self.now,
            expires_at=self.now + timedelta(minutes=5),
            nonce="reset-clock-test",
        ).sign(
            "risk-officer", RESET_KEY_ID_A, RESET_SECRET_A
        ).sign(
            "operations-officer", RESET_KEY_ID_B, RESET_SECRET_B
        )
        approver_keys = {
            "risk-officer": (RESET_KEY_ID_A, RESET_SECRET_A),
            "operations-officer": (RESET_KEY_ID_B, RESET_SECRET_B),
        }
        expired_now = self.now + timedelta(minutes=6)
        with self.assertRaisesRegex(ValueError, "trusted clock"):
            authorize_kill_switch_reset(
                permit,
                approver_keys,
                now=self.now,
                expected_journal_sha256=self.journal.journal_sha256,
                expected_latched_at_utc=latched_at,
                expected_reason=reset_reason,
                clock_provider=lambda: expired_now,
            )
        with self.assertRaisesRegex(PermissionError, "stale"):
            authorize_kill_switch_reset(
                permit,
                approver_keys,
                expected_journal_sha256=self.journal.journal_sha256,
                expected_latched_at_utc=latched_at,
                expected_reason=reset_reason,
                clock_provider=lambda: expired_now,
            )
        authorization = authorize_kill_switch_reset(
            permit,
            approver_keys,
            now=self.now,
            expected_journal_sha256=self.journal.journal_sha256,
            expected_latched_at_utc=latched_at,
            expected_reason=reset_reason,
            clock_provider=lambda: self.clock_now,
        )
        self.clock_now = expired_now
        with self.assertRaisesRegex(ValueError, "trusted journal clock"):
            self.journal.reset_kill_switch(
                authorization=authorization,
                reason=reset_reason,
                occurred_at=self.now,
            )
        with self.assertRaisesRegex(PermissionError, "stale"):
            self.journal.reset_kill_switch(
                authorization=authorization,
                reason=reset_reason,
            )

    def test_final_submission_guard_rechecks_fence_after_reservation(self):
        token = self.journal.claim_executor(
            "executor-a", now=self.now, lease_seconds=60
        )
        self._prepare_reservation("intent-final", token, self.now)
        self.journal.reserve_submission(
            "intent-final",
            owner_id="executor-a",
            fence_token=token,
            submission_evidence=self.submission_evidence["intent-final"],
            occurred_at=self.now,
        )
        replacement = self.journal.claim_executor(
            "executor-a",
            now=self.now + timedelta(milliseconds=1),
            lease_seconds=60,
        )
        with self.assertRaises(ExecutorFenceError):
            with self.journal.final_submission_guard(
                "intent-final",
                owner_id="executor-a",
                fence_token=token,
                execution_gate_sha256="a" * 64,
                authorization_sha256="b" * 64,
                broker_request_sha256="1" * 64,
                occurred_at=self.now + timedelta(milliseconds=1),
            ):
                self.fail("stale fence entered final submission guard")
        with self.journal.final_submission_guard(
            "intent-final",
            owner_id="executor-a",
            fence_token=replacement,
            execution_gate_sha256="a" * 64,
            authorization_sha256="b" * 64,
            broker_request_sha256="1" * 64,
            occurred_at=self.now + timedelta(milliseconds=1),
        ):
            self.assertEqual(
                "SUBMITTING", self.journal.get_intent("intent-final").state
            )

    def test_final_authorization_consumption_survives_journal_restart(self):
        token = self.journal.claim_executor(
            "executor-a", now=self.now, lease_seconds=60
        )
        self._prepare_reservation("intent-durable-auth", token, self.now)
        self.journal.reserve_submission(
            "intent-durable-auth",
            owner_id="executor-a",
            fence_token=token,
            submission_evidence=self.submission_evidence["intent-durable-auth"],
            occurred_at=self.now,
        )
        gate_hash = "c" * 64
        authorization_hash = "d" * 64
        with self.journal.final_submission_guard(
            "intent-durable-auth",
            owner_id="executor-a",
            fence_token=token,
            execution_gate_sha256=gate_hash,
            authorization_sha256=authorization_hash,
            broker_request_sha256="1" * 64,
            occurred_at=self.now,
        ):
            pass

        restarted = ExecutionJournal(
            self.path,
            clock_provider=lambda: self.clock_now,
        )
        with self.assertRaises(SubmissionLimitError) as raised:
            with restarted.final_submission_guard(
                "intent-durable-auth",
                owner_id="executor-a",
                fence_token=token,
                execution_gate_sha256=gate_hash,
                authorization_sha256=authorization_hash,
                broker_request_sha256="1" * 64,
                occurred_at=self.now,
            ):
                self.fail("a consumed authorization was reminted after restart")
        self.assertEqual("AUTHORIZATION_ALREADY_CONSUMED", raised.exception.reason_code)

    def test_final_guard_does_not_hold_sqlite_write_lock_across_broker_io(self):
        token = self.journal.claim_executor(
            "executor-a", now=self.now, lease_seconds=60
        )
        intent_id = "intent-nonblocking-final-guard"
        self._prepare_reservation(intent_id, token, self.now)
        self.journal.reserve_submission(
            intent_id,
            owner_id="executor-a",
            fence_token=token,
            submission_evidence=self.submission_evidence[intent_id],
            occurred_at=self.now,
        )
        gate_hash = "e" * 64
        authorization_hash = "f" * 64
        restarted = ExecutionJournal(
            self.path,
            clock_provider=lambda: self.clock_now,
        )
        with self.journal.final_submission_guard(
            intent_id,
            owner_id="executor-a",
            fence_token=token,
            execution_gate_sha256=gate_hash,
            authorization_sha256=authorization_hash,
            broker_request_sha256="1" * 64,
            occurred_at=self.now,
        ) as submission_lease:
            restarted.latch_kill_switch(
                "operator emergency stop",
                source="TEST",
                occurred_at=self.now,
            )
            with self.assertRaises(KillSwitchLatchedError):
                submission_lease.consume(
                    journal_sha256=self.journal.journal_sha256,
                    intent_id=intent_id,
                    execution_gate_sha256=gate_hash,
                    authorization_sha256=authorization_hash,
                    broker_request_sha256="1" * 64,
                )

    def test_naive_timestamp_is_rejected(self):
        with self.assertRaises(ValueError):
            self.journal.create_intent(
                intent_id="intent-naive",
                decision_id="decision-naive",
                symbol="EURUSD",
                payload={},
                created_at=datetime(2026, 7, 15, 12, 0),
            )
        with self.assertRaises(ValueError):
            self.journal.claim_executor(
                "executor-offset",
                now=self.now.astimezone(timezone(timedelta(hours=9))),
            )

    def test_security_boundaries_reject_stale_caller_clock(self):
        token = self.journal.claim_executor(
            "executor-clock",
            now=self.now,
            lease_seconds=60,
        )
        with self.assertRaisesRegex(ValueError, "trusted journal clock"):
            self.journal.assert_executor_fence(
                "executor-clock",
                token,
                now=self.now + timedelta(seconds=1),
            )

        with self.assertRaisesRegex(ValueError, "trusted journal clock"):
            self.journal.create_intent(
                intent_id="intent-forged-created-at",
                decision_id="decision-forged-created-at",
                symbol="EURUSD",
                payload={},
                created_at=self.now + timedelta(seconds=1),
            )

        self.create("intent-timestamp-boundaries")
        with self.assertRaisesRegex(ValueError, "trusted journal clock"):
            self.journal.transition(
                "intent-timestamp-boundaries",
                "RISK_APPROVED",
                occurred_at=self.now + timedelta(seconds=1),
            )
        with self.assertRaisesRegex(ValueError, "trusted journal clock"):
            self.journal.append_receipt(
                "intent-timestamp-boundaries",
                "TEST_RECEIPT",
                {},
                occurred_at=self.now + timedelta(seconds=1),
            )
        with self.assertRaisesRegex(ValueError, "trusted journal clock"):
            self.journal.latch_kill_switch(
                "forged-time incident",
                source="TEST",
                occurred_at=self.now + timedelta(seconds=1),
            )

        self._prepare_reservation("intent-clock", token, self.now)
        with self.assertRaisesRegex(ValueError, "trusted journal clock"):
            self.journal.reserve_submission(
                "intent-clock",
                owner_id="executor-clock",
                fence_token=token,
                submission_evidence=self.submission_evidence["intent-clock"],
                occurred_at=self.now + timedelta(seconds=1),
            )
        self.journal.reserve_submission(
            "intent-clock",
            owner_id="executor-clock",
            fence_token=token,
            submission_evidence=self.submission_evidence["intent-clock"],
            occurred_at=self.now,
        )
        with self.assertRaisesRegex(ValueError, "trusted journal clock"):
            with self.journal.final_submission_guard(
                "intent-clock",
                owner_id="executor-clock",
                fence_token=token,
                execution_gate_sha256="a" * 64,
                authorization_sha256="b" * 64,
                broker_request_sha256="1" * 64,
                occurred_at=self.now + timedelta(seconds=1),
            ):
                self.fail("stale clock entered final submission boundary")

    def test_short_one_way_recording_delay_uses_journal_clock(self):
        self.clock_now = self.now + timedelta(seconds=2)
        record = self.journal.create_intent(
            intent_id="intent-short-recording-delay",
            decision_id="decision-short-recording-delay",
            symbol="EURUSD",
            payload={},
            created_at=self.now,
        )
        self.assertEqual(self.clock_now, record.created_at_utc)

        with self.assertRaisesRegex(ValueError, "stale"):
            self.journal.create_intent(
                intent_id="intent-excessive-recording-delay",
                decision_id="decision-excessive-recording-delay",
                symbol="EURUSD",
                payload={},
                created_at=self.now - timedelta(seconds=4),
            )


if __name__ == "__main__":
    unittest.main()
