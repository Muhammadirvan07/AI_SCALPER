import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from live_runtime.journal import (
    DuplicateIntentError,
    ExecutionJournal,
    ExecutorFenceError,
    InvalidTransitionError,
    KillSwitchLatchedError,
    SubmissionLimitError,
)
from live_runtime.permit import (
    KillSwitchResetPermit,
    authorize_kill_switch_reset,
    reset_reason_sha256,
)


UTC = timezone.utc
RESET_SECRET_A = "journal-reset-approver-a-secret-at-least-32-bytes"
RESET_SECRET_B = "journal-reset-approver-b-secret-at-least-32-bytes"
RESET_KEY_ID_A = "risk-reset-key-v1"
RESET_KEY_ID_B = "operations-reset-key-v1"


class ExecutionJournalTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.path = Path(self.tempdir.name) / "journal.sqlite"
        self.now = datetime(2026, 7, 15, 12, 0, tzinfo=UTC)
        self.clock_now = self.now
        self.journal = ExecutionJournal(
            self.path,
            clock_provider=lambda: self.clock_now,
        )

    def create(self, intent_id="intent-1", *, decision_id=None):
        return self.journal.create_intent(
            intent_id=intent_id,
            decision_id=decision_id or f"decision-{intent_id}",
            symbol="xauusd",
            payload={"lot": 0.01, "mode": "SHADOW"},
            created_at=self.now,
        )

    def test_intent_is_idempotent_but_payload_reuse_is_rejected(self):
        self.assertEqual(3, self.journal.schema_version())
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
            created_at=self.now + timedelta(milliseconds=100),
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
        self.create()
        with self.assertRaises(InvalidTransitionError):
            self.journal.transition("intent-1", "FILLED")

        for state in (
            "RISK_APPROVED",
            "PREFLIGHT_PASSED",
            "SUBMITTING",
            "ACKNOWLEDGED",
            "FILLED",
            "CLOSED",
        ):
            self.journal.transition("intent-1", state, occurred_at=self.now)
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
                "ACKNOWLEDGED",
                "FILLED",
                "CLOSED",
            ],
        )

    def test_uncertain_state_can_only_be_resolved_by_reconciliation_states(self):
        self.create()
        for state in ("RISK_APPROVED", "PREFLIGHT_PASSED", "SUBMITTING", "UNCERTAIN"):
            self.journal.transition("intent-1", state, occurred_at=self.now)
        with self.assertRaises(InvalidTransitionError):
            self.journal.transition("intent-1", "SUBMITTING")
        resolved = self.journal.transition(
            "intent-1",
            "FILLED",
            broker_position_ticket="42",
            protective_sl_tp_confirmed=True,
            occurred_at=self.now,
        )
        self.assertEqual(resolved.broker_position_ticket, "42")
        self.assertTrue(resolved.protective_sl_tp_confirmed)

    def test_single_executor_fence_survives_restart(self):
        token = self.journal.claim_executor("executor-a", now=self.now, lease_seconds=15)
        self.journal.assert_executor_fence("executor-a", token, now=self.now)
        restarted = ExecutionJournal(self.path)
        with self.assertRaises(ExecutorFenceError):
            restarted.claim_executor(
                "executor-b", now=self.now + timedelta(seconds=5), lease_seconds=15
            )
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
        replacement = self.journal.claim_executor(
            "executor-a", now=self.now + timedelta(seconds=1), lease_seconds=30
        )
        self.assertGreater(replacement, token)
        with self.assertRaises(ExecutorFenceError):
            self.journal.assert_executor_fence(
                "executor-a", token, now=self.now + timedelta(seconds=1)
            )
        self.create()
        self.journal.transition("intent-1", "RISK_APPROVED", occurred_at=self.now)
        self.journal.transition("intent-1", "PREFLIGHT_PASSED", occurred_at=self.now)
        self.journal.latch_kill_switch("incident", source="TEST", occurred_at=self.now)
        with self.assertRaises(KillSwitchLatchedError):
            self.journal.reserve_submission(
                "intent-1",
                owner_id="executor-a",
                fence_token=replacement,
                occurred_at=self.now + timedelta(seconds=1),
            )
        self.assertEqual("PREFLIGHT_PASSED", self.journal.get_intent("intent-1").state)

    def test_same_state_reconciliation_evidence_updates_protection(self):
        self.create()
        for state in ("RISK_APPROVED", "PREFLIGHT_PASSED", "SUBMITTING", "FILLED"):
            self.journal.transition("intent-1", state, occurred_at=self.now)
        updated = self.journal.record_reconciliation(
            "intent-1",
            expected_state="FILLED",
            broker_position_ticket="42",
            protective_sl_tp_confirmed=True,
            details={"source": "TEST"},
            occurred_at=self.now,
        )
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
        with self.assertRaises(InvalidTransitionError):
            self.journal.reserve_submission(
                "intent-1",
                owner_id="executor-a",
                fence_token=token,
                occurred_at=self.now,
            )
        self.assertEqual("PREFLIGHT_PASSED", self.journal.get_intent("intent-1").state)

    def _prepare_reservation(self, intent_id: str, token: int, when: datetime) -> None:
        self.create(intent_id)
        self.journal.transition(intent_id, "RISK_APPROVED", occurred_at=when)
        self.journal.transition(intent_id, "PREFLIGHT_PASSED", occurred_at=when)
        for receipt_type, payload in (
            ("RISK_DECISION", {"allowed": True, "symbol": "XAUUSD"}),
            ("MT5_PREFLIGHT", {"passed": True, "intent_id": intent_id}),
            (
                "SUBMISSION_GUARD",
                {
                    "active_order_count": 0,
                    "active_position_count": 0,
                    "broker_spec_sha256": None,
                },
            ),
        ):
            self.journal.append_receipt(intent_id, receipt_type, payload, when)

    def test_atomic_reservation_blocks_second_global_exposure(self):
        token = self.journal.claim_executor("executor-a", now=self.now, lease_seconds=60)
        self._prepare_reservation("intent-1", token, self.now)
        self.journal.reserve_submission(
            "intent-1",
            owner_id="executor-a",
            fence_token=token,
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
                occurred_at=self.now,
            )
        self.assertEqual("PREFLIGHT_PASSED", self.journal.get_intent("intent-2").state)

    def test_atomic_reservation_enforces_four_entry_daily_limit(self):
        token = self.journal.claim_executor("executor-a", now=self.now, lease_seconds=60)
        for index in range(4):
            intent_id = f"intent-{index}"
            self._prepare_reservation(intent_id, token, self.now)
            self.journal.reserve_submission(
                intent_id,
                owner_id="executor-a",
                fence_token=token,
                occurred_at=self.now,
            )
            self.journal.transition(
                intent_id,
                "REJECTED",
                expected_state="SUBMITTING",
                occurred_at=self.now,
            )
        self._prepare_reservation("intent-5", token, self.now)
        with self.assertRaisesRegex(SubmissionLimitError, "DAILY_ENTRY_LIMIT"):
            self.journal.reserve_submission(
                "intent-5",
                owner_id="executor-a",
                fence_token=token,
                occurred_at=self.now,
            )

        # UTC-day accounting resets at midnight; it does not silently inherit
        # yesterday's four attempts.
        tomorrow = self.now + timedelta(days=1)
        next_token = self.journal.claim_executor(
            "executor-a", now=tomorrow, lease_seconds=60
        )
        self._prepare_reservation("intent-next-day", next_token, tomorrow)
        reserved = self.journal.reserve_submission(
            "intent-next-day",
            owner_id="executor-a",
            fence_token=next_token,
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
                occurred_at=self.now + timedelta(milliseconds=1),
            ):
                self.fail("stale fence entered final submission guard")
        with self.journal.final_submission_guard(
            "intent-final",
            owner_id="executor-a",
            fence_token=replacement,
            execution_gate_sha256="a" * 64,
            authorization_sha256="b" * 64,
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
                occurred_at=self.now,
            ):
                self.fail("a consumed authorization was reminted after restart")
        self.assertEqual("AUTHORIZATION_ALREADY_CONSUMED", raised.exception.reason_code)

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


if __name__ == "__main__":
    unittest.main()
