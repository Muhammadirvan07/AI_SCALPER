import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from live_runtime.journal import ExecutionJournal
from live_runtime.reconciliation import reconcile_broker_state


UTC = timezone.utc
NOW = datetime(2026, 7, 15, 12, 0, tzinfo=UTC)
MAGIC = 260615


class ReconciliationTests(unittest.TestCase):
    def setUp(self):
        tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(tempdir.cleanup)
        self.journal = ExecutionJournal(
            Path(tempdir.name) / "journal.sqlite",
            clock_provider=lambda: NOW,
        )

    def create_submitting(self, comment="AIS:abc"):
        self.journal.create_intent(
            intent_id="intent-1",
            decision_id="decision-1",
            symbol="XAUUSD",
            payload={
                "broker_comment": comment,
                "intent": {
                    "requested_lot": 0.01,
                    "side": "BUY",
                    "stop_loss": 2399.5,
                    "take_profit": 2401.0,
                },
                "broker_spec": {
                    "broker_symbol": "GOLD.a",
                    "point": 0.01,
                    "tick_size": 0.01,
                },
            },
            created_at=NOW,
        )
        self.seed_state("SUBMITTING")

    def seed_state(
        self,
        state,
        *,
        broker_order_ticket=None,
        broker_position_ticket=None,
        filled_volume=0.0,
        protective_sl_tp_confirmed=False,
    ):
        """Simulate a restart fixture after a previously trusted journal write."""

        with self.journal._transaction() as connection:
            previous = connection.execute(
                "SELECT state FROM intents WHERE intent_id='intent-1'"
            ).fetchone()["state"]
            connection.execute(
                """
                UPDATE intents
                SET state=?, broker_order_ticket=?, broker_position_ticket=?,
                    filled_volume=?, protective_sl_tp_confirmed=?,
                    updated_at_utc=?
                WHERE intent_id='intent-1'
                """,
                (
                    state,
                    broker_order_ticket,
                    broker_position_ticket,
                    filled_volume,
                    int(protective_sl_tp_confirmed),
                    NOW.isoformat(),
                ),
            )
            connection.execute(
                """
                INSERT INTO transitions(
                    intent_id, from_state, to_state, occurred_at_utc, details_json
                ) VALUES('intent-1', ?, ?, ?, '{"fixture":"trusted_restart"}')
                """,
                (previous, state, NOW.isoformat()),
            )

    def test_restart_after_submit_recovers_position_by_comment(self):
        self.create_submitting()
        self.journal.transition("intent-1", "UNCERTAIN", occurred_at=NOW)
        result = reconcile_broker_state(
            self.journal,
            broker_orders=[],
            broker_positions=[
                {
                    "ticket": 42,
                    "magic": MAGIC,
                    "comment": "AIS:abc",
                    "symbol": "GOLD.a",
                    "type": 0,
                    "volume": 0.01,
                    "sl": 2399.5,
                    "tp": 2401.0,
                }
            ],
            broker_deals=[],
            magic_number=MAGIC,
            occurred_at=NOW,
        )
        record = self.journal.get_intent("intent-1")
        self.assertEqual(record.state, "FILLED")
        self.assertEqual(record.broker_position_ticket, "42")
        self.assertTrue(record.protective_sl_tp_confirmed)
        self.assertFalse(result.kill_switch_latched)

    def test_orphan_position_latches_kill_switch(self):
        result = reconcile_broker_state(
            self.journal,
            broker_orders=[],
            broker_positions=[{"ticket": 99, "magic": MAGIC, "comment": "unknown", "sl": 1, "tp": 2}],
            broker_deals=[],
            magic_number=MAGIC,
            occurred_at=NOW,
        )
        self.assertEqual(result.status, "RECONCILIATION_CRITICAL_HOLD")
        self.assertEqual(result.orphan_position_tickets, ("99",))
        self.assertTrue(result.kill_switch_latched)

    def test_missing_server_side_protection_latches_kill_switch(self):
        self.create_submitting()
        result = reconcile_broker_state(
            self.journal,
            broker_orders=[],
            broker_positions=[
                {
                    "ticket": 42,
                    "magic": MAGIC,
                    "comment": "AIS:abc",
                    "symbol": "GOLD.a",
                    "type": 0,
                    "volume": 0.01,
                    "sl": 0,
                    "tp": 0,
                }
            ],
            broker_deals=[],
            magic_number=MAGIC,
            occurred_at=NOW,
        )
        self.assertEqual(result.protection_failures, ("intent-1",))
        self.assertTrue(result.kill_switch_latched)
        self.assertFalse(self.journal.get_intent("intent-1").protective_sl_tp_confirmed)

    def test_positive_but_wrong_server_protection_is_not_accepted(self):
        self.create_submitting()
        result = reconcile_broker_state(
            self.journal,
            broker_orders=[],
            broker_positions=[
                {
                    "ticket": 42,
                    "magic": MAGIC,
                    "comment": "AIS:abc",
                    "symbol": "GOLD.a",
                    "type": 0,
                    "volume": 0.01,
                    "sl": 2300.0,
                    "tp": 2500.0,
                }
            ],
            broker_deals=[],
            magic_number=MAGIC,
            occurred_at=NOW,
        )
        self.assertEqual(("intent-1",), result.protection_failures)
        self.assertFalse(self.journal.get_intent("intent-1").protective_sl_tp_confirmed)

    def test_external_close_is_reconciled_from_exit_deal(self):
        self.create_submitting()
        self.seed_state(
            "FILLED",
            broker_position_ticket="42",
            filled_volume=0.01,
            protective_sl_tp_confirmed=True,
        )
        result = reconcile_broker_state(
            self.journal,
            broker_orders=[],
            broker_positions=[],
            broker_deals=[
                {
                    "ticket": 81,
                    "position": 42,
                    "magic": MAGIC,
                    "entry": 1,
                    "symbol": "GOLD.a",
                    "type": 1,
                    "volume": 0.01,
                    "time_msc": int(NOW.timestamp() * 1000),
                }
            ],
            magic_number=MAGIC,
            occurred_at=NOW,
        )
        self.assertEqual(self.journal.get_intent("intent-1").state, "CLOSED")
        self.assertEqual(result.closed_intents, ("intent-1",))

    def test_exit_deal_with_wrong_side_or_incomplete_volume_never_closes(self):
        self.create_submitting()
        self.seed_state(
            "FILLED",
            broker_position_ticket="42",
            filled_volume=0.01,
            protective_sl_tp_confirmed=True,
        )
        result = reconcile_broker_state(
            self.journal,
            broker_orders=[],
            broker_positions=[],
            broker_deals=[
                {
                    "ticket": 82,
                    "position": 42,
                    "magic": MAGIC,
                    "entry": 1,
                    "symbol": "GOLD.a",
                    "type": 0,
                    "volume": 0.005,
                    "time_msc": int(NOW.timestamp() * 1000),
                }
            ],
            magic_number=MAGIC,
            occurred_at=NOW,
        )
        self.assertEqual("UNCERTAIN", self.journal.get_intent("intent-1").state)
        self.assertEqual((), result.closed_intents)
        self.assertEqual(("intent-1",), result.binding_failures)
        self.assertEqual(("intent-1",), result.volume_failures)
        self.assertTrue(result.kill_switch_latched)

    def test_no_broker_object_moves_submitting_to_uncertain_without_retry(self):
        self.create_submitting()
        result = reconcile_broker_state(
            self.journal,
            broker_orders=[],
            broker_positions=[],
            broker_deals=[],
            magic_number=MAGIC,
            occurred_at=NOW,
        )
        self.assertEqual(self.journal.get_intent("intent-1").state, "UNCERTAIN")
        self.assertEqual(result.uncertain_intents, ("intent-1",))
        self.assertEqual(result.status, "RECONCILIATION_PENDING")

    def test_missing_position_and_delayed_history_moves_filled_to_uncertain(self):
        self.create_submitting()
        self.seed_state(
            "FILLED",
            broker_position_ticket="42",
            filled_volume=0.01,
            protective_sl_tp_confirmed=True,
        )
        result = reconcile_broker_state(
            self.journal,
            broker_orders=[],
            broker_positions=[],
            broker_deals=[],
            magic_number=MAGIC,
            occurred_at=NOW,
        )
        self.assertEqual(self.journal.get_intent("intent-1").state, "UNCERTAIN")
        self.assertEqual(result.uncertain_intents, ("intent-1",))

    def test_manual_or_foreign_magic_position_is_still_an_orphan(self):
        result = reconcile_broker_state(
            self.journal,
            broker_orders=[],
            broker_positions=[
                {
                    "ticket": 100,
                    "magic": 0,
                    "comment": "manual",
                    "symbol": "GOLD.a",
                    "type": 0,
                    "volume": 0.01,
                    "sl": 2399.5,
                    "tp": 2401.0,
                }
            ],
            broker_deals=[],
            magic_number=MAGIC,
            occurred_at=NOW,
        )
        self.assertEqual(("100",), result.orphan_position_tickets)
        self.assertTrue(result.kill_switch_latched)

    def test_partial_volume_remains_partial_and_full_same_state_confirms_protection(self):
        self.create_submitting()
        partial = reconcile_broker_state(
            self.journal,
            broker_orders=[],
            broker_positions=[
                {
                    "ticket": 42,
                    "magic": MAGIC,
                    "comment": "AIS:abc",
                    "symbol": "GOLD.a",
                    "type": 0,
                    "volume": 0.005,
                    "sl": 2399.5,
                    "tp": 2401.0,
                }
            ],
            broker_deals=[],
            magic_number=MAGIC,
            occurred_at=NOW,
        )
        self.assertEqual("PARTIAL", self.journal.get_intent("intent-1").state)
        self.assertFalse(partial.kill_switch_latched)

        full = reconcile_broker_state(
            self.journal,
            broker_orders=[],
            broker_positions=[
                {
                    "ticket": 42,
                    "magic": MAGIC,
                    "comment": "AIS:abc",
                    "symbol": "GOLD.a",
                    "type": 0,
                    "volume": 0.01,
                    "sl": 2399.5,
                    "tp": 2401.0,
                }
            ],
            broker_deals=[],
            magic_number=MAGIC,
            occurred_at=NOW,
        )
        record = self.journal.get_intent("intent-1")
        self.assertEqual("FILLED", record.state)
        self.assertTrue(record.protective_sl_tp_confirmed)
        self.assertEqual(0.01, record.filled_volume)
        self.assertFalse(full.kill_switch_latched)

    def test_legitimate_partial_fill_closes_against_observed_filled_volume(self):
        self.create_submitting()
        partial = reconcile_broker_state(
            self.journal,
            broker_orders=[],
            broker_positions=[
                {
                    "ticket": 42,
                    "magic": MAGIC,
                    "comment": "AIS:abc",
                    "symbol": "GOLD.a",
                    "type": 0,
                    "volume": 0.005,
                    "sl": 2399.5,
                    "tp": 2401.0,
                }
            ],
            broker_deals=[],
            magic_number=MAGIC,
            occurred_at=NOW,
        )
        record = self.journal.get_intent("intent-1")
        self.assertEqual("PARTIAL", record.state)
        self.assertEqual(0.005, record.filled_volume)
        self.assertFalse(partial.kill_switch_latched)

        closed = reconcile_broker_state(
            self.journal,
            broker_orders=[],
            broker_positions=[],
            broker_deals=[
                {
                    "ticket": 83,
                    "position": 42,
                    "magic": MAGIC,
                    "entry": 1,
                    "symbol": "GOLD.a",
                    "type": 1,
                    "volume": 0.005,
                    "time_msc": int(NOW.timestamp() * 1000),
                }
            ],
            magic_number=MAGIC,
            occurred_at=NOW,
        )
        self.assertEqual("CLOSED", self.journal.get_intent("intent-1").state)
        self.assertEqual(("intent-1",), closed.closed_intents)
        self.assertFalse(closed.kill_switch_latched)

    def test_acknowledged_active_order_does_not_oscillate_to_uncertain(self):
        self.create_submitting()
        self.seed_state("ACKNOWLEDGED", broker_order_ticket="77")
        result = reconcile_broker_state(
            self.journal,
            broker_orders=[
                {
                    "ticket": 77,
                    "magic": MAGIC,
                    "comment": "AIS:abc",
                    "symbol": "GOLD.a",
                    "type": 0,
                    "volume_current": 0.01,
                }
            ],
            broker_positions=[],
            broker_deals=[],
            magic_number=MAGIC,
            occurred_at=NOW,
        )
        self.assertEqual("ACKNOWLEDGED", self.journal.get_intent("intent-1").state)
        self.assertEqual((), result.uncertain_intents)

    def test_non_utc_reconciliation_timestamp_is_rejected(self):
        with self.assertRaises(ValueError):
            reconcile_broker_state(
                self.journal,
                broker_orders=[],
                broker_positions=[],
                broker_deals=[],
                magic_number=MAGIC,
                occurred_at=NOW.astimezone(timezone(timedelta(hours=9))),
            )


if __name__ == "__main__":
    unittest.main()
