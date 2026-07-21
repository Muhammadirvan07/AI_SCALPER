from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
import sqlite3
import tempfile
import unittest

from live_runtime.journal import ExecutionJournal
from live_runtime.reconciliation import ReconciliationResult
from live_runtime.reconciliation_supervisor import (
    ReconciliationSupervisor,
    ReconciliationSupervisorStore,
    SupervisorFenceError,
)


UTC = timezone.utc
NOW = datetime(2026, 7, 21, 12, 0, tzinfo=UTC)


class MutableClock:
    def __init__(self, value: datetime = NOW):
        self.value = value

    def __call__(self) -> datetime:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += timedelta(seconds=seconds)


def result(status: str = "RECONCILIATION_COMPLETE") -> ReconciliationResult:
    return ReconciliationResult(
        status=status,
        matched_intents=(),
        uncertain_intents=("intent-pending",) if status == "RECONCILIATION_PENDING" else (),
        closed_intents=(),
        orphan_position_tickets=("orphan",) if status == "RECONCILIATION_CRITICAL_HOLD" else (),
        orphan_order_tickets=(),
        protection_failures=(),
        volume_failures=(),
        binding_failures=(),
        kill_switch_latched=status == "RECONCILIATION_CRITICAL_HOLD",
    )


class FakeService:
    def __init__(self, journal: ExecutionJournal, outcomes):
        self.journal = journal
        self.outcomes = list(outcomes)
        self.calls = []

    def reconcile_once(self, *, history_start_utc, now=None):
        self.calls.append((history_start_utc, now))
        item = self.outcomes.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


class ReconciliationSupervisorTests(unittest.TestCase):
    def _components(self, outcomes):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        clock = MutableClock()
        journal = ExecutionJournal(root / "execution.sqlite3", clock_provider=clock)
        store = ReconciliationSupervisorStore(
            root / "supervisor.sqlite3",
            clock_provider=clock,
        )
        service = FakeService(journal, outcomes)
        supervisor = ReconciliationSupervisor(
            service=service,
            store=store,
            clock_provider=clock,
            sleep_provider=clock.advance,
            poll_seconds=5,
            history_lookback=timedelta(days=7),
            lease_seconds=15,
        )
        return clock, journal, store, service, supervisor

    def test_ac1_three_cycles_are_contiguous_and_startup_reconciles(self):
        _, _, store, service, supervisor = self._components([result(), result(), result()])
        run = supervisor.run(owner_id="reconciler-a", max_cycles=3)
        self.assertEqual(run.status, "STOPPED_AFTER_MAX_CYCLES")
        self.assertEqual(len(service.calls), 3)
        self.assertEqual(len(store.cycle_receipts()), 3)
        self.assertTrue(store.verify_chain())
        self.assertEqual(store.cycle_receipts()[0]["status"], "COMPLETE")

    def test_ac2_unexpired_owner_blocks_second_owner(self):
        _, _, store, _, _ = self._components([result()])
        store.claim("owner-a", lease_seconds=30)
        with self.assertRaises(SupervisorFenceError):
            store.claim("owner-b", lease_seconds=30)
        self.assertEqual(store.cycle_receipts(), [])

    def test_owner_id_is_normalized_once_for_lease_and_receipt(self):
        _, _, store, _, supervisor = self._components([result()])
        run = supervisor.run(owner_id="  reconciler-a  ", max_cycles=1)
        self.assertEqual(run.owner_id, "reconciler-a")
        self.assertEqual(store.cycle_receipts()[0]["owner_id"], "reconciler-a")

    def test_ac3_exception_latches_and_stops(self):
        _, journal, store, service, supervisor = self._components([RuntimeError("broker timeout")])
        run = supervisor.run(owner_id="reconciler-a", max_cycles=3)
        self.assertEqual(run.status, "FAILED_LATCHED")
        self.assertEqual(len(service.calls), 1)
        self.assertTrue(journal.kill_switch_status()["latched"])
        self.assertEqual(store.cycle_receipts()[0]["status"], "FAILED")

    def test_ac3_critical_result_latches_and_stops(self):
        _, journal, store, service, supervisor = self._components(
            [result("RECONCILIATION_CRITICAL_HOLD"), result()]
        )
        run = supervisor.run(owner_id="reconciler-a", max_cycles=2)
        self.assertEqual(run.status, "CRITICAL_HOLD_LATCHED")
        self.assertEqual(len(service.calls), 1)
        self.assertTrue(journal.kill_switch_status()["latched"])
        self.assertEqual(store.cycle_receipts()[0]["status"], "CRITICAL_HOLD")

    def test_unknown_reconciliation_status_latches_and_stops(self):
        _, journal, store, service, supervisor = self._components(
            [result("BROKER_STATUS_DRIFT")]
        )
        run = supervisor.run(owner_id="reconciler-a", max_cycles=2)
        self.assertEqual(run.status, "FAILED_LATCHED")
        self.assertEqual(len(service.calls), 1)
        self.assertTrue(journal.kill_switch_status()["latched"])
        self.assertEqual(store.cycle_receipts()[0]["status"], "FAILED")

    def test_ac4_expired_lease_allows_higher_fence_and_chain_resume(self):
        clock, _, store, _, supervisor = self._components([result(), result()])
        first = supervisor.run(owner_id="owner-a", max_cycles=1)
        clock.advance(20)
        second = supervisor.run(owner_id="owner-b", max_cycles=1)
        self.assertGreater(second.fence_token, first.fence_token)
        self.assertEqual(len(store.cycle_receipts()), 2)
        self.assertTrue(store.verify_chain())

    def test_cycle_chain_tamper_is_detected(self):
        _, _, store, _, supervisor = self._components([result()])
        supervisor.run(owner_id="owner-a", max_cycles=1)
        connection = sqlite3.connect(store.path)
        try:
            connection.execute(
                "UPDATE reconciliation_cycles SET payload_json='{}' WHERE sequence=1"
            )
            connection.commit()
        finally:
            connection.close()
        self.assertFalse(store.verify_chain())


if __name__ == "__main__":
    unittest.main()
