from datetime import datetime, timezone
from pathlib import Path
import tempfile
import unittest

from live_runtime.broker_exporter import BrokerExportResult
from live_runtime.shadow_phase import (
    BrokerCandidateRegistration,
    ReadOnlyShadowService,
    ShadowSessionStore,
)


UTC = timezone.utc
SYMBOLS = ("XAUUSD", "EURUSD", "USDJPY", "AUDUSD")


def registration() -> BrokerCandidateRegistration:
    return BrokerCandidateRegistration(
        candidate_id="fbs-demo-exact",
        legal_name="Observed Legal Name",
        server="Observed-Demo-Server",
        account_type="Observed Demo Type",
        regulatory_reference="PENDING_INDEPENDENT_REVIEW",
        legal_eligible=False,
        broker_symbols={symbol: symbol + ".observed" for symbol in SYMBOLS},
        instrument_spec_sha256={symbol: "a" * 64 for symbol in SYMBOLS},
    )


def export_result(symbol: str, status: str = "FINALIZED_EVIDENCE_APPENDED") -> BrokerExportResult:
    # The session store hashes the complete exporter receipt. A deliberately
    # minimal frozen instance keeps this unit test independent of filesystem
    # evidence append mechanics, which are tested by broker_exporter tests.
    result = object.__new__(BrokerExportResult)
    values = {
        "contract_id": "contract-1",
        "symbol": symbol,
        "raw_tick_partition": {"payload_sha256": "b" * 64} if status.startswith("FINALIZED") else None,
        "finalized_bar_segment": {"payload_sha256": "c" * 64} if status.startswith("FINALIZED") else None,
        "exported_at": datetime(2026, 7, 16, 0, 0, tzinfo=UTC),
        "coverage_metadata": {"test_fixture": True},
        "broker_binding_sha256": "d" * 64,
        "status": status,
        "paired_commit_receipt": None,
    }
    for key, value in values.items():
        object.__setattr__(result, key, value)
    return result


class ShadowPhaseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "shadow.sqlite3"
        self.store = ShadowSessionStore(self.path)
        self.addCleanup(self.store.close)
        self.registration = registration()
        self.now = datetime(2026, 7, 16, 0, 0, tzinfo=UTC)

    def test_registration_requires_exact_four_symbol_binding(self):
        with self.assertRaisesRegex(ValueError, "exactly the four"):
            BrokerCandidateRegistration(
                candidate_id="xm", legal_name="XM observed", server="XM-Demo",
                account_type="demo", regulatory_reference="pending",
                legal_eligible=False, broker_symbols={"XAUUSD": "GOLD"},
                instrument_spec_sha256={"XAUUSD": "a" * 64},
            )

    def test_complete_session_is_idempotent_and_persistent(self):
        results = {symbol: export_result(symbol) for symbol in SYMBOLS}
        first = self.store.record(
            self.registration, session_id="session-01", observed_at=self.now,
            results=results,
        )
        second = self.store.record(
            self.registration, session_id="session-01", observed_at=self.now,
            results=results,
        )
        self.assertEqual(first.payload_sha256, second.payload_sha256)
        self.assertEqual(first.status, "COMPLETE")
        self.assertEqual(self.store.completed_sessions(self.registration.candidate_id), 1)

    def test_same_session_cannot_be_rebound(self):
        results = {symbol: export_result(symbol) for symbol in SYMBOLS}
        self.store.record(self.registration, session_id="session-01", observed_at=self.now, results=results)
        with self.assertRaisesRegex(ValueError, "different evidence"):
            self.store.record(
                self.registration, session_id="session-01",
                observed_at=datetime(2026, 7, 16, 1, 0, tzinfo=UTC), results=results,
            )

    def test_only_twenty_complete_sessions_unlock_benchmark_review(self):
        results = {symbol: export_result(symbol) for symbol in SYMBOLS}
        for index in range(20):
            self.store.record(
                self.registration, session_id=f"session-{index:02d}",
                observed_at=self.now, results=results,
            )
            self.assertEqual(self.store.benchmark_ready(self.registration.candidate_id), index >= 19)

    def test_read_only_service_calls_all_symbols_and_holds_on_failure(self):
        calls = []
        def make(symbol):
            def run():
                calls.append(symbol)
                if symbol == "USDJPY":
                    raise ConnectionError("simulated read failure")
                return export_result(symbol)
            return run
        receipt = ReadOnlyShadowService(self.store).run_once(
            self.registration, session_id="failed-session", observed_at=self.now,
            exporters={symbol: make(symbol) for symbol in SYMBOLS},
        )
        self.assertEqual(set(calls), set(SYMBOLS))
        self.assertEqual(receipt.status, "HOLD")
        self.assertFalse(receipt.live_allowed)
        self.assertFalse(receipt.safe_to_demo_auto_order)
        self.assertEqual(receipt.max_lot, 0.01)


if __name__ == "__main__":
    unittest.main()
