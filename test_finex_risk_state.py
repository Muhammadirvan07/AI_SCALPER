from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from live_runtime.contracts import BrokerSpec
from live_runtime.finex_risk_state import (
    FinexRiskStateError,
    produce_finex_account_risk_state,
)
from live_runtime.health import MIN_FREE_DISK_BYTES
from live_runtime.journal import ExecutionJournal
from live_runtime.runtime_fact_collector import RuntimeFactCollector
from test_finex_readiness_binding import _hashes, _issue


UTC = timezone.utc
NOW = datetime(2026, 8, 28, 12, 0, tzinfo=UTC)
SYMBOL = "AUDUSD"
ALIAS = "a" * 64
IDENTITY = "b" * 64
SOURCE_KEY_ID = "risk-source-audusd-v1"
LEDGER_KEY_ID = "risk-state-audusd-v1"
SOURCE_KEY = b"finex-risk-source-audusd-test-key-32-bytes"
LEDGER_KEY = b"finex-risk-ledger-audusd-test-key-32-bytes"


class Adapter:
    max_tick_age_seconds = 1.0

    def __init__(self, spec):
        self.spec = spec

    def assert_account_binding(self):
        return {
            "account_alias": ALIAS,
            "server": "FinexBisnisSolusi-Demo",
            "currency": "USD",
            "balance": 1000.0,
            "equity": 1000.0,
            "margin": 0.0,
            "margin_free": 1000.0,
            "margin_level": 0.0,
            "trade_allowed": False,
            "trade_expert": True,
            "captured_at_utc": NOW,
        }

    def execution_fence_identity(self):
        return IDENTITY

    def get_broker_spec(self, symbol, broker_symbol, *, now):
        return self.spec

    def current_tick(self, broker_symbol, *, now):
        return {
            "bid": 0.65000,
            "ask": 0.65002,
            "time_utc": NOW - timedelta(milliseconds=100),
        }


class FinexRiskStateTests(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.journal = ExecutionJournal(self.root / "journal.sqlite3", clock_provider=lambda: NOW)
        self.spec = BrokerSpec(
            account_id=ALIAS,
            broker_legal_name="PT Finex Bisnis Solusi Futures",
            server="FinexBisnisSolusi-Demo",
            environment="DEMO",
            symbol=SYMBOL,
            broker_symbol="AUDUSD",
            account_currency="USD",
            digits=5,
            point=0.00001,
            tick_size=0.00001,
            tick_value=1.0,
            contract_size=100000.0,
            volume_min=0.01,
            volume_max=100.0,
            volume_step=0.01,
            stops_level_points=0,
            freeze_level_points=0,
            margin_per_lot=1000.0,
            session_calendar_sha256="c" * 64,
            captured_at=NOW,
        )
        specs = dict(_hashes(20))
        specs[SYMBOL] = self.spec.content_sha256
        self.binding = _issue(
            account_id_sha256=IDENTITY,
            account_alias_sha256=ALIAS,
            journal_sha256=self.journal.journal_sha256,
            broker_spec_sha256_by_symbol=tuple(specs.items()),
            risk_source_issuer_id_by_symbol=tuple(
                (symbol, f"risk-source-issuer-{symbol.lower()}-v1")
                for symbol in specs
            ),
            risk_source_key_id_by_symbol=tuple(
                (symbol, SOURCE_KEY_ID if symbol == SYMBOL else f"risk-source-{symbol.lower()}-v1")
                for symbol in specs
            ),
            risk_key_id_by_symbol=tuple(
                (symbol, LEDGER_KEY_ID if symbol == SYMBOL else f"risk-state-{symbol.lower()}-v1")
                for symbol in specs
            ),
        )

    def keys(self, key_id):
        if key_id == SOURCE_KEY_ID:
            return SOURCE_KEY
        if key_id == LEDGER_KEY_ID:
            return LEDGER_KEY
        raise KeyError(key_id)

    def fact(self, *, healthy=True):
        collector = RuntimeFactCollector(
            adapter=Adapter(self.spec),
            journal=self.journal,
            key_id=SOURCE_KEY_ID,
            key_provider=self.keys,
            clock_provider=lambda: NOW,
            clock_drift_provider=lambda: 0.0,
            heartbeat_provider=lambda: NOW - timedelta(seconds=1),
            audit_export_status_provider=lambda: healthy,
            backup_status_provider=lambda: True,
            health_source_evidence_sha256="d" * 64,
            health_trust_policy_sha256=self.binding.trust_policy_sha256,
            disk_free_provider=lambda _path: MIN_FREE_DISK_BYTES + 1,
        )
        return collector.collect(symbol=SYMBOL, broker_symbol="AUDUSD")

    def test_verified_runtime_fact_mints_bound_risk_state(self):
        evidence = produce_finex_account_risk_state(
            binding=self.binding,
            symbol=SYMBOL,
            runtime_fact_receipt=self.fact(),
            ledger_path=self.root / "risk.sqlite3",
            key_provider=self.keys,
            now=NOW + timedelta(milliseconds=500),
        )
        self.assertEqual(1, evidence.risk_receipt.event_sequence)
        self.assertEqual(LEDGER_KEY_ID, evidence.risk_receipt.key_id)
        self.assertEqual(SOURCE_KEY_ID, evidence.risk_receipt.latest_source_key_id)
        self.assertEqual(1000.0, evidence.risk_receipt.current_equity)

    def test_unhealthy_or_wrong_source_key_fails_before_ledger_creation(self):
        with self.assertRaisesRegex(FinexRiskStateError, "unhealthy"):
            produce_finex_account_risk_state(
                binding=self.binding,
                symbol=SYMBOL,
                runtime_fact_receipt=self.fact(healthy=False),
                ledger_path=self.root / "unhealthy.sqlite3",
                key_provider=self.keys,
                now=NOW + timedelta(milliseconds=500),
            )
        self.assertFalse((self.root / "unhealthy.sqlite3").exists())


if __name__ == "__main__":
    unittest.main()
