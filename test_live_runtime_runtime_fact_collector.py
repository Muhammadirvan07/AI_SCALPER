from __future__ import annotations

from dataclasses import fields, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
import tempfile
import unittest

from live_runtime.contracts import BrokerSpec
from live_runtime.health import MIN_FREE_DISK_BYTES
from live_runtime.health import RuntimeHealthDecision
from live_runtime.journal import ExecutionJournal
from live_runtime.runtime_fact_collector import (
    RUNTIME_FACT_RECEIPT_MAX_AGE_SECONDS,
    RuntimeFactCollectionError,
    RuntimeFactCollector,
    RuntimeFactReceipt,
    RuntimeFactVerificationError,
    verify_runtime_fact_receipt,
)


UTC = timezone.utc
NOW = datetime(2026, 7, 22, 3, 0, tzinfo=UTC)
TICK_AT = NOW - timedelta(milliseconds=250)
SECRET = "runtime-fact-receipt-secret-material-at-least-32-bytes"
KEY_ID = "runtime-fact-key-v1"
ACCOUNT_ID = "phillip-fx-demo"
SERVER = "PhillipSecuritiesJP-PROD"
SYMBOL = "EURUSD"
BROKER_SYMBOL = "EURUSD.ps01"
IDENTITY_SHA256 = "a" * 64


def broker_spec() -> BrokerSpec:
    return BrokerSpec(
        account_id=ACCOUNT_ID,
        broker_legal_name="Phillip Securities Japan, Ltd.",
        server=SERVER,
        environment="DEMO",
        symbol=SYMBOL,
        broker_symbol=BROKER_SYMBOL,
        account_currency="JPY",
        digits=5,
        point=0.00001,
        tick_size=0.00001,
        tick_value=100.0,
        contract_size=100_000.0,
        volume_min=0.01,
        volume_max=50.0,
        volume_step=0.01,
        stops_level_points=0,
        freeze_level_points=0,
        margin_per_lot=4_000.0,
        session_calendar_sha256="b" * 64,
        captured_at=NOW,
    )


class FakeAdapter:
    def __init__(self) -> None:
        self.account_calls = 0
        self.spec_calls: list[tuple[str, str, datetime]] = []
        self.tick_calls: list[tuple[str, datetime]] = []
        self.fail_at: str | None = None
        self.max_tick_age_seconds = 1.0

    def assert_account_binding(self):
        self.account_calls += 1
        if self.fail_at == "account":
            raise RuntimeError("account unavailable")
        return {
            "account_alias": ACCOUNT_ID,
            "server": SERVER,
            "currency": "JPY",
            "balance": 1_000_000.0,
            "equity": 1_000_000.0,
            "margin": 0.0,
            "margin_free": 1_000_000.0,
            "margin_level": 0.0,
            "trade_allowed": False,
            "trade_expert": True,
            "captured_at_utc": NOW,
        }

    def execution_fence_identity(self):
        return IDENTITY_SHA256

    def get_broker_spec(self, symbol, broker_symbol, *, now):
        self.spec_calls.append((symbol, broker_symbol, now))
        if self.fail_at == "spec":
            raise RuntimeError("spec unavailable")
        return broker_spec()

    def current_tick(self, broker_symbol, *, now):
        self.tick_calls.append((broker_symbol, now))
        if self.fail_at == "tick":
            raise RuntimeError("tick unavailable")
        return {
            "bid": 1.17234,
            "ask": 1.17236,
            "time_utc": TICK_AT,
            "age_seconds": 0.25,
        }


class JournalView:
    def __init__(
        self,
        path: Path,
        *,
        integrity_ok: bool = True,
        kill_switch_latched: bool = False,
    ) -> None:
        self.path = path
        self.journal_sha256 = "c" * 64
        self.integrity_ok = integrity_ok
        self.kill_switch_latched = kill_switch_latched

    def integrity_check(self):
        return self.integrity_ok

    def kill_switch_status(self):
        return {"latched": self.kill_switch_latched}


def key_provider(key_id: str):
    if key_id != KEY_ID:
        raise KeyError(key_id)
    return SECRET


class RuntimeFactCollectorTests(unittest.TestCase):
    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.journal = ExecutionJournal(
            self.root / "execution.sqlite3",
            clock_provider=lambda: NOW,
        )
        self.adapter = FakeAdapter()

    def collector(self, **changes) -> RuntimeFactCollector:
        values = {
            "adapter": self.adapter,
            "journal": self.journal,
            "key_id": KEY_ID,
            "key_provider": key_provider,
            "clock_provider": lambda: NOW,
            "clock_drift_provider": lambda: 0.125,
            "heartbeat_provider": lambda: NOW - timedelta(seconds=5),
            "audit_export_status_provider": lambda: True,
            "backup_status_provider": lambda: True,
            "disk_free_provider": lambda _path: MIN_FREE_DISK_BYTES + 1,
        }
        values.update(changes)
        return RuntimeFactCollector(**values)

    def verify(self, receipt, **changes):
        values = {
            "expected_account_id": ACCOUNT_ID,
            "expected_server": SERVER,
            "expected_environment": "DEMO",
            "expected_symbol": SYMBOL,
            "expected_broker_symbol": BROKER_SYMBOL,
            "expected_account_runtime_identity_sha256": IDENTITY_SHA256,
            "expected_broker_spec_sha256": broker_spec().content_sha256,
            "expected_journal_sha256": self.journal.journal_sha256,
            "expected_key_id": KEY_ID,
            "key_provider": key_provider,
            "clock_provider": lambda: NOW + timedelta(milliseconds=500),
        }
        values.update(changes)
        return verify_runtime_fact_receipt(receipt, **values)

    def test_collects_exact_adapter_and_journal_facts_and_verifies_receipt(self):
        receipt = self.collector().collect(
            symbol=SYMBOL,
            broker_symbol=BROKER_SYMBOL,
        )

        self.assertEqual(1, self.adapter.account_calls)
        self.assertEqual([(SYMBOL, BROKER_SYMBOL, NOW)], self.adapter.spec_calls)
        self.assertEqual([(BROKER_SYMBOL, NOW)], self.adapter.tick_calls)
        self.assertEqual(ACCOUNT_ID, receipt.account_id)
        self.assertEqual(SERVER, receipt.server)
        self.assertEqual(IDENTITY_SHA256, receipt.account_runtime_identity_sha256)
        self.assertEqual(1_000_000.0, receipt.account_fact.equity)
        self.assertEqual("JPY", receipt.account_fact.currency)
        self.assertEqual(broker_spec(), receipt.broker_spec)
        self.assertEqual(1.17234, receipt.tick.bid)
        self.assertEqual(TICK_AT, receipt.tick.time_utc)
        self.assertEqual(self.journal.journal_sha256, receipt.journal_sha256)
        self.assertEqual(KEY_ID, receipt.key_id)
        self.assertTrue(receipt.health_decision.healthy)
        self.assertFalse(receipt.live_allowed)
        self.assertFalse(receipt.safe_to_demo_auto_order)
        self.assertTrue(receipt.verify_signature(SECRET))
        self.assertIs(receipt, self.verify(receipt))

    def test_receipt_subclass_cannot_override_signature_verification(self):
        class ForgedRuntimeFactReceipt(RuntimeFactReceipt):
            def verify_signature(self, secret):  # type: ignore[no-untyped-def]
                return True

        unsigned = self.collector().collect(
            symbol=SYMBOL,
            broker_symbol=BROKER_SYMBOL,
        )
        forged = ForgedRuntimeFactReceipt(
            **{
                field.name: getattr(unsigned, field.name)
                for field in fields(RuntimeFactReceipt)
            }
        )
        with self.assertRaisesRegex(TypeError, "exact RuntimeFactReceipt"):
            self.verify(forged)

    def test_nested_health_decision_subclass_is_rejected(self):
        class ForgedHealthDecision(RuntimeHealthDecision):
            pass

        receipt = self.collector().collect(
            symbol=SYMBOL,
            broker_symbol=BROKER_SYMBOL,
        )
        forged_decision = object.__new__(ForgedHealthDecision)
        for field in fields(RuntimeHealthDecision):
            object.__setattr__(
                forged_decision,
                field.name,
                getattr(receipt.health_decision, field.name),
            )
        with self.assertRaisesRegex(TypeError, "exact RuntimeHealthDecision"):
            replace(receipt, health_decision=forged_decision)

    def test_observed_unhealthy_facts_mint_signed_deny_receipt(self):
        journal = JournalView(
            self.root / "execution.sqlite3",
            integrity_ok=False,
            kill_switch_latched=True,
        )
        receipt = self.collector(
            journal=journal,
            clock_drift_provider=lambda: 2.0,
            heartbeat_provider=lambda: NOW - timedelta(seconds=31),
            audit_export_status_provider=lambda: False,
            backup_status_provider=lambda: False,
            disk_free_provider=lambda _path: MIN_FREE_DISK_BYTES - 1,
        ).collect(symbol=SYMBOL, broker_symbol=BROKER_SYMBOL)

        self.assertFalse(receipt.health_decision.healthy)
        self.assertEqual(
            {
                "AUDIT_EXPORT_FAILED",
                "BACKUP_STALE",
                "CLOCK_DRIFT_EXCEEDED",
                "DATABASE_INTEGRITY_FAILED",
                "DISK_SPACE_LOW",
                "KILL_SWITCH_LATCHED",
                "OFF_HOST_HEARTBEAT_STALE",
            },
            set(receipt.health_decision.reason_codes),
        )
        self.assertTrue(receipt.verify_signature(SECRET))
        verified = self.verify(
            receipt,
            expected_journal_sha256=journal.journal_sha256,
        )
        self.assertIs(receipt, verified)

    def test_missing_or_unavailable_required_provider_fails_closed(self):
        with self.assertRaisesRegex(TypeError, "heartbeat_provider"):
            self.collector(heartbeat_provider=None)

        def unavailable_heartbeat():
            raise OSError("network unavailable")

        collector = self.collector(heartbeat_provider=unavailable_heartbeat)
        with self.assertRaises(RuntimeFactCollectionError) as raised:
            collector.collect(symbol=SYMBOL, broker_symbol=BROKER_SYMBOL)
        self.assertEqual(
            "OFF_HOST_HEARTBEAT_PROVIDER_UNAVAILABLE",
            raised.exception.reason_code,
        )

    def test_adapter_or_signing_key_failure_produces_no_receipt(self):
        self.adapter.fail_at = "tick"
        with self.assertRaises(RuntimeFactCollectionError) as raised:
            self.collector().collect(symbol=SYMBOL, broker_symbol=BROKER_SYMBOL)
        self.assertEqual("ADAPTER_CURRENT_TICK_UNAVAILABLE", raised.exception.reason_code)

        self.adapter.fail_at = None
        with self.assertRaises(RuntimeFactCollectionError) as raised:
            self.collector(
                key_provider=lambda _key_id: (_ for _ in ()).throw(KeyError("missing"))
            ).collect(symbol=SYMBOL, broker_symbol=BROKER_SYMBOL)
        self.assertEqual("SIGNING_KEY_UNAVAILABLE", raised.exception.reason_code)

    def test_verifier_rejects_tamper_stale_and_key_mismatch(self):
        receipt = self.collector().collect(
            symbol=SYMBOL,
            broker_symbol=BROKER_SYMBOL,
        )
        tampered_tick = replace(receipt.tick, bid=receipt.tick.bid - 0.00001)
        tampered = replace(
            receipt,
            tick=tampered_tick,
            tick_sha256=tampered_tick.content_sha256,
        )
        with self.assertRaises(RuntimeFactVerificationError) as raised:
            self.verify(tampered)
        self.assertIn("INVALID_SIGNATURE", raised.exception.reason_codes)

        with self.assertRaises(RuntimeFactVerificationError) as raised:
            self.verify(
                receipt,
                clock_provider=lambda: receipt.valid_until_utc,
            )
        self.assertIn("RUNTIME_FACT_RECEIPT_STALE", raised.exception.reason_codes)

        with self.assertRaises(RuntimeFactVerificationError) as raised:
            self.verify(receipt, expected_key_id="runtime-fact-key-v2")
        self.assertIn("KEY_ID_MISMATCH", raised.exception.reason_codes)

    def test_verifier_rejects_binding_mismatch_and_unavailable_key(self):
        receipt = self.collector().collect(
            symbol=SYMBOL,
            broker_symbol=BROKER_SYMBOL,
        )
        with self.assertRaises(RuntimeFactVerificationError) as raised:
            self.verify(receipt, expected_server="Other-Server")
        self.assertIn("SERVER_BINDING_MISMATCH", raised.exception.reason_codes)

        with self.assertRaises(RuntimeFactVerificationError) as raised:
            self.verify(
                receipt,
                key_provider=lambda _key_id: (_ for _ in ()).throw(KeyError("missing")),
            )
        self.assertIn("VERIFICATION_KEY_UNAVAILABLE", raised.exception.reason_codes)

    def test_receipt_lifetime_is_bounded_to_executor_fact_age(self):
        receipt = self.collector().collect(
            symbol=SYMBOL,
            broker_symbol=BROKER_SYMBOL,
        )
        self.assertEqual(
            timedelta(seconds=RUNTIME_FACT_RECEIPT_MAX_AGE_SECONDS),
            receipt.valid_until_utc - receipt.observed_at_utc,
        )

    def test_receipt_time_is_sampled_after_all_fact_providers(self):
        clock = {"now": NOW}

        def delayed_backup():
            clock["now"] = NOW + timedelta(milliseconds=500)
            return True

        receipt = self.collector(
            clock_provider=lambda: clock["now"],
            backup_status_provider=delayed_backup,
        ).collect(symbol=SYMBOL, broker_symbol=BROKER_SYMBOL)

        self.assertEqual(NOW + timedelta(milliseconds=500), receipt.observed_at_utc)
        self.assertEqual(0.75, receipt.tick.age_seconds)
        self.assertTrue(receipt.health_decision.healthy)

    def test_collection_that_exceeds_receipt_age_fails_closed(self):
        clock = {"now": NOW}

        def delayed_backup():
            clock["now"] = NOW + timedelta(seconds=2)
            return True

        with self.assertRaises(RuntimeFactCollectionError) as raised:
            self.collector(
                clock_provider=lambda: clock["now"],
                backup_status_provider=delayed_backup,
            ).collect(symbol=SYMBOL, broker_symbol=BROKER_SYMBOL)
        self.assertEqual(
            "BROKER_FACT_COLLECTION_EXPIRED",
            raised.exception.reason_code,
        )


if __name__ == "__main__":
    unittest.main()
