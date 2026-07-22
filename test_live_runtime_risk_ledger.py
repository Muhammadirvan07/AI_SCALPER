from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from dataclasses import InitVar, dataclass
import hashlib
import hmac
import sqlite3
import tempfile
import unittest

from live_runtime.risk_ledger import (
    AccountRiskSnapshot,
    ClosedTradeRiskEvent,
    DurableRiskLedger,
    EntryRiskEvent,
    RiskLedgerBinding,
    RiskLedgerBindingError,
    RiskLedgerDuplicateError,
    RiskLedgerIntegrityError,
    RiskLedgerRollbackError,
    RiskLedgerSourceError,
    RiskSourceReceipt,
    RiskStateReceipt,
    verify_risk_source_receipt,
    verify_risk_state_receipt,
)
from live_runtime.contracts import CanonicalContract, canonical_json


UTC = timezone.utc
START = datetime(2026, 7, 22, 0, 0, 0, tzinfo=UTC)
JOURNAL_SHA256 = "a" * 64
BROKER_SPEC_SHA256 = "b" * 64
RAW_ACCOUNT_LOGIN = "987654321"
ACCOUNT_ID_SHA256 = hashlib.sha256(RAW_ACCOUNT_LOGIN.encode("utf-8")).hexdigest()
KEY_ID = "risk-ledger-key-v1"
KEY = b"risk-ledger-test-key-material-32-bytes-minimum"
SOURCE_KEY_ID = "risk-source-key-v1"
SOURCE_KEY = b"risk-source-test-key-material-32-bytes-minimum"
SOURCE_ISSUER = "test-broker-evidence-issuer"
SOURCE_DOMAIN = b"AI_SCALPER_DURABLE_RISK_SOURCE_V1\x00"
_UPSTREAM_SEAL = object()


@dataclass(frozen=True)
class TestUpstreamReceipt(CanonicalContract):
    receipt_type: str
    receipt_id: str
    _seal: InitVar[object | None] = None

    def __post_init__(self, _seal: object | None) -> None:
        if _seal is not _UPSTREAM_SEAL:
            raise TypeError("test upstream receipt is sealed")


def _upstream_verifier(receipt_type: str, receipt: object) -> object:
    if type(receipt) is not TestUpstreamReceipt:
        raise TypeError("upstream receipt type is not exact")
    if receipt.receipt_type != receipt_type:
        raise ValueError("upstream receipt kind does not match")
    return receipt


def _signed_source_payload(unsigned: dict[str, object]) -> dict[str, object]:
    signature = hmac.new(
        SOURCE_KEY,
        SOURCE_DOMAIN + canonical_json(unsigned).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return {**unsigned, "signature_hmac_sha256": signature}


class TrustedLedgerFixture(DurableRiskLedger):
    """Test-only source issuer; production has no raw ingestion fallback."""

    def _provenance(self, event: CanonicalContract, source_kind: str):
        upstream_type = {
            "ACCOUNT_SNAPSHOT": "RUNTIME_FACT_RECEIPT",
            "ENTRY": "EXECUTION_RECEIPT",
            "CLOSED_TRADE": "BROKER_DEAL_RECEIPT",
        }[source_kind]
        upstream = TestUpstreamReceipt(
            receipt_type=upstream_type,
            receipt_id=f"upstream-{source_kind.lower()}-{event.content_sha256[:20]}",
            _seal=_UPSTREAM_SEAL,
        )
        event_time = getattr(event, "observed_at_utc", None) or getattr(
            event, "occurred_at_utc"
        )
        unsigned = {
            "source_receipt_id": f"source-{event.content_sha256[:32]}",
            "source_kind": source_kind,
            "issuer_id": SOURCE_ISSUER,
            "key_id": SOURCE_KEY_ID,
            "binding": self.binding.to_canonical_dict(),
            "event_sha256": event.content_sha256,
            "upstream_receipt_type": upstream_type,
            "upstream_receipt_sha256": upstream.content_sha256,
            "observed_at_utc": event_time,
            "valid_until_utc": event_time + timedelta(seconds=5),
            "schema_version": "durable-risk-source-receipt-v1",
        }
        payload = _signed_source_payload(unsigned)
        source = verify_risk_source_receipt(
            payload,
            expected_event=event,
            expected_binding=self.binding,
            key_provider=lambda _key_id: SOURCE_KEY,
            trusted_issuer_keys={SOURCE_ISSUER: (SOURCE_KEY_ID,)},
            clock_provider=self._clock_provider,
        )
        return source, upstream

    def append_account_snapshot(self, snapshot, **kwargs):
        if kwargs:
            return super().append_account_snapshot(snapshot, **kwargs)
        source, upstream = self._provenance(snapshot, "ACCOUNT_SNAPSHOT")
        return super().append_account_snapshot(
            snapshot, source_receipt=source, upstream_receipt=upstream
        )

    def append_entry(self, event, **kwargs):
        if kwargs:
            return super().append_entry(event, **kwargs)
        source, upstream = self._provenance(event, "ENTRY")
        return super().append_entry(
            event, source_receipt=source, upstream_receipt=upstream
        )

    def append_closed_trade(self, event, **kwargs):
        if kwargs:
            return super().append_closed_trade(event, **kwargs)
        source, upstream = self._provenance(event, "CLOSED_TRADE")
        return super().append_closed_trade(
            event, source_receipt=source, upstream_receipt=upstream
        )


class MutableClock:
    def __init__(self, value: datetime) -> None:
        self.value = value

    def __call__(self) -> datetime:
        return self.value


class DurableRiskLedgerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "risk-ledger.sqlite3"
        self.binding = RiskLedgerBinding(
            account_id_sha256=ACCOUNT_ID_SHA256,
            server="PhillipSecuritiesJP-PROD",
            environment="DEMO",
            journal_sha256=JOURNAL_SHA256,
            broker_spec_sha256=BROKER_SPEC_SHA256,
            account_currency="JPY",
        )
        self.clock = MutableClock(START)
        self.keys = {KEY_ID: KEY}

    def _key_provider(self, key_id: str) -> bytes:
        return self.keys[key_id]

    def _ledger(
        self,
        *,
        path: Path | None = None,
        binding: RiskLedgerBinding | None = None,
        expected_receipt: RiskStateReceipt | None = None,
        key_provider=None,
    ) -> TrustedLedgerFixture:
        return TrustedLedgerFixture(
            path or self.path,
            binding=binding or self.binding,
            key_id=KEY_ID,
            key_provider=key_provider or self._key_provider,
            source_key_provider=lambda _key_id: SOURCE_KEY,
            trusted_source_issuer_keys={SOURCE_ISSUER: (SOURCE_KEY_ID,)},
            upstream_receipt_verifier=_upstream_verifier,
            clock_provider=self.clock,
            expected_receipt=expected_receipt,
        )

    def _snapshot(
        self,
        snapshot_id: str,
        *,
        at: datetime,
        daily: str = "day-2026-07-22",
        weekly: str = "week-2026-W30",
        equity: float = 100_000.0,
    ) -> AccountRiskSnapshot:
        self.clock.value = at
        return AccountRiskSnapshot(
            snapshot_id=snapshot_id,
            binding=self.binding,
            observed_at_utc=at,
            daily_baseline_id=daily,
            weekly_baseline_id=weekly,
            equity=equity,
        )

    def _entry(
        self,
        entry_id: str,
        *,
        at: datetime,
        daily: str = "day-2026-07-22",
        weekly: str = "week-2026-W30",
        symbol: str = "XAUUSD",
    ) -> EntryRiskEvent:
        self.clock.value = at
        return EntryRiskEvent(
            entry_id=entry_id,
            binding=self.binding,
            occurred_at_utc=at,
            daily_baseline_id=daily,
            weekly_baseline_id=weekly,
            symbol=symbol,
        )

    def _closed_trade(
        self,
        trade_id: str,
        entry_id: str,
        *,
        at: datetime,
        outcome: str,
        pnl: float,
        daily: str = "day-2026-07-22",
        weekly: str = "week-2026-W30",
        symbol: str = "XAUUSD",
    ) -> ClosedTradeRiskEvent:
        self.clock.value = at
        return ClosedTradeRiskEvent(
            trade_id=trade_id,
            entry_id=entry_id,
            binding=self.binding,
            occurred_at_utc=at,
            daily_baseline_id=daily,
            weekly_baseline_id=weekly,
            symbol=symbol,
            outcome=outcome,
            realized_pnl_account_currency=pnl,
        )

    def test_wal_full_and_state_survive_restart_with_checkpoint(self) -> None:
        ledger = self._ledger()
        self.assertEqual(
            {"journal_mode": "WAL", "synchronous": "FULL"},
            dict(ledger.storage_settings()),
        )
        ledger.append_account_snapshot(self._snapshot("snapshot-1", at=START))
        entry_receipt = ledger.append_entry(
            self._entry("entry-1", at=START + timedelta(seconds=1))
        )
        self.assertEqual(2, entry_receipt.event_sequence)
        self.assertEqual(1, entry_receipt.entries_today)
        self.assertTrue(verify_risk_state_receipt(entry_receipt, self._key_provider))

        self.clock.value = START + timedelta(seconds=2)
        restarted = self._ledger(expected_receipt=entry_receipt)
        restarted_receipt = restarted.current_receipt()
        self.assertEqual(entry_receipt.head_hmac_sha256, restarted_receipt.head_hmac_sha256)
        self.assertEqual(1, restarted_receipt.entries_today)
        self.assertEqual(100_000.0, restarted_receipt.current_equity)
        self.assertTrue(restarted.verify_integrity(expected_receipt=entry_receipt))

    def test_two_losses_latch_and_persist_across_restart(self) -> None:
        ledger = self._ledger()
        ledger.append_account_snapshot(self._snapshot("snapshot-1", at=START))
        ledger.append_entry(self._entry("entry-1", at=START + timedelta(seconds=1)))
        first_loss = ledger.append_closed_trade(
            self._closed_trade(
                "trade-1",
                "entry-1",
                at=START + timedelta(seconds=2),
                outcome="LOSS",
                pnl=-250.0,
            )
        )
        self.assertEqual(1, first_loss.consecutive_losses)
        self.assertFalse(first_loss.loss_latch_active)

        ledger.append_entry(self._entry("entry-2", at=START + timedelta(seconds=3)))
        second_loss = ledger.append_closed_trade(
            self._closed_trade(
                "trade-2",
                "entry-2",
                at=START + timedelta(seconds=4),
                outcome="LOSS",
                pnl=-125.0,
            )
        )
        self.assertEqual(2, second_loss.consecutive_losses)
        self.assertTrue(second_loss.loss_latch_active)

        self.clock.value = START + timedelta(seconds=5)
        restarted = self._ledger(expected_receipt=second_loss)
        receipt = restarted.current_receipt()
        self.assertEqual(2, receipt.consecutive_losses)
        self.assertTrue(receipt.loss_latch_active)

    def test_daily_and_weekly_baselines_roll_only_on_exact_new_ids(self) -> None:
        ledger = self._ledger()
        ledger.append_account_snapshot(
            self._snapshot("snapshot-1", at=START, equity=100_000.0)
        )
        ledger.append_entry(self._entry("entry-1", at=START + timedelta(seconds=1)))
        same_session = ledger.append_account_snapshot(
            self._snapshot(
                "snapshot-2",
                at=START + timedelta(seconds=2),
                equity=110_000.0,
            )
        )
        self.assertEqual(100_000.0, same_session.daily_baseline_equity)
        self.assertEqual(100_000.0, same_session.weekly_baseline_equity)
        self.assertEqual(110_000.0, same_session.high_water_equity)
        self.assertEqual(1, same_session.entries_today)

        next_day = ledger.append_account_snapshot(
            self._snapshot(
                "snapshot-3",
                at=START + timedelta(seconds=3),
                daily="day-2026-07-23",
                equity=105_000.0,
            )
        )
        self.assertEqual("day-2026-07-23", next_day.daily_baseline_id)
        self.assertEqual(105_000.0, next_day.daily_baseline_equity)
        self.assertEqual(100_000.0, next_day.weekly_baseline_equity)
        self.assertEqual(0, next_day.entries_today)
        ledger.append_entry(
            self._entry(
                "entry-2",
                at=START + timedelta(seconds=4),
                daily="day-2026-07-23",
            )
        )

        next_week = ledger.append_account_snapshot(
            self._snapshot(
                "snapshot-4",
                at=START + timedelta(seconds=5),
                daily="day-2026-07-27",
                weekly="week-2026-W31",
                equity=120_000.0,
            )
        )
        self.assertEqual(120_000.0, next_week.daily_baseline_equity)
        self.assertEqual(120_000.0, next_week.weekly_baseline_equity)
        self.assertEqual(120_000.0, next_week.high_water_equity)
        self.assertEqual(0, next_week.entries_today)

        with self.assertRaisesRegex(RiskLedgerRollbackError, "daily baseline"):
            ledger.append_account_snapshot(
                self._snapshot(
                    "snapshot-rollback",
                    at=START + timedelta(seconds=6),
                    daily="day-2026-07-22",
                    weekly="week-2026-W31",
                    equity=119_000.0,
                )
            )

    def test_duplicate_event_and_duplicate_closed_entry_fail_closed(self) -> None:
        ledger = self._ledger()
        ledger.append_account_snapshot(self._snapshot("snapshot-1", at=START))
        entry = self._entry("entry-1", at=START + timedelta(seconds=1))
        first = ledger.append_entry(entry)
        with self.assertRaises(RiskLedgerDuplicateError):
            ledger.append_entry(entry)
        self.assertEqual(first.head_hmac_sha256, ledger.current_receipt().head_hmac_sha256)

        ledger.append_closed_trade(
            self._closed_trade(
                "trade-1",
                "entry-1",
                at=START + timedelta(seconds=2),
                outcome="WIN",
                pnl=500.0,
            )
        )
        with self.assertRaises(RiskLedgerDuplicateError):
            ledger.append_closed_trade(
                self._closed_trade(
                    "trade-2",
                    "entry-1",
                    at=START + timedelta(seconds=3),
                    outcome="WIN",
                    pnl=100.0,
                )
            )

    def test_semantic_sql_tamper_is_detected_and_events_are_append_only(self) -> None:
        ledger = self._ledger()
        ledger.append_account_snapshot(self._snapshot("snapshot-1", at=START))
        ledger.append_entry(self._entry("entry-1", at=START + timedelta(seconds=1)))

        connection = sqlite3.connect(self.path)
        with self.assertRaisesRegex(sqlite3.DatabaseError, "append_only"):
            connection.execute(
                "UPDATE risk_events SET daily_baseline_id='tampered' WHERE sequence=1"
            )
        connection.rollback()
        connection.execute("UPDATE risk_state SET entries_today=99 WHERE singleton=1")
        connection.commit()
        connection.close()

        with self.assertRaisesRegex(RiskLedgerIntegrityError, "materialized risk state"):
            ledger.current_receipt()
        with self.assertRaises(RiskLedgerIntegrityError):
            self._ledger()

    def test_key_mismatch_is_rejected_on_restart_and_receipt_verification(self) -> None:
        ledger = self._ledger()
        receipt = ledger.append_account_snapshot(self._snapshot("snapshot-1", at=START))
        wrong_provider = lambda _key_id: b"different-risk-ledger-key-material-32-bytes"

        self.assertFalse(verify_risk_state_receipt(receipt, wrong_provider))
        with self.assertRaisesRegex(RiskLedgerIntegrityError, "key does not match"):
            self._ledger(key_provider=wrong_provider)

    def test_naive_timestamps_and_future_or_regressed_events_are_rejected(self) -> None:
        naive = START.replace(tzinfo=None)
        with self.assertRaisesRegex(ValueError, "timezone-aware UTC"):
            AccountRiskSnapshot(
                snapshot_id="snapshot-naive",
                binding=self.binding,
                observed_at_utc=naive,
                daily_baseline_id="day-2026-07-22",
                weekly_baseline_id="week-2026-W30",
                equity=100_000.0,
            )

        ledger = self._ledger()
        ledger.append_account_snapshot(self._snapshot("snapshot-1", at=START))
        with self.assertRaisesRegex(RiskLedgerSourceError, "future"):
            ledger.append_entry(
                EntryRiskEvent(
                    entry_id="entry-future",
                    binding=self.binding,
                    occurred_at_utc=START + timedelta(seconds=5),
                    daily_baseline_id="day-2026-07-22",
                    weekly_baseline_id="week-2026-W30",
                    symbol="XAUUSD",
                )
            )

        self.clock.value = START + timedelta(seconds=10)
        ledger.append_entry(
            EntryRiskEvent(
                entry_id="entry-1",
                binding=self.binding,
                occurred_at_utc=START + timedelta(seconds=10),
                daily_baseline_id="day-2026-07-22",
                weekly_baseline_id="week-2026-W30",
                symbol="XAUUSD",
            )
        )
        with self.assertRaisesRegex(RiskLedgerRollbackError, "timestamp regressed"):
            ledger.append_account_snapshot(
                AccountRiskSnapshot(
                    snapshot_id="snapshot-old",
                    binding=self.binding,
                    observed_at_utc=START + timedelta(seconds=9),
                    daily_baseline_id="day-2026-07-22",
                    weekly_baseline_id="week-2026-W30",
                    equity=99_000.0,
                )
            )

    def test_external_receipt_detects_database_rollback(self) -> None:
        ledger = self._ledger()
        ledger.append_account_snapshot(self._snapshot("snapshot-1", at=START))
        old_path = Path(self.directory.name) / "risk-ledger-old.sqlite3"
        source = sqlite3.connect(self.path)
        destination = sqlite3.connect(old_path)
        source.backup(destination)
        destination.close()
        source.close()

        latest = ledger.append_entry(
            self._entry("entry-1", at=START + timedelta(seconds=1))
        )
        self.clock.value = START + timedelta(seconds=2)
        with self.assertRaisesRegex(RiskLedgerRollbackError, "older"):
            self._ledger(path=old_path, expected_receipt=latest)

    def test_exact_account_server_journal_and_currency_binding_is_enforced(self) -> None:
        ledger = self._ledger()
        ledger.append_account_snapshot(self._snapshot("snapshot-1", at=START))
        wrong_binding = RiskLedgerBinding(
            account_id_sha256=self.binding.account_id_sha256,
            server="DIFFERENT-SERVER",
            environment=self.binding.environment,
            journal_sha256=self.binding.journal_sha256,
            broker_spec_sha256=self.binding.broker_spec_sha256,
            account_currency=self.binding.account_currency,
        )
        with self.assertRaises(RiskLedgerBindingError):
            self._ledger(binding=wrong_binding)

        self.clock.value = START + timedelta(seconds=1)
        with self.assertRaises(RiskLedgerBindingError):
            ledger.append_entry(
                EntryRiskEvent(
                    entry_id="entry-wrong-binding",
                    binding=wrong_binding,
                    occurred_at_utc=self.clock.value,
                    daily_baseline_id="day-2026-07-22",
                    weekly_baseline_id="week-2026-W30",
                    symbol="XAUUSD",
                )
            )

    def test_raw_ingestion_is_disabled_and_receipt_exposes_verified_sources(self) -> None:
        ledger = self._ledger()
        snapshot = self._snapshot("snapshot-source-1", at=START)
        entry = self._entry("entry-source-1", at=START)
        closed = self._closed_trade(
            "trade-source-1",
            "entry-source-1",
            at=START,
            outcome="WIN",
            pnl=1.0,
        )
        for method, event in (
            (DurableRiskLedger.append_account_snapshot, snapshot),
            (DurableRiskLedger.append_entry, entry),
            (DurableRiskLedger.append_closed_trade, closed),
        ):
            with self.subTest(method=method.__name__):
                with self.assertRaisesRegex(TypeError, "source_receipt"):
                    method(ledger, event)

        receipt = ledger.append_account_snapshot(snapshot)
        self.assertTrue(receipt.source_verified)
        self.assertEqual(1, receipt.source_evidence_count)
        self.assertEqual(SOURCE_ISSUER, receipt.latest_source_issuer_id)
        self.assertEqual(SOURCE_KEY_ID, receipt.latest_source_key_id)
        self.assertNotEqual("0" * 64, receipt.source_receipt_chain_sha256)

    def test_forged_stale_future_and_cross_binding_sources_fail_closed(self) -> None:
        ledger = self._ledger()
        snapshot = self._snapshot("snapshot-source-1", at=START)
        source, _upstream = ledger._provenance(snapshot, "ACCOUNT_SNAPSHOT")

        forged = source.to_canonical_dict()
        forged["signature_hmac_sha256"] = "0" * 64
        with self.assertRaisesRegex(RiskLedgerSourceError, "HMAC"):
            verify_risk_source_receipt(
                forged,
                expected_event=snapshot,
                expected_binding=self.binding,
                key_provider=lambda _key_id: SOURCE_KEY,
                trusted_issuer_keys={SOURCE_ISSUER: (SOURCE_KEY_ID,)},
                clock_provider=self.clock,
            )

        self.clock.value = START + timedelta(seconds=6)
        with self.assertRaisesRegex(RiskLedgerSourceError, "stale"):
            DurableRiskLedger.append_account_snapshot(
                ledger,
                snapshot,
                source_receipt=source,
                upstream_receipt=_upstream,
            )
        self.clock.value = START

        for field, replacement in (
            ("account_id_sha256", "d" * 64),
            ("server", "OTHER-SERVER"),
            ("environment", "LIVE"),
            ("journal_sha256", "e" * 64),
            ("broker_spec_sha256", "f" * 64),
            ("account_currency", "USD"),
        ):
            with self.subTest(field=field):
                unsigned = source.signing_payload
                unsigned["binding"] = dict(unsigned["binding"])
                unsigned["binding"][field] = replacement
                cross_bound = _signed_source_payload(unsigned)
                with self.assertRaises(RiskLedgerBindingError):
                    verify_risk_source_receipt(
                        cross_bound,
                        expected_event=snapshot,
                        expected_binding=self.binding,
                        key_provider=lambda _key_id: SOURCE_KEY,
                        trusted_issuer_keys={SOURCE_ISSUER: (SOURCE_KEY_ID,)},
                        clock_provider=self.clock,
                    )

        future_event = AccountRiskSnapshot(
            snapshot_id="snapshot-future-source",
            binding=self.binding,
            observed_at_utc=START + timedelta(seconds=3),
            daily_baseline_id="day-2026-07-22",
            weekly_baseline_id="week-2026-W30",
            equity=100_000.0,
        )
        upstream = TestUpstreamReceipt(
            receipt_type="RUNTIME_FACT_RECEIPT",
            receipt_id="upstream-future",
            _seal=_UPSTREAM_SEAL,
        )
        future_unsigned = {
            "source_receipt_id": "source-future",
            "source_kind": "ACCOUNT_SNAPSHOT",
            "issuer_id": SOURCE_ISSUER,
            "key_id": SOURCE_KEY_ID,
            "binding": self.binding.to_canonical_dict(),
            "event_sha256": future_event.content_sha256,
            "upstream_receipt_type": "RUNTIME_FACT_RECEIPT",
            "upstream_receipt_sha256": upstream.content_sha256,
            "observed_at_utc": START + timedelta(seconds=3),
            "valid_until_utc": START + timedelta(seconds=5),
            "schema_version": "durable-risk-source-receipt-v1",
        }
        with self.assertRaisesRegex(RiskLedgerSourceError, "future"):
            verify_risk_source_receipt(
                _signed_source_payload(future_unsigned),
                expected_event=future_event,
                expected_binding=self.binding,
                key_provider=lambda _key_id: SOURCE_KEY,
                trusted_issuer_keys={SOURCE_ISSUER: (SOURCE_KEY_ID,)},
                clock_provider=self.clock,
            )

    def test_exact_upstream_receipt_and_one_time_source_consumption_are_required(self) -> None:
        ledger = self._ledger()
        snapshot = self._snapshot("snapshot-source-1", at=START)
        source, upstream = ledger._provenance(snapshot, "ACCOUNT_SNAPSHOT")

        with self.assertRaisesRegex(RiskLedgerSourceError, "upstream"):
            DurableRiskLedger.append_account_snapshot(
                ledger,
                snapshot,
                source_receipt=source,
                upstream_receipt=object(),
            )
        wrong_upstream = TestUpstreamReceipt(
            receipt_type="RUNTIME_FACT_RECEIPT",
            receipt_id="wrong-upstream",
            _seal=_UPSTREAM_SEAL,
        )
        with self.assertRaisesRegex(RiskLedgerSourceError, "hash"):
            DurableRiskLedger.append_account_snapshot(
                ledger,
                snapshot,
                source_receipt=source,
                upstream_receipt=wrong_upstream,
            )

        DurableRiskLedger.append_account_snapshot(
            ledger,
            snapshot,
            source_receipt=source,
            upstream_receipt=upstream,
        )
        with self.assertRaises(RiskLedgerDuplicateError):
            DurableRiskLedger.append_account_snapshot(
                ledger,
                snapshot,
                source_receipt=source,
                upstream_receipt=upstream,
            )

        next_snapshot = self._snapshot(
            "snapshot-source-2", at=START + timedelta(seconds=1)
        )
        replay_unsigned = {
            "source_receipt_id": "source-new-envelope-reused-upstream",
            "source_kind": "ACCOUNT_SNAPSHOT",
            "issuer_id": SOURCE_ISSUER,
            "key_id": SOURCE_KEY_ID,
            "binding": self.binding.to_canonical_dict(),
            "event_sha256": next_snapshot.content_sha256,
            "upstream_receipt_type": "RUNTIME_FACT_RECEIPT",
            "upstream_receipt_sha256": upstream.content_sha256,
            "observed_at_utc": self.clock.value,
            "valid_until_utc": self.clock.value + timedelta(seconds=5),
            "schema_version": "durable-risk-source-receipt-v1",
        }
        replay_source = verify_risk_source_receipt(
            _signed_source_payload(replay_unsigned),
            expected_event=next_snapshot,
            expected_binding=self.binding,
            key_provider=lambda _key_id: SOURCE_KEY,
            trusted_issuer_keys={SOURCE_ISSUER: (SOURCE_KEY_ID,)},
            clock_provider=self.clock,
        )
        with self.assertRaisesRegex(RiskLedgerDuplicateError, "upstream"):
            DurableRiskLedger.append_account_snapshot(
                ledger,
                next_snapshot,
                source_receipt=replay_source,
                upstream_receipt=upstream,
            )

    def test_raw_broker_login_is_not_persisted_in_database_or_receipt(self) -> None:
        ledger = self._ledger()
        receipt = ledger.append_account_snapshot(
            self._snapshot("snapshot-source-1", at=START)
        )
        self.assertEqual(ACCOUNT_ID_SHA256, receipt.binding.account_id_sha256)
        self.assertNotIn(RAW_ACCOUNT_LOGIN, receipt.canonical_json())

        with sqlite3.connect(self.path) as connection:
            columns = {
                row[1]
                for row in connection.execute("PRAGMA table_info(risk_ledger_identity)")
            }
            values = " ".join(
                str(item)
                for row in connection.execute("SELECT * FROM risk_ledger_identity")
                for item in row
            )
        self.assertIn("account_id_sha256", columns)
        self.assertNotIn("account_id", columns)
        self.assertNotIn(RAW_ACCOUNT_LOGIN, values)


if __name__ == "__main__":
    unittest.main()
