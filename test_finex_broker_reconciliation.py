from __future__ import annotations

from contextlib import closing
from datetime import datetime, timedelta, timezone
import hashlib
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from live_runtime.account_identity import account_identity_sha256
from live_runtime.finex_broker_reconciliation import (
    FinexBrokerReconciliationError,
    FinexReconciliationCustodyStore,
    ReadOnlyMT5ReconciliationFacade,
    capture_finex_reconciliation,
)
from live_runtime.journal import ExecutionJournal


UTC = timezone.utc
NOW = datetime(2026, 8, 28, 8, 0, tzinfo=UTC)
KEY = b"finex-reconciliation-test-key-material-32-bytes"
IDENTITY_KEY = b"finex-account-identity-test-key-32-bytes"


class FakeInfo(dict):
    def _asdict(self):
        return dict(self)


class FakeMT5:
    ACCOUNT_TRADE_MODE_DEMO = 0

    def __init__(self):
        self.account = FakeInfo(
            login=123456,
            company="PT Finex Bisnis Solusi Futures",
            server="FinexBisnisSolusi-Demo",
            currency="USD",
            trade_mode=0,
            margin_mode=2,
            trade_allowed=False,
            trade_expert=True,
        )

    def account_info(self):
        return self.account

    def terminal_info(self):
        return FakeInfo(trade_allowed=False, tradeapi_disabled=True)

    def symbol_info(self, _symbol):
        return FakeInfo()

    def copy_ticks_range(self, *_args):
        return ()

    def orders_get(self):
        return ()

    def positions_get(self):
        return ()

    def history_deals_get(self, _start, _end):
        return ()


class FinexBrokerReconciliationTests(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.mt5 = FakeMT5()
        self.facade = ReadOnlyMT5ReconciliationFacade(self.mt5)
        self.journal = ExecutionJournal(self.root / "journal.sqlite3")
        self.account_sha = account_identity_sha256(
            self.mt5.account, IDENTITY_KEY, environment="DEMO"
        )

    def custody(self):
        return FinexReconciliationCustodyStore(
            self.root / "custody.sqlite3",
            account_id_sha256=self.account_sha,
            server="FinexBisnisSolusi-Demo",
            journal_sha256=self.journal.journal_sha256,
            provider_id="finex-mt5-readonly-reconciler-v1",
            key_id="finex-broker-reconciliation-v1",
            key_provider=lambda key_id: KEY,
        )

    def capture(self, at=NOW):
        return capture_finex_reconciliation(
            self.facade,
            journal=self.journal,
            custody=self.custody(),
            expected_account_id_sha256=self.account_sha,
            expected_server="FinexBisnisSolusi-Demo",
            account_identity_key=IDENTITY_KEY,
            query_from_utc=at - timedelta(hours=1),
            query_to_utc=at - timedelta(seconds=1),
            magic_number=260828,
            now_provider=lambda: at,
        )

    def test_read_only_capture_is_complete_and_chain_survives_restart(self):
        self.assertFalse(hasattr(self.facade, "order_send"))
        self.assertFalse(hasattr(self.facade, "initialize"))
        first = self.capture()
        second = self.capture(NOW + timedelta(seconds=1))
        self.assertEqual("RECONCILIATION_COMPLETE", first.result.status)
        self.assertEqual(1, first.receipt.source_sequence)
        self.assertEqual(2, second.receipt.source_sequence)
        self.assertEqual(first.receipt.content_sha256, second.receipt.previous_receipt_sha256)
        self.assertEqual(2, self.custody().latest(now=NOW + timedelta(seconds=1)).receipt.source_sequence)

    def test_failed_mt5_query_does_not_advance_custody(self):
        self.mt5.orders_get = lambda: None
        facade = ReadOnlyMT5ReconciliationFacade(self.mt5)
        with self.assertRaisesRegex(FinexBrokerReconciliationError, "orders query failed"):
            capture_finex_reconciliation(
                facade,
                journal=self.journal,
                custody=self.custody(),
                expected_account_id_sha256=self.account_sha,
                expected_server="FinexBisnisSolusi-Demo",
                account_identity_key=IDENTITY_KEY,
                query_from_utc=NOW - timedelta(hours=1),
                query_to_utc=NOW - timedelta(seconds=1),
                magic_number=260828,
                now_provider=lambda: NOW,
            )
        with self.assertRaisesRegex(FinexBrokerReconciliationError, "empty"):
            self.custody().latest(now=NOW)

    def test_database_tamper_is_rejected(self):
        self.capture()
        import sqlite3

        with closing(sqlite3.connect(self.root / "custody.sqlite3")) as connection:
            with connection:
                connection.execute(
                    "UPDATE reconciliation_history SET receipt_sha256=? WHERE source_sequence=1",
                    (hashlib.sha256(b"tampered").hexdigest(),),
                )
        with self.assertRaisesRegex(FinexBrokerReconciliationError, "hash mismatch"):
            self.custody().latest(now=NOW)


if __name__ == "__main__":
    unittest.main()
