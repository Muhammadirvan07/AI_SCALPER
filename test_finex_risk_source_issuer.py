from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
import unittest

from live_runtime.contracts import CanonicalContract
from live_runtime.risk_ledger import (
    AccountRiskSnapshot,
    RiskLedgerBinding,
    RiskLedgerSourceError,
    issue_risk_source_receipt,
    verify_risk_source_receipt,
)


NOW = datetime(2026, 8, 28, 11, 0, tzinfo=timezone.utc)
KEY = b"finex-risk-source-issuer-test-key-material-32-bytes"
ISSUER = "finex-runtime-fact-source-audusd-v1"
KEY_ID = "finex-risk-source-audusd-v1"


@dataclass(frozen=True)
class UpstreamReceipt(CanonicalContract):
    receipt_id: str


class FinexRiskSourceIssuerTests(unittest.TestCase):
    def setUp(self):
        self.binding = RiskLedgerBinding(
            account_id_sha256="1" * 64,
            server="FinexBisnisSolusi-Demo",
            environment="DEMO",
            journal_sha256="2" * 64,
            broker_spec_sha256="3" * 64,
            account_currency="USD",
        )
        self.event = AccountRiskSnapshot(
            snapshot_id="finex-account-snapshot-audusd-1",
            binding=self.binding,
            observed_at_utc=NOW,
            daily_baseline_id="day-2026-08-28",
            weekly_baseline_id="week-2026-W35",
            equity=1000.0,
        )
        self.upstream = UpstreamReceipt("runtime-fact-audusd-1")

    def issue(self):
        return issue_risk_source_receipt(
            event=self.event,
            binding=self.binding,
            upstream_receipt_type="RUNTIME_FACT_RECEIPT",
            upstream_receipt=self.upstream,
            issuer_id=ISSUER,
            key_id=KEY_ID,
            key=KEY,
            observed_at_utc=NOW,
            valid_until_utc=NOW + timedelta(seconds=5),
        )

    def test_issuer_returns_exact_sealed_and_verifiable_receipt(self):
        receipt = self.issue()
        verified = verify_risk_source_receipt(
            receipt.to_canonical_dict(),
            expected_event=self.event,
            expected_binding=self.binding,
            key_provider=lambda _: KEY,
            trusted_issuer_keys={ISSUER: (KEY_ID,)},
            clock_provider=lambda: NOW,
        )
        self.assertIs(type(receipt), type(verified))
        self.assertEqual(self.upstream.content_sha256, receipt.upstream_receipt_sha256)
        self.assertTrue(receipt.source_verified)

    def test_wrong_binding_and_noncanonical_upstream_fail_closed(self):
        with self.assertRaisesRegex(RiskLedgerSourceError, "canonical upstream"):
            issue_risk_source_receipt(
                event=self.event,
                binding=self.binding,
                upstream_receipt_type="RUNTIME_FACT_RECEIPT",
                upstream_receipt=object(),
                issuer_id=ISSUER,
                key_id=KEY_ID,
                key=KEY,
                observed_at_utc=NOW,
                valid_until_utc=NOW + timedelta(seconds=5),
            )
        other = replace(self.binding, broker_spec_sha256="4" * 64)
        with self.assertRaisesRegex(Exception, "binding"):
            issue_risk_source_receipt(
                event=self.event,
                binding=other,
                upstream_receipt_type="RUNTIME_FACT_RECEIPT",
                upstream_receipt=self.upstream,
                issuer_id=ISSUER,
                key_id=KEY_ID,
                key=KEY,
                observed_at_utc=NOW,
                valid_until_utc=NOW + timedelta(seconds=5),
            )


if __name__ == "__main__":
    unittest.main()
