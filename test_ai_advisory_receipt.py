from datetime import datetime, timedelta, timezone
import unittest

from live_runtime.ai_advisory_receipt import (
    AIAdvisoryReceiptError,
    issue_ai_advisory_receipt,
    verify_ai_advisory_receipt,
)


NOW = datetime(2026, 8, 28, 8, 0, tzinfo=timezone.utc)
KEY = b"a" * 32


def _issue(**changes):
    values = dict(
        issuer_id="decision-runtime",
        key_id="ai-advisory-test-v1",
        key=KEY,
        account_id_sha256="1" * 64,
        server="FinexBisnisSolusi-Demo",
        environment="DEMO",
        symbol="EURUSD",
        model="gpt-5.4-mini",
        reasoning_effort="high",
        execution_scope="PAPER_ONLY",
        decision_snapshot_sha256="2" * 64,
        news_payload_sha256="3" * 64,
        advisory_output_sha256="4" * 64,
        policy_sha256="5" * 64,
        deterministic_action="BUY",
        recommendation="BUY",
        status="APPROVED",
        confidence=0.9,
        generated_at_utc=NOW,
        valid_until_utc=NOW + timedelta(seconds=30),
    )
    values.update(changes)
    return issue_ai_advisory_receipt(**values)


class AIAdvisoryReceiptTests(unittest.TestCase):
    def test_signed_paper_receipt_verifies_but_never_grants_capability(self):
        receipt = _issue()
        verified = verify_ai_advisory_receipt(
            receipt,
            expected_account_id_sha256="1" * 64,
            expected_server="FinexBisnisSolusi-Demo",
            expected_environment="DEMO",
            expected_execution_scope="PAPER_ONLY",
            expected_policy_sha256="5" * 64,
            key_provider=lambda _: KEY,
            now=NOW + timedelta(seconds=1),
        )
        self.assertTrue(verified.advisory_only)
        self.assertFalse(verified.safe_to_demo_auto_order)
        self.assertEqual("DISABLED", verified.order_capability)

    def test_demo_auto_scope_requires_news_and_stage_bindings(self):
        with self.assertRaises(ValueError):
            _issue(execution_scope="DEMO_AUTO_VETO_ONLY")

    def test_demo_auto_scope_forbids_fallback(self):
        with self.assertRaises(ValueError):
            _issue(
                execution_scope="DEMO_AUTO_VETO_ONLY",
                status="FALLBACK_DETERMINISTIC",
                news_guard_receipt_sha256="6" * 64,
                stage_binding_sha256="7" * 64,
            )

    def test_wrong_binding_is_rejected(self):
        receipt = _issue()
        with self.assertRaises(AIAdvisoryReceiptError):
            verify_ai_advisory_receipt(
                receipt,
                expected_account_id_sha256="8" * 64,
                expected_server="FinexBisnisSolusi-Demo",
                expected_environment="DEMO",
                expected_execution_scope="PAPER_ONLY",
                expected_policy_sha256="5" * 64,
                key_provider=lambda _: KEY,
                now=NOW + timedelta(seconds=1),
            )


if __name__ == "__main__":
    unittest.main()
