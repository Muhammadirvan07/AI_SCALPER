from __future__ import annotations

from datetime import datetime, timedelta, timezone
import unittest

from live_runtime.ai_advisory_receipt import (
    AIAdvisoryReceiptError,
    ai_advisory_receipt_from_mapping,
    issue_ai_advisory_receipt,
    verify_ai_advisory_receipt,
)
from live_runtime.runtime_supervisor import (
    RuntimeSupervisorIntegrityError,
    issue_runtime_news_guard_receipt,
    runtime_news_guard_receipt_from_mapping,
    verify_runtime_news_guard_receipt,
)


NOW = datetime(2026, 8, 28, 9, 0, tzinfo=timezone.utc)
ACCOUNT = "1" * 64
SERVER = "FinexBisnisSolusi-Demo"
NEWS_KEY = b"news-guard-persistence-key-material-01"
AI_KEY = b"ai-advisory-persistence-key-material-1"


def _news():
    return issue_runtime_news_guard_receipt(
        provider_id="finex-news-runtime-v1",
        key_id="finex-news-key-v1",
        key=NEWS_KEY,
        account_id_sha256=ACCOUNT,
        server=SERVER,
        environment="DEMO",
        observed_at_utc=NOW,
        valid_until_utc=NOW + timedelta(seconds=30),
        feed_sequence=1,
        feed_payload_sha256="2" * 64,
        previous_receipt_sha256="0" * 64,
        news_feed_fresh=True,
        news_blackout_active=False,
        rollover_blackout_active=False,
        blackout_window_sha256="3" * 64,
        ruleset_sha256="4" * 64,
        config_sha256="5" * 64,
    )


def _advisory(news_sha256: str):
    return issue_ai_advisory_receipt(
        issuer_id="decision-runtime",
        key_id="finex-ai-advisory-v1",
        key=AI_KEY,
        account_id_sha256=ACCOUNT,
        server=SERVER,
        environment="DEMO",
        symbol="EURUSD",
        model="gpt-5.4-mini",
        reasoning_effort="high",
        execution_scope="DEMO_AUTO_VETO_ONLY",
        decision_snapshot_sha256="6" * 64,
        news_payload_sha256="7" * 64,
        advisory_output_sha256="8" * 64,
        policy_sha256="9" * 64,
        deterministic_action="BUY",
        recommendation="BUY",
        status="APPROVED",
        confidence=0.9,
        generated_at_utc=NOW,
        valid_until_utc=NOW + timedelta(seconds=30),
        news_guard_receipt_sha256=news_sha256,
        stage_binding_sha256="a" * 64,
    )


class FinexAINewsReceiptPersistenceTests(unittest.TestCase):
    def test_exact_round_trip_retains_signature_and_deny_only_contract(self):
        news = runtime_news_guard_receipt_from_mapping(_news().to_canonical_dict())
        verify_runtime_news_guard_receipt(
            news,
            expected_provider_id="finex-news-runtime-v1",
            expected_key_id="finex-news-key-v1",
            expected_account_id_sha256=ACCOUNT,
            expected_server=SERVER,
            expected_environment="DEMO",
            expected_config_sha256="5" * 64,
            key_provider=lambda _: NEWS_KEY,
            now=NOW + timedelta(seconds=1),
        )
        advisory = ai_advisory_receipt_from_mapping(
            _advisory(news.content_sha256).to_canonical_dict()
        )
        verified = verify_ai_advisory_receipt(
            advisory,
            expected_account_id_sha256=ACCOUNT,
            expected_server=SERVER,
            expected_environment="DEMO",
            expected_execution_scope="DEMO_AUTO_VETO_ONLY",
            expected_policy_sha256="9" * 64,
            expected_news_guard_receipt_sha256=news.content_sha256,
            expected_stage_binding_sha256="a" * 64,
            key_provider=lambda _: AI_KEY,
            now=NOW + timedelta(seconds=1),
        )
        self.assertFalse(verified.safe_to_demo_auto_order)
        self.assertEqual("DISABLED", verified.order_capability)

    def test_shape_timestamp_and_signature_tamper_fail_closed(self):
        news_payload = _news().to_canonical_dict()
        news_payload["unexpected"] = True
        with self.assertRaises(RuntimeSupervisorIntegrityError):
            runtime_news_guard_receipt_from_mapping(news_payload)

        ai_payload = _advisory(_news().content_sha256).to_canonical_dict()
        ai_payload["generated_at_utc"] = "2026-08-28T09:00:00"
        with self.assertRaisesRegex(AIAdvisoryReceiptError, "TIMESTAMP_NAIVE"):
            ai_advisory_receipt_from_mapping(ai_payload)

        ai_payload = _advisory(_news().content_sha256).to_canonical_dict()
        ai_payload["confidence"] = 0.8
        loaded = ai_advisory_receipt_from_mapping(ai_payload)
        with self.assertRaisesRegex(AIAdvisoryReceiptError, "SIGNATURE_INVALID"):
            verify_ai_advisory_receipt(
                loaded,
                expected_account_id_sha256=ACCOUNT,
                expected_server=SERVER,
                expected_environment="DEMO",
                expected_execution_scope="DEMO_AUTO_VETO_ONLY",
                expected_policy_sha256="9" * 64,
                expected_news_guard_receipt_sha256=loaded.news_guard_receipt_sha256,
                expected_stage_binding_sha256="a" * 64,
                key_provider=lambda _: AI_KEY,
                now=NOW + timedelta(seconds=1),
            )


if __name__ == "__main__":
    unittest.main()
