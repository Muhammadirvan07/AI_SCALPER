from __future__ import annotations

from datetime import datetime, timezone
import unittest

from live_runtime.contracts import canonical_sha256
from live_runtime.finex_calendar_review_v2 import (
    DECISION,
    FinexCalendarReviewV2Error,
    KEY_ID,
    assemble_incomplete_review,
    sign_incomplete_review,
    validate_request,
    verify_incomplete_review,
)


KEY = b"k" * 32
NOW = datetime(2026, 8, 27, 12, 0, tzinfo=timezone.utc)
EVIDENCE_HASH = "a" * 64
SCHEDULE_HASH = "b" * 64


def request() -> dict[str, object]:
    body: dict[str, object] = {
        "schema_version": "finex-calendar-review-request-v2",
        "candidate_id": "finex",
        "calendar_version": "finex-window-01-v2",
        "designated_reviewer_id": "putra",
        "reviewer_independence_attested": False,
        "independence_requirement": "REVIEWER_MUST_NOT_BE_OPERATOR_DEVELOPER_OR_EVIDENCE_COLLECTOR",
        "required_reviewer_role": "CALENDAR_REVIEW",
        "required_key_id": KEY_ID,
        "evidence_bundle_sha256": EVIDENCE_HASH,
        "schedule_claim_sha256": SCHEDULE_HASH,
        "official_sources": [{"source_id": "finex-rules"}],
        "observation_start_at_utc": "2026-08-31T12:00:00Z",
        "blind_until_utc": "2026-10-26T12:00:00Z",
        "current_special_hours_attested": False,
        "current_future_exception_completeness": False,
        "required_checks": ["VERIFY_TRADING_RULES_SOURCE_HASH"],
        "authorization_granted": False,
        "order_capability": "DISABLED",
        "promotion_eligible": False,
        "safe_to_demo_auto_order": False,
        "live_allowed": False,
    }
    return {**body, "request_sha256": canonical_sha256(body)}


def evidence() -> dict[str, object]:
    return {
        "candidate_id": "finex",
        "calendar_version": "finex-window-01-v2",
        "evidence_bundle_sha256": EVIDENCE_HASH,
        "schedule_claim_sha256": SCHEDULE_HASH,
        "future_exception_completeness": False,
        "special_hours_attested": False,
        "execution_enabled": False,
        "promotion_eligible": False,
        "safe_to_demo_auto_order": False,
        "live_allowed": False,
    }


class FinexCalendarReviewV2Tests(unittest.TestCase):
    def sign(self) -> dict[str, object]:
        return sign_incomplete_review(
            request(),
            evidence(),
            reviewer_id="putra",
            key_id=KEY_ID,
            signing_key=KEY,
            independence_attested=True,
            now_provider=lambda: NOW,
        )

    def test_receipt_binds_request_evidence_reviewer_and_independence(self) -> None:
        receipt = self.sign()
        verified = verify_incomplete_review(
            request(), evidence(), receipt, key_provider=lambda _: KEY
        )
        self.assertEqual(DECISION, verified["decision"])
        self.assertTrue(verified["independence_attested"])
        self.assertEqual(request()["request_sha256"], verified["request_sha256"])

    def test_signing_requires_explicit_independence_and_designated_reviewer(self) -> None:
        for reviewer, attested in (("putra", False), ("operator", True)):
            with self.subTest(reviewer=reviewer, attested=attested):
                with self.assertRaises(FinexCalendarReviewV2Error):
                    sign_incomplete_review(
                        request(),
                        evidence(),
                        reviewer_id=reviewer,
                        key_id=KEY_ID,
                        signing_key=KEY,
                        independence_attested=attested,
                        now_provider=lambda: NOW,
                    )

    def test_request_and_receipt_tampering_fail_closed(self) -> None:
        changed_request = request()
        changed_request["required_checks"] = ["DIFFERENT"]
        with self.assertRaisesRegex(FinexCalendarReviewV2Error, "hash mismatch"):
            validate_request(changed_request)
        receipt = self.sign()
        receipt["decision"] = "APPROVED"
        with self.assertRaises(FinexCalendarReviewV2Error):
            verify_incomplete_review(
                request(), evidence(), receipt, key_provider=lambda _: KEY
            )

    def test_assembly_is_permanently_deny_only(self) -> None:
        assembled = assemble_incomplete_review(
            request(),
            evidence(),
            self.sign(),
            key_provider=lambda _: KEY,
            now_provider=lambda: NOW,
        )
        self.assertFalse(assembled["authorization_granted"])
        self.assertFalse(assembled["promotion_eligible"])
        self.assertFalse(assembled["safe_to_demo_auto_order"])
        self.assertFalse(assembled["live_allowed"])
        self.assertEqual("DISABLED", assembled["order_capability"])


if __name__ == "__main__":
    unittest.main()
