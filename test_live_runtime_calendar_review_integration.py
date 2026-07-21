from __future__ import annotations

import copy
from datetime import datetime, timezone
from pathlib import Path
import tempfile
import unittest

from live_runtime.broker_window_plan import (
    BrokerWindowPlanError,
    SIGNED_REVIEW_PLAN_SCHEMA_VERSION,
    SIGNED_REVIEW_TEMPLATE_SCHEMA_VERSION,
    prepare_broker_calendar_plan,
    verify_broker_calendar_template,
    verify_prepared_broker_calendar_plan,
)
from live_runtime.calendar_review import calendar_review_key_name
from live_runtime.session_calendar import build_calendar_bundle
from test_live_runtime_calendar_review import (
    KEY as CALENDAR_KEY,
    approved_review,
    candidate_config,
    template_for,
)
from test_live_runtime_evidence_bootstrap import TEST_KEY, discovery_receipt


UTC = timezone.utc
NOW = datetime(2026, 7, 21, 12, 0, tzinfo=UTC)


def signed_template(root: Path) -> dict[str, object]:
    template, _, review = approved_review(root, "phillip-fx")
    result = copy.deepcopy(template)
    result["schema_version"] = SIGNED_REVIEW_TEMPLATE_SCHEMA_VERSION
    result["prewindow_calendar_review"] = review
    return result


def phillip_discovery(template: dict[str, object]) -> dict[str, object]:
    symbols = tuple(template["broker_symbols"])
    return discovery_receipt(
        candidate_id="phillip-fx",
        company="Phillip Securities Japan, Ltd.",
        server="PhillipSecuritiesJP-PROD",
        required_symbols=symbols,
        broker_symbols=dict(template["broker_symbols"]),
        trade_expert=True,
    )


class CalendarReviewIntegrationTests(unittest.TestCase):
    def test_schema_v3_plan_requires_and_reverifies_calendar_review_key(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            template = signed_template(Path(directory))
        key_id = calendar_review_key_name("phillip-fx")
        provider = {key_id: CALENDAR_KEY}.get
        verify_broker_calendar_template(template)
        plan = prepare_broker_calendar_plan(
            template,
            phillip_discovery(template),
            candidate_config(),
            TEST_KEY,
            now_provider=lambda: NOW,
            regulatory_approval_key_provider=lambda _: b"unused",
            calendar_review_key_provider=provider,
            legal_binding_verifier=lambda *args, **kwargs: None,
        )
        self.assertEqual(SIGNED_REVIEW_PLAN_SCHEMA_VERSION, plan["schema_version"])
        verify_prepared_broker_calendar_plan(
            plan,
            template=template,
            calendar_review_key_provider=provider,
            now_provider=lambda: NOW,
        )
        bundle = build_calendar_bundle(plan)
        self.assertEqual(
            template["prewindow_calendar_review"]["review_artifact_sha256"],
            bundle["prewindow_calendar_review_sha256"],
        )

    def test_schema_v3_plan_fails_without_or_with_wrong_review_key(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            template = signed_template(Path(directory))
        base = dict(
            template=template,
            discovery=phillip_discovery(template),
            candidate_config=candidate_config(),
            signing_key=TEST_KEY,
            now_provider=lambda: NOW,
            legal_binding_verifier=lambda *args, **kwargs: None,
        )
        for provider in (None, {}.get, {calendar_review_key_name("phillip-fx"): b"wrong-key-material-at-least-32-bytes"}.get):
            with self.subTest(provider=provider), self.assertRaises(BrokerWindowPlanError):
                prepare_broker_calendar_plan(
                    base["template"], base["discovery"], base["candidate_config"],
                    base["signing_key"], now_provider=base["now_provider"],
                    calendar_review_key_provider=provider,
                    legal_binding_verifier=base["legal_binding_verifier"],
                )

    def test_schema_v3_static_template_rejects_review_or_schedule_drift(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            template = signed_template(Path(directory))
        drifted = copy.deepcopy(template)
        drifted["weekly_m15_sessions"]["EURUSD"][0]["open_local"] = "07:15"
        with self.assertRaisesRegex(BrokerWindowPlanError, "pre-window"):
            verify_broker_calendar_template(drifted)
        tampered = copy.deepcopy(template)
        tampered["prewindow_calendar_review"]["future_exception_completeness"] = True
        with self.assertRaisesRegex(BrokerWindowPlanError, "pre-window"):
            verify_broker_calendar_template(tampered)

        unsafe = copy.deepcopy(template)
        review = unsafe["prewindow_calendar_review"]
        review["execution_enabled"] = True
        evidence = {
            key: copy.deepcopy(value)
            for key, value in review.items()
            if key
            not in {
                "review_artifact_sha256",
                "calendar_review_approval",
                "amendment_chain_required",
                "post_window_completeness_required",
            }
        }
        evidence["schema_version"] = "prewindow-calendar-evidence-v1"
        from live_runtime.contracts import canonical_sha256
        evidence_body = {
            key: value
            for key, value in evidence.items()
            if key != "evidence_bundle_sha256"
        }
        review["evidence_bundle_sha256"] = canonical_sha256(evidence_body)
        review["calendar_review_approval"]["evidence_bundle_sha256"] = review[
            "evidence_bundle_sha256"
        ]
        review_body = {
            key: value
            for key, value in review.items()
            if key != "review_artifact_sha256"
        }
        review["review_artifact_sha256"] = canonical_sha256(review_body)
        with self.assertRaisesRegex(BrokerWindowPlanError, "pre-window"):
            verify_broker_calendar_template(unsafe)

    def test_schema_v3_plan_verification_rejects_review_drift_and_missing_provider(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            template = signed_template(Path(directory))
        key_id = calendar_review_key_name("phillip-fx")
        provider = {key_id: CALENDAR_KEY}.get
        plan = prepare_broker_calendar_plan(
            template, phillip_discovery(template), candidate_config(), TEST_KEY,
            now_provider=lambda: NOW,
            calendar_review_key_provider=provider,
            legal_binding_verifier=lambda *args, **kwargs: None,
        )
        with self.assertRaisesRegex(BrokerWindowPlanError, "key|review"):
            verify_prepared_broker_calendar_plan(
                plan, template=template, now_provider=lambda: NOW
            )
        tampered = copy.deepcopy(plan)
        tampered["prewindow_calendar_review"]["review_artifact_sha256"] = "0" * 64
        from live_runtime.contracts import canonical_sha256
        body = {k: v for k, v in tampered.items() if k != "plan_payload_sha256"}
        tampered["plan_payload_sha256"] = canonical_sha256(body)
        with self.assertRaises(BrokerWindowPlanError):
            verify_prepared_broker_calendar_plan(
                tampered,
                template=template,
                calendar_review_key_provider=provider,
                now_provider=lambda: NOW,
            )

    def test_schema_v2_behavior_remains_unchanged(self) -> None:
        template = template_for("phillip-fx")
        verify_broker_calendar_template(template)
        plan = prepare_broker_calendar_plan(
            template,
            phillip_discovery(template),
            candidate_config(),
            TEST_KEY,
            now_provider=lambda: NOW,
            legal_binding_verifier=lambda *args, **kwargs: None,
        )
        verify_prepared_broker_calendar_plan(plan, template=template)
        bundle = build_calendar_bundle(plan)
        self.assertNotIn("prewindow_calendar_review_sha256", bundle)


if __name__ == "__main__":
    unittest.main()
