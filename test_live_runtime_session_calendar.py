import copy
import json
from pathlib import Path
import tempfile
import unittest

from live_runtime.contracts import canonical_sha256
from live_runtime.session_calendar import (
    SessionCalendarError,
    build_calendar_bundle,
    write_calendar_bundle_exclusive,
)
from live_runtime.xm_window_plan import XMWindowPlanError, verify_prepared_xm_calendar_plan
from validation_evidence import canonical_evidence_payload_sha256


PLAN_PATH = Path("config/xm_calendar_window_01.json")


class SessionCalendarTests(unittest.TestCase):
    def plan(self):
        return json.loads(PLAN_PATH.read_text(encoding="utf-8"))

    def test_window_builds_four_verified_utc_calendars(self):
        bundle = build_calendar_bundle(self.plan())
        self.assertEqual(set(bundle["calendars"]), {"XAUUSD", "EURUSD", "USDJPY", "AUDUSD"})
        self.assertFalse(bundle["execution_enabled"])
        self.assertFalse(bundle["live_allowed"])
        self.assertFalse(bundle["safe_to_demo_auto_order"])
        self.assertEqual(bundle["max_lot"], 0.01)
        for symbol, calendar in bundle["calendars"].items():
            self.assertEqual(calendar["timezone"], "UTC")
            self.assertEqual(
                bundle["session_calendar_sha256"][symbol],
                canonical_evidence_payload_sha256(calendar),
            )
        self.assertEqual(
            {calendar["metadata"]["source_instance_id"] for calendar in bundle["calendars"].values()},
            {"xm-a53b6c55e91c6afb-window-01"},
        )

    def test_terminal_cohort_id_is_required(self):
        plan = self.plan()
        plan.pop("source_instance_id")
        with self.assertRaisesRegex(SessionCalendarError, "terminal cohort"):
            build_calendar_bundle(plan)

    def test_partial_session_buckets_are_closed_conservatively(self):
        calendars = build_calendar_bundle(self.plan())["calendars"]
        gold_reasons = {item["reason_code"] for item in calendars["XAUUSD"]["closures"]}
        fx_reasons = {item["reason_code"] for item in calendars["EURUSD"]["closures"]}
        self.assertEqual(
            gold_reasons,
            {"DAILY_BREAK", "PARTIAL_SESSION_CLOSE", "WEEKEND"},
        )
        self.assertEqual(
            fx_reasons,
            {"PARTIAL_SESSION_CLOSE", "WEEKEND"},
        )
        self.assertEqual(
            calendars["EURUSD"]["market_open_intervals"][0]["open_at_utc"],
            "2026-07-19T21:00:00Z",
        )
        self.assertEqual(
            calendars["XAUUSD"]["market_open_intervals"][0]["open_at_utc"],
            "2026-07-19T22:00:00Z",
        )
        self.assertEqual(
            calendars["EURUSD"]["market_open_intervals"][0]["close_at_utc"],
            "2026-07-24T20:45:00Z",
        )
        self.assertEqual(
            calendars["XAUUSD"]["market_open_intervals"][0]["close_at_utc"],
            "2026-07-20T20:45:00Z",
        )
        self.assertTrue(
            any(
                closure["start_at_utc"] == "2026-07-24T20:45:00Z"
                and closure["end_at_utc"] == "2026-07-24T21:00:00Z"
                and closure["reason_code"] == "PARTIAL_SESSION_CLOSE"
                for closure in calendars["EURUSD"]["closures"]
            )
        )

    def test_missing_or_short_special_hours_review_fails_closed(self):
        plan = self.plan()
        plan["special_hours_review"]["attested"] = False
        with self.assertRaisesRegex(SessionCalendarError, "explicitly attested"):
            build_calendar_bundle(plan)
        plan = self.plan()
        plan["special_hours_review"]["covered_through_server_date"] = "2026-07-24"
        with self.assertRaisesRegex(SessionCalendarError, "does not cover"):
            build_calendar_bundle(plan)

    def test_affected_required_symbol_cannot_be_silently_ignored(self):
        plan = self.plan()
        plan["special_hours_review"]["affected_required_symbols"] = ["XAUUSD"]
        with self.assertRaisesRegex(SessionCalendarError, "explicit closure"):
            build_calendar_bundle(plan)

    def test_bundle_output_is_create_exclusive(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "calendar.json"
            payload = build_calendar_bundle(self.plan())
            write_calendar_bundle_exclusive(path, payload)
            with self.assertRaises(FileExistsError):
                write_calendar_bundle_exclusive(path, copy.deepcopy(payload))

    def test_prepared_window_02_plan_is_hash_checked_before_calendar_build(self):
        old = self.plan()
        receipt_sha256 = "b" * 64
        body = {
            **old,
            "schema_version": "xm-calendar-plan-v1",
            "calendar_version": "xm-window-02-v3",
            "operating_jurisdiction": "JP",
            "validation_profile": "DIAGNOSTIC",
            "execution_enabled": False,
            "live_allowed": False,
            "safe_to_demo_auto_order": False,
            "max_lot": 0.01,
            "discovery_receipt_sha256": receipt_sha256,
            "source_instance_id": "xm-" + receipt_sha256[:32] + "-window-02-v3",
            "plan_template_sha256": "c" * 64,
            "regulatory_observation_sha256": "d" * 64,
        }
        body.pop("captured_at_utc")
        body["captured_at_utc"] = "2026-07-16T08:00:00Z"
        plan = {**body, "plan_payload_sha256": canonical_sha256(body)}
        verify_prepared_xm_calendar_plan(plan)
        bundle = build_calendar_bundle(plan)
        self.assertEqual(bundle["discovery_receipt_sha256"], receipt_sha256)
        tampered = copy.deepcopy(plan)
        tampered["broker_server"] = "Wrong"
        with self.assertRaisesRegex(XMWindowPlanError, "SHA-256"):
            verify_prepared_xm_calendar_plan(tampered)


if __name__ == "__main__":
    unittest.main()
