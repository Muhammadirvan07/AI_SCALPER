import copy
import json
from pathlib import Path
import tempfile
import unittest

from live_runtime.session_calendar import (
    SessionCalendarError,
    build_calendar_bundle,
    write_calendar_bundle_exclusive,
)
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

    def test_gold_has_daily_breaks_but_fx_does_not(self):
        calendars = build_calendar_bundle(self.plan())["calendars"]
        gold_reasons = {item["reason_code"] for item in calendars["XAUUSD"]["closures"]}
        fx_reasons = {item["reason_code"] for item in calendars["EURUSD"]["closures"]}
        self.assertEqual(gold_reasons, {"DAILY_BREAK", "WEEKEND"})
        self.assertEqual(fx_reasons, {"WEEKEND"})
        self.assertEqual(
            calendars["EURUSD"]["market_open_intervals"][0]["open_at_utc"],
            "2026-07-19T21:00:00Z",
        )
        self.assertEqual(
            calendars["XAUUSD"]["market_open_intervals"][0]["open_at_utc"],
            "2026-07-19T22:00:00Z",
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


if __name__ == "__main__":
    unittest.main()
