from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import tempfile
import unittest

from live_runtime.finex_calendar_email_monitor import (
    FinexCalendarEmailMonitorError,
    assemble_monitor_report,
    create_checkpoint,
    verify_checkpoint,
)


START = datetime(2026, 8, 31, 12, tzinfo=timezone.utc)
BLIND = datetime(2026, 10, 26, 12, tzinfo=timezone.utc)
KEY = b"calendar-monitor-test-key-material" * 2


def _contract() -> dict[str, object]:
    return {
        "schema_version": "finex-calendar-email-monitor-contract-v1",
        "candidate_id": "finex",
        "calendar_version": "finex-window-01-v2",
        "monitoring_channel": "FINEX_REGISTERED_EMAIL",
        "observation_start_at_utc": "2026-08-31T12:00:00Z",
        "blind_until_utc": "2026-10-26T12:00:00Z",
        "max_checkpoint_gap_hours": 168,
        "max_checkpoint_recording_lag_hours": 24,
        "accepted_export_suffixes": [".eml", ".html", ".json", ".mhtml", ".pdf"],
        "required_query_scope": (
            "ALL_FINEX_TRADING_HOURS_HOLIDAY_AND_MARKET_CLOSURE_NOTICES"
        ),
        "final_independent_review_required": True,
        "execution_enabled": False,
        "live_allowed": False,
        "safe_to_demo_auto_order": False,
        "authorization_granted": False,
        "order_capability": "DISABLED",
    }


class FinexCalendarEmailMonitorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="finex-email-monitor-")
        self.root = Path(self.temp.name)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _export(self, name: str, value: object) -> Path:
        path = self.root / name
        path.write_text(json.dumps(value), encoding="utf-8")
        return path

    def _checkpoint(self, start: datetime, end: datetime, index: int):
        return create_checkpoint(
            _contract(),
            mailbox_export_path=self._export(
                f"mailbox-{index}.json", {"matches": []}
            ),
            coverage_start_at=start,
            coverage_end_at=end,
            result="NO_RELEVANT_NOTICE",
            notice_count=0,
            operator_id="operator_irvan",
            signing_key=KEY,
            complete_export_attested=True,
            now_provider=lambda: end,
        )

    def test_checkpoint_is_signed_and_deny_only(self) -> None:
        checkpoint = self._checkpoint(START, START.replace(day=7, month=9), 1)
        verified = verify_checkpoint(
            _contract(),
            checkpoint,
            signing_key=KEY,
            now_provider=lambda: START.replace(day=7, month=9),
        )
        self.assertFalse(verified["future_exception_completeness"])
        self.assertFalse(verified["authorization_granted"])
        self.assertEqual(verified["order_capability"], "DISABLED")

    def test_signature_tamper_is_rejected(self) -> None:
        checkpoint = self._checkpoint(START, START.replace(day=7, month=9), 1)
        checkpoint["notice_count"] = 1
        with self.assertRaises(FinexCalendarEmailMonitorError):
            verify_checkpoint(
                _contract(),
                checkpoint,
                signing_key=KEY,
                now_provider=lambda: START.replace(day=7, month=9),
            )

    def test_gap_is_reported(self) -> None:
        first_end = datetime(2026, 9, 7, 12, tzinfo=timezone.utc)
        second_start = datetime(2026, 9, 8, 12, tzinfo=timezone.utc)
        second_end = datetime(2026, 9, 15, 12, tzinfo=timezone.utc)
        report = assemble_monitor_report(
            _contract(),
            [
                self._checkpoint(START, first_end, 1),
                self._checkpoint(second_start, second_end, 2),
            ],
            signing_key=KEY,
            now_provider=lambda: second_end,
        )
        self.assertEqual(report["status"], "INCOMPLETE_GAPS")
        self.assertEqual(len(report["coverage_gaps"]), 1)
        self.assertFalse(report["future_exception_completeness"])

    def test_full_coverage_still_requires_independent_review(self) -> None:
        checkpoints = []
        cursor = START
        for index in range(8):
            end = min(cursor.replace(day=cursor.day) + (BLIND - START) / 8, BLIND)
            checkpoints.append(self._checkpoint(cursor, end, index))
            cursor = end
        report = assemble_monitor_report(
            _contract(),
            checkpoints,
            signing_key=KEY,
            now_provider=lambda: BLIND,
        )
        self.assertEqual(report["status"], "PENDING_INDEPENDENT_FINAL_REVIEW")
        self.assertFalse(report["final_independent_review_complete"])
        self.assertFalse(report["future_exception_completeness"])
        self.assertEqual(report["order_capability"], "DISABLED")

    def test_checkpoint_cannot_cover_future_mailbox_state(self) -> None:
        export = self._export("future.json", {"matches": []})
        with self.assertRaises(FinexCalendarEmailMonitorError):
            create_checkpoint(
                _contract(),
                mailbox_export_path=export,
                coverage_start_at=START,
                coverage_end_at=datetime(2026, 9, 7, 12, tzinfo=timezone.utc),
                result="NO_RELEVANT_NOTICE",
                notice_count=0,
                operator_id="operator_irvan",
                signing_key=KEY,
                complete_export_attested=True,
                now_provider=lambda: START,
            )

    def test_checkpoint_cannot_be_backfilled_after_recording_deadline(self) -> None:
        export = self._export("late.json", {"matches": []})
        coverage_end = datetime(2026, 9, 7, 12, tzinfo=timezone.utc)
        with self.assertRaises(FinexCalendarEmailMonitorError):
            create_checkpoint(
                _contract(),
                mailbox_export_path=export,
                coverage_start_at=START,
                coverage_end_at=coverage_end,
                result="NO_RELEVANT_NOTICE",
                notice_count=0,
                operator_id="operator_irvan",
                signing_key=KEY,
                complete_export_attested=True,
                now_provider=lambda: datetime(
                    2026, 9, 8, 12, 6, tzinfo=timezone.utc
                ),
            )


if __name__ == "__main__":
    unittest.main()
