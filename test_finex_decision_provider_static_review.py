from __future__ import annotations

from datetime import datetime, timedelta, timezone
import unittest

from finex_decision_provider_static_review import (
    ReviewError,
    _validate_attestation_time,
    _validate_request_time,
)


UTC = timezone.utc
NOW = datetime(2026, 8, 30, 4, 0, tzinfo=UTC)


class FinexDecisionProviderStaticReviewTests(unittest.TestCase):
    @staticmethod
    def request(*, issued=NOW - timedelta(minutes=1), valid=NOW + timedelta(days=1)):
        return {
            "issued_at_utc": issued.isoformat(),
            "valid_until_utc": valid.isoformat(),
        }

    def test_request_and_attestation_inside_window_are_valid(self):
        request = self.request()
        issued, valid = _validate_request_time(request, now=NOW)
        self.assertLess(issued, NOW)
        self.assertGreater(valid, NOW)
        reviewed = _validate_attestation_time(
            request, (NOW - timedelta(seconds=1)).isoformat(), now=NOW
        )
        self.assertEqual(NOW - timedelta(seconds=1), reviewed)

    def test_expired_future_and_overlong_requests_are_rejected(self):
        cases = (
            self.request(valid=NOW - timedelta(seconds=1)),
            self.request(issued=NOW + timedelta(seconds=1)),
            self.request(
                issued=NOW - timedelta(seconds=1),
                valid=NOW + timedelta(days=14, seconds=1),
            ),
        )
        for request in cases:
            with self.subTest(request=request), self.assertRaisesRegex(
                ReviewError, "REVIEW_REQUEST_TIME_INVALID"
            ):
                _validate_request_time(request, now=NOW)

    def test_non_utc_and_out_of_window_review_are_rejected(self):
        request = self.request()
        non_utc = dict(request, issued_at_utc="2026-08-30T12:59:00+09:00")
        with self.assertRaisesRegex(ReviewError, "REQUEST_ISSUED_AT_UTC_REQUIRED"):
            _validate_request_time(non_utc, now=NOW)
        for reviewed in (
            NOW - timedelta(minutes=2),
            NOW + timedelta(minutes=1, seconds=1),
        ):
            with self.subTest(reviewed=reviewed), self.assertRaisesRegex(
                ReviewError, "ATTESTATION_TIME_INVALID"
            ):
                _validate_attestation_time(request, reviewed.isoformat(), now=NOW)


if __name__ == "__main__":
    unittest.main()
