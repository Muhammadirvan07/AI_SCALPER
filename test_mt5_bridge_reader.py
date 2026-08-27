import unittest
from datetime import datetime, timedelta, timezone

import mt5_bridge_reader as bridge


class MT5BridgeTimestampTests(unittest.TestCase):
    def test_parser_rejects_naive_or_invalid_timestamp(self):
        self.assertIsNone(bridge.parse_datetime("2026-08-26T12:00:00"))
        self.assertIsNone(bridge.parse_datetime("not-a-timestamp"))
        self.assertIsNone(bridge.parse_datetime(None))

    def test_parser_normalizes_aware_timestamp_to_utc(self):
        parsed = bridge.parse_datetime("2026-08-26T19:00:00+07:00")
        self.assertEqual(datetime(2026, 8, 26, 12, 0, tzinfo=timezone.utc), parsed)

    def test_validation_rejects_naive_created_or_expiry_timestamp(self):
        aware = "2026-08-26T12:30:00+00:00"
        naive = "2026-08-26T12:00:00"
        for order, expected in (
            ({"status": "PENDING_EXECUTION", "created_at": naive, "expires_at": aware}, "created_at"),
            ({"status": "PENDING_EXECUTION", "created_at": aware, "expires_at": naive}, "expires_at"),
        ):
            with self.subTest(expected=expected):
                valid, reason = bridge.validate_order(order, {}, {})
                self.assertFalse(valid)
                self.assertIn(expected, reason)

    def test_validation_rejects_nonpositive_expiry_window(self):
        timestamp = "2026-08-26T12:00:00Z"
        valid, reason = bridge.validate_signal_timestamps(
            {"created_at": timestamp, "expires_at": timestamp}
        )
        self.assertFalse(valid)
        self.assertIn("later", reason)

    def test_expiry_comparison_uses_utc_aware_time(self):
        now = datetime.now(timezone.utc)
        self.assertTrue(bridge.is_signal_expired({"expires_at": (now - timedelta(seconds=1)).isoformat()}))
        self.assertFalse(bridge.is_signal_expired({"expires_at": (now + timedelta(minutes=5)).isoformat()}))


if __name__ == "__main__":
    unittest.main()
