from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import unittest

from live_runtime.health import RuntimeHealthFacts, evaluate_runtime_health


class RuntimeHealthTests(unittest.TestCase):
    def setUp(self) -> None:
        self.now = datetime(2026, 7, 15, 1, 0, tzinfo=timezone.utc)
        self.facts = RuntimeHealthFacts(
            observed_at=self.now,
            heartbeat_at=self.now - timedelta(seconds=5),
            clock_drift_seconds=0.2,
            free_disk_bytes=2_000_000_000,
            database_integrity_ok=True,
            broker_connected=True,
            data_feed_fresh=True,
            audit_export_healthy=True,
            backup_recent=True,
            kill_switch_latched=False,
        )

    def test_all_healthy_facts_are_healthy_but_cannot_unlock(self) -> None:
        decision = evaluate_runtime_health(self.facts)
        self.assertTrue(decision.healthy)
        self.assertFalse(decision.live_allowed)
        self.assertFalse(decision.safe_to_demo_auto_order)

    def test_clock_and_heartbeat_limits_fail_closed(self) -> None:
        facts = replace(
            self.facts,
            clock_drift_seconds=1.01,
            heartbeat_at=self.now - timedelta(seconds=31),
        )
        decision = evaluate_runtime_health(facts)
        self.assertFalse(decision.healthy)
        self.assertIn("CLOCK_DRIFT_EXCEEDED", decision.reason_codes)
        self.assertIn("OFF_HOST_HEARTBEAT_STALE", decision.reason_codes)

    def test_operational_failures_are_all_reported(self) -> None:
        facts = replace(
            self.facts,
            free_disk_bytes=10,
            database_integrity_ok=False,
            broker_connected=False,
            data_feed_fresh=False,
            audit_export_healthy=False,
            backup_recent=False,
            kill_switch_latched=True,
        )
        decision = evaluate_runtime_health(facts)
        self.assertFalse(decision.healthy)
        self.assertEqual(
            {
                "DISK_SPACE_LOW",
                "DATABASE_INTEGRITY_FAILED",
                "BROKER_DISCONNECTED",
                "DATA_FEED_STALE",
                "AUDIT_EXPORT_FAILED",
                "BACKUP_STALE",
                "KILL_SWITCH_LATCHED",
            },
            set(decision.reason_codes),
        )

    def test_naive_timestamp_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            replace(self.facts, observed_at=datetime(2026, 7, 15, 1, 0))


if __name__ == "__main__":
    unittest.main()
