import unittest

from live_runtime.live_grade_gate_catalog import (
    GATE_CATALOG,
    GateCatalogError,
    GateCategory,
    catalog_report,
    classify_gate_codes,
    pending_nonlocal_gate_codes,
)


class LiveGradeGateCatalogTests(unittest.TestCase):
    def test_catalog_is_unique_and_all_current_gates_are_nonlocal(self):
        codes = [gate.code for gate in GATE_CATALOG]
        self.assertEqual(len(codes), len(set(codes)))
        self.assertTrue(codes)
        self.assertTrue(
            all(gate.category is not GateCategory.LOCAL_FOUNDATION for gate in GATE_CATALOG)
        )
        self.assertEqual(tuple(sorted(codes)), pending_nonlocal_gate_codes())

    def test_classification_is_sorted_and_duplicate_insensitive(self):
        result = classify_gate_codes(
            (
                "MANUAL_SHIP_APPROVAL_REQUIRED",
                "BROKER_FORWARD_8_WEEKS_REQUIRED",
                "MANUAL_SHIP_APPROVAL_REQUIRED",
                "EXTERNAL_TRUSTED_CLOCK_PROVIDER_REQUIRED",
            )
        )
        self.assertEqual((), result["LOCAL_FOUNDATION"])
        self.assertEqual(
            ("EXTERNAL_TRUSTED_CLOCK_PROVIDER_REQUIRED",),
            result["EXTERNAL_CONFIGURATION"],
        )
        self.assertEqual(
            ("BROKER_FORWARD_8_WEEKS_REQUIRED",),
            result["TEMPORAL_EVIDENCE"],
        )
        self.assertEqual(
            ("MANUAL_SHIP_APPROVAL_REQUIRED",), result["MANUAL_APPROVAL"]
        )

    def test_unknown_or_non_normalized_gate_fails_closed(self):
        for value in ("UNKNOWN_GATE", "manual_ship_approval_required", " X"):
            with self.subTest(value=value), self.assertRaises(GateCatalogError):
                classify_gate_codes((value,))
        with self.assertRaises(GateCatalogError):
            classify_gate_codes((1,))  # type: ignore[arg-type]

    def test_static_report_never_claims_readiness(self):
        report = catalog_report()
        self.assertFalse(report["production_execution_ready"])
        self.assertFalse(report["promotion_eligible"])
        self.assertFalse(report["live_allowed"])
        self.assertFalse(report["safe_to_demo_auto_order"])
        self.assertEqual(0.01, report["max_lot"])
        self.assertEqual("DISABLED", report["order_capability"])
        self.assertEqual(report["gate_count"], report["pending_gate_count"])
        self.assertIn(
            "DEMO_AUTO_SOAK_30_DAYS_REQUIRED", report["pending_gates"]
        )
        self.assertIn(
            "LIVE_CANARY_APPROVAL_REQUIRED", report["pending_gates"]
        )
        self.assertIn(
            "XAUUSD_MINIMUM_LOT_RISK_FEASIBILITY_REQUIRED",
            report["pending_gates"],
        )
        self.assertIn(
            "EXTERNAL_CROSS_ACCOUNT_PORTFOLIO_EXPOSURE_CUSTODY_REQUIRED",
            report["pending_gates"],
        )


if __name__ == "__main__":
    unittest.main()
