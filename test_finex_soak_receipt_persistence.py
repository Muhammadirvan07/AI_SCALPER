from __future__ import annotations

import unittest

from live_runtime.demo_auto_soak_cohort_contracts import (
    DemoAutoSoakCohortBindingError,
    DemoAutoSoakCohortIntegrityError,
    demo_auto_soak_cohort_binding_from_mapping,
    demo_auto_soak_cohort_receipt_from_mapping,
    verify_demo_auto_soak_cohort_receipt,
)
from test_live_runtime_demo_auto_soak_cohort import Fixture, NOW


class FinexSoakReceiptPersistenceTests(unittest.TestCase):
    def test_signed_cohort_and_binding_round_trip_then_verify(self):
        fixture = Fixture()
        binding = demo_auto_soak_cohort_binding_from_mapping(
            fixture.binding.to_canonical_dict()
        )
        receipt = demo_auto_soak_cohort_receipt_from_mapping(
            fixture.aggregate().to_canonical_dict()
        )
        self.assertTrue(
            verify_demo_auto_soak_cohort_receipt(
                receipt,
                binding=binding,
                key_provider=fixture.aggregator_key,
                enforce_freshness=True,
                now=NOW,
            )
        )
        self.assertFalse(receipt.safe_to_demo_auto_order)
        self.assertEqual("DISABLED", receipt.order_capability)

    def test_shape_and_signature_tamper_fail_closed(self):
        fixture = Fixture()
        binding_payload = fixture.binding.to_canonical_dict()
        binding_payload["unexpected"] = True
        with self.assertRaises(DemoAutoSoakCohortBindingError):
            demo_auto_soak_cohort_binding_from_mapping(binding_payload)

        binding = demo_auto_soak_cohort_binding_from_mapping(
            fixture.binding.to_canonical_dict()
        )
        receipt_payload = fixture.aggregate().to_canonical_dict()
        receipt_payload["previous_receipt_sha256"] = "f" * 64
        receipt = demo_auto_soak_cohort_receipt_from_mapping(receipt_payload)
        self.assertFalse(
            verify_demo_auto_soak_cohort_receipt(
                receipt,
                binding=binding,
                key_provider=fixture.aggregator_key,
                enforce_freshness=True,
                now=NOW,
            )
        )

        receipt_payload = fixture.aggregate().to_canonical_dict()
        receipt_payload["issued_at_utc"] = "2026-08-28T09:00:00"
        with self.assertRaises(DemoAutoSoakCohortIntegrityError):
            demo_auto_soak_cohort_receipt_from_mapping(receipt_payload)


if __name__ == "__main__":
    unittest.main()
