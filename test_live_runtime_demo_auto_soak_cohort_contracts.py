from __future__ import annotations

import ast
from pathlib import Path
import unittest

import live_runtime.demo_auto_soak_cohort as aggregate_module
import live_runtime.demo_auto_soak_cohort_contracts as contract_module
from test_live_runtime_demo_auto_soak_cohort import Fixture, NOW


class DemoAutoSoakCohortContractBoundaryTests(unittest.TestCase):
    def test_execution_aggregator_reexports_exact_contract_identity(self) -> None:
        for name in (
            "DemoAutoSoakCohortMemberBinding",
            "DemoAutoSoakCohortBinding",
            "DemoAutoSoakCohortMemberSnapshot",
            "DemoAutoSoakCohortReceipt",
            "verify_demo_auto_soak_cohort_receipt",
        ):
            with self.subTest(name=name):
                self.assertIs(
                    getattr(aggregate_module, name),
                    getattr(contract_module, name),
                )
        self.assertIs(
            aggregate_module._COHORT_RECEIPT_SEAL,
            contract_module._COHORT_RECEIPT_SEAL,
        )

    def test_aggregated_receipt_verifies_through_minimal_boundary(self) -> None:
        fixture = Fixture()
        receipt = fixture.aggregate()
        self.assertIs(type(receipt), contract_module.DemoAutoSoakCohortReceipt)
        self.assertTrue(
            contract_module.verify_demo_auto_soak_cohort_receipt(
                receipt,
                binding=fixture.binding,
                key_provider=fixture.aggregator_key,
                enforce_freshness=True,
                now=NOW,
            )
        )
        self.assertFalse(receipt.live_allowed)
        self.assertFalse(receipt.activation_authorized)
        self.assertEqual("DISABLED", receipt.order_capability)

    def test_minimal_boundary_has_no_execution_or_broker_import(self) -> None:
        path = Path(contract_module.__file__)
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        local_imports = {
            node.module or ""
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom)
        }
        rendered = "\n".join(sorted(local_imports))
        for forbidden in (
            "journal",
            "reconciliation",
            "soak_tracker",
            "demo_auto_soak_projection",
            "mt5",
            "executor",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, rendered)


if __name__ == "__main__":
    unittest.main()
