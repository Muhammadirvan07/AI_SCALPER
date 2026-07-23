import ast
from pathlib import Path
import unittest

import execution_policy


ROOT = Path(__file__).resolve().parent


class ModeAwareExecutionSymbolPolicyTests(unittest.TestCase):
    def test_exact_mode_scope_matrix_preserves_legacy_and_xau_canary(self):
        expected = {
            "DRY_RUN": frozenset({"EURUSD"}),
            "PAPER": frozenset({"EURUSD"}),
            "DEMO": frozenset({"EURUSD", "XAUUSD"}),
            "DEMO_AUTO": frozenset({"XAUUSD"}),
            "LIVE": frozenset({"XAUUSD"}),
        }
        for mode, symbols in expected.items():
            with self.subTest(mode=mode):
                self.assertEqual(
                    symbols,
                    execution_policy.execution_approved_symbols_for_mode(mode),
                )

        self.assertEqual(
            frozenset({"EURUSD"}),
            execution_policy.execution_approved_symbols_for_mode(None),
        )

    def test_mode_aware_validator_restricts_first_auto_and_live_lane_to_xau(self):
        for mode in ("DEMO_AUTO", "LIVE"):
            with self.subTest(mode=mode):
                self.assertTrue(
                    execution_policy.validate_execution_symbol(
                        "XAUUSD",
                        mode=mode,
                    )[0]
                )
                self.assertFalse(
                    execution_policy.validate_execution_symbol(
                        "EURUSD",
                        mode=mode,
                    )[0]
                )

    def test_legacy_stays_eurusd_only_and_manual_demo_adds_controlled_xau(self):
        self.assertTrue(execution_policy.validate_execution_symbol("EURUSD")[0])
        self.assertFalse(execution_policy.validate_execution_symbol("XAUUSD")[0])
        self.assertTrue(
            execution_policy.validate_execution_symbol(
                "EURUSD",
                mode="DEMO",
            )[0]
        )
        self.assertTrue(
            execution_policy.validate_execution_symbol(
                "XAUUSD",
                mode="DEMO",
            )[0]
        )

    def test_explicit_invalid_mode_fails_closed(self):
        for mode in ("", "UNKNOWN", 1, True):
            with self.subTest(mode=mode):
                allowed, reason = execution_policy.validate_execution_symbol(
                    "EURUSD",
                    mode=mode,
                )
                self.assertFalse(allowed)
                self.assertIn("mode", reason.lower())
                self.assertEqual(
                    frozenset(),
                    execution_policy.execution_approved_symbols_for_mode(mode),
                )

    def test_blocked_shadow_and_mt5_binding_still_override_mode_scope(self):
        self.assertFalse(
            execution_policy.validate_execution_symbol(
                "GBPUSD",
                mode="DEMO_AUTO",
            )[0]
        )
        self.assertFalse(
            execution_policy.validate_execution_symbol(
                "BTCUSD",
                mode="DEMO_AUTO",
            )[0]
        )
        allowed, reason = execution_policy.validate_execution_symbol(
            "XAUUSD",
            "GOLD",
            require_mt5_match=True,
            mode="DEMO_AUTO",
        )
        self.assertFalse(allowed)
        self.assertIn("mismatch", reason.lower())

    def test_symbol_scope_does_not_open_checked_in_mode_locks(self):
        self.assertTrue(
            execution_policy.validate_execution_symbol(
                "XAUUSD",
                mode="DEMO_AUTO",
            )[0]
        )
        self.assertEqual(
            (False, ("DEMO_AUTO_ORDER_LOCKED",)),
            execution_policy.execution_mode_policy_decision("DEMO_AUTO"),
        )
        self.assertEqual(
            (False, ("LIVE_MODE_LOCKED",)),
            execution_policy.execution_mode_policy_decision("LIVE"),
        )

    def test_every_live_runtime_symbol_boundary_supplies_exact_mode(self):
        expected_files = {
            "executor.py",
            "mt5_adapter.py",
            "production_bootstrap.py",
            "risk.py",
            "runtime_service.py",
            "runtime_supervisor.py",
        }
        observed_files = set()
        for path in sorted((ROOT / "live_runtime").glob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                target = node.func
                name = (
                    target.id
                    if isinstance(target, ast.Name)
                    else target.attr
                    if isinstance(target, ast.Attribute)
                    else ""
                )
                if name != "validate_execution_symbol":
                    continue
                observed_files.add(path.name)
                self.assertIn(
                    "mode",
                    {keyword.arg for keyword in node.keywords},
                    f"{path.name}:{node.lineno} omits exact execution mode",
                )
        self.assertEqual(expected_files, observed_files)


if __name__ == "__main__":
    unittest.main()
