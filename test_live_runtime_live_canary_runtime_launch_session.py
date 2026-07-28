from __future__ import annotations

import ast
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import timedelta
from pathlib import Path
import unittest
from unittest import mock

import execution_policy
from live_runtime.live_canary_runtime_launch_session import (
    LiveCanaryRuntimeLaunchSession,
    LiveCanaryRuntimeLaunchSessionError,
    activate_live_canary_runtime_launch_session,
    is_live_canary_runtime_launch_session,
)
import test_live_runtime_live_canary_portable_launch_custody as custody_module


NOW = custody_module.NOW


class LiveCanaryRuntimeLaunchSessionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        custody_module.LiveCanaryPortableLaunchCustodyTests.setUpClass()

    @classmethod
    def tearDownClass(cls) -> None:
        custody_module.LiveCanaryPortableLaunchCustodyTests.tearDownClass()
        super().tearDownClass()

    def setUp(self) -> None:
        fixture = custody_module.LiveCanaryPortableLaunchCustodyTests(
            methodName="runTest"
        )
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.fixture = fixture
        fixture.launcher_attestation = fixture._launcher_attestation(
            f"runtime-session-{self._testMethodName}"
        )
        self.capability = fixture._consume()
        self.checkpoint_calls = 0
        self.nonce_calls = 0

    def _checkpoint(self) -> bytes:
        self.checkpoint_calls += 1
        payload = self.fixture.external.head
        if type(payload) is not bytes:
            raise RuntimeError("fixture checkpoint is absent")
        return payload

    def _nonce(self, nonce_sha256: str) -> bool:
        self.nonce_calls += 1
        return self.fixture.external.nonce_seen(nonce_sha256)

    def _kwargs(self) -> dict[str, object]:
        return {
            "candidate": self.fixture.candidate,
            "admission": self.fixture.admission,
            "launch_capability": self.capability,
            "expected_candidate_sha256": (
                self.fixture.candidate.content_sha256
            ),
            "expected_admission_sha256": (
                self.fixture.admission.content_sha256
            ),
            "expected_launch_capability_sha256": (
                self.capability.content_sha256
            ),
            "expected_checkpoint_sha256": self.capability.checkpoint_sha256,
            "expected_launch_nonce_sha256": (
                self.capability.launch_nonce_sha256
            ),
            "expected_runtime_profile_sha256": (
                self.fixture.candidate.runtime_profile_sha256
            ),
            "expected_release_manifest_sha256": (
                self.fixture.candidate.release_manifest_sha256
            ),
            "expected_live_stage_binding_sha256": (
                self.fixture.candidate.live_stage_binding_sha256
            ),
            "launcher_policy": self.fixture.launcher_policy,
            "expected_launcher_policy_sha256": (
                self.fixture.launcher_policy.content_sha256
            ),
            "expected_deployment_host_alias_sha256": (
                self.fixture.launcher_policy.deployment_host_alias_sha256
            ),
            "expected_service_account_alias_sha256": (
                self.fixture.launcher_policy.service_account_alias_sha256
            ),
            "expected_task_definition_sha256": (
                self.fixture.launcher_policy.task_definition_sha256
            ),
            "external_checkpoint_provider": self._checkpoint,
            "external_nonce_seen_provider": self._nonce,
            "clock_provider": iter(
                (
                    NOW + timedelta(seconds=4),
                    NOW + timedelta(seconds=5),
                )
            ).__next__,
        }

    def _activate(self, **overrides: object):
        kwargs = self._kwargs()
        kwargs.update(overrides)
        with mock.patch.object(execution_policy, "LIVE_ALLOWED", True):
            return activate_live_canary_runtime_launch_session(**kwargs)

    def test_ac1_checked_in_lock_and_mutual_exclusion_fail_before_callbacks(self):
        with self.assertRaisesRegex(
            LiveCanaryRuntimeLaunchSessionError,
            "CENTRAL_LIVE_LOCK_NOT_ENABLED",
        ):
            activate_live_canary_runtime_launch_session(**self._kwargs())
        self.assertEqual((0, 0), (self.checkpoint_calls, self.nonce_calls))

        with (
            mock.patch.object(execution_policy, "LIVE_ALLOWED", True),
            mock.patch.object(
                execution_policy,
                "SAFE_TO_DEMO_AUTO_ORDER",
                True,
            ),
            self.assertRaisesRegex(
                LiveCanaryRuntimeLaunchSessionError,
                "MUTUAL_EXCLUSION",
            ),
        ):
            activate_live_canary_runtime_launch_session(**self._kwargs())
        self.assertEqual((0, 0), (self.checkpoint_calls, self.nonce_calls))

        with mock.patch.object(
            execution_policy,
            "LIVE_CANARY_EXECUTION_APPROVED_SYMBOLS",
            frozenset({"XAUUSD", "EURUSD"}),
        ), self.assertRaisesRegex(
            LiveCanaryRuntimeLaunchSessionError,
            "CENTRAL_LIVE_SYMBOL_SCOPE_DRIFT",
        ):
            self._activate()
        self.assertEqual((0, 0), (self.checkpoint_calls, self.nonce_calls))

    def test_ac2_exact_types_and_independent_pins_precede_callbacks(self):
        scenarios = {
            "expected_candidate_sha256": custody_module.digest("wrong-candidate"),
            "expected_admission_sha256": custody_module.digest("wrong-admission"),
            "expected_launch_capability_sha256": custody_module.digest(
                "wrong-capability"
            ),
            "expected_checkpoint_sha256": custody_module.digest("wrong-head"),
            "expected_launch_nonce_sha256": custody_module.digest("wrong-nonce"),
            "expected_runtime_profile_sha256": custody_module.digest(
                "wrong-runtime"
            ),
            "expected_release_manifest_sha256": custody_module.digest(
                "wrong-release"
            ),
            "expected_live_stage_binding_sha256": custody_module.digest(
                "wrong-stage"
            ),
            "expected_launcher_policy_sha256": custody_module.digest(
                "wrong-launcher-policy"
            ),
            "expected_deployment_host_alias_sha256": custody_module.digest(
                "wrong-host"
            ),
            "expected_service_account_alias_sha256": custody_module.digest(
                "wrong-service"
            ),
            "expected_task_definition_sha256": custody_module.digest(
                "wrong-task"
            ),
        }
        for field, wrong in scenarios.items():
            with self.subTest(field=field), self.assertRaisesRegex(
                LiveCanaryRuntimeLaunchSessionError,
                "BINDING_MISMATCH",
            ):
                self._activate(**{field: wrong})
        self.assertEqual((0, 0), (self.checkpoint_calls, self.nonce_calls))

        with self.assertRaisesRegex(
            LiveCanaryRuntimeLaunchSessionError,
            "CANDIDATE_NOT_EXACT",
        ):
            self._activate(candidate=object())
        forged = object.__new__(LiveCanaryRuntimeLaunchSession)
        self.assertFalse(is_live_canary_runtime_launch_session(forged))

    def test_ac3_current_checkpoint_and_nonce_are_observed_twice(self):
        with self.assertRaisesRegex(
            LiveCanaryRuntimeLaunchSessionError,
            "NONCE_NOT_CONSUMED",
        ):
            self._activate(external_nonce_seen_provider=lambda _nonce: False)
        self.assertEqual(1, self.checkpoint_calls)

        with self.assertRaisesRegex(
            LiveCanaryRuntimeLaunchSessionError,
            "EXTERNAL_NONCE_INITIAL_READ_INVALID",
        ):
            self._activate(external_nonce_seen_provider=lambda _nonce: 1)

        self.checkpoint_calls = 0
        self.nonce_calls = 0
        session = self._activate()
        self.assertEqual((2, 2), (self.checkpoint_calls, self.nonce_calls))
        self.assertEqual(
            self.capability.checkpoint_sha256,
            session.checkpoint_sha256,
        )
        self.assertEqual(
            self.capability.launch_nonce_sha256,
            session.launch_nonce_sha256,
        )

    def test_ac4_success_is_sealed_launch_only_authority(self):
        def activate_once():
            return activate_live_canary_runtime_launch_session(**self._kwargs())

        with mock.patch.object(execution_policy, "LIVE_ALLOWED", True):
            with ThreadPoolExecutor(max_workers=2) as pool:
                futures = tuple(pool.submit(activate_once) for _ in range(2))
                results: list[object] = []
                errors: list[Exception] = []
                for future in futures:
                    try:
                        results.append(future.result())
                    except Exception as exc:
                        errors.append(exc)
        self.assertEqual(1, len(results))
        self.assertEqual(1, len(errors))
        self.assertIsInstance(errors[0], LiveCanaryRuntimeLaunchSessionError)
        self.assertEqual(
            "LIVE_CANARY_LAUNCH_CAPABILITY_REPLAYED",
            str(errors[0]),
        )
        session = results[0]
        self.assertIsInstance(session, LiveCanaryRuntimeLaunchSession)
        self.assertTrue(is_live_canary_runtime_launch_session(session))
        self.assertTrue(session.central_live_policy_enabled)
        self.assertTrue(session.bootstrap_authorized)
        self.assertTrue(session.process_launch_authorized)
        self.assertTrue(session.live_allowed)
        self.assertFalse(session.execution_authorized)
        self.assertFalse(session.broker_mutation_authorized)
        self.assertEqual("GATED_PRESENT", session.order_capability)
        self.assertEqual("XAUUSD", session.symbol)
        self.assertEqual(0.01, session.max_lot)
        self.assertEqual(1, session.max_concurrent_positions)
        with self.assertRaises(TypeError):
            replace(session)

        with mock.patch.object(execution_policy, "LIVE_ALLOWED", True):
            session.assert_current(now=NOW + timedelta(seconds=6))
        with self.assertRaisesRegex(
            LiveCanaryRuntimeLaunchSessionError,
            "CENTRAL_LIVE_LOCK_NOT_ENABLED",
        ):
            session.assert_current(now=NOW + timedelta(seconds=6))

    def test_ac5_race_expiry_relock_and_callback_errors_fail_closed(self):
        original_head = self.fixture.external.head
        reads = iter((original_head, b"{}"))
        with self.assertRaisesRegex(
            LiveCanaryRuntimeLaunchSessionError,
            "CHECKPOINT_CHANGED_DURING_ACTIVATION",
        ):
            self._activate(external_checkpoint_provider=reads.__next__)

        with self.assertRaisesRegex(
            LiveCanaryRuntimeLaunchSessionError,
            "CHECKPOINT_DOCUMENT_INVALID",
        ):
            self._activate(external_checkpoint_provider=lambda: b"{}")

        clocks = iter(
            (
                NOW + timedelta(seconds=5),
                NOW + timedelta(seconds=4),
            )
        )
        with self.assertRaisesRegex(
            LiveCanaryRuntimeLaunchSessionError,
            "CLOCK_WINDOW_INVALID",
        ):
            self._activate(clock_provider=clocks.__next__)

        def secret_failure() -> bytes:
            raise RuntimeError("broker-password=must-not-leak")

        with self.assertRaises(
            LiveCanaryRuntimeLaunchSessionError
        ) as captured:
            self._activate(external_checkpoint_provider=secret_failure)
        self.assertEqual(
            "EXTERNAL_CHECKPOINT_INITIAL_READ_FAILED",
            str(captured.exception),
        )
        self.assertNotIn("password", str(captured.exception))

        relock_calls = 0

        def relocking_nonce(nonce_sha256: str) -> bool:
            nonlocal relock_calls
            relock_calls += 1
            seen = self.fixture.external.nonce_seen(nonce_sha256)
            if relock_calls == 2:
                execution_policy.LIVE_ALLOWED = False
            return seen

        kwargs = self._kwargs()
        kwargs["external_nonce_seen_provider"] = relocking_nonce
        try:
            execution_policy.LIVE_ALLOWED = True
            with self.assertRaisesRegex(
                LiveCanaryRuntimeLaunchSessionError,
                "CENTRAL_LIVE_LOCK_NOT_ENABLED",
            ):
                activate_live_canary_runtime_launch_session(**kwargs)
        finally:
            execution_policy.LIVE_ALLOWED = False

    def test_ac6_static_surface_has_no_effect_calls_or_assert_statements(self):
        source_path = Path(
            "live_runtime/live_canary_runtime_launch_session.py"
        )
        source = source_path.read_text(encoding="utf-8")
        tree = ast.parse(source)
        self.assertFalse(any(isinstance(node, ast.Assert) for node in ast.walk(tree)))
        imported_roots = {
            alias.name.split(".")[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        }
        imported_roots.update(
            (node.module or "").split(".")[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom)
        )
        self.assertTrue(
            imported_roots.isdisjoint(
                {
                    "MetaTrader5",
                    "requests",
                    "socket",
                    "subprocess",
                    "urllib",
                }
            )
        )
        forbidden_calls = {
            "order_send",
            "initialize",
            "Popen",
            "run",
            "system",
            "open",
        }
        observed_calls = {
            (
                node.func.attr
                if isinstance(node.func, ast.Attribute)
                else node.func.id
                if isinstance(node.func, ast.Name)
                else ""
            )
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
        }
        self.assertTrue(observed_calls.isdisjoint(forbidden_calls))

        policy_tree = ast.parse(Path("execution_policy.py").read_text("utf-8"))
        live_assignments = [
            node
            for node in policy_tree.body
            if isinstance(node, ast.Assign)
            and any(
                isinstance(target, ast.Name) and target.id == "LIVE_ALLOWED"
                for target in node.targets
            )
        ]
        self.assertEqual(1, len(live_assignments))
        self.assertIsInstance(live_assignments[0].value, ast.Constant)
        self.assertIs(False, live_assignments[0].value.value)


if __name__ == "__main__":
    unittest.main()
