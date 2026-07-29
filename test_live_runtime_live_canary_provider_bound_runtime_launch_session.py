from __future__ import annotations

import ast
from dataclasses import replace
from datetime import timedelta
from pathlib import Path
import subprocess
import sys
import time
import unittest
from unittest import mock

import execution_policy
from live_runtime.live_canary_provider_bound_runtime_launch_session import (
    LiveCanaryProviderBoundRuntimeLaunchSession,
    activate_live_canary_provider_bound_runtime_launch_session,
    is_live_canary_provider_bound_runtime_launch_session,
)
from live_runtime.live_canary_runtime_authority import (
    LiveCanaryRuntimeLaunchSessionError,
    is_live_canary_runtime_launch_session,
)
from live_runtime.live_canary_runtime_launch_session import (
    activate_live_canary_runtime_launch_session,
)
import test_live_runtime_live_canary_portable_launch_custody as legacy_support
import test_live_runtime_live_canary_provider_bound_portable_custody as provider_support


NOW = legacy_support.NOW


class LiveCanaryProviderBoundRuntimeLaunchSessionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        legacy_prebootstrap = (
            legacy_support.prebootstrap_module.LiveCanaryPrebootstrapAdmissionTests
        )
        legacy_prebootstrap.setUpClass()
        provider_support.LiveCanaryProviderBoundPortableCustodyTests.setUpClass()

    @classmethod
    def tearDownClass(cls) -> None:
        provider_support.LiveCanaryProviderBoundPortableCustodyTests.tearDownClass()
        legacy_prebootstrap = (
            legacy_support.prebootstrap_module.LiveCanaryPrebootstrapAdmissionTests
        )
        legacy_prebootstrap.tearDownClass()
        super().tearDownClass()

    def setUp(self) -> None:
        provider = provider_support.LiveCanaryProviderBoundPortableCustodyTests(
            methodName="runTest"
        )
        provider.setUp()
        self.addCleanup(provider.doCleanups)
        self.provider = provider
        self.fixture = provider.fixture
        self.now = provider.now
        self.candidate = provider.fixture.candidate
        self.legacy_admission = provider.fixture.legacy_admission
        self.provider_bound_admission = provider.admission
        self.provider_bound_custody = provider._verify()

        legacy = legacy_support.LiveCanaryPortableLaunchCustodyTests(
            methodName="runTest"
        )
        legacy.fixture = provider.fixture.legacy_fixture
        legacy.candidate = self.candidate
        legacy.admission = self.legacy_admission
        legacy.launcher_policy = provider.launcher_policy
        legacy.custody_policy = provider.policy
        legacy.receipt = legacy._custody_receipt(uploaded_at=self.now)
        legacy.readback_calls = []
        legacy.custody_verification = legacy._verify_custody(
            now=self.now + timedelta(seconds=1)
        )
        legacy.launcher_attestation = legacy._launcher_attestation(
            f"provider-bound-session-{self._testMethodName}"
        )
        legacy.external = legacy_support.ExternalReservationCustody(
            legacy.custody_policy
        )
        self.legacy = legacy
        self.capability = legacy._consume()
        self.checkpoint_calls = 0
        self.nonce_calls = 0

    def _checkpoint(self) -> bytes:
        self.checkpoint_calls += 1
        payload = self.legacy.external.head
        if type(payload) is not bytes:
            raise RuntimeError("fixture checkpoint unavailable")
        return payload

    def _nonce(self, nonce_sha256: str) -> bool:
        self.nonce_calls += 1
        return self.legacy.external.nonce_seen(nonce_sha256)

    def _kwargs(self) -> dict[str, object]:
        return {
            "candidate": self.candidate,
            "legacy_admission": self.legacy_admission,
            "provider_bound_admission": self.provider_bound_admission,
            "provider_bound_custody": self.provider_bound_custody,
            "legacy_custody_verification": (
                self.legacy.custody_verification
            ),
            "launch_capability": self.capability,
            "expected_candidate_sha256": self.candidate.content_sha256,
            "expected_admission_sha256": (
                self.legacy_admission.content_sha256
            ),
            "expected_launch_capability_sha256": (
                self.capability.content_sha256
            ),
            "expected_checkpoint_sha256": self.capability.checkpoint_sha256,
            "expected_launch_nonce_sha256": (
                self.capability.launch_nonce_sha256
            ),
            "expected_runtime_profile_sha256": (
                self.candidate.runtime_profile_sha256
            ),
            "expected_release_manifest_sha256": (
                self.candidate.release_manifest_sha256
            ),
            "expected_live_stage_binding_sha256": (
                self.candidate.live_stage_binding_sha256
            ),
            "launcher_policy": self.legacy.launcher_policy,
            "expected_launcher_policy_sha256": (
                self.legacy.launcher_policy.content_sha256
            ),
            "expected_deployment_host_alias_sha256": (
                self.legacy.launcher_policy.deployment_host_alias_sha256
            ),
            "expected_service_account_alias_sha256": (
                self.legacy.launcher_policy.service_account_alias_sha256
            ),
            "expected_task_definition_sha256": (
                self.legacy.launcher_policy.task_definition_sha256
            ),
            "expected_provider_bound_admission_sha256": (
                self.provider_bound_admission.content_sha256
            ),
            "expected_provider_bound_custody_sha256": (
                self.provider_bound_custody.content_sha256
            ),
            "external_checkpoint_provider": self._checkpoint,
            "external_nonce_seen_provider": self._nonce,
            "clock_provider": iter(
                (
                    self.now + timedelta(seconds=4),
                    self.now + timedelta(seconds=5),
                    self.now + timedelta(seconds=6),
                    self.now + timedelta(seconds=7),
                )
            ).__next__,
        }

    def _activate(self, **changes: object):
        values = self._kwargs()
        values.update(changes)
        with mock.patch.object(execution_policy, "LIVE_ALLOWED", True):
            return activate_live_canary_provider_bound_runtime_launch_session(
                **values
            )

    def _legacy_activate(self, *, fresh: bool = False):
        capability = self.capability
        if fresh:
            self.legacy.launcher_attestation = (
                self.legacy._launcher_attestation(
                    f"legacy-only-{self._testMethodName}"
                )
            )
            capability = self.legacy._consume()
        values = self._kwargs()
        values["launch_capability"] = capability
        values["expected_launch_capability_sha256"] = (
            capability.content_sha256
        )
        values["expected_checkpoint_sha256"] = (
            capability.checkpoint_sha256
        )
        values["expected_launch_nonce_sha256"] = (
            capability.launch_nonce_sha256
        )
        legacy_values = {
            name: value
            for name, value in values.items()
            if name
            not in {
                "legacy_admission",
                "provider_bound_admission",
                "provider_bound_custody",
                "legacy_custody_verification",
                "expected_provider_bound_admission_sha256",
                "expected_provider_bound_custody_sha256",
            }
        }
        legacy_values["admission"] = self.legacy_admission
        legacy_values["clock_provider"] = iter(
            (
                self.now + timedelta(seconds=9 if fresh else 5),
                self.now + timedelta(seconds=10 if fresh else 6),
            )
        ).__next__
        with mock.patch.object(execution_policy, "LIVE_ALLOWED", True):
            return activate_live_canary_runtime_launch_session(**legacy_values)

    def test_ac4_exact_legacy_cas_is_composed_once(self) -> None:
        started = time.monotonic()
        session = self._activate()
        self.assertLess(time.monotonic() - started, 2.0)
        self.assertEqual((2, 2), (self.checkpoint_calls, self.nonce_calls))
        self.assertTrue(
            is_live_canary_provider_bound_runtime_launch_session(session)
        )
        self.assertFalse(is_live_canary_runtime_launch_session(session))
        self.assertEqual(
            self.provider_bound_admission.content_sha256,
            session.provider_bound_admission_sha256,
        )
        self.assertEqual(
            self.provider_bound_custody.content_sha256,
            session.provider_bound_custody_sha256,
        )
        self.assertEqual(
            min(
                self.capability.expires_at_utc,
                self.provider_bound_admission.provider_acceptance_valid_until_utc,
                self.provider_bound_custody.valid_until_utc,
            ),
            session.valid_until_utc,
        )

    def test_ac5_provider_target_and_independent_pins_fail_before_reads(self) -> None:
        scenarios = {
            "expected_provider_bound_admission_sha256": (
                provider_support.digest("wrong-provider-admission")
            ),
            "expected_provider_bound_custody_sha256": provider_support.digest(
                "wrong-provider-custody"
            ),
            "expected_deployment_host_alias_sha256": provider_support.digest(
                "wrong-host"
            ),
        }
        for name, value in scenarios.items():
            with self.subTest(name=name), self.assertRaisesRegex(
                LiveCanaryRuntimeLaunchSessionError,
                "BINDING_MISMATCH",
            ):
                self._activate(**{name: value})
        self.assertEqual((0, 0), (self.checkpoint_calls, self.nonce_calls))

        wrong_candidate = replace(
            self.candidate,
            installed_environment_sha256=provider_support.digest(
                "wrong-environment"
            ),
        )
        with self.assertRaisesRegex(
            LiveCanaryRuntimeLaunchSessionError,
            "PROVIDER_BOUND_LAUNCH_BINDING_MISMATCH",
        ):
            self._activate(candidate=wrong_candidate)
        self.assertEqual((0, 0), (self.checkpoint_calls, self.nonce_calls))

    def test_ac6_expiry_relock_and_safety_are_fail_closed(self) -> None:
        session = self._activate()
        self.assertIsInstance(
            session,
            LiveCanaryProviderBoundRuntimeLaunchSession,
        )
        self.assertTrue(session.bootstrap_authorized)
        self.assertTrue(session.process_launch_authorized)
        self.assertTrue(session.live_allowed)
        self.assertFalse(session.execution_authorized)
        self.assertFalse(session.broker_mutation_authorized)
        self.assertFalse(session.safe_to_demo_auto_order)
        self.assertTrue(session.independent_per_order_authorization_required)
        self.assertEqual("GATED_PRESENT", session.order_capability)
        with self.assertRaises(TypeError):
            replace(session)
        with mock.patch.object(execution_policy, "LIVE_ALLOWED", True):
            session.assert_current(now=self.now + timedelta(seconds=8))
        with self.assertRaisesRegex(
            LiveCanaryRuntimeLaunchSessionError,
            "CENTRAL_LIVE_LOCK_NOT_ENABLED",
        ):
            session.assert_current(now=self.now + timedelta(seconds=8))

    def test_ac7_legacy_session_does_not_satisfy_v2_predicate(self) -> None:
        legacy = self._legacy_activate()
        self.assertTrue(is_live_canary_runtime_launch_session(legacy))
        self.assertFalse(
            is_live_canary_provider_bound_runtime_launch_session(legacy)
        )
        forged = object.__new__(LiveCanaryProviderBoundRuntimeLaunchSession)
        self.assertFalse(
            is_live_canary_provider_bound_runtime_launch_session(forged)
        )

    def test_ac8_callback_failure_and_replay_are_sanitized(self) -> None:
        def private_failure() -> bytes:
            raise RuntimeError("credential-and-private-provider-path")

        with self.assertRaises(
            LiveCanaryRuntimeLaunchSessionError
        ) as captured:
            self._activate(external_checkpoint_provider=private_failure)
        self.assertEqual(
            "EXTERNAL_CHECKPOINT_INITIAL_READ_FAILED",
            captured.exception.reason_code,
        )
        self.assertNotIn("credential", str(captured.exception))

        session = self._activate()
        self.assertTrue(
            is_live_canary_provider_bound_runtime_launch_session(session)
        )
        with self.assertRaisesRegex(
            LiveCanaryRuntimeLaunchSessionError,
            "REPLAYED",
        ):
            self._activate()

    def test_ac9_static_surface_and_optimized_mode(self) -> None:
        source_path = Path(
            "live_runtime/live_canary_provider_bound_runtime_launch_session.py"
        )
        source = source_path.read_text(encoding="utf-8")
        tree = ast.parse(source)
        self.assertFalse(
            any(isinstance(node, ast.Assert) for node in ast.walk(tree))
        )
        forbidden = {
            "MetaTrader5",
            "requests",
            "socket",
            "subprocess",
            "urllib",
            "sqlite3",
            "order_send",
            "initialize",
            "Popen",
            "system",
            "open",
        }
        self.assertTrue(forbidden.isdisjoint(source.split()))
        self.assertIs(False, execution_policy.LIVE_ALLOWED)
        if sys.flags.optimize:
            self.skipTest("already running under optimized mode")
        completed = subprocess.run(
            [
                sys.executable,
                "-O",
                "-B",
                "-m",
                "unittest",
                (
                    "test_live_runtime_live_canary_provider_bound_runtime_"
                    "launch_session."
                    "LiveCanaryProviderBoundRuntimeLaunchSessionTests."
                    "test_ac4_exact_legacy_cas_is_composed_once"
                ),
            ],
            cwd=Path(__file__).resolve().parent,
            capture_output=True,
            text=True,
            timeout=180,
        )
        self.assertEqual(0, completed.returncode, completed.stderr)


if __name__ == "__main__":
    unittest.main()
