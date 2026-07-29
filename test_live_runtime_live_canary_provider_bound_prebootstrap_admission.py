from __future__ import annotations

from dataclasses import replace
from datetime import timedelta
import inspect
from pathlib import Path
import subprocess
import sys
import time
import types
import unittest
from unittest import mock

import execution_policy
from live_runtime.contracts import canonical_sha256
from live_runtime.live_canary_prebootstrap_admission import (
    assess_live_canary_prebootstrap_admission,
)
from live_runtime.live_canary_provider_bound_prebootstrap_admission import (
    ADMISSION_STATUS,
    LiveCanaryProviderBoundPrebootstrapAdmission,
    LiveCanaryProviderBoundPrebootstrapAdmissionError,
    assess_live_canary_provider_bound_prebootstrap_admission,
    is_live_canary_provider_bound_prebootstrap_admission,
)
from live_runtime.windows_provider_conformance_review import (
    live_execution_source_binding_from_verification,
)
import test_live_runtime_live_canary_prebootstrap_admission as legacy_module
import test_live_runtime_windows_live_provider_conformance_acceptance as provider_module


class LiveCanaryProviderBoundPrebootstrapAdmissionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        provider = provider_module.WindowsLiveProviderConformanceAcceptanceTests(
            methodName="test_exact_two_authority_acceptance_remains_non_executable"
        )
        provider.setUp()
        checked_at = legacy_module.NOW
        observed_at = (checked_at - timedelta(minutes=10)).strftime(
            "%Y-%m-%dT%H:%M:%S.%fZ"
        )
        for service in provider.fixture.evidence["services"]:
            for item in service["provider_evidence"]:
                item["observed_at_utc"] = observed_at
        with mock.patch.object(provider_module.v4_support, "NOW", checked_at):
            conformance_input = provider.fixture._assemble_v4().conformance_input
        provider.source = provider.fixture.live_bound
        provider.review = (
            provider_module.prepare_windows_three_service_provider_conformance_review(
                conformance_input,
                live_execution_source_bound_verification=provider.source,
                clock_provider=lambda: checked_at,
            )
        )
        provider.checked_at = checked_at
        identities = {
            str(item["service_role"]): str(
                item["configured_release_identity_sha256"]
            )
            for item in provider.review.services
        }
        provider.host_sha256 = provider_module.digest(
            "windows-live-target-host"
        )
        provider.policy = provider_module.WindowsLiveProviderAcceptancePolicy(
            policy_id="windows-live-provider-acceptance-policy-v1",
            provider_conformance_review_sha256=(
                provider.review.content_sha256
            ),
            live_bound_archive_sha256=provider.source.archive_sha256,
            live_binding_identity_sha256=(
                provider.source.binding_identity_sha256
            ),
            source_bound_archive_sha256=(
                provider.source.source_bound_archive_sha256
            ),
            source_archive_sha256=provider.source.source_archive_sha256,
            suite_identity_sha256=provider.source.suite_identity_sha256,
            decision_release_identity_sha256=identities["DECISION"],
            execution_release_identity_sha256=identities["EXECUTION"],
            status_monitor_release_identity_sha256=identities[
                "STATUS_MONITOR"
            ],
            target_host_identity_sha256=provider.host_sha256,
            owner_authority_id="live-provider-service-owner",
            owner_authority_key_id="live-provider-owner-rsa-v1",
            owner_rsa_modulus_hex=provider_module.OWNER_RSA_N_HEX,
            owner_rsa_exponent=65537,
            owner_public_key_fingerprint_sha256=(
                provider_module.rsa_public_key_fingerprint_sha256(
                    provider_module.OWNER_RSA_N_HEX,
                    65537,
                )
            ),
            runtime_authority_id="windows-live-runtime-authority",
            runtime_authority_key_id="windows-live-runtime-rsa-v1",
            runtime_rsa_modulus_hex=provider_module.RUNTIME_RSA_N_HEX,
            runtime_rsa_exponent=65537,
            runtime_public_key_fingerprint_sha256=(
                provider_module.rsa_public_key_fingerprint_sha256(
                    provider_module.RUNTIME_RSA_N_HEX,
                    65537,
                )
            ),
            maximum_acceptance_ttl_seconds=600,
        )
        provider.owner = provider._owner()
        provider.runtime = provider._runtime()
        cls.provider = provider
        cls.now = provider.checked_at
        cls.live_source = provider.source
        cls.demo_source = provider.fixture.live_fixture.source_bound

    @classmethod
    def tearDownClass(cls) -> None:
        cls.provider.doCleanups()
        super().tearDownClass()

    def setUp(self) -> None:
        fixture = legacy_module.LiveCanaryPrebootstrapAdmissionTests(
            methodName="runTest"
        )
        fixture.source = self.demo_source
        original_candidate = fixture._candidate

        def provider_bound_candidate(instance, activation):
            del instance
            candidate = original_candidate(activation)
            return replace(
                candidate,
                release_manifest_sha256=(
                    self.live_source.configured_release_identity_sha256
                ),
                installed_environment_sha256=(
                    self.provider.runtime.installed_environment_sha256
                ),
            )

        fixture._candidate = types.MethodType(
            provider_bound_candidate,
            fixture,
        )
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.legacy_fixture = fixture
        self.candidate = fixture.candidate
        self.legacy_admission = assess_live_canary_prebootstrap_admission(
            candidate=fixture.candidate,
            source_bound_verification=fixture.source,
            trust_policy=fixture.activation.policy,
            authorization=fixture.activation.authorization,
            validation=fixture.validation,
            clock_provider=lambda: self.now,
        )

    def _arguments(self) -> dict[str, object]:
        return {
            "candidate": self.candidate,
            "legacy_admission": self.legacy_admission,
            "demo_source_bound_verification": self.demo_source,
            "live_source_bound_verification": self.live_source,
            "conformance_review": self.provider.review,
            "provider_acceptance_policy": self.provider.policy,
            "owner_acceptance": self.provider.owner,
            "runtime_attestation": self.provider.runtime,
            "owner_validation_receipt_bytes": self.provider.owner_receipt,
            "runtime_evidence_bytes": self.provider.runtime_evidence,
            "runtime_validation_receipt_bytes": self.provider.runtime_receipt,
            "expected_provider_acceptance_policy_sha256": (
                self.provider.policy.content_sha256
            ),
            "expected_target_host_identity_sha256": self.provider.host_sha256,
            "activation_trust_policy": self.legacy_fixture.activation.policy,
            "authorization": self.legacy_fixture.activation.authorization,
            "validation": self.legacy_fixture.validation,
            "clock_provider": lambda: self.now,
        }

    def _assess(self, **changes: object):
        values = self._arguments()
        values.update(changes)
        return assess_live_canary_provider_bound_prebootstrap_admission(
            **values
        )

    def test_ac1_exact_legacy_and_live_ancestry_compose(self) -> None:
        result = self._assess()
        self.assertEqual(
            self.legacy_admission.content_sha256,
            result.legacy_admission_sha256,
        )
        self.assertEqual(
            canonical_sha256(
                live_execution_source_binding_from_verification(
                    self.live_source
                )
            ),
            result.live_source_bound_verification_sha256,
        )
        self.assertEqual(
            self.live_source.configured_release_identity_sha256,
            result.live_execution_release_identity_sha256,
        )
        self.assertEqual(
            self.live_source.task_definition_sha256,
            result.live_execution_task_definition_sha256,
        )

    def test_ac2_provider_acceptance_is_freshly_reverified(self) -> None:
        signature = inspect.signature(
            assess_live_canary_provider_bound_prebootstrap_admission
        )
        self.assertNotIn("provider_acceptance", signature.parameters)
        expired_owner = self.provider._owner(
            expires_at_utc=self.now,
        )
        with self.assertRaisesRegex(
            LiveCanaryProviderBoundPrebootstrapAdmissionError,
            "PROVIDER_ACCEPTANCE_INVALID",
        ):
            self._assess(owner_acceptance=expired_owner)

    def test_ac3_host_environment_release_and_task_are_exact(self) -> None:
        changed_runtime = self.provider._runtime(
            installed_environment_sha256=provider_module.digest(
                "another-installed-environment"
            )
        )
        with self.assertRaisesRegex(
            LiveCanaryProviderBoundPrebootstrapAdmissionError,
            "INSTALLED_ENVIRONMENT_MISMATCH",
        ):
            self._assess(runtime_attestation=changed_runtime)

        changed_candidate = replace(
            self.candidate,
            release_manifest_sha256=provider_module.digest(
                "another-live-release"
            ),
        )
        with self.assertRaisesRegex(
            LiveCanaryProviderBoundPrebootstrapAdmissionError,
            "LEGACY_ADMISSION_BINDING_MISMATCH",
        ):
            self._assess(candidate=changed_candidate)

    def test_ac4_provider_authorities_cannot_reuse_runtime_trust(self) -> None:
        original_policy = self.provider.policy
        try:
            changed_policy = replace(
                original_policy,
                owner_authority_key_id=self.candidate.news_guard_key_id,
            )
            self.provider.policy = changed_policy
            changed_owner = self.provider._owner()
            changed_runtime = self.provider._runtime()
        finally:
            self.provider.policy = original_policy
        with self.assertRaisesRegex(
            LiveCanaryProviderBoundPrebootstrapAdmissionError,
            "PROVIDER_AUTHORITY_REUSE",
        ):
            self._assess(
                provider_acceptance_policy=changed_policy,
                owner_acceptance=changed_owner,
                runtime_attestation=changed_runtime,
                expected_provider_acceptance_policy_sha256=(
                    changed_policy.content_sha256
                ),
            )

    def test_ac5_earliest_expiry_and_clock_regression_fail_closed(self) -> None:
        result = self._assess()
        expected_expiry = min(
            self.provider.owner.expires_at_utc,
            self.provider.runtime.expires_at_utc,
            self.legacy_fixture.activation.request.expires_at,
        )
        self.assertEqual(
            expected_expiry,
            result.provider_acceptance_valid_until_utc,
        )

        readings = iter(
            (
                self.now,
                self.now,
                self.now,
                self.now - timedelta(microseconds=1),
            )
        )
        with self.assertRaisesRegex(
            LiveCanaryProviderBoundPrebootstrapAdmissionError,
            "CLOCK_WINDOW_INVALID",
        ):
            self._assess(clock_provider=lambda: next(readings))

    def test_ac6_central_lock_is_checked_at_entry_and_completion(self) -> None:
        with mock.patch.object(execution_policy, "LIVE_ALLOWED", True):
            with self.assertRaisesRegex(
                LiveCanaryProviderBoundPrebootstrapAdmissionError,
                "CENTRAL_LIVE_LOCK_NOT_FALSE",
            ):
                self._assess()

        original_decision = execution_policy.execution_mode_policy_decision
        calls = 0

        def drifting(mode: str):
            nonlocal calls
            calls += 1
            if calls == 1:
                return original_decision(mode)
            return False, ("LIVE_MODE_LOCKED", "POLICY_DRIFT")

        with mock.patch.object(
            execution_policy,
            "execution_mode_policy_decision",
            drifting,
        ):
            with self.assertRaisesRegex(
                LiveCanaryProviderBoundPrebootstrapAdmissionError,
                "CENTRAL_LIVE_POLICY_DECISION_DRIFT",
            ):
                self._assess()

    def test_ac7_success_is_sealed_canonical_and_deny_only(self) -> None:
        started = time.monotonic()
        first = self._assess()
        second = self._assess()
        self.assertLess(time.monotonic() - started, 2.0)
        self.assertEqual(first.to_canonical_dict(), second.to_canonical_dict())
        self.assertEqual(ADMISSION_STATUS, first.status)
        self.assertTrue(first.provider_accepted)
        self.assertTrue(first.provider_binding_complete)
        self.assertTrue(first.portable_custody_required)
        self.assertTrue(first.central_unlock_required)
        self.assertFalse(first.bootstrap_authorized)
        self.assertFalse(first.process_launch_authorized)
        self.assertFalse(first.execution_authorized)
        self.assertFalse(first.activation_authorized)
        self.assertFalse(first.broker_mutation_authorized)
        self.assertFalse(first.live_allowed)
        self.assertFalse(first.safe_to_demo_auto_order)
        self.assertFalse(first.promotion_eligible)
        self.assertEqual("DISABLED", first.order_capability)
        self.assertEqual(0.01, first.max_lot)
        self.assertTrue(
            is_live_canary_provider_bound_prebootstrap_admission(first)
        )
        with self.assertRaises(TypeError):
            replace(first)

    def test_ac8_unsealed_and_cross_candidate_inputs_fail_closed(self) -> None:
        forged = object.__new__(type(self.legacy_admission))
        with self.assertRaisesRegex(
            LiveCanaryProviderBoundPrebootstrapAdmissionError,
            "LEGACY_PREBOOTSTRAP_ADMISSION_UNSEALED",
        ):
            self._assess(legacy_admission=forged)
        lookalike = object.__new__(
            LiveCanaryProviderBoundPrebootstrapAdmission
        )
        self.assertFalse(
            is_live_canary_provider_bound_prebootstrap_admission(lookalike)
        )

    def test_ac9_static_surface_and_optimized_mode(self) -> None:
        source = Path(
            "live_runtime/live_canary_provider_bound_prebootstrap_admission.py"
        ).read_text(encoding="utf-8")
        forbidden = (
            "order_send",
            "subprocess",
            "socket",
            "requests",
            "urllib",
            "sqlite3",
            "CredentialManager",
            "MetaTrader5",
            "Popen",
        )
        for token in forbidden:
            with self.subTest(token=token):
                self.assertNotIn(token, source)
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
                    "test_live_runtime_live_canary_provider_bound_"
                    "prebootstrap_admission."
                    "LiveCanaryProviderBoundPrebootstrapAdmissionTests."
                    "test_ac7_success_is_sealed_canonical_and_deny_only"
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
