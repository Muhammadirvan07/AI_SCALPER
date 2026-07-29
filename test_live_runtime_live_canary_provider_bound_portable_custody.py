from __future__ import annotations

from dataclasses import replace
from datetime import timedelta
import hashlib
from pathlib import Path
import subprocess
import sys
import time
import unittest
from unittest import mock

import execution_policy
from live_runtime.asymmetric_release_trust import (
    EXECUTION_RELEASE_PROFILE,
    ExternalLauncherTrustPolicy,
    rsa_public_key_fingerprint_sha256,
)
from live_runtime.live_canary_portable_launch_custody import (
    LiveCanaryPortableCustodyPolicy,
)
from live_runtime.live_canary_provider_bound_portable_custody import (
    LiveCanaryProviderBoundAdmissionCustodyReceipt,
    LiveCanaryProviderBoundPortableCustodyError,
    VerifiedLiveCanaryProviderBoundAdmissionCustody,
    decode_live_canary_provider_bound_admission_custody_receipt,
    is_verified_live_canary_provider_bound_admission_custody,
    provider_bound_admission_custody_signing_message,
    verify_live_canary_provider_bound_admission_custody,
)
import test_live_runtime_live_canary_portable_launch_custody as custody_support
from test_live_runtime_live_canary_provider_bound_prebootstrap_admission import (
    LiveCanaryProviderBoundPrebootstrapAdmissionTests as ProviderAdmissionTests,
)


def digest(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


class LiveCanaryProviderBoundPortableCustodyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        ProviderAdmissionTests.setUpClass()

    @classmethod
    def tearDownClass(cls) -> None:
        ProviderAdmissionTests.tearDownClass()
        super().tearDownClass()

    def setUp(self) -> None:
        fixture = ProviderAdmissionTests(
            methodName="runTest"
        )
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.fixture = fixture
        self.admission = fixture._assess()
        self.now = fixture.now
        self.launcher_policy = ExternalLauncherTrustPolicy(
            policy_id="xm-provider-bound-launcher-policy-v2",
            release_profile=EXECUTION_RELEASE_PROFILE,
            issuer_id="offline-xm-live-launcher-authority",
            issuer_key_id="xm-live-launcher-rsa-key-v1",
            rsa_modulus_hex=custody_support.LAUNCHER_N,
            rsa_exponent=65_537,
            public_key_fingerprint_sha256=(
                rsa_public_key_fingerprint_sha256(
                    custody_support.LAUNCHER_N,
                    65_537,
                )
            ),
            deployment_host_alias_sha256=(
                self.admission.target_host_identity_sha256
            ),
            service_account_alias_sha256=digest(
                "xm-live-service-account"
            ),
            task_definition_sha256=(
                self.admission.live_execution_task_definition_sha256
            ),
            maximum_ttl_seconds=300,
        )
        self.policy = self._policy()
        self.receipt = self._receipt()
        self.readback_calls: list[tuple[str, str, str]] = []

    def _policy(self, **changes: object) -> LiveCanaryPortableCustodyPolicy:
        values: dict[str, object] = {
            "policy_id": "xm-provider-bound-portable-custody-v2",
            "custody_issuer_id": "offhost-xm-live-worm-custodian",
            "custody_key_id": "xm-live-worm-rsa-key-v1",
            "rsa_modulus_hex": custody_support.CUSTODY_N,
            "rsa_exponent": 65_537,
            "public_key_fingerprint_sha256": (
                rsa_public_key_fingerprint_sha256(
                    custody_support.CUSTODY_N,
                    65_537,
                )
            ),
            "worm_repository_alias_sha256": digest(
                "xm-provider-bound-worm-repository"
            ),
            "deployment_host_alias_sha256": (
                self.admission.target_host_identity_sha256
            ),
            "service_account_alias_sha256": (
                self.launcher_policy.service_account_alias_sha256
            ),
            "task_definition_sha256": (
                self.admission.live_execution_task_definition_sha256
            ),
            "launcher_trust_policy_sha256": (
                self.launcher_policy.content_sha256
            ),
            "minimum_retention_seconds": 31_536_000,
            "maximum_receipt_age_seconds": 300,
            "maximum_launch_ttl_seconds": 30,
        }
        values.update(changes)
        return LiveCanaryPortableCustodyPolicy(**values)

    def _receipt(
        self,
        *,
        policy: LiveCanaryPortableCustodyPolicy | None = None,
        admission=None,
        uploaded_at=None,
        retain_until=None,
    ) -> LiveCanaryProviderBoundAdmissionCustodyReceipt:
        selected_policy = policy or self.policy
        selected_admission = admission or self.admission
        uploaded = uploaded_at or self.now
        content = selected_admission.canonical_json().encode("utf-8")
        unsigned = LiveCanaryProviderBoundAdmissionCustodyReceipt(
            receipt_id="xm-provider-bound-admission-worm-receipt-1",
            custody_policy_sha256=selected_policy.content_sha256,
            provider_bound_admission_sha256=(
                selected_admission.content_sha256
            ),
            legacy_admission_sha256=(
                selected_admission.legacy_admission_sha256
            ),
            candidate_sha256=selected_admission.candidate_sha256,
            demo_source_bound_verification_sha256=(
                selected_admission.demo_source_bound_verification_sha256
            ),
            live_source_bound_verification_sha256=(
                selected_admission.live_source_bound_verification_sha256
            ),
            provider_acceptance_sha256=(
                selected_admission.provider_acceptance_sha256
            ),
            provider_acceptance_policy_sha256=(
                selected_admission.provider_acceptance_policy_sha256
            ),
            provider_conformance_review_sha256=(
                selected_admission.provider_conformance_review_sha256
            ),
            target_host_identity_sha256=(
                selected_admission.target_host_identity_sha256
            ),
            launcher_trust_policy_sha256=(
                selected_policy.launcher_trust_policy_sha256
            ),
            service_account_alias_sha256=(
                selected_policy.service_account_alias_sha256
            ),
            installed_environment_sha256=(
                selected_admission.installed_environment_sha256
            ),
            live_execution_release_identity_sha256=(
                selected_admission.live_execution_release_identity_sha256
            ),
            live_execution_task_definition_sha256=(
                selected_admission.live_execution_task_definition_sha256
            ),
            authorization_sha256=selected_admission.authorization_sha256,
            validation_sha256=selected_admission.validation_sha256,
            provider_acceptance_valid_until_utc=(
                selected_admission.provider_acceptance_valid_until_utc
            ),
            worm_repository_alias_sha256=(
                selected_policy.worm_repository_alias_sha256
            ),
            object_key_sha256=digest("provider-bound-worm-object-key"),
            object_version_sha256=digest(
                "provider-bound-worm-object-version-1"
            ),
            stored_content_sha256=hashlib.sha256(content).hexdigest(),
            stored_content_size_bytes=len(content),
            uploaded_at_utc=uploaded,
            retain_until_utc=(
                retain_until or uploaded + timedelta(days=366)
            ),
            custody_issuer_id=selected_policy.custody_issuer_id,
            custody_key_id=selected_policy.custody_key_id,
            public_key_fingerprint_sha256=(
                selected_policy.public_key_fingerprint_sha256
            ),
        )
        return replace(
            unsigned,
            signature_rsa_pkcs1v15_sha256_hex=(
                custody_support.custody_signature(
                    provider_bound_admission_custody_signing_message(
                        unsigned
                    )
                )
            ),
        )

    def _readback(self, repository: str, key: str, version: str) -> bytes:
        self.readback_calls.append((repository, key, version))
        return self.admission.canonical_json().encode("utf-8")

    def _verify(self, **changes: object):
        values: dict[str, object] = {
            "receipt_payload": self.receipt.canonical_json().encode("utf-8"),
            "policy": self.policy,
            "expected_policy_sha256": self.policy.content_sha256,
            "admission": self.admission,
            "provider_acceptance_policy": self.fixture.provider.policy,
            "object_readback_provider": self._readback,
            "clock_provider": lambda: self.now + timedelta(seconds=1),
        }
        values.update(changes)
        return verify_live_canary_provider_bound_admission_custody(**values)

    def test_ac1_exact_provider_bound_worm_custody_is_sealed(self) -> None:
        started = time.monotonic()
        first = self._verify()
        second = self._verify()
        self.assertLess(time.monotonic() - started, 2.0)
        self.assertEqual(first.to_canonical_dict(), second.to_canonical_dict())
        self.assertTrue(
            is_verified_live_canary_provider_bound_admission_custody(first)
        )
        self.assertEqual(
            self.admission.content_sha256,
            first.provider_bound_admission_sha256,
        )
        self.assertEqual(
            self.admission.provider_acceptance_sha256,
            first.provider_acceptance_sha256,
        )
        self.assertEqual(
            self.launcher_policy.content_sha256,
            first.launcher_trust_policy_sha256,
        )
        self.assertEqual(
            self.launcher_policy.service_account_alias_sha256,
            first.service_account_alias_sha256,
        )
        self.assertEqual(2, len(self.readback_calls))
        self.assertFalse(first.live_allowed)
        self.assertFalse(first.execution_authorized)
        self.assertFalse(first.process_launch_authorized)
        self.assertEqual("DISABLED", first.order_capability)

    def test_ac2_provider_authority_host_and_task_separation(self) -> None:
        original_provider_policy = self.fixture.provider.policy
        reused_policy = replace(
            original_provider_policy,
            owner_authority_key_id=self.policy.custody_key_id,
        )
        self.fixture.provider.policy = reused_policy
        try:
            with self.assertRaisesRegex(
                LiveCanaryProviderBoundPortableCustodyError,
                "CUSTODY_PROVIDER_AUTHORITY_REUSE",
            ):
                self._verify(provider_acceptance_policy=reused_policy)
        finally:
            self.fixture.provider.policy = original_provider_policy
        self.assertEqual([], self.readback_calls)

        for field in (
            "deployment_host_alias_sha256",
            "task_definition_sha256",
        ):
            with self.subTest(field=field):
                changed = self._policy(**{field: digest(f"wrong:{field}")})
                with self.assertRaisesRegex(
                    LiveCanaryProviderBoundPortableCustodyError,
                    "CUSTODY_TARGET_BINDING_MISMATCH",
                ):
                    self._verify(
                        policy=changed,
                        expected_policy_sha256=changed.content_sha256,
                    )

    def test_ac3_time_retention_and_readback_fail_closed(self) -> None:
        expired = self._receipt(
            uploaded_at=self.now - timedelta(minutes=10),
        )
        short_retention = self._receipt(
            retain_until=self.now + timedelta(days=1),
        )
        scenarios = (
            {
                "receipt_payload": expired.canonical_json().encode("utf-8")
            },
            {
                "receipt_payload": short_retention.canonical_json().encode(
                    "utf-8"
                )
            },
            {"object_readback_provider": lambda *_args: b"{}"},
            {"object_readback_provider": lambda *_args: "not-bytes"},
            {
                "clock_provider": lambda: (
                    self.admission.provider_acceptance_valid_until_utc
                )
            },
        )
        for changes in scenarios:
            with self.subTest(changes=tuple(changes)), self.assertRaises(
                LiveCanaryProviderBoundPortableCustodyError
            ):
                self._verify(**changes)

        def private_failure(*_args):
            raise RuntimeError("private-storage-path-and-credential")

        with self.assertRaises(
            LiveCanaryProviderBoundPortableCustodyError
        ) as caught:
            self._verify(object_readback_provider=private_failure)
        self.assertEqual(
            "PROVIDER_BOUND_CUSTODY_READBACK_FAILED",
            caught.exception.reason_code,
        )
        self.assertIsNone(caught.exception.__cause__)

    def test_ac4_signature_and_strict_canonical_json_are_required(self) -> None:
        tampered = replace(
            self.receipt,
            signature_rsa_pkcs1v15_sha256_hex=(
                "0" * len(self.receipt.signature_rsa_pkcs1v15_sha256_hex)
            ),
        )
        with self.assertRaisesRegex(
            LiveCanaryProviderBoundPortableCustodyError,
            "SIGNATURE_INVALID",
        ):
            self._verify(
                receipt_payload=tampered.canonical_json().encode("utf-8")
            )
        duplicate = self.receipt.canonical_json().encode("utf-8").replace(
            b"{",
            b'{"receipt_id":"duplicate",',
            1,
        )
        with self.assertRaisesRegex(
            LiveCanaryProviderBoundPortableCustodyError,
            "DUPLICATE_KEY",
        ):
            decode_live_canary_provider_bound_admission_custody_receipt(
                duplicate
            )

    def test_ac5_seals_and_central_lock_are_mandatory(self) -> None:
        forged = object.__new__(type(self.admission))
        with self.assertRaisesRegex(
            LiveCanaryProviderBoundPortableCustodyError,
            "PROVIDER_BOUND_ADMISSION_UNSEALED",
        ):
            self._verify(admission=forged)
        with mock.patch.object(execution_policy, "LIVE_ALLOWED", True):
            with self.assertRaisesRegex(
                LiveCanaryProviderBoundPortableCustodyError,
                "CENTRAL_LIVE_LOCK_NOT_FALSE",
            ):
                self._verify()
        with self.assertRaises(TypeError):
            VerifiedLiveCanaryProviderBoundAdmissionCustody(
                checked_at_utc=self.now,
                valid_until_utc=self.now + timedelta(seconds=1),
                receipt_sha256="1" * 64,
                custody_policy_sha256="2" * 64,
                provider_bound_admission_sha256="3" * 64,
                legacy_admission_sha256="4" * 64,
                candidate_sha256="5" * 64,
                provider_acceptance_sha256="6" * 64,
                provider_acceptance_policy_sha256="7" * 64,
                provider_conformance_review_sha256="8" * 64,
                target_host_identity_sha256="9" * 64,
                launcher_trust_policy_sha256="a" * 64,
                service_account_alias_sha256="b" * 64,
                installed_environment_sha256="a" * 64,
                live_execution_release_identity_sha256="b" * 64,
                live_execution_task_definition_sha256="c" * 64,
                authorization_sha256="d" * 64,
                validation_sha256="e" * 64,
                worm_repository_alias_sha256="f" * 64,
                object_key_sha256="1" * 64,
                object_version_sha256="2" * 64,
                stored_content_sha256="3" * 64,
                stored_content_size_bytes=1,
                retain_until_utc=self.now + timedelta(days=1),
                provider_acceptance_valid_until_utc=(
                    self.now + timedelta(seconds=1)
                ),
            )

    def test_ac9_static_surface_and_optimized_mode(self) -> None:
        source = Path(
            "live_runtime/live_canary_provider_bound_portable_custody.py"
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
            "private_exponent",
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
                    "test_live_runtime_live_canary_provider_bound_portable_"
                    "custody."
                    "LiveCanaryProviderBoundPortableCustodyTests."
                    "test_ac1_exact_provider_bound_worm_custody_is_sealed"
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
