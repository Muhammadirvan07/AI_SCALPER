from __future__ import annotations

from dataclasses import fields as dataclass_fields, replace
from datetime import timedelta
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest import mock

import execution_policy
from live_runtime.asymmetric_release_trust import (
    EXECUTION_RELEASE_PROFILE,
    ExternalLauncherTrustPolicy,
    VerifiedExternalLauncherAttestation,
    is_verified_external_launcher_attestation,
    rsa_public_key_fingerprint_sha256,
    verify_external_launcher_attestation,
)
from live_runtime.contracts import canonical_json
from live_runtime.live_canary_portable_launch_custody import (
    LiveCanaryAdmissionCustodyReceipt,
    LiveCanaryLaunchReservationAcknowledgement,
    LiveCanaryLaunchReservationCheckpoint,
    LiveCanaryOneUseLaunchCapability,
    LiveCanaryPortableCustodyPolicy,
    LiveCanaryPortableLaunchCustodyError,
    VerifiedLiveCanaryAdmissionCustody,
    admission_custody_signing_message,
    consume_live_canary_launch_reservation,
    decode_live_canary_admission_custody_receipt,
    decode_live_canary_launch_checkpoint,
    decode_live_canary_launch_proposal,
    is_live_canary_one_use_launch_capability,
    is_verified_live_canary_admission_custody,
    launch_acknowledgement_signing_message,
    launch_checkpoint_signing_message,
    verify_live_canary_admission_custody,
)
from live_runtime.live_canary_prebootstrap_admission import (
    LiveCanaryPrebootstrapAdmission,
    is_live_canary_prebootstrap_admission,
)
import test_live_runtime_asymmetric_release_trust as launcher_fixture_module
import test_live_runtime_live_canary_prebootstrap_admission as prebootstrap_module


NOW = prebootstrap_module.NOW
LAUNCHER_N = launcher_fixture_module.TEST_RSA_N_HEX
LAUNCHER_D = launcher_fixture_module.TEST_RSA_D_HEX
CUSTODY_N = (
    "a4c80a13bc1f3f73563025b57abaa7e292f479bce64d6f31c547b34984fce516"
    "b8a1a6b7ff478082bdf1802626c911e934e9811e6320f01c1fc94a11f4923d18"
    "32e3e076bf5781764dd305b64eeb07b9337830bd8bbf38e928d058b7bd386462"
    "d0eb405771f2aa674affc0037a46f0c099c90df5c246ab656da289565c386938"
    "f7033034e959d45e5a98e8be831a75c0854ec0bcf1907f471120ea0a89a95f34"
    "8e6c146c808681a4535a2a0bcdaf387b9fd353d92ec6641ebd4330dd62b214fc"
    "f46248e28209bf844be0379676fda2f5f201e7bdf4ab3af393c41eb92a310b00"
    "f2147365a779b8e57944cd58384422155c2677cc7f17693237553af3f9eb6288"
    "44bc7202aa8d4c68c7775c13e1b2e3cad197b19f60bdb6cbbf61e97dab7909f6"
    "4733156a76107b8548fb2738e36b6c04ed71aa5153e73ea383b4b21287ae8392"
    "35919e44b259050f6840d3a13c09781176216bd5486a03eb05c2bc15d649df09"
    "5ca38df0d47acb2150cd772f59c9f45f875c058d3eab3b564a50cf8de1ecbdad"
)
CUSTODY_D = (
    "0f204dcc81f85c5aba0eb167775cab0ca170cfbc0768144cfd4f17a6280f0ef8"
    "86fa4fd3941b7c30843f2704598b1b99ccc1a298a780de89b66143eb62080a93"
    "ae183d02a98dded47d5061b5da88b8acc78cc0eca5676851feed2137bca6f090"
    "219d76ca902b367944e935371c8266974786ad4162141aa7b4e8b6b2b6c476e4"
    "43c8872454476ab73e99cac3b2453b89f0b2c9fe8e2e3580d091b4ea42b8c984"
    "898e6251937ac56bd03af6a11ec076eee23d03f56bd5ca5b0804a2f7af97a955"
    "69176a1800b49186ea3e6b108096ede8ad103df868fd0d5e8c92450a1e57acc4"
    "593b5c9c0075714bda2a7c0ff91a504b76c1c18e1f19c5ccdaa603b3bc1ad28"
    "017405c086416fdfe49099fcc8a14a161cf9b98d758d7a03aba482596c8aaa6f7"
    "fd400fe75b16f12020ec95877a8956ed25ad4f212e7734e2bf1ad0d4cb583a54"
    "6045b427c47964bf0b121f56fc6b596eb2de8f41a317c8ae0b50e3963c9dddaa"
    "ba1d5de46783b69c6fd0f10f75ed7ac5faa83ceec20a4af72f18fbef026ce3"
)
RSA_DIGEST_INFO_PREFIX = bytes.fromhex(
    "3031300d060960864801650304020105000420"
)
LAUNCHER_DOMAIN = b"AI_SCALPER:WINDOWS_EXTERNAL_LAUNCHER_ATTESTATION:v1\x00"


def digest(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def rsa_sign(message: bytes, *, modulus_hex: str, private_hex: str) -> str:
    modulus = int(modulus_hex, 16)
    private_exponent = int(private_hex, 16)
    length = (modulus.bit_length() + 7) // 8
    digest_info = RSA_DIGEST_INFO_PREFIX + hashlib.sha256(message).digest()
    padding = b"\xff" * (length - len(digest_info) - 3)
    encoded = b"\x00\x01" + padding + b"\x00" + digest_info
    signature = pow(
        int.from_bytes(encoded, "big"),
        private_exponent,
        modulus,
    ).to_bytes(length, "big")
    return signature.hex()


def launcher_signature(message: bytes) -> str:
    return rsa_sign(
        message,
        modulus_hex=LAUNCHER_N,
        private_hex=LAUNCHER_D,
    )


def custody_signature(message: bytes) -> str:
    return rsa_sign(
        message,
        modulus_hex=CUSTODY_N,
        private_hex=CUSTODY_D,
    )


class ExternalReservationCustody:
    def __init__(self, policy: LiveCanaryPortableCustodyPolicy) -> None:
        self.policy = policy
        self.head: bytes | None = None
        self.seen: set[str] = set()
        self.cas_calls = 0
        self.reject_cas = False
        self.tamper_ack = False
        self.readback_mismatch = False
        self.omit_nonce_commit = False

    def checkpoint_provider(self) -> bytes | None:
        if self.readback_mismatch and self.head is not None:
            return b"{}"
        return self.head

    def nonce_seen(self, nonce_sha256: str) -> bool:
        return nonce_sha256 in self.seen

    def cas(self, expected: str, proposal_payload: bytes) -> tuple[bytes, bytes]:
        self.cas_calls += 1
        if self.reject_cas:
            raise RuntimeError("simulated CAS rejection")
        current = "0" * 64 if self.head is None else hashlib.sha256(
            self.head
        ).hexdigest()
        if expected != current:
            raise RuntimeError("simulated stale predecessor")
        proposal = decode_live_canary_launch_proposal(proposal_payload)
        if proposal.launcher_nonce_sha256 in self.seen:
            raise RuntimeError("simulated nonce replay")
        committed = proposal.requested_at_utc
        unsigned_checkpoint = LiveCanaryLaunchReservationCheckpoint(
            proposal=proposal,
            proposal_sha256=proposal.content_sha256,
            committed_at_utc=committed,
            custody_issuer_id=self.policy.custody_issuer_id,
            custody_key_id=self.policy.custody_key_id,
            public_key_fingerprint_sha256=(
                self.policy.public_key_fingerprint_sha256
            ),
        )
        checkpoint = replace(
            unsigned_checkpoint,
            signature_rsa_pkcs1v15_sha256_hex=custody_signature(
                launch_checkpoint_signing_message(unsigned_checkpoint)
            ),
        )
        unsigned_ack = LiveCanaryLaunchReservationAcknowledgement(
            expected_predecessor_checkpoint_sha256=expected,
            written_checkpoint_sha256=checkpoint.content_sha256,
            proposal_sha256=proposal.content_sha256,
            launcher_nonce_sha256=proposal.launcher_nonce_sha256,
            sequence=proposal.sequence,
            acknowledged_at_utc=committed + timedelta(microseconds=1),
            custody_issuer_id=self.policy.custody_issuer_id,
            custody_key_id=self.policy.custody_key_id,
            public_key_fingerprint_sha256=(
                self.policy.public_key_fingerprint_sha256
            ),
        )
        ack_signature = custody_signature(
            launch_acknowledgement_signing_message(unsigned_ack)
        )
        if self.tamper_ack:
            ack_signature = "0" * len(ack_signature)
        acknowledgement = replace(
            unsigned_ack,
            signature_rsa_pkcs1v15_sha256_hex=ack_signature,
        )
        checkpoint_payload = checkpoint.canonical_json().encode("utf-8")
        self.head = checkpoint_payload
        if not self.omit_nonce_commit:
            self.seen.add(proposal.launcher_nonce_sha256)
        return (
            checkpoint_payload,
            acknowledgement.canonical_json().encode("utf-8"),
        )


class LiveCanaryPortableLaunchCustodyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        prebootstrap_module.LiveCanaryPrebootstrapAdmissionTests.setUpClass()

    @classmethod
    def tearDownClass(cls) -> None:
        prebootstrap_module.LiveCanaryPrebootstrapAdmissionTests.tearDownClass()
        super().tearDownClass()

    def setUp(self) -> None:
        fixture = prebootstrap_module.LiveCanaryPrebootstrapAdmissionTests(
            methodName="runTest"
        )
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.fixture = fixture
        self.candidate = fixture.candidate
        self.admission = fixture._assess()
        self.launcher_policy = self._launcher_policy()
        self.custody_policy = self._custody_policy()
        self.receipt = self._custody_receipt()
        self.readback_calls: list[tuple[str, str, str]] = []
        self.custody_verification = self._verify_custody()
        self.launcher_attestation = self._launcher_attestation("launch-nonce-1")
        self.external = ExternalReservationCustody(self.custody_policy)

    def _launcher_policy(self) -> ExternalLauncherTrustPolicy:
        return ExternalLauncherTrustPolicy(
            policy_id="xm-live-canary-launcher-policy-v1",
            release_profile=EXECUTION_RELEASE_PROFILE,
            issuer_id="offline-xm-live-launcher-authority",
            issuer_key_id="xm-live-launcher-rsa-key-v1",
            rsa_modulus_hex=LAUNCHER_N,
            rsa_exponent=65_537,
            public_key_fingerprint_sha256=(
                rsa_public_key_fingerprint_sha256(LAUNCHER_N, 65_537)
            ),
            deployment_host_alias_sha256=digest("xm-live-windows-host"),
            service_account_alias_sha256=digest("xm-live-service-account"),
            task_definition_sha256=digest("xm-live-canary-task"),
            maximum_ttl_seconds=300,
        )

    def _custody_policy(
        self,
        **overrides: object,
    ) -> LiveCanaryPortableCustodyPolicy:
        values: dict[str, object] = {
            "policy_id": "xm-live-canary-portable-custody-v1",
            "custody_issuer_id": "offhost-xm-live-worm-custodian",
            "custody_key_id": "xm-live-worm-rsa-key-v1",
            "rsa_modulus_hex": CUSTODY_N,
            "rsa_exponent": 65_537,
            "public_key_fingerprint_sha256": (
                rsa_public_key_fingerprint_sha256(CUSTODY_N, 65_537)
            ),
            "worm_repository_alias_sha256": digest("xm-live-worm-repository"),
            "deployment_host_alias_sha256": (
                self.launcher_policy.deployment_host_alias_sha256
            ),
            "service_account_alias_sha256": (
                self.launcher_policy.service_account_alias_sha256
            ),
            "task_definition_sha256": (
                self.launcher_policy.task_definition_sha256
            ),
            "launcher_trust_policy_sha256": (
                self.launcher_policy.content_sha256
            ),
            "minimum_retention_seconds": 31_536_000,
            "maximum_receipt_age_seconds": 300,
            "maximum_launch_ttl_seconds": 30,
        }
        values.update(overrides)
        return LiveCanaryPortableCustodyPolicy(**values)

    def _custody_receipt(
        self,
        *,
        policy: LiveCanaryPortableCustodyPolicy | None = None,
        admission: LiveCanaryPrebootstrapAdmission | None = None,
        uploaded_at=NOW,
        retain_until=None,
    ) -> LiveCanaryAdmissionCustodyReceipt:
        selected_policy = policy or self.custody_policy
        selected_admission = admission or self.admission
        content = selected_admission.canonical_json().encode("utf-8")
        unsigned = LiveCanaryAdmissionCustodyReceipt(
            receipt_id="xm-live-canary-admission-worm-receipt-1",
            custody_policy_sha256=selected_policy.content_sha256,
            admission_sha256=selected_admission.content_sha256,
            candidate_sha256=selected_admission.candidate_sha256,
            source_bound_verification_sha256=(
                selected_admission.source_bound_verification_sha256
            ),
            authorization_sha256=selected_admission.authorization_sha256,
            validation_sha256=selected_admission.validation_sha256,
            worm_repository_alias_sha256=(
                selected_policy.worm_repository_alias_sha256
            ),
            object_key_sha256=digest("worm-object-key"),
            object_version_sha256=digest("worm-object-version-1"),
            stored_content_sha256=hashlib.sha256(content).hexdigest(),
            stored_content_size_bytes=len(content),
            uploaded_at_utc=uploaded_at,
            retain_until_utc=(
                retain_until or uploaded_at + timedelta(days=366)
            ),
            custody_issuer_id=selected_policy.custody_issuer_id,
            custody_key_id=selected_policy.custody_key_id,
            public_key_fingerprint_sha256=(
                selected_policy.public_key_fingerprint_sha256
            ),
        )
        return replace(
            unsigned,
            signature_rsa_pkcs1v15_sha256_hex=custody_signature(
                admission_custody_signing_message(unsigned)
            ),
        )

    def _readback(self, repository: str, key: str, version: str) -> bytes:
        self.readback_calls.append((repository, key, version))
        return self.admission.canonical_json().encode("utf-8")

    def _verify_custody(
        self,
        *,
        receipt: LiveCanaryAdmissionCustodyReceipt | None = None,
        policy: LiveCanaryPortableCustodyPolicy | None = None,
        admission: LiveCanaryPrebootstrapAdmission | None = None,
        readback_provider=None,
        now=NOW + timedelta(seconds=1),
    ) -> VerifiedLiveCanaryAdmissionCustody:
        selected_receipt = receipt or self.receipt
        selected_policy = policy or self.custody_policy
        return verify_live_canary_admission_custody(
            selected_receipt.canonical_json().encode("utf-8"),
            policy=selected_policy,
            expected_policy_sha256=selected_policy.content_sha256,
            admission=admission or self.admission,
            object_readback_provider=readback_provider or self._readback,
            clock_provider=lambda: now,
        )

    def _launcher_attestation(
        self,
        nonce_label: str,
    ) -> VerifiedExternalLauncherAttestation:
        nonce = digest(nonce_label)
        unsigned = {
            "attestation_id": f"xm-live-{nonce_label}",
            "trust_policy_sha256": self.launcher_policy.content_sha256,
            "release_profile": EXECUTION_RELEASE_PROFILE,
            "release_identity_sha256": self.candidate.release_manifest_sha256,
            "deployment_host_alias_sha256": (
                self.launcher_policy.deployment_host_alias_sha256
            ),
            "service_account_alias_sha256": (
                self.launcher_policy.service_account_alias_sha256
            ),
            "task_definition_sha256": (
                self.launcher_policy.task_definition_sha256
            ),
            "nonce_sha256": nonce,
            "issued_at_utc": NOW.isoformat(timespec="microseconds").replace(
                "+00:00",
                "Z",
            ),
            "not_before_utc": NOW.isoformat(timespec="microseconds").replace(
                "+00:00",
                "Z",
            ),
            "expires_at_utc": (
                NOW + timedelta(minutes=2)
            ).isoformat(timespec="microseconds").replace("+00:00", "Z"),
            "issuer_id": self.launcher_policy.issuer_id,
            "issuer_key_id": self.launcher_policy.issuer_key_id,
            "public_key_fingerprint_sha256": (
                self.launcher_policy.public_key_fingerprint_sha256
            ),
            "live_allowed": False,
            "safe_to_demo_auto_order": False,
            "execution_authority_granted": False,
            "order_capability": "DISABLED",
            "signature_algorithm": "RSASSA-PKCS1-v1_5-SHA256",
            "schema_version": "windows-external-launcher-attestation-v1",
        }
        signature = launcher_signature(
            LAUNCHER_DOMAIN + canonical_json(unsigned).encode("utf-8")
        )
        payload = canonical_json(
            {
                **unsigned,
                "signature_rsa_pkcs1v15_sha256_hex": signature,
            }
        )
        return verify_external_launcher_attestation(
            payload,
            policy_payload=self.launcher_policy.canonical_json(),
            expected_policy_sha256=self.launcher_policy.content_sha256,
            expected_release_identity_sha256=(
                self.candidate.release_manifest_sha256
            ),
            expected_release_profile=EXECUTION_RELEASE_PROFILE,
            clock_provider=lambda: NOW + timedelta(seconds=1),
        )

    def _consume(
        self,
        *,
        external: ExternalReservationCustody | None = None,
        launcher_attestation: VerifiedExternalLauncherAttestation | None = None,
        candidate=None,
        admission=None,
        custody_verification=None,
        custody_policy=None,
        expected_policy_sha256=None,
        expected_predecessor_checkpoint_sha256=None,
        clock_provider=None,
    ) -> LiveCanaryOneUseLaunchCapability:
        selected_external = external or self.external
        if expected_predecessor_checkpoint_sha256 is None:
            expected_predecessor_checkpoint_sha256 = (
                "0" * 64
                if selected_external.head is None
                else hashlib.sha256(selected_external.head).hexdigest()
            )
        readings = iter(
            (
                NOW + timedelta(seconds=2),
                NOW + timedelta(seconds=3),
            )
        )
        return consume_live_canary_launch_reservation(
            candidate=candidate or self.candidate,
            admission=admission or self.admission,
            custody_verification=(
                custody_verification or self.custody_verification
            ),
            activation_trust_policy=self.fixture.activation.policy,
            authorization=self.fixture.activation.authorization,
            validation=self.fixture.validation,
            custody_policy=custody_policy or self.custody_policy,
            expected_custody_policy_sha256=(
                expected_policy_sha256 or self.custody_policy.content_sha256
            ),
            launcher_policy=self.launcher_policy,
            launcher_attestation=(
                launcher_attestation or self.launcher_attestation
            ),
            expected_predecessor_checkpoint_sha256=(
                expected_predecessor_checkpoint_sha256
            ),
            external_checkpoint_provider=selected_external.checkpoint_provider,
            external_checkpoint_cas=selected_external.cas,
            external_nonce_seen_provider=selected_external.nonce_seen,
            clock_provider=clock_provider or (lambda: next(readings)),
        )

    def test_ac1_policy_is_canonical_public_and_deny_only(self):
        self.assertEqual(65_537, self.custody_policy.rsa_exponent)
        self.assertNotEqual(
            self.custody_policy.public_key_fingerprint_sha256,
            self.launcher_policy.public_key_fingerprint_sha256,
        )
        self.assertFalse(self.custody_policy.live_allowed)
        self.assertFalse(self.custody_policy.bootstrap_authorized)
        self.assertEqual("DISABLED", self.custody_policy.order_capability)

    def test_ac2_exact_worm_readback_returns_sealed_custody(self):
        verified = self.custody_verification
        self.assertTrue(verified.custody_verified)
        self.assertTrue(is_verified_live_canary_admission_custody(verified))
        self.assertFalse(verified.bootstrap_authorized)
        self.assertEqual(
            [(self.receipt.worm_repository_alias_sha256,
              self.receipt.object_key_sha256,
              self.receipt.object_version_sha256)],
            self.readback_calls,
        )

    def test_ac3_receipt_signature_readback_and_retention_tamper_fail(self):
        bad_signature = replace(
            self.receipt,
            signature_rsa_pkcs1v15_sha256_hex=(
                "0" * len(self.receipt.signature_rsa_pkcs1v15_sha256_hex)
            ),
        )
        with self.assertRaisesRegex(
            LiveCanaryPortableLaunchCustodyError,
            "ADMISSION_CUSTODY_SIGNATURE_INVALID",
        ):
            self._verify_custody(receipt=bad_signature)
        with self.assertRaisesRegex(
            LiveCanaryPortableLaunchCustodyError,
            "ADMISSION_CUSTODY_READBACK_MISMATCH",
        ):
            self._verify_custody(readback_provider=lambda *_: b"different")
        short = self._custody_receipt(
            retain_until=NOW + timedelta(days=1),
        )
        with self.assertRaisesRegex(
            LiveCanaryPortableLaunchCustodyError,
            "TIME_OR_RETENTION_INVALID",
        ):
            self._verify_custody(receipt=short)
        clock_readings = iter(
            (
                NOW + timedelta(seconds=1),
                NOW + timedelta(seconds=301),
            )
        )
        with self.assertRaisesRegex(
            LiveCanaryPortableLaunchCustodyError,
            "ADMISSION_CUSTODY_CLOCK_WINDOW_INVALID",
        ):
            verify_live_canary_admission_custody(
                self.receipt.canonical_json().encode("utf-8"),
                policy=self.custody_policy,
                expected_policy_sha256=self.custody_policy.content_sha256,
                admission=self.admission,
                object_readback_provider=self._readback,
                clock_provider=lambda: next(clock_readings),
            )

    def test_ac4_launcher_binding_and_authority_separation_precede_cas(self):
        different_candidate = replace(
            self.candidate,
            release_manifest_sha256=digest("different-live-release"),
        )
        with self.assertRaisesRegex(
            LiveCanaryPortableLaunchCustodyError,
            "LAUNCH_INPUT_BINDING_MISMATCH",
        ):
            self._consume(candidate=different_candidate)
        self.assertEqual(0, self.external.cas_calls)

        overlapping = self._custody_policy(
            custody_key_id=self.launcher_policy.issuer_key_id,
        )
        overlapping_receipt = self._custody_receipt(policy=overlapping)
        overlapping_verification = self._verify_custody(
            receipt=overlapping_receipt,
            policy=overlapping,
        )
        overlapping_external = ExternalReservationCustody(overlapping)
        with self.assertRaisesRegex(
            LiveCanaryPortableLaunchCustodyError,
            "LAUNCH_AUTHORITY_REUSE",
        ):
            self._consume(
                external=overlapping_external,
                custody_verification=overlapping_verification,
                custody_policy=overlapping,
                expected_policy_sha256=overlapping.content_sha256,
            )
        self.assertEqual(0, overlapping_external.cas_calls)

        self._consume()
        current = decode_live_canary_launch_checkpoint(self.external.head)
        wrong_proposal = replace(
            current.proposal,
            candidate_sha256=digest("cross-lane-candidate"),
        )
        unsigned_wrong_checkpoint = replace(
            current,
            proposal=wrong_proposal,
            proposal_sha256=wrong_proposal.content_sha256,
            signature_rsa_pkcs1v15_sha256_hex="",
        )
        wrong_checkpoint = replace(
            unsigned_wrong_checkpoint,
            signature_rsa_pkcs1v15_sha256_hex=custody_signature(
                launch_checkpoint_signing_message(
                    unsigned_wrong_checkpoint
                )
            ),
        )
        self.external.head = wrong_checkpoint.canonical_json().encode("utf-8")
        with self.assertRaisesRegex(
            LiveCanaryPortableLaunchCustodyError,
            "EXTERNAL_CHECKPOINT_LANE_BINDING_MISMATCH",
        ):
            self._consume(
                launcher_attestation=self._launcher_attestation(
                    "launch-nonce-cross-lane"
                )
            )
        self.assertEqual(1, self.external.cas_calls)

    def test_ac5_first_reservation_is_one_use_and_non_authoritative(self):
        capability = self._consume()
        self.assertTrue(is_live_canary_one_use_launch_capability(capability))
        self.assertEqual(1, capability.sequence)
        self.assertTrue(capability.launch_reservation_consumed_once)
        self.assertTrue(capability.launch_prerequisite_verified)
        self.assertTrue(capability.central_unlock_required)
        self.assertFalse(capability.process_launch_authorized)
        self.assertFalse(capability.bootstrap_authorized)
        self.assertFalse(capability.live_allowed)
        self.assertEqual("DISABLED", capability.order_capability)
        with self.assertRaisesRegex(
            LiveCanaryPortableLaunchCustodyError,
            "NONCE_REPLAYED",
        ):
            self._consume()
        self.assertEqual(1, self.external.cas_calls)

    def test_ac6_second_distinct_nonce_extends_exact_signed_head(self):
        first = self._consume()
        first_head = self.external.head
        second_attestation = self._launcher_attestation("launch-nonce-2")
        second = self._consume(launcher_attestation=second_attestation)
        self.assertEqual(1, first.sequence)
        self.assertEqual(2, second.sequence)
        self.assertNotEqual(first.checkpoint_sha256, second.checkpoint_sha256)
        self.assertEqual(2, self.external.cas_calls)
        self.external.head = first_head
        third_attestation = self._launcher_attestation("launch-nonce-3")
        with self.assertRaisesRegex(
            LiveCanaryPortableLaunchCustodyError,
            "EXTERNAL_CHECKPOINT_PIN_MISMATCH",
        ):
            self._consume(
                launcher_attestation=third_attestation,
                expected_predecessor_checkpoint_sha256=(
                    second.checkpoint_sha256
                ),
            )
        self.assertEqual(2, self.external.cas_calls)

    def test_ac7_cas_ack_readback_and_nonce_ambiguity_fail_closed(self):
        scenarios = ("reject_cas", "tamper_ack", "readback_mismatch", "omit_nonce_commit")
        for scenario in scenarios:
            external = ExternalReservationCustody(self.custody_policy)
            setattr(external, scenario, True)
            with self.subTest(scenario=scenario), self.assertRaises(
                LiveCanaryPortableLaunchCustodyError
            ):
                self._consume(external=external)
            self.assertEqual(1, external.cas_calls)

        missing_predecessor_nonce = ExternalReservationCustody(
            self.custody_policy
        )
        self._consume(external=missing_predecessor_nonce)
        missing_predecessor_nonce.seen.clear()
        with self.assertRaisesRegex(
            LiveCanaryPortableLaunchCustodyError,
            "EXTERNAL_PREDECESSOR_NONCE_MISSING",
        ):
            self._consume(
                external=missing_predecessor_nonce,
                launcher_attestation=self._launcher_attestation(
                    "launch-nonce-missing-predecessor"
                ),
            )
        self.assertEqual(1, missing_predecessor_nonce.cas_calls)

        future_checkpoint = ExternalReservationCustody(self.custody_policy)
        self._consume(external=future_checkpoint)
        current = decode_live_canary_launch_checkpoint(future_checkpoint.head)
        future_proposal = replace(
            current.proposal,
            requested_at_utc=NOW + timedelta(seconds=10),
            expires_at_utc=NOW + timedelta(seconds=20),
        )
        unsigned_future = replace(
            current,
            proposal=future_proposal,
            proposal_sha256=future_proposal.content_sha256,
            committed_at_utc=NOW + timedelta(seconds=11),
            signature_rsa_pkcs1v15_sha256_hex="",
        )
        signed_future = replace(
            unsigned_future,
            signature_rsa_pkcs1v15_sha256_hex=custody_signature(
                launch_checkpoint_signing_message(unsigned_future)
            ),
        )
        future_checkpoint.head = signed_future.canonical_json().encode("utf-8")
        with self.assertRaisesRegex(
            LiveCanaryPortableLaunchCustodyError,
            "EXTERNAL_CHECKPOINT_FROM_FUTURE",
        ):
            self._consume(
                external=future_checkpoint,
                launcher_attestation=self._launcher_attestation(
                    "launch-nonce-future-checkpoint"
                ),
            )
        self.assertEqual(1, future_checkpoint.cas_calls)

    def test_ac8_upstream_and_output_seals_plus_central_lock_are_required(self):
        self.assertTrue(is_live_canary_prebootstrap_admission(self.admission))
        self.assertTrue(
            is_verified_external_launcher_attestation(
                self.launcher_attestation
            )
        )
        forged_admission = object.__new__(LiveCanaryPrebootstrapAdmission)
        for item in dataclass_fields(self.admission):
            if item.name != "_admission_seal":
                object.__setattr__(
                    forged_admission,
                    item.name,
                    getattr(self.admission, item.name),
                )
        self.assertFalse(is_live_canary_prebootstrap_admission(forged_admission))
        with self.assertRaisesRegex(
            LiveCanaryPortableLaunchCustodyError,
            "PREBOOTSTRAP_ADMISSION_UNSEALED",
        ):
            self._verify_custody(admission=forged_admission)
        forged_launcher = object.__new__(VerifiedExternalLauncherAttestation)
        for item in dataclass_fields(self.launcher_attestation):
            if item.name != "_verification_seal":
                object.__setattr__(
                    forged_launcher,
                    item.name,
                    getattr(self.launcher_attestation, item.name),
                )
        self.assertFalse(
            is_verified_external_launcher_attestation(forged_launcher)
        )
        with self.assertRaisesRegex(
            LiveCanaryPortableLaunchCustodyError,
            "EXTERNAL_LAUNCHER_ATTESTATION_UNSEALED",
        ):
            self._consume(launcher_attestation=forged_launcher)
        with mock.patch.object(execution_policy, "LIVE_ALLOWED", True):
            with self.assertRaisesRegex(
                LiveCanaryPortableLaunchCustodyError,
                "CENTRAL_LIVE_LOCK_NOT_FALSE",
            ):
                self._consume()
        with self.assertRaises(TypeError):
            VerifiedLiveCanaryAdmissionCustody(
                checked_at_utc=NOW,
                receipt_sha256="1" * 64,
                custody_policy_sha256="2" * 64,
                admission_sha256="3" * 64,
                candidate_sha256="4" * 64,
                source_bound_verification_sha256="5" * 64,
                authorization_sha256="6" * 64,
                validation_sha256="7" * 64,
                worm_repository_alias_sha256="8" * 64,
                object_key_sha256="9" * 64,
                object_version_sha256="a" * 64,
                stored_content_sha256="b" * 64,
                stored_content_size_bytes=1,
                retain_until_utc=NOW + timedelta(days=1),
            )
        with self.assertRaises(TypeError):
            LiveCanaryOneUseLaunchCapability(
                checked_at_utc=NOW,
                expires_at_utc=NOW + timedelta(seconds=1),
                sequence=1,
                launch_nonce_sha256="1" * 64,
                candidate_sha256="2" * 64,
                admission_sha256="3" * 64,
                custody_verification_sha256="4" * 64,
                launcher_attestation_sha256="5" * 64,
                proposal_sha256="6" * 64,
                checkpoint_sha256="7" * 64,
                acknowledgement_sha256="8" * 64,
            )

    def test_edge_strict_json_and_policy_validation_fail_closed(self):
        payload = self.receipt.canonical_json().encode("utf-8")
        duplicate = payload.replace(
            b"{",
            b'{"receipt_id":"duplicate",',
            1,
        )
        with self.assertRaisesRegex(
            LiveCanaryPortableLaunchCustodyError,
            "DUPLICATE_KEY",
        ):
            decode_live_canary_admission_custody_receipt(duplicate)
        parsed = json.loads(payload)
        parsed["unknown"] = True
        with self.assertRaisesRegex(
            LiveCanaryPortableLaunchCustodyError,
            "SCHEMA_INVALID",
        ):
            decode_live_canary_admission_custody_receipt(
                canonical_json(parsed).encode("utf-8")
            )
        hostile_provider = ExternalReservationCustody(self.custody_policy)

        def leak_provider_error():
            raise LiveCanaryPortableLaunchCustodyError(
                "PRIVATE_PROVIDER_DETAIL_MUST_NOT_ESCAPE"
            )

        hostile_provider.checkpoint_provider = leak_provider_error
        with self.assertRaises(
            LiveCanaryPortableLaunchCustodyError
        ) as provider_context:
            self._consume(external=hostile_provider)
        self.assertEqual(
            "EXTERNAL_CHECKPOINT_READ_FAILED",
            provider_context.exception.reason_code,
        )
        self.assertIsNone(provider_context.exception.__cause__)
        with self.assertRaises(
            LiveCanaryPortableLaunchCustodyError
        ) as clock_context:
            self._consume(clock_provider=leak_provider_error)
        self.assertEqual(
            "TRUSTED_CLOCK_START_UNAVAILABLE",
            clock_context.exception.reason_code,
        )
        self.assertIsNone(clock_context.exception.__cause__)
        with self.assertRaises(LiveCanaryPortableLaunchCustodyError):
            self._custody_policy(rsa_exponent=3)

    def test_ac9_static_surface_and_optimized_mode(self):
        source = Path(
            "live_runtime/live_canary_portable_launch_custody.py"
        ).read_text(encoding="utf-8")
        forbidden = (
            "order_send",
            "MetaTrader5",
            "CredentialManager",
            "create_subprocess",
            "Popen",
            "requests",
            "urllib",
            "sqlite3",
            "assert ",
        )
        for token in forbidden:
            with self.subTest(token=token):
                self.assertNotIn(token, source)
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
                    "test_live_runtime_live_canary_portable_launch_custody."
                    "LiveCanaryPortableLaunchCustodyTests."
                    "test_ac5_first_reservation_is_one_use_and_non_authoritative"
                ),
            ],
            cwd=Path(__file__).resolve().parent,
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        self.assertEqual(
            0,
            completed.returncode,
            completed.stdout + completed.stderr,
        )


if __name__ == "__main__":
    unittest.main()
