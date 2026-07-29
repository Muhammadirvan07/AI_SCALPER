from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
from dataclasses import replace
from datetime import datetime, timedelta
import hashlib
import io
import json
from pathlib import Path
import tempfile
import time
import unittest

from live_runtime.asymmetric_release_trust import (
    rsa_public_key_fingerprint_sha256,
)
from live_runtime.contracts import canonical_json
from live_runtime.windows_live_provider_conformance_acceptance import (
    ACCEPTANCE_SCHEMA_VERSION,
    ACCEPTANCE_STATUS,
    OWNER_ACCEPTANCE_DOMAIN,
    RUNTIME_ATTESTATION_DOMAIN,
    WindowsLiveProviderAcceptancePolicy,
    WindowsLiveProviderConformanceAcceptanceError,
    WindowsLiveProviderOwnerAcceptance,
    WindowsLiveProviderRuntimeAttestation,
    decode_windows_live_provider_acceptance_policy,
    decode_windows_live_provider_owner_acceptance,
    decode_windows_live_provider_runtime_attestation,
    prepare_windows_live_provider_conformance_acceptance,
    prepare_windows_live_provider_conformance_acceptance_file,
    verify_windows_live_provider_conformance_acceptance,
)
from live_runtime.windows_provider_conformance_review import (
    is_windows_three_service_provider_conformance_review,
    prepare_windows_three_service_provider_conformance_review,
)
from test_live_runtime_asymmetric_release_trust import (
    TEST_RSA_D_HEX as OWNER_RSA_D_HEX,
    TEST_RSA_N_HEX as OWNER_RSA_N_HEX,
)
import test_live_runtime_windows_provider_conformance_v4 as v4_support
import verify_windows_live_provider_conformance_acceptance as cli


NOW = v4_support.NOW


RUNTIME_RSA_N_HEX = (
    "9c7155414705ee80c0deff13f274222384175ccadea1cc8e922111911d8331f7c"
    "933fa4b29428dfb63d55ed41dc72bf4a54ece8c92aeeb35da6739dbfe88bceee"
    "6b8a13ff7450494f4f50b1b8005f73f2425a0da6cb9538a4e0cce8890fbf9ff"
    "53e9817171d2fc0eeeaba6b09c79403100ed3da385bac36a681a791550aa5d434"
    "681d17a7c3747383863c9ef1cd35cec096ab0b66e0a9de4be9698121a8ee1ea8"
    "2013477ba5a7c9e495e3fa83e7d506f395eeff38eafbacc65b11952ec5478ad41"
    "34fb3a605017bf50be579db129b31f2b75bea2f56ccd209b9dbc44280d4aa9f0"
    "a897b5f1622fc2c562e97af0ef00282e7def628d71bbdc4ecede149a4a69a07b"
    "3e73206cf1fa0be3521b8a021a4771ff9e360a926323885dec4075cad655e4c5e"
    "7f97123a2436c344dee11a16c01449aa71430e3ac0b678ca0d502378aec3f9e09"
    "c95eee4bdc9511a18f8c7f6cfedc38c2281562391769fd4260d2120185c659b31"
    "ab5b0264bfb5be42a799fb827dbbca97719a4fea028721226bf3d6d35d3"
)
RUNTIME_RSA_D_HEX = (
    "0a46a98121af57e4c3868253d1990e45adf4b39181d68d44ba2ae0e8057bc0d"
    "4540b8d7fd2b9d3f0b4df3c478b9ddc7073f6a810f4c64cf345cc2d069b2d69"
    "2cfa211b8fc392c2d91ea405484251b7556c443fd0c92927e8784b0010041201"
    "1b0e9727d107572d5bb512b7b421d06c712b973f2016cb2c9b388905f6154d3"
    "380bff3615ffdce75bcfc25eb35967ba3141564442f9f82795a4aa89806ec66ab"
    "f146fbd99c99b43d90fa246e3858c3cb7cf029a11d0052365f71b8947f6d6af"
    "90832100bef054a5152274871581c66952335a0fd081354658be3969605de0947"
    "51d991fea1b25d75286ba3fe682c58cdcf7587e9044f6b8d69255dc76bf9f55d"
    "88e2a6387115485ad3b8306562804cc837448eb914e8ca1a248958eff759b1054"
    "25ff712d04ee547bfeeeb7538524d42204247936977df671d6811e88a42ce1773"
    "6f6b3f0d247c4c7eac8bde5decb61a13bff3cc6d88a280b2df85aaea2bae701"
    "e0593428297ca8dd7de9d202343ad5cee1ea4b9efe12d9ea4fea0208b95504af9"
)
SHA256_DIGEST_INFO_PREFIX = bytes.fromhex(
    "3031300d060960864801650304020105000420"
)


def digest(value: bytes | str) -> str:
    if isinstance(value, str):
        value = value.encode("utf-8")
    return hashlib.sha256(value).hexdigest()


def rsa_sign(message: bytes, *, modulus_hex: str, private_hex: str) -> str:
    modulus = int(modulus_hex, 16)
    length = (modulus.bit_length() + 7) // 8
    digest_info = SHA256_DIGEST_INFO_PREFIX + hashlib.sha256(message).digest()
    padding = b"\xff" * (length - len(digest_info) - 3)
    encoded = b"\x00\x01" + padding + b"\x00" + digest_info
    return pow(
        int.from_bytes(encoded, "big"),
        int(private_hex, 16),
        modulus,
    ).to_bytes(length, "big").hex()


def canonical_file(value: object) -> bytes:
    return (canonical_json(value) + "\n").encode("utf-8")


class WindowsLiveProviderConformanceAcceptanceTests(unittest.TestCase):
    def setUp(self) -> None:
        fixture = v4_support.WindowsProviderConformanceV4Tests(
            methodName="test_v4_reconstructs_exact_live_closure_and_68_providers"
        )
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.fixture = fixture
        self.source = fixture.live_bound
        conformance_input = fixture._assemble_v4().conformance_input
        self.review = prepare_windows_three_service_provider_conformance_review(
            conformance_input,
            live_execution_source_bound_verification=self.source,
            clock_provider=lambda: NOW,
        )
        self.checked_at = NOW + timedelta(minutes=5)
        self.owner_receipt = b"owner-validation-receipt-v1"
        self.runtime_evidence = b"runtime-provider-evidence-v1"
        self.runtime_receipt = b"runtime-validation-receipt-v1"
        identities = {
            str(item["service_role"]): str(
                item["configured_release_identity_sha256"]
            )
            for item in self.review.services
        }
        self.host_sha256 = digest("windows-live-target-host")
        self.policy = WindowsLiveProviderAcceptancePolicy(
            policy_id="windows-live-provider-acceptance-policy-v1",
            provider_conformance_review_sha256=self.review.content_sha256,
            live_bound_archive_sha256=self.source.archive_sha256,
            live_binding_identity_sha256=(
                self.source.binding_identity_sha256
            ),
            source_bound_archive_sha256=(
                self.source.source_bound_archive_sha256
            ),
            source_archive_sha256=self.source.source_archive_sha256,
            suite_identity_sha256=self.source.suite_identity_sha256,
            decision_release_identity_sha256=identities["DECISION"],
            execution_release_identity_sha256=identities["EXECUTION"],
            status_monitor_release_identity_sha256=identities[
                "STATUS_MONITOR"
            ],
            target_host_identity_sha256=self.host_sha256,
            owner_authority_id="live-provider-service-owner",
            owner_authority_key_id="live-provider-owner-rsa-v1",
            owner_rsa_modulus_hex=OWNER_RSA_N_HEX,
            owner_rsa_exponent=65537,
            owner_public_key_fingerprint_sha256=(
                rsa_public_key_fingerprint_sha256(
                    OWNER_RSA_N_HEX,
                    65537,
                )
            ),
            runtime_authority_id="windows-live-runtime-authority",
            runtime_authority_key_id="windows-live-runtime-rsa-v1",
            runtime_rsa_modulus_hex=RUNTIME_RSA_N_HEX,
            runtime_rsa_exponent=65537,
            runtime_public_key_fingerprint_sha256=(
                rsa_public_key_fingerprint_sha256(
                    RUNTIME_RSA_N_HEX,
                    65537,
                )
            ),
            maximum_acceptance_ttl_seconds=600,
        )
        self.owner = self._owner()
        self.runtime = self._runtime()

    def _owner(self, **changes: object) -> WindowsLiveProviderOwnerAcceptance:
        values: dict[str, object] = {
            "acceptance_id": "owner-acceptance-001",
            "trust_policy_sha256": self.policy.content_sha256,
            "provider_conformance_review_sha256": self.review.content_sha256,
            "provider_evidence_set_sha256": (
                self.review.provider_evidence_set_sha256
            ),
            "decision_release_identity_sha256": (
                self.policy.decision_release_identity_sha256
            ),
            "execution_release_identity_sha256": (
                self.policy.execution_release_identity_sha256
            ),
            "status_monitor_release_identity_sha256": (
                self.policy.status_monitor_release_identity_sha256
            ),
            "target_host_identity_sha256": self.host_sha256,
            "provider_count": 68,
            "source_evidence_sha256": self.review.content_sha256,
            "validation_receipt_sha256": digest(self.owner_receipt),
            "outcome": "PASSED",
            "observed_at_utc": self.checked_at - timedelta(minutes=2),
            "not_before_utc": self.checked_at - timedelta(minutes=1),
            "expires_at_utc": self.checked_at + timedelta(minutes=5),
            "authority_id": self.policy.owner_authority_id,
            "authority_key_id": self.policy.owner_authority_key_id,
            "public_key_fingerprint_sha256": (
                self.policy.owner_public_key_fingerprint_sha256
            ),
            "signature_rsa_pkcs1v15_sha256_hex": "00" * 384,
        }
        values.update(changes)
        unsigned = WindowsLiveProviderOwnerAcceptance(**values)
        signature = rsa_sign(
            OWNER_ACCEPTANCE_DOMAIN
            + canonical_json(unsigned.signing_dict).encode("utf-8"),
            modulus_hex=OWNER_RSA_N_HEX,
            private_hex=OWNER_RSA_D_HEX,
        )
        return replace(
            unsigned,
            signature_rsa_pkcs1v15_sha256_hex=signature,
        )

    def _runtime(
        self, **changes: object
    ) -> WindowsLiveProviderRuntimeAttestation:
        values: dict[str, object] = {
            "attestation_id": "runtime-attestation-001",
            "trust_policy_sha256": self.policy.content_sha256,
            "provider_conformance_review_sha256": self.review.content_sha256,
            "live_bound_archive_sha256": self.source.archive_sha256,
            "live_binding_identity_sha256": (
                self.source.binding_identity_sha256
            ),
            "target_host_identity_sha256": self.host_sha256,
            "installed_environment_sha256": digest(
                "installed-windows-environment"
            ),
            "runtime_evidence_sha256": digest(self.runtime_evidence),
            "validation_receipt_sha256": digest(self.runtime_receipt),
            "provider_count": 68,
            "credential_reference_count": 12,
            "runtime_mode": "LIVE",
            "outcome": "PASSED",
            "observed_at_utc": self.checked_at - timedelta(minutes=2),
            "not_before_utc": self.checked_at - timedelta(minutes=1),
            "expires_at_utc": self.checked_at + timedelta(minutes=5),
            "authority_id": self.policy.runtime_authority_id,
            "authority_key_id": self.policy.runtime_authority_key_id,
            "public_key_fingerprint_sha256": (
                self.policy.runtime_public_key_fingerprint_sha256
            ),
            "signature_rsa_pkcs1v15_sha256_hex": "00" * 384,
        }
        values.update(changes)
        unsigned = WindowsLiveProviderRuntimeAttestation(**values)
        signature = rsa_sign(
            RUNTIME_ATTESTATION_DOMAIN
            + canonical_json(unsigned.signing_dict).encode("utf-8"),
            modulus_hex=RUNTIME_RSA_N_HEX,
            private_hex=RUNTIME_RSA_D_HEX,
        )
        return replace(
            unsigned,
            signature_rsa_pkcs1v15_sha256_hex=signature,
        )

    def _arguments(self) -> dict[str, object]:
        return {
            "source_verification": self.source,
            "conformance_review": self.review,
            "trust_policy": self.policy,
            "owner_acceptance": self.owner,
            "runtime_attestation": self.runtime,
            "owner_validation_receipt_bytes": self.owner_receipt,
            "runtime_evidence_bytes": self.runtime_evidence,
            "runtime_validation_receipt_bytes": self.runtime_receipt,
            "expected_policy_sha256": self.policy.content_sha256,
            "expected_target_host_identity_sha256": self.host_sha256,
            "clock_provider": lambda: self.checked_at,
        }

    def test_exact_two_authority_acceptance_remains_non_executable(self) -> None:
        started = time.monotonic()
        first = prepare_windows_live_provider_conformance_acceptance(
            **self._arguments()
        )
        second = prepare_windows_live_provider_conformance_acceptance(
            **self._arguments()
        )
        self.assertLess(time.monotonic() - started, 2.0)
        self.assertEqual(first.to_canonical_dict(), second.to_canonical_dict())
        self.assertEqual(ACCEPTANCE_SCHEMA_VERSION, first.schema_version)
        self.assertEqual(ACCEPTANCE_STATUS, first.status)
        self.assertTrue(first.provider_accepted)
        self.assertTrue(first.prebootstrap_binding_required)
        self.assertFalse(first.activation_allowed)
        self.assertFalse(first.execution_enabled)
        self.assertFalse(first.production_execution_ready)
        self.assertFalse(first.credential_access_performed)
        self.assertFalse(first.provider_imported)
        self.assertFalse(first.provider_materialized)
        self.assertFalse(first.broker_mutation_performed)
        self.assertFalse(first.live_allowed)
        self.assertFalse(first.safe_to_demo_auto_order)
        self.assertFalse(first.promotion_eligible)
        self.assertEqual("DISABLED", first.order_capability)
        self.assertEqual(0.01, first.max_lot)

    def test_review_is_exactly_sealed_and_v4(self) -> None:
        self.assertTrue(
            is_windows_three_service_provider_conformance_review(self.review)
        )
        lookalike = object.__new__(type(self.review))
        args = self._arguments()
        args["conformance_review"] = lookalike
        with self.assertRaisesRegex(
            WindowsLiveProviderConformanceAcceptanceError,
            "SEALED_PROVIDER_CONFORMANCE_REVIEW_REQUIRED",
        ):
            prepare_windows_live_provider_conformance_acceptance(**args)

    def test_external_policy_and_host_pins_are_mandatory(self) -> None:
        for name in (
            "expected_policy_sha256",
            "expected_target_host_identity_sha256",
        ):
            args = self._arguments()
            args[name] = digest(f"wrong:{name}")
            with self.subTest(name=name), self.assertRaises(
                WindowsLiveProviderConformanceAcceptanceError
            ):
                prepare_windows_live_provider_conformance_acceptance(**args)

    def test_authorities_and_public_keys_must_be_distinct(self) -> None:
        with self.assertRaisesRegex(ValueError, "must be distinct"):
            replace(
                self.policy,
                runtime_authority_id=self.policy.owner_authority_id,
            )
        with self.assertRaisesRegex(ValueError, "must be distinct"):
            replace(
                self.policy,
                runtime_rsa_modulus_hex=OWNER_RSA_N_HEX,
                runtime_public_key_fingerprint_sha256=(
                    self.policy.owner_public_key_fingerprint_sha256
                ),
            )

    def test_signature_and_evidence_tampering_fail_closed(self) -> None:
        args = self._arguments()
        last = self.owner.signature_rsa_pkcs1v15_sha256_hex[-1]
        args["owner_acceptance"] = replace(
            self.owner,
            signature_rsa_pkcs1v15_sha256_hex=(
                self.owner.signature_rsa_pkcs1v15_sha256_hex[:-1]
                + ("1" if last != "1" else "0")
            ),
        )
        with self.assertRaisesRegex(
            WindowsLiveProviderConformanceAcceptanceError,
            "OWNER_ACCEPTANCE_SIGNATURE_INVALID",
        ):
            prepare_windows_live_provider_conformance_acceptance(**args)
        args = self._arguments()
        args["runtime_evidence_bytes"] = self.runtime_evidence + b"tamper"
        with self.assertRaisesRegex(
            WindowsLiveProviderConformanceAcceptanceError,
            "RUNTIME_ATTESTATION_BINDING_MISMATCH",
        ):
            prepare_windows_live_provider_conformance_acceptance(**args)

    def test_runtime_observation_must_follow_all_provider_evidence(self) -> None:
        latest = max(
            datetime.fromisoformat(
                str(item["observed_at_utc"])[:-1] + "+00:00"
            )
            for service in self.review.services
            for item in service["provider_evidence"]
        )
        runtime = self._runtime(
            observed_at_utc=latest - timedelta(microseconds=1),
            not_before_utc=self.checked_at - timedelta(minutes=1),
        )
        args = self._arguments()
        args["runtime_attestation"] = runtime
        with self.assertRaisesRegex(
            WindowsLiveProviderConformanceAcceptanceError,
            "RUNTIME_OBSERVATION_PREDATES_PROVIDER_EVIDENCE",
        ):
            prepare_windows_live_provider_conformance_acceptance(**args)

    def test_expired_or_regressing_clock_fails_closed(self) -> None:
        args = self._arguments()
        args["clock_provider"] = lambda: self.checked_at + timedelta(minutes=6)
        with self.assertRaisesRegex(
            WindowsLiveProviderConformanceAcceptanceError,
            "OWNER_ACCEPTANCE_EXPIRED",
        ):
            prepare_windows_live_provider_conformance_acceptance(**args)

        moments = iter(
            (self.checked_at, self.checked_at - timedelta(microseconds=1))
        )
        args = self._arguments()
        args["clock_provider"] = lambda: next(moments)
        with self.assertRaisesRegex(
            WindowsLiveProviderConformanceAcceptanceError,
            "TRUSTED_ACCEPTANCE_CLOCK_REGRESSION",
        ):
            prepare_windows_live_provider_conformance_acceptance(**args)

    def test_assessment_reconstruction_rejects_tampering(self) -> None:
        result = prepare_windows_live_provider_conformance_acceptance(
            **self._arguments()
        )
        verified = verify_windows_live_provider_conformance_acceptance(
            result.to_canonical_dict(),
            **self._arguments(),
        )
        self.assertEqual(result.content_sha256, verified.content_sha256)
        tampered = result.to_canonical_dict()
        tampered["provider_accepted"] = False
        with self.assertRaisesRegex(
            WindowsLiveProviderConformanceAcceptanceError,
            "ACCEPTANCE_RESULT_RECONSTRUCTION_MISMATCH",
        ):
            verify_windows_live_provider_conformance_acceptance(
                tampered,
                **self._arguments(),
            )

    def test_strict_public_documents_round_trip_and_reject_pretty_json(
        self,
    ) -> None:
        policy = decode_windows_live_provider_acceptance_policy(
            canonical_file(self.policy.to_canonical_dict())
        )
        owner = decode_windows_live_provider_owner_acceptance(
            canonical_file(self.owner.to_canonical_dict())
        )
        runtime = decode_windows_live_provider_runtime_attestation(
            canonical_file(self.runtime.to_canonical_dict())
        )
        self.assertEqual(self.policy, policy)
        self.assertEqual(self.owner, owner)
        self.assertEqual(self.runtime, runtime)
        pretty = json.dumps(self.policy.to_canonical_dict(), indent=2)
        with self.assertRaisesRegex(
            WindowsLiveProviderConformanceAcceptanceError,
            "ACCEPTANCE_POLICY_JSON_NOT_CANONICAL",
        ):
            decode_windows_live_provider_acceptance_policy(pretty)

    def test_file_api_hashes_exact_bytes_and_never_overwrites(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve(strict=True)
            paths = {
                "policy": root / "policy.json",
                "owner": root / "owner.json",
                "runtime": root / "runtime.json",
                "owner_receipt": root / "owner-receipt.bin",
                "runtime_evidence": root / "runtime-evidence.bin",
                "runtime_receipt": root / "runtime-receipt.bin",
                "output": root / "acceptance.json",
            }
            paths["policy"].write_bytes(
                canonical_file(self.policy.to_canonical_dict())
            )
            paths["owner"].write_bytes(
                canonical_file(self.owner.to_canonical_dict())
            )
            paths["runtime"].write_bytes(
                canonical_file(self.runtime.to_canonical_dict())
            )
            paths["owner_receipt"].write_bytes(self.owner_receipt)
            paths["runtime_evidence"].write_bytes(self.runtime_evidence)
            paths["runtime_receipt"].write_bytes(self.runtime_receipt)
            result = prepare_windows_live_provider_conformance_acceptance_file(
                source_verification=self.source,
                conformance_review=self.review,
                trust_policy_path=paths["policy"],
                owner_acceptance_path=paths["owner"],
                runtime_attestation_path=paths["runtime"],
                owner_validation_receipt_path=paths["owner_receipt"],
                runtime_evidence_path=paths["runtime_evidence"],
                runtime_validation_receipt_path=paths["runtime_receipt"],
                expected_policy_sha256=self.policy.content_sha256,
                expected_target_host_identity_sha256=self.host_sha256,
                output_path=paths["output"],
                clock_provider=lambda: self.checked_at,
            )
            self.assertEqual(
                result.to_canonical_dict(),
                json.loads(paths["output"].read_bytes()),
            )
            original = paths["output"].read_bytes()
            with self.assertRaisesRegex(
                WindowsLiveProviderConformanceAcceptanceError,
                "ACCEPTANCE_OUTPUT_EXISTS",
            ):
                prepare_windows_live_provider_conformance_acceptance_file(
                    source_verification=self.source,
                    conformance_review=self.review,
                    trust_policy_path=paths["policy"],
                    owner_acceptance_path=paths["owner"],
                    runtime_attestation_path=paths["runtime"],
                    owner_validation_receipt_path=paths["owner_receipt"],
                    runtime_evidence_path=paths["runtime_evidence"],
                    runtime_validation_receipt_path=paths["runtime_receipt"],
                    expected_policy_sha256=self.policy.content_sha256,
                    expected_target_host_identity_sha256=self.host_sha256,
                    output_path=paths["output"],
                    clock_provider=lambda: self.checked_at,
                )
            self.assertEqual(original, paths["output"].read_bytes())

    def test_cli_reverifies_ten_pins_review_and_external_files(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve(strict=True)
            review_path = root / "review.json"
            policy_path = root / "policy.json"
            owner_path = root / "owner.json"
            runtime_path = root / "runtime.json"
            owner_receipt_path = root / "owner-receipt.bin"
            runtime_evidence_path = root / "runtime-evidence.bin"
            runtime_receipt_path = root / "runtime-receipt.bin"
            output_path = root / "acceptance.json"
            review_path.write_bytes(
                canonical_file(self.review.to_canonical_dict())
            )
            policy_path.write_bytes(
                canonical_file(self.policy.to_canonical_dict())
            )
            owner_path.write_bytes(
                canonical_file(self.owner.to_canonical_dict())
            )
            runtime_path.write_bytes(
                canonical_file(self.runtime.to_canonical_dict())
            )
            owner_receipt_path.write_bytes(self.owner_receipt)
            runtime_evidence_path.write_bytes(self.runtime_evidence)
            runtime_receipt_path.write_bytes(self.runtime_receipt)
            pins = self.fixture._live_file_arguments()
            arguments = [
                "--live-source-bound-candidate",
                str(self.fixture.live_bound_path),
                "--base-suite-root",
                str(pins["base_suite_root"]),
                "--execution-base-release",
                str(pins["execution_base_release"]),
                "--expected-live-bound-archive-sha256",
                str(pins["expected_live_bound_archive_sha256"]),
                "--expected-source-bound-archive-sha256",
                str(pins["expected_source_bound_archive_sha256"]),
                "--expected-source-archive-sha256",
                str(pins["expected_source_archive_sha256"]),
                "--expected-champion-archive-sha256",
                str(pins["expected_champion_archive_sha256"]),
                "--expected-model-artifact-sha256",
                str(pins["expected_model_artifact_sha256"]),
                "--expected-training-snapshot-sha256",
                str(pins["expected_training_snapshot_sha256"]),
                "--expected-config-sha256",
                str(pins["expected_config_sha256"]),
                "--expected-git-commit",
                str(pins["expected_git_commit"]),
                "--expected-git-tree",
                str(pins["expected_git_tree"]),
                "--expected-suite-identity-sha256",
                str(pins["expected_suite_identity_sha256"]),
                "--conformance-review",
                str(review_path),
                "--trust-policy",
                str(policy_path),
                "--owner-acceptance",
                str(owner_path),
                "--runtime-attestation",
                str(runtime_path),
                "--owner-validation-receipt",
                str(owner_receipt_path),
                "--runtime-evidence",
                str(runtime_evidence_path),
                "--runtime-validation-receipt",
                str(runtime_receipt_path),
                "--expected-policy-sha256",
                self.policy.content_sha256,
                "--expected-target-host-identity-sha256",
                self.host_sha256,
                "--output",
                str(output_path),
            ]
            stdout = io.StringIO()
            stderr = io.StringIO()
            original_clock = cli.trusted_utc_now
            cli.trusted_utc_now = lambda: self.checked_at
            try:
                with redirect_stdout(stdout), redirect_stderr(stderr):
                    code = cli.main(arguments)
            finally:
                cli.trusted_utc_now = original_clock
            self.assertEqual(0, code, stderr.getvalue())
            self.assertIn(
                "WINDOWS_LIVE_PROVIDER_CONFORMANCE_ACCEPTED",
                stdout.getvalue(),
            )
            self.assertEqual(
                ACCEPTANCE_SCHEMA_VERSION,
                json.loads(output_path.read_bytes())["schema_version"],
            )

            incomplete_output = root / "incomplete.json"
            with redirect_stdout(io.StringIO()), redirect_stderr(
                io.StringIO()
            ):
                code = cli.main(
                    [
                        "--live-source-bound-candidate",
                        str(self.fixture.live_bound_path),
                        "--output",
                        str(incomplete_output),
                    ]
                )
            self.assertEqual(2, code)
            self.assertFalse(incomplete_output.exists())


if __name__ == "__main__":
    unittest.main()
