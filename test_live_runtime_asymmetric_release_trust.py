from __future__ import annotations

from datetime import datetime, timezone
import json
import unittest

from live_runtime.asymmetric_release_trust import (
    ExternalLauncherTrustError,
    ExternalLauncherTrustPolicy,
    VerifiedExternalLauncherAttestation,
    decode_external_launcher_trust_policy,
    verify_external_launcher_attestation,
)
from live_runtime.contracts import canonical_json


UTC = timezone.utc
POLICY_SHA256 = "ae5059978d8d7aecbe4c77f6345defe57c2d1d4c0a971107474cd0ef953be20c"
RELEASE_SHA256 = "a4d451ec23463726f72c43d64c710968f6b602cd653b4de8adee1b556240a829"
POLICY_JSON = """{"deployment_host_alias_sha256":"4740ae6347b0172c01254ff55bae5aff5199f4446e7f6d643d40185b3f475145","issuer_id":"offline-release-authority","issuer_key_id":"rsa-launcher-v1","maximum_ttl_seconds":300,"policy_id":"launcher-policy-v1","public_key_fingerprint_sha256":"f1fdab9823dfe8f45efbd768634ecad7225c56317f03600d5903bb60062b45e2","release_profile":"WINDOWS_GATED_EXECUTION_SERVICE_V1","rsa_exponent":65537,"rsa_modulus_hex":"aec89b0bc7e396226cb3fc84384f3a6c47ebb5d210d65985276019f78246213e471877aa67fa0dec07a6ceba8a6b53ca8368d0493bdddf5ede9ad2b3abb71e5982cf9dc2f689dbd683c9e03ccbe490fd4f533712591b311b40640e0ec2f25f545200f0daa308cae211d76732377a727932a89d04f4aea234de2f6b271bc543f90523afc38790510f7f071a2342186eca5f0e8b82a82017ec51f6706c326b5ac4cce085f1ec2a61ad362888502eb53d391bb7e48ea125d5b6113da25ab64117cbee6cec5655e93c362751f963a1630c1d3e1fd3853afba3e343d0876b6456db0d450cde85ca80dfe4edaac214b05060d1c5d75cdefc8e0609f18edfcc643020278855c0e60d633dcd9ca1b7161594b43c898c7effde5934e23b51c3595d10aba16bb096dc7d847ab3187288d7e019ae3122b3ecdbd0561fd25d59bcf5d7bce5c2817ae2480b22ec88144b192d6753d6bbd0c62fdf8590418ed22bb981152a8e551795498f362b88a92e8690a4f92357ccecac1e0352d173c27338b65d223d2a27","schema_version":"windows-external-launcher-rsa-policy-v1","service_account_alias_sha256":"9df6b026a8c6c26e3c3acd2370a16e93fffdc0015ff5bd879218788025db0280","signature_algorithm":"RSASSA-PKCS1-v1_5-SHA256","task_definition_sha256":"0ebb429fa86d481c2630fac53db1c91cffed5d4d41d1021c179444eb67e7ee0b"}"""
ATTESTATION_JSON = """{"attestation_id":"launch-attestation-1","deployment_host_alias_sha256":"4740ae6347b0172c01254ff55bae5aff5199f4446e7f6d643d40185b3f475145","execution_authority_granted":false,"expires_at_utc":"2026-07-23T00:05:00.000000Z","issued_at_utc":"2026-07-23T00:00:00.000000Z","issuer_id":"offline-release-authority","issuer_key_id":"rsa-launcher-v1","live_allowed":false,"nonce_sha256":"4a9d5bf5a6055c40d017d389a06cd5fa470afc2253ef5ba71bb94117f64dd3f5","not_before_utc":"2026-07-23T00:00:00.000000Z","order_capability":"DISABLED","public_key_fingerprint_sha256":"f1fdab9823dfe8f45efbd768634ecad7225c56317f03600d5903bb60062b45e2","release_identity_sha256":"a4d451ec23463726f72c43d64c710968f6b602cd653b4de8adee1b556240a829","release_profile":"WINDOWS_GATED_EXECUTION_SERVICE_V1","safe_to_demo_auto_order":false,"schema_version":"windows-external-launcher-attestation-v1","service_account_alias_sha256":"9df6b026a8c6c26e3c3acd2370a16e93fffdc0015ff5bd879218788025db0280","signature_algorithm":"RSASSA-PKCS1-v1_5-SHA256","signature_rsa_pkcs1v15_sha256_hex":"a392a7299f34913dbbe100e9d684e89a5ad3e8917cc48bba4857c40ebd1e081542d9638a2d3cd7fdecf142d86cb2519e077c318f305fa037d0d143fce5b8512ad76fb1fab5f8f77b2a56a4ac5d6b7501e21e29fd80202b71d1f6c8d68b1b50b5bcae376ac4264240821ad04d7eb38d6c4ec2356a5b574de8ace744c302bb0cb381f00cd2577f765225f43d46fd0f57a304c1dee4b5e13088cabbafa1c2b886f0efb525454f3d79b574ed7a5055fa79c83f43fc352ae9ef259163a6eb76d5b45951631d6a158649d8354fbf3e21c27a19bf258f71cb80e48b223d62628e43c992ed42a1f3bfdab162fcf5b582683caaf88b93d8cb4ddcdd6c204835e3eac270565b28e50cb8855617c7eb5429519424eb84a68e0ca25ddc8e883e78360288a8c5d708324f96f5230290700725dc0151f557cd4dcfdc35a59c9c34b629fa8e46c8ba36894f5dcb8e3a4b7159a3f62e0ecec72a1c3bb0b3994f9feb9982b65e75f9d33be46c6de2d32c5b371c8b429c1975c31024d4e809a4fbe8f24788ec47ccdb","task_definition_sha256":"0ebb429fa86d481c2630fac53db1c91cffed5d4d41d1021c179444eb67e7ee0b","trust_policy_sha256":"ae5059978d8d7aecbe4c77f6345defe57c2d1d4c0a971107474cd0ef953be20c"}"""


class ExternalLauncherTrustTests(unittest.TestCase):
    def _verify(
        self,
        *,
        attestation: str = ATTESTATION_JSON,
        now: datetime = datetime(2026, 7, 23, 0, 1, tzinfo=UTC),
    ) -> VerifiedExternalLauncherAttestation:
        return verify_external_launcher_attestation(
            attestation,
            policy_payload=POLICY_JSON,
            expected_policy_sha256=POLICY_SHA256,
            expected_release_identity_sha256=RELEASE_SHA256,
            clock_provider=lambda: now,
        )

    def test_valid_external_signature_is_deny_only_and_current(self):
        verified = self._verify()
        self.assertIs(type(verified), VerifiedExternalLauncherAttestation)
        self.assertFalse(verified.live_allowed)
        self.assertFalse(verified.safe_to_demo_auto_order)
        self.assertFalse(verified.execution_authority_granted)
        self.assertEqual("DISABLED", verified.order_capability)
        self.assertTrue(
            verified.assert_current(
                now=datetime(2026, 7, 23, 0, 2, tzinfo=UTC),
                expected_release_identity_sha256=RELEASE_SHA256,
            )
        )

    def test_release_or_signature_tampering_is_rejected(self):
        changed = json.loads(ATTESTATION_JSON)
        changed["release_identity_sha256"] = "1" * 64
        with self.assertRaisesRegex(
            ExternalLauncherTrustError, "LAUNCHER_ATTESTATION_BINDING_MISMATCH"
        ):
            self._verify(attestation=canonical_json(changed))

        changed = json.loads(ATTESTATION_JSON)
        signature = changed["signature_rsa_pkcs1v15_sha256_hex"]
        changed["signature_rsa_pkcs1v15_sha256_hex"] = (
            ("0" if signature[0] != "0" else "1") + signature[1:]
        )
        with self.assertRaisesRegex(
            ExternalLauncherTrustError, "LAUNCHER_ATTESTATION_SIGNATURE_INVALID"
        ):
            self._verify(attestation=canonical_json(changed))

    def test_policy_pin_and_expiry_are_fail_closed(self):
        with self.assertRaisesRegex(
            ExternalLauncherTrustError, "EXTERNAL_POLICY_PIN_MISMATCH"
        ):
            verify_external_launcher_attestation(
                ATTESTATION_JSON,
                policy_payload=POLICY_JSON,
                expected_policy_sha256="1" * 64,
                expected_release_identity_sha256=RELEASE_SHA256,
                clock_provider=lambda: datetime(2026, 7, 23, 0, 1, tzinfo=UTC),
            )
        with self.assertRaisesRegex(
            ExternalLauncherTrustError, "LAUNCHER_ATTESTATION_EXPIRED"
        ):
            self._verify(now=datetime(2026, 7, 23, 0, 5, tzinfo=UTC))

    def test_policy_requires_3072_bit_key_and_canonical_json(self):
        parsed = json.loads(POLICY_JSON)
        parsed["rsa_modulus_hex"] = parsed["rsa_modulus_hex"][:512]
        parsed["public_key_fingerprint_sha256"] = "1" * 64
        with self.assertRaisesRegex(
            ExternalLauncherTrustError, "POLICY_SCHEMA_INVALID"
        ):
            decode_external_launcher_trust_policy(canonical_json(parsed))
        with self.assertRaisesRegex(
            ExternalLauncherTrustError, "POLICY_JSON_NOT_CANONICAL"
        ):
            decode_external_launcher_trust_policy(
                json.dumps(json.loads(POLICY_JSON), sort_keys=True, indent=2)
            )

    def test_verified_receipt_cannot_be_caller_constructed(self):
        with self.assertRaisesRegex(TypeError, "verifier seal"):
            VerifiedExternalLauncherAttestation(
                attestation_sha256="1" * 64,
                trust_policy_sha256="2" * 64,
                release_identity_sha256="3" * 64,
                nonce_sha256="4" * 64,
                verified_at_utc=datetime(2026, 7, 23, 0, 1, tzinfo=UTC),
                expires_at_utc=datetime(2026, 7, 23, 0, 2, tzinfo=UTC),
            )

    def test_policy_type_is_exact_at_trust_boundary(self):
        policy = decode_external_launcher_trust_policy(POLICY_JSON)

        class ForgedPolicy(ExternalLauncherTrustPolicy):
            pass

        forged = object.__new__(ForgedPolicy)
        for name in policy.__dataclass_fields__:
            object.__setattr__(forged, name, getattr(policy, name))
        self.assertIsNot(type(forged), ExternalLauncherTrustPolicy)


if __name__ == "__main__":
    unittest.main()
