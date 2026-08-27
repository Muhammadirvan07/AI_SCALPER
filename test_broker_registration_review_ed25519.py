from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from live_runtime.registration_review_ed25519 import (
    RegulatoryEd25519Error,
    assemble_dual_review,
    build_approved_attestation,
    build_role_request,
    canonical_bytes,
    derive_public_key,
    sign_attestation,
    verify_attestation,
    verify_dual_observation,
    verify_receipt,
)
from live_runtime.contracts import canonical_sha256


NOW = datetime(2026, 8, 27, 14, 30, tzinfo=timezone.utc)


def _evidence() -> dict[str, object]:
    body: dict[str, object] = {
        "schema_version": "regulatory-evidence-v1",
        "candidate_id": "finex",
        "environment": "DEMO",
        "operating_jurisdiction": "ID",
        "broker_legal_name": "PT. Finex Bisnis Solusi Futures",
        "entity": "PT. Finex Bisnis Solusi Futures",
        "broker_server": "FinexBisnisSolusi-Demo",
        "binding_scope": "ALL",
        "broker_symbols": {
            "AUDUSD": "AUDUSD",
            "EURUSD": "EURUSD",
            "USDJPY": "USDJPY",
            "XAUUSD": "XAUUSD",
        },
        "calendar_template_sha256": "b" * 64,
        "broker_claim_observed": True,
        "legal_eligible": True,
        "independent_registry_verification": True,
        "independent_registry_sources": [
            {
                "authority": "BAPPEBTI",
                "url": (
                    "https://bappebti.go.id/pialang_berjangka/"
                    "list_pialang?limit=1000000&offset=0&order=asc"
                ),
                "entity": "PT. Finex Bisnis Solusi Futures",
                "result": "REGISTERED_INDONESIAN_FUTURES_BROKER",
                "registry_record_id": "47/BAPPEBTI/SI/04/2013",
                "observed_at_utc": "2026-08-27T13:45:00Z",
                "captured_content_sha256": "c" * 64,
                "captured_content_bytes": 20169,
            }
        ],
        "verified_at_utc": "2026-08-27T14:08:32Z",
        "verification_status": "VERIFIED_ELIGIBLE_SIGNED_REVIEW",
        "japan_residency_eligibility": "NOT_ASSESSED",
        "indonesia_return_eligibility": "VERIFIED_ELIGIBLE",
        "decision": "DIAGNOSTIC_EVIDENCE_REGISTRATION_REVIEW_ONLY",
        "execution_enabled": False,
        "live_allowed": False,
        "promotion_eligible": False,
        "safe_to_demo_auto_order": False,
        "max_lot": 0.01,
    }
    return {**body, "evidence_bundle_sha256": canonical_sha256(body)}


@unittest.skipUnless(shutil.which("ssh-keygen"), "ssh-keygen unavailable")
class RegulatoryEd25519Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="regulatory-ed25519-test-")
        self.root = Path(self.temp.name)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _key(self, name: str) -> tuple[Path, str]:
        private = self.root / name
        subprocess.run(
            [
                str(shutil.which("ssh-keygen")),
                "-q",
                "-t",
                "ed25519",
                "-N",
                "",
                "-f",
                str(private),
            ],
            check=True,
            capture_output=True,
        )
        return private, derive_public_key(private)

    def _receipt(
        self, role: str, reviewer: str, private: Path, public: str
    ) -> dict[str, object]:
        evidence = _evidence()
        request = build_role_request(
            evidence,
            approver_role=role,
            approver_id=reviewer,
            public_key_text=public,
        )
        attestation = build_approved_attestation(
            request,
            evidence,
            independence_attested=True,
            evidence_matches_sources_attested=True,
            license_record_verified_attested=True,
            now_provider=lambda: NOW,
        )
        payload = canonical_bytes(attestation)
        signature = sign_attestation(payload, private)
        return verify_attestation(
            request,
            evidence,
            payload,
            signature,
            public_key_text=public,
            now_provider=lambda: NOW,
        )

    def test_dual_review_is_reverifiable_and_deny_only(self) -> None:
        compliance_key, compliance_public = self._key("compliance")
        legal_key, legal_public = self._key("legal")
        compliance = self._receipt(
            "COMPLIANCE_REVIEW", "reviewer_a", compliance_key, compliance_public
        )
        legal = self._receipt(
            "LEGAL_REVIEW", "reviewer_b", legal_key, legal_public
        )
        self.assertEqual(
            verify_receipt(_evidence(), compliance, now_provider=lambda: NOW),
            compliance,
        )
        observation = assemble_dual_review(
            _evidence(), compliance, legal, now_provider=lambda: NOW
        )
        self.assertTrue(observation["independent_reviewers_verified"])
        self.assertFalse(observation["activation_eligible"])
        self.assertFalse(observation["safe_to_demo_auto_order"])
        self.assertEqual(observation["order_capability"], "DISABLED")
        self.assertEqual(
            verify_dual_observation(observation, now_provider=lambda: NOW),
            observation,
        )

        tampered = dict(observation)
        tampered["broker_server"] = "attacker-demo"
        with self.assertRaises(RegulatoryEd25519Error):
            verify_dual_observation(tampered, now_provider=lambda: NOW)

    def test_tampered_embedded_signature_is_rejected(self) -> None:
        private, public = self._key("reviewer")
        receipt = self._receipt(
            "COMPLIANCE_REVIEW", "reviewer_a", private, public
        )
        receipt["signature_base64"] = "QUJDRA=="
        with self.assertRaises(RegulatoryEd25519Error):
            verify_receipt(_evidence(), receipt, now_provider=lambda: NOW)

    def test_same_reviewer_cannot_hold_both_roles(self) -> None:
        first_key, first_public = self._key("first")
        second_key, second_public = self._key("second")
        compliance = self._receipt(
            "COMPLIANCE_REVIEW", "same_reviewer", first_key, first_public
        )
        legal = self._receipt(
            "LEGAL_REVIEW", "same_reviewer", second_key, second_public
        )
        with self.assertRaises(RegulatoryEd25519Error):
            assemble_dual_review(
                _evidence(), compliance, legal, now_provider=lambda: NOW
            )

    def test_attestation_requires_all_explicit_assertions(self) -> None:
        _, public = self._key("reviewer")
        request = build_role_request(
            _evidence(),
            approver_role="LEGAL_REVIEW",
            approver_id="reviewer_a",
            public_key_text=public,
        )
        with self.assertRaises(RegulatoryEd25519Error):
            build_approved_attestation(
                request,
                _evidence(),
                independence_attested=True,
                evidence_matches_sources_attested=False,
                license_record_verified_attested=True,
                now_provider=lambda: NOW,
            )


if __name__ == "__main__":
    unittest.main()
