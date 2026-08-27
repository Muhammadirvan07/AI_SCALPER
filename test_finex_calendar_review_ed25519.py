from __future__ import annotations

import base64
from datetime import datetime, timezone
from pathlib import Path
import json
import shutil
import struct
import subprocess
import tempfile
import unittest

from live_runtime.contracts import canonical_sha256
from live_runtime.finex_calendar_review_ed25519 import (
    FinexCalendarReviewEd25519Error,
    assemble_incomplete_review,
    build_request,
    normalize_public_key,
    sign_incomplete_review,
    validate_request,
    verify_detached_incomplete_attestation,
    verify_incomplete_review,
)


NOW = datetime(2026, 8, 27, 12, 0, tzinfo=timezone.utc)
EVIDENCE_HASH = "a" * 64
SCHEDULE_HASH = "b" * 64


def _wire(value: bytes) -> bytes:
    return struct.pack(">I", len(value)) + value


def public_key(key_bytes: bytes = bytes(range(32))) -> str:
    blob = _wire(b"ssh-ed25519") + _wire(key_bytes)
    return "ssh-ed25519 " + base64.b64encode(blob).decode("ascii")


def base_request() -> dict[str, object]:
    body: dict[str, object] = {
        "schema_version": "finex-calendar-review-request-v2",
        "candidate_id": "finex",
        "calendar_version": "finex-window-01-v2",
        "designated_reviewer_id": "putra",
        "reviewer_independence_attested": False,
        "independence_requirement": "REVIEWER_MUST_NOT_BE_OPERATOR_DEVELOPER_OR_EVIDENCE_COLLECTOR",
        "required_reviewer_role": "CALENDAR_REVIEW",
        "required_key_id": "finex-prewindow-calendar-review-v2",
        "evidence_bundle_sha256": EVIDENCE_HASH,
        "schedule_claim_sha256": SCHEDULE_HASH,
        "official_sources": [{"source_id": "finex-rules"}],
        "observation_start_at_utc": "2026-08-31T12:00:00Z",
        "blind_until_utc": "2026-10-26T12:00:00Z",
        "current_special_hours_attested": False,
        "current_future_exception_completeness": False,
        "required_checks": ["VERIFY_TRADING_RULES_SOURCE_HASH"],
        "authorization_granted": False,
        "order_capability": "DISABLED",
        "promotion_eligible": False,
        "safe_to_demo_auto_order": False,
        "live_allowed": False,
    }
    return {**body, "request_sha256": canonical_sha256(body)}


def evidence() -> dict[str, object]:
    return {
        "candidate_id": "finex",
        "calendar_version": "finex-window-01-v2",
        "evidence_bundle_sha256": EVIDENCE_HASH,
        "schedule_claim_sha256": SCHEDULE_HASH,
        "future_exception_completeness": False,
        "special_hours_attested": False,
        "execution_enabled": False,
        "promotion_eligible": False,
        "safe_to_demo_auto_order": False,
        "live_allowed": False,
    }


class FinexCalendarReviewEd25519Tests(unittest.TestCase):
    def test_request_binds_exact_public_key_and_stays_deny_only(self) -> None:
        request = build_request(base_request(), public_key())
        validated = validate_request(request, public_key())
        self.assertFalse(validated["authorization_granted"])
        self.assertEqual("DISABLED", validated["order_capability"])
        with self.assertRaises(FinexCalendarReviewEd25519Error):
            validate_request(request, public_key(b"x" * 32))

    def test_malformed_ed25519_key_is_rejected(self) -> None:
        for value in ("", "ssh-rsa AAAA", "ssh-ed25519 !!!!"):
            with self.subTest(value=value), self.assertRaises(
                FinexCalendarReviewEd25519Error
            ):
                normalize_public_key(value)

    @unittest.skipUnless(shutil.which("ssh-keygen"), "OpenSSH is unavailable")
    def test_real_sshsig_round_trip_and_tamper_rejection(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            private_key = Path(directory) / "reviewer"
            subprocess.run(
                [
                    str(shutil.which("ssh-keygen")),
                    "-q",
                    "-t",
                    "ed25519",
                    "-N",
                    "",
                    "-f",
                    str(private_key),
                ],
                check=True,
            )
            pub = Path(str(private_key) + ".pub").read_text(encoding="ascii")
            request = build_request(base_request(), pub)
            receipt = sign_incomplete_review(
                request,
                evidence(),
                reviewer_id="putra",
                public_key_text=pub,
                private_key_path=private_key,
                independence_attested=True,
                now_provider=lambda: NOW,
            )
            verify_incomplete_review(request, evidence(), receipt, public_key_text=pub)
            assembled = assemble_incomplete_review(
                request,
                evidence(),
                receipt,
                public_key_text=pub,
                now_provider=lambda: NOW,
            )
            self.assertFalse(assembled["authorization_granted"])
            changed = dict(receipt)
            changed["decision"] = "APPROVED"
            with self.assertRaises(FinexCalendarReviewEd25519Error):
                verify_incomplete_review(
                    request, evidence(), changed, public_key_text=pub
                )

    @unittest.skipUnless(shutil.which("ssh-keygen"), "OpenSSH is unavailable")
    def test_detached_attestation_verifies_exact_bytes_and_remains_blocked(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            private_key = root / "reviewer"
            subprocess.run(
                [
                    str(shutil.which("ssh-keygen")),
                    "-q",
                    "-t",
                    "ed25519",
                    "-N",
                    "",
                    "-f",
                    str(private_key),
                ],
                check=True,
            )
            pub = Path(str(private_key) + ".pub").read_text(encoding="ascii")
            request = build_request(base_request(), pub)
            attestation = {
                "schema_version": "finex-calendar-review-attestation-v3-ed25519",
                "candidate_id": "finex",
                "calendar_version": "finex-window-01-v2",
                "request_sha256": request["request_sha256"],
                "base_request_sha256": request["base_request_sha256"],
                "evidence_bundle_sha256": EVIDENCE_HASH,
                "schedule_claim_sha256": SCHEDULE_HASH,
                "reviewer_id": "putra",
                "reviewer_role": "CALENDAR_REVIEW",
                "reviewer_public_key_sha256": request["reviewer_public_key_sha256"],
                "independence_attested": True,
                "independence_statement": "I attest that I am not the terminal operator, project developer, or evidence collector for this FINEX calendar review.",
                "decision": "REVIEWED_INCOMPLETE_PENDING_EMAIL_MONITORING",
                "signature_namespace": "ai-scalper-finex-calendar-review-v3",
                "future_exception_completeness": False,
                "special_hours_attested": False,
                "authorization_granted": False,
                "promotion_eligible": False,
                "safe_to_demo_auto_order": False,
                "live_allowed": False,
                "order_capability": "DISABLED",
            }
            payload = json.dumps(attestation, indent=2).encode("utf-8")
            payload_path = root / "attestation.json"
            payload_path.write_bytes(payload)
            subprocess.run(
                [
                    str(shutil.which("ssh-keygen")),
                    "-Y",
                    "sign",
                    "-f",
                    str(private_key),
                    "-n",
                    "ai-scalper-finex-calendar-review-v3",
                    str(payload_path),
                ],
                check=True,
                capture_output=True,
            )
            signature = Path(str(payload_path) + ".sig").read_bytes()
            validation = verify_detached_incomplete_attestation(
                request,
                evidence(),
                payload,
                signature,
                public_key_text=pub,
            )
            self.assertTrue(validation["signature_verified"])
            self.assertFalse(validation["authorization_granted"])
            self.assertEqual("DISABLED", validation["order_capability"])
            with self.assertRaises(FinexCalendarReviewEd25519Error):
                verify_detached_incomplete_attestation(
                    request,
                    evidence(),
                    payload + b" ",
                    signature,
                    public_key_text=pub,
                )


if __name__ == "__main__":
    unittest.main()
