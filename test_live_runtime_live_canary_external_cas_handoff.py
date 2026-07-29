from __future__ import annotations

import ast
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import zipfile

import execution_policy
from live_runtime.asymmetric_release_trust import (
    rsa_public_key_fingerprint_sha256,
)
from live_runtime.contracts import canonical_json
from live_runtime.live_canary_portable_launch_custody import (
    LiveCanaryLaunchReservationAcknowledgement,
    LiveCanaryLaunchReservationCheckpoint,
    LiveCanaryLaunchReservationProposal,
    LiveCanaryPortableCustodyPolicy,
    launch_acknowledgement_signing_message,
    launch_checkpoint_signing_message,
)
from live_runtime.live_canary_external_cas_handoff import (
    ACKNOWLEDGEMENT_MEMBER,
    CHECKPOINT_MEMBER,
    CUSTODY_POLICY_MEMBER,
    HEAD_READBACK_MEMBER,
    LiveCanaryExternalCasHandoffError,
    NONCE_READBACK_MEMBER,
    PROPOSAL_MEMBER,
    REQUEST_MANIFEST_MEMBER,
    REQUEST_MEMBER_ORDER,
    external_cas_nonce_readback_signing_message,
    prepare_live_canary_external_cas_request,
    verify_live_canary_external_cas_request_path,
    verify_live_canary_external_cas_response,
)
import test_live_runtime_live_canary_portable_launch_custody as custody_fixture


NOW = datetime(2026, 7, 29, 3, 0, tzinfo=timezone.utc)
ZERO_SHA256 = "0" * 64


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _utc(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(
        timespec="microseconds"
    ).replace("+00:00", "Z")


class LiveCanaryExternalCasHandoffTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.host_sha256 = _digest("xm-live-host")
        self.service_sha256 = _digest("xm-live-service")
        self.task_sha256 = _digest("xm-live-task")
        self.launcher_policy_sha256 = _digest("xm-launcher-policy")
        self.policy = LiveCanaryPortableCustodyPolicy(
            policy_id="xm-live-portable-custody-v1",
            custody_issuer_id="xm-offhost-cas-custodian",
            custody_key_id="xm-offhost-cas-rsa-key-v1",
            rsa_modulus_hex=custody_fixture.CUSTODY_N,
            rsa_exponent=65_537,
            public_key_fingerprint_sha256=(
                rsa_public_key_fingerprint_sha256(
                    custody_fixture.CUSTODY_N,
                    65_537,
                )
            ),
            worm_repository_alias_sha256=_digest("xm-worm-cas-ledger"),
            deployment_host_alias_sha256=self.host_sha256,
            service_account_alias_sha256=self.service_sha256,
            task_definition_sha256=self.task_sha256,
            launcher_trust_policy_sha256=self.launcher_policy_sha256,
            minimum_retention_seconds=31_536_000,
            maximum_receipt_age_seconds=300,
            maximum_launch_ttl_seconds=30,
        )
        self.proposal = LiveCanaryLaunchReservationProposal(
            sequence=1,
            predecessor_checkpoint_sha256=ZERO_SHA256,
            custody_policy_sha256=self.policy.content_sha256,
            custody_verification_sha256=_digest("legacy-custody-verification"),
            admission_sha256=_digest("legacy-admission"),
            candidate_sha256=_digest("xm-live-candidate"),
            authorization_sha256=_digest("live-authorization"),
            validation_sha256=_digest("live-validation"),
            launcher_trust_policy_sha256=self.launcher_policy_sha256,
            launcher_attestation_sha256=_digest("launcher-attestation"),
            launcher_nonce_sha256=_digest("launcher-nonce"),
            release_identity_sha256=_digest("xm-live-execution-release"),
            deployment_host_alias_sha256=self.host_sha256,
            service_account_alias_sha256=self.service_sha256,
            task_definition_sha256=self.task_sha256,
            requested_at_utc=NOW,
            expires_at_utc=NOW + timedelta(seconds=30),
        )
        self.proposal_data = self.proposal.canonical_json().encode("utf-8")
        self.policy_data = self.policy.canonical_json().encode("utf-8")
        self.proposal_path = self.root / "launch-proposal.json"
        self.policy_path = self.root / "portable-custody-policy.json"
        self.proposal_path.write_bytes(self.proposal_data)
        self.policy_path.write_bytes(self.policy_data)

    def _pins(self, **changes: str) -> dict[str, str]:
        values = {
            "expected_proposal_sha256": _sha256(self.proposal_data),
            "expected_custody_policy_sha256": _sha256(self.policy_data),
            "expected_predecessor_checkpoint_sha256": ZERO_SHA256,
            "expected_launcher_nonce_sha256": (
                self.proposal.launcher_nonce_sha256
            ),
            "expected_candidate_sha256": self.proposal.candidate_sha256,
            "expected_admission_sha256": self.proposal.admission_sha256,
            "expected_custody_verification_sha256": (
                self.proposal.custody_verification_sha256
            ),
            "expected_authorization_sha256": (
                self.proposal.authorization_sha256
            ),
            "expected_validation_sha256": self.proposal.validation_sha256,
            "expected_launcher_trust_policy_sha256": (
                self.proposal.launcher_trust_policy_sha256
            ),
            "expected_launcher_attestation_sha256": (
                self.proposal.launcher_attestation_sha256
            ),
            "expected_release_identity_sha256": (
                self.proposal.release_identity_sha256
            ),
            "expected_deployment_host_alias_sha256": self.host_sha256,
            "expected_service_account_alias_sha256": self.service_sha256,
            "expected_task_definition_sha256": self.task_sha256,
        }
        values.update(changes)
        return values

    def _cli_pins(self) -> list[str]:
        result: list[str] = []
        for name, value in self._pins().items():
            result.extend(("--" + name.replace("_", "-"), value))
        return result

    def _prepare(
        self,
        suffix: str,
        *,
        proposal_path: Path | None = None,
        policy_path: Path | None = None,
        pins: dict[str, str] | None = None,
    ) -> tuple[Path, dict[str, object]]:
        output = self.root / f"live-canary-external-cas-request-{suffix}.zip"
        result = prepare_live_canary_external_cas_request(
            proposal_path=proposal_path or self.proposal_path,
            custody_policy_path=policy_path or self.policy_path,
            request_id="xm-live-cas-reservation-v1",
            output=output,
            **(pins or self._pins()),
        )
        return output, result

    def _signed_response(
        self,
        request_result: dict[str, object],
        *,
        acknowledgement_overrides: dict[str, object] | None = None,
        nonce_overrides: dict[str, object] | None = None,
        checkpoint_signature: str | None = None,
    ) -> dict[str, Path]:
        unsigned_checkpoint = LiveCanaryLaunchReservationCheckpoint(
            proposal=self.proposal,
            proposal_sha256=self.proposal.content_sha256,
            committed_at_utc=NOW + timedelta(microseconds=1),
            custody_issuer_id=self.policy.custody_issuer_id,
            custody_key_id=self.policy.custody_key_id,
            public_key_fingerprint_sha256=(
                self.policy.public_key_fingerprint_sha256
            ),
        )
        checkpoint = replace(
            unsigned_checkpoint,
            signature_rsa_pkcs1v15_sha256_hex=(
                checkpoint_signature
                or custody_fixture.custody_signature(
                    launch_checkpoint_signing_message(unsigned_checkpoint)
                )
            ),
        )
        checkpoint_data = checkpoint.canonical_json().encode("utf-8")
        ack_values: dict[str, object] = {
            "expected_predecessor_checkpoint_sha256": ZERO_SHA256,
            "written_checkpoint_sha256": checkpoint.content_sha256,
            "proposal_sha256": self.proposal.content_sha256,
            "launcher_nonce_sha256": self.proposal.launcher_nonce_sha256,
            "sequence": self.proposal.sequence,
            "acknowledged_at_utc": NOW + timedelta(microseconds=2),
            "custody_issuer_id": self.policy.custody_issuer_id,
            "custody_key_id": self.policy.custody_key_id,
            "public_key_fingerprint_sha256": (
                self.policy.public_key_fingerprint_sha256
            ),
        }
        ack_values.update(acknowledgement_overrides or {})
        unsigned_ack = LiveCanaryLaunchReservationAcknowledgement(**ack_values)
        acknowledgement = replace(
            unsigned_ack,
            signature_rsa_pkcs1v15_sha256_hex=(
                custody_fixture.custody_signature(
                    launch_acknowledgement_signing_message(unsigned_ack)
                )
            ),
        )
        ack_data = acknowledgement.canonical_json().encode("utf-8")
        nonce_values: dict[str, object] = {
            "schema_version": "live-canary-external-cas-nonce-readback-v1",
            "request_identity_sha256": request_result[
                "request_identity_sha256"
            ],
            "proposal_sha256": self.proposal.content_sha256,
            "checkpoint_sha256": checkpoint.content_sha256,
            "acknowledgement_sha256": acknowledgement.content_sha256,
            "expected_predecessor_checkpoint_sha256": ZERO_SHA256,
            "observed_head_sha256": checkpoint.content_sha256,
            "launcher_nonce_sha256": self.proposal.launcher_nonce_sha256,
            "sequence": self.proposal.sequence,
            "nonce_seen": True,
            "observed_at_utc": _utc(NOW + timedelta(microseconds=3)),
            "custody_issuer_id": self.policy.custody_issuer_id,
            "custody_key_id": self.policy.custody_key_id,
            "public_key_fingerprint_sha256": (
                self.policy.public_key_fingerprint_sha256
            ),
            "signature_algorithm": "RSASSA-PKCS1-v1_5-SHA256",
            "signature_rsa_pkcs1v15_sha256_hex": "",
            "live_allowed": False,
            "execution_authorized": False,
            "bootstrap_authorized": False,
            "process_launch_authorized": False,
            "order_capability": "DISABLED",
        }
        nonce_values.update(nonce_overrides or {})
        nonce_values["signature_rsa_pkcs1v15_sha256_hex"] = (
            custody_fixture.custody_signature(
                external_cas_nonce_readback_signing_message(nonce_values)
            )
        )
        nonce_data = canonical_json(nonce_values).encode("utf-8")
        paths = {
            CHECKPOINT_MEMBER: self.root / CHECKPOINT_MEMBER,
            ACKNOWLEDGEMENT_MEMBER: self.root / ACKNOWLEDGEMENT_MEMBER,
            HEAD_READBACK_MEMBER: self.root / HEAD_READBACK_MEMBER,
            NONCE_READBACK_MEMBER: self.root / NONCE_READBACK_MEMBER,
        }
        paths[CHECKPOINT_MEMBER].write_bytes(checkpoint_data)
        paths[ACKNOWLEDGEMENT_MEMBER].write_bytes(ack_data)
        paths[HEAD_READBACK_MEMBER].write_bytes(checkpoint_data)
        paths[NONCE_READBACK_MEMBER].write_bytes(nonce_data)
        return paths

    def _verify_response(
        self,
        request: Path,
        request_result: dict[str, object],
        response: dict[str, Path],
        *,
        suffix: str,
        head_sha256: str | None = None,
    ) -> dict[str, object]:
        output = self.root / (
            f"live-canary-external-cas-assessment-{suffix}.json"
        )
        return verify_live_canary_external_cas_response(
            request_archive=request,
            expected_request_archive_sha256=_sha256(request.read_bytes()),
            checkpoint_path=response[CHECKPOINT_MEMBER],
            acknowledgement_path=response[ACKNOWLEDGEMENT_MEMBER],
            head_readback_path=response[HEAD_READBACK_MEMBER],
            nonce_readback_path=response[NONCE_READBACK_MEMBER],
            expected_head_readback_sha256=(
                head_sha256
                or _sha256(response[HEAD_READBACK_MEMBER].read_bytes())
            ),
            verified_at_utc=_utc(NOW + timedelta(microseconds=4)),
            assessment_output=output,
            **self._pins(),
        )

    def test_ac1_request_is_exact_and_deterministic(self) -> None:
        first, first_result = self._prepare("first")
        second, second_result = self._prepare("second")
        self.assertEqual(first.read_bytes(), second.read_bytes())
        self.assertEqual(
            first_result["request_identity_sha256"],
            second_result["request_identity_sha256"],
        )
        verified = verify_live_canary_external_cas_request_path(
            first,
            expected_request_archive_sha256=_sha256(first.read_bytes()),
            **self._pins(),
        )
        self.assertEqual(
            "LIVE_CANARY_EXTERNAL_CAS_REQUEST_VERIFIED",
            verified["status"],
        )
        with zipfile.ZipFile(first) as archive:
            self.assertEqual(REQUEST_MEMBER_ORDER, tuple(archive.namelist()))
            self.assertEqual(self.proposal_data, archive.read(PROPOSAL_MEMBER))
            self.assertEqual(
                self.policy_data,
                archive.read(CUSTODY_POLICY_MEMBER),
            )
            self.assertTrue(archive.read(REQUEST_MANIFEST_MEMBER))
            for info in archive.infolist():
                self.assertEqual((1980, 1, 1, 0, 0, 0), info.date_time)
                self.assertEqual(zipfile.ZIP_STORED, info.compress_type)
                self.assertEqual(b"", info.extra)
                self.assertEqual(b"", info.comment)

    def test_ac2_substitution_archive_collision_and_lock_fail_closed(self) -> None:
        with self.assertRaisesRegex(
            LiveCanaryExternalCasHandoffError,
            "HANDOFF_EXTERNAL_PIN_MISMATCH",
        ):
            self._prepare(
                "wrong-pin",
                pins=self._pins(expected_candidate_sha256=_digest("other")),
            )
        request, _ = self._prepare("collision")
        original = request.read_bytes()
        with self.assertRaisesRegex(
            LiveCanaryExternalCasHandoffError,
            "REQUEST_DESTINATION_INVALID",
        ):
            prepare_live_canary_external_cas_request(
                proposal_path=self.proposal_path,
                custody_policy_path=self.policy_path,
                request_id="xm-live-cas-reservation-v1",
                output=request,
                **self._pins(),
            )
        self.assertEqual(original, request.read_bytes())
        tampered = self.root / "live-canary-external-cas-request-tampered.zip"
        tampered.write_bytes(original + b"x")
        with self.assertRaises(LiveCanaryExternalCasHandoffError):
            verify_live_canary_external_cas_request_path(
                tampered,
                expected_request_archive_sha256=_sha256(tampered.read_bytes()),
                **self._pins(),
            )
        with mock.patch.object(execution_policy, "LIVE_ALLOWED", True):
            with self.assertRaisesRegex(
                LiveCanaryExternalCasHandoffError,
                "CENTRAL_LIVE_LOCK_NOT_FALSE",
            ):
                verify_live_canary_external_cas_request_path(
                    request,
                    expected_request_archive_sha256=_sha256(original),
                    **self._pins(),
                )

    def test_ac3_signed_cas_result_is_bound_end_to_end(self) -> None:
        request, request_result = self._prepare("valid-response")
        response = self._signed_response(request_result)
        result = self._verify_response(
            request,
            request_result,
            response,
            suffix="valid-response",
        )
        self.assertEqual(
            "LIVE_CANARY_EXTERNAL_CAS_RESPONSE_VERIFIED",
            result["status"],
        )
        self.assertTrue(result["signed_checkpoint_accepted"])
        self.assertTrue(result["signed_acknowledgement_accepted"])
        self.assertTrue(result["byte_identical_head_readback_accepted"])
        self.assertTrue(result["signed_nonce_readback_accepted"])
        assessment_path = Path(str(result["assessment"]))
        self.assertEqual(
            result["assessment_sha256"],
            _sha256(assessment_path.read_bytes()),
        )

    def test_ac4_forgery_cross_request_nonce_and_readback_fail_closed(self) -> None:
        request, request_result = self._prepare("negative-response")
        bad_signature = self._signed_response(
            request_result,
            checkpoint_signature="0" * 768,
        )
        with self.assertRaisesRegex(
            LiveCanaryExternalCasHandoffError,
            "LAUNCH_CHECKPOINT_SIGNATURE_INVALID",
        ):
            self._verify_response(
                request,
                request_result,
                bad_signature,
                suffix="bad-signature",
            )

        drift = self._signed_response(request_result)
        drift[HEAD_READBACK_MEMBER].write_bytes(b"{}")
        with self.assertRaisesRegex(
            LiveCanaryExternalCasHandoffError,
            "HEAD_READBACK_CONTENT_MISMATCH",
        ):
            self._verify_response(
                request,
                request_result,
                drift,
                suffix="head-drift",
                head_sha256=_sha256(b"{}"),
            )

        unseen = self._signed_response(
            request_result,
            nonce_overrides={"nonce_seen": False},
        )
        with self.assertRaisesRegex(
            LiveCanaryExternalCasHandoffError,
            "NONCE_READBACK_SAFETY_DRIFT",
        ):
            self._verify_response(
                request,
                request_result,
                unseen,
                suffix="nonce-unseen",
            )

        cross = self._signed_response(
            request_result,
            nonce_overrides={
                "request_identity_sha256": _digest("other-request")
            },
        )
        with self.assertRaisesRegex(
            LiveCanaryExternalCasHandoffError,
            "NONCE_READBACK_BINDING_MISMATCH",
        ):
            self._verify_response(
                request,
                request_result,
                cross,
                suffix="cross-request",
            )

    def test_ac5_assessment_is_evidence_only(self) -> None:
        request, request_result = self._prepare("deny-only")
        response = self._signed_response(request_result)
        result = self._verify_response(
            request,
            request_result,
            response,
            suffix="deny-only",
        )
        for key in (
            "runtime_cas_callback_executed",
            "runtime_nonce_consumed_by_tool",
            "runtime_launch_capability_emitted",
            "runtime_admission_seal",
            "runtime_custody_seal",
            "central_unlock_performed",
            "process_launch_performed",
            "bootstrap_authorized",
            "process_launch_authorized",
            "execution_authorized",
            "broker_mutation_authorized",
            "live_allowed",
        ):
            self.assertIs(False, result[key], key)
        self.assertEqual("DISABLED", result["order_capability"])
        self.assertEqual("NOT_PERFORMED", result["broker_mutation"])
        self.assertNotIn("launch_capability", result)

    def test_ac6_cli_isolated_normal_and_optimized(self) -> None:
        script = Path("manage_live_canary_external_cas_handoff.py").resolve()
        for optimized in (False, True):
            prefix = [sys.executable, "-I", "-S"]
            if optimized:
                prefix.append("-O")
            prefix.extend(("-B", str(script)))
            request = self.root / (
                "live-canary-external-cas-request-cli-"
                f"{int(optimized)}.zip"
            )
            prepare = subprocess.run(
                [
                    *prefix,
                    "prepare-request",
                    "--proposal",
                    str(self.proposal_path),
                    "--custody-policy",
                    str(self.policy_path),
                    *self._cli_pins(),
                    "--request-id",
                    "xm-live-cas-reservation-cli-v1",
                    "--output",
                    str(request),
                ],
                cwd=self.root,
                capture_output=True,
                text=True,
                timeout=30,
            )
            self.assertEqual(0, prepare.returncode, prepare.stderr)
            self.assertIn("LIVE_CANARY_EXTERNAL_CAS_REQUEST_READY", prepare.stdout)
            verify = subprocess.run(
                [
                    *prefix,
                    "verify-request",
                    "--request-archive",
                    str(request),
                    "--expected-request-archive-sha256",
                    _sha256(request.read_bytes()),
                    *self._cli_pins(),
                ],
                cwd=self.root,
                capture_output=True,
                text=True,
                timeout=30,
            )
            self.assertEqual(0, verify.returncode, verify.stderr)
            self.assertIn(
                "LIVE_CANARY_EXTERNAL_CAS_REQUEST_VERIFIED",
                verify.stdout,
            )
            request_result = verify_live_canary_external_cas_request_path(
                request,
                expected_request_archive_sha256=_sha256(request.read_bytes()),
                **self._pins(),
            )
            response = self._signed_response(request_result)
            assessment = self.root / (
                "live-canary-external-cas-assessment-cli-"
                f"{int(optimized)}.json"
            )
            verify_response = subprocess.run(
                [
                    *prefix,
                    "verify-response",
                    "--request-archive",
                    str(request),
                    "--expected-request-archive-sha256",
                    _sha256(request.read_bytes()),
                    *self._cli_pins(),
                    "--checkpoint",
                    str(response[CHECKPOINT_MEMBER]),
                    "--acknowledgement",
                    str(response[ACKNOWLEDGEMENT_MEMBER]),
                    "--head-readback",
                    str(response[HEAD_READBACK_MEMBER]),
                    "--nonce-readback",
                    str(response[NONCE_READBACK_MEMBER]),
                    "--expected-head-readback-sha256",
                    _sha256(response[HEAD_READBACK_MEMBER].read_bytes()),
                    "--verified-at-utc",
                    _utc(NOW + timedelta(microseconds=4)),
                    "--assessment-output",
                    str(assessment),
                ],
                cwd=self.root,
                capture_output=True,
                text=True,
                timeout=30,
            )
            self.assertEqual(
                0,
                verify_response.returncode,
                verify_response.stderr,
            )
            self.assertIn(
                "LIVE_CANARY_EXTERNAL_CAS_RESPONSE_VERIFIED",
                verify_response.stdout,
            )

    def test_ac7_static_surface_and_canonical_nonce_domain(self) -> None:
        source = Path(
            "live_runtime/live_canary_external_cas_handoff.py"
        ).read_text(encoding="utf-8")
        tree = ast.parse(source)
        imports: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.update(alias.name.split(".", 1)[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imports.add(node.module.split(".", 1)[0])
            self.assertNotIsInstance(node, ast.Assert)
        self.assertTrue(
            imports.isdisjoint(
                {
                    "MetaTrader5",
                    "boto3",
                    "ctypes",
                    "keyring",
                    "requests",
                    "socket",
                    "sqlite3",
                    "subprocess",
                    "urllib",
                    "win32cred",
                }
            )
        )
        self.assertIs(False, execution_policy.LIVE_ALLOWED)
        unsigned = {
            "schema_version": "live-canary-external-cas-nonce-readback-v1",
            "request_identity_sha256": _digest("request"),
            "proposal_sha256": _digest("proposal"),
            "checkpoint_sha256": _digest("checkpoint"),
            "acknowledgement_sha256": _digest("ack"),
            "expected_predecessor_checkpoint_sha256": ZERO_SHA256,
            "observed_head_sha256": _digest("checkpoint"),
            "launcher_nonce_sha256": _digest("nonce"),
            "sequence": 1,
            "nonce_seen": True,
            "observed_at_utc": _utc(NOW),
            "custody_issuer_id": "issuer",
            "custody_key_id": "key",
            "public_key_fingerprint_sha256": _digest("fingerprint"),
            "signature_algorithm": "RSASSA-PKCS1-v1_5-SHA256",
            "signature_rsa_pkcs1v15_sha256_hex": "",
            "live_allowed": False,
            "execution_authorized": False,
            "bootstrap_authorized": False,
            "process_launch_authorized": False,
            "order_capability": "DISABLED",
        }
        first = external_cas_nonce_readback_signing_message(unsigned)
        second = external_cas_nonce_readback_signing_message(
            json.loads(canonical_json(unsigned))
        )
        self.assertEqual(first, second)
        self.assertTrue(
            first.startswith(
                b"AI_SCALPER:LIVE_CANARY:EXTERNAL_CAS_NONCE_READBACK:v1\x00"
            )
        )

    def test_ec1_ec2_strict_json_sequence_and_symlink_guards(self) -> None:
        duplicate = self.root / "duplicate-proposal.json"
        duplicate.write_text(
            '{"sequence":1,"sequence":1}',
            encoding="utf-8",
        )
        with self.assertRaisesRegex(
            LiveCanaryExternalCasHandoffError,
            "LAUNCH_PROPOSAL_JSON_DUPLICATE_KEY",
        ):
            self._prepare("duplicate", proposal_path=duplicate)

        invalid_values = json.loads(self.proposal.canonical_json())
        invalid_values["sequence"] = 2
        invalid = self.root / "invalid-sequence-proposal.json"
        invalid.write_text(canonical_json(invalid_values), encoding="utf-8")
        with self.assertRaisesRegex(
            LiveCanaryExternalCasHandoffError,
            "LAUNCH_PROPOSAL_WINDOW_OR_PREDECESSOR_INVALID",
        ):
            self._prepare("invalid-sequence", proposal_path=invalid)

        second = replace(
            self.proposal,
            sequence=2,
            predecessor_checkpoint_sha256=_digest("first-checkpoint"),
        )
        second_data = second.canonical_json().encode("utf-8")
        second_path = self.root / "second-proposal.json"
        second_path.write_bytes(second_data)
        second_pins = self._pins(
            expected_proposal_sha256=_sha256(second_data),
            expected_predecessor_checkpoint_sha256=(
                second.predecessor_checkpoint_sha256
            ),
        )
        second_request, result = self._prepare(
            "second-sequence",
            proposal_path=second_path,
            pins=second_pins,
        )
        self.assertTrue(second_request.is_file())
        self.assertEqual(2, result["sequence"])

        link = self.root / "proposal-link.json"
        try:
            link.symlink_to(self.proposal_path)
        except (OSError, NotImplementedError):
            self.skipTest("symlink creation is unavailable")
        with self.assertRaisesRegex(
            LiveCanaryExternalCasHandoffError,
            "LAUNCH_PROPOSAL_FILE_INVALID",
        ):
            self._prepare("symlink", proposal_path=link)

    def test_ec6_ec7_valid_signatures_with_wrong_bindings_reject(self) -> None:
        request, request_result = self._prepare("wrong-bindings")
        response = self._signed_response(
            request_result,
            acknowledgement_overrides={
                "expected_predecessor_checkpoint_sha256": _digest(
                    "wrong-predecessor"
                )
            },
        )
        with self.assertRaisesRegex(
            LiveCanaryExternalCasHandoffError,
            "LAUNCH_ACKNOWLEDGEMENT_BINDING_MISMATCH",
        ):
            self._verify_response(
                request,
                request_result,
                response,
                suffix="wrong-bindings",
            )

    def test_ec9_ec11_expiry_and_assessment_collision_reject(self) -> None:
        request, request_result = self._prepare("expiry-collision")
        expired = self._signed_response(
            request_result,
            nonce_overrides={
                "observed_at_utc": _utc(self.proposal.expires_at_utc)
            },
        )
        with self.assertRaisesRegex(
            LiveCanaryExternalCasHandoffError,
            "NONCE_READBACK_TIME_INVALID",
        ):
            self._verify_response(
                request,
                request_result,
                expired,
                suffix="expired",
            )

        valid = self._signed_response(request_result)
        first = self._verify_response(
            request,
            request_result,
            valid,
            suffix="collision",
        )
        assessment = Path(str(first["assessment"]))
        original = assessment.read_bytes()
        valid = self._signed_response(request_result)
        with self.assertRaisesRegex(
            LiveCanaryExternalCasHandoffError,
            "ASSESSMENT_DESTINATION_INVALID",
        ):
            self._verify_response(
                request,
                request_result,
                valid,
                suffix="collision",
            )
        self.assertEqual(original, assessment.read_bytes())


if __name__ == "__main__":
    unittest.main()
