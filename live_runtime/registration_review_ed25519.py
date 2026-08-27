"""Self-contained Ed25519 regulatory review receipts for the FINEX lane.

The receipts produced here are deny-only review evidence.  They do not enable
registration, execution, or order submission.  Every receipt embeds the exact
request, attestation, public key, and SSHSIG bytes so a downstream consumer can
repeat cryptographic verification without access to reviewer secrets.
"""

from __future__ import annotations

import base64
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import re
import shutil
import struct
import subprocess
import tempfile
from typing import Callable, Mapping

REQUEST_SCHEMA = "regulatory-ed25519-request-v1"
ATTESTATION_SCHEMA = "regulatory-ed25519-attestation-v1"
RECEIPT_SCHEMA = "regulatory-ed25519-approval-v1"
OBSERVATION_SCHEMA = "regulatory-ed25519-observation-v1"
SIGNATURE_NAMESPACE = "ai-scalper-finex-regulatory-review-v1"
ROLES = frozenset({"COMPLIANCE_REVIEW", "LEGAL_REVIEW"})
_IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9._-]{1,63}$")
_MAX_CLOCK_SKEW = timedelta(minutes=5)
_MAX_EMBEDDED_BYTES = 256 * 1024
_PUBLIC_KEY_ALGORITHM = "ssh-ed25519"
_REGULATORY_EVIDENCE_FIELDS = frozenset(
    {
        "schema_version",
        "candidate_id",
        "entity",
        "broker_legal_name",
        "broker_server",
        "environment",
        "binding_scope",
        "operating_jurisdiction",
        "broker_symbols",
        "calendar_template_sha256",
        "broker_claim_observed",
        "independent_registry_verification",
        "verified_at_utc",
        "verification_status",
        "independent_registry_sources",
        "japan_residency_eligibility",
        "indonesia_return_eligibility",
        "legal_eligible",
        "decision",
        "execution_enabled",
        "live_allowed",
        "safe_to_demo_auto_order",
        "promotion_eligible",
        "max_lot",
        "evidence_bundle_sha256",
    }
)


class RegulatoryEd25519Error(ValueError):
    """Raised when asymmetric regulatory evidence is invalid."""


def normalize_public_key(public_key_text: str) -> tuple[str, str]:
    """Validate and canonicalize one OpenSSH Ed25519 public key."""

    parts = str(public_key_text or "").strip().split()
    if len(parts) < 2 or parts[0] != _PUBLIC_KEY_ALGORITHM:
        raise RegulatoryEd25519Error("reviewer public key must be ssh-ed25519")
    try:
        blob = base64.b64decode(parts[1], validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise RegulatoryEd25519Error("reviewer public key is malformed") from exc

    def read_field(offset: int) -> tuple[bytes, int]:
        if offset + 4 > len(blob):
            raise RegulatoryEd25519Error("reviewer public key is truncated")
        length = struct.unpack(">I", blob[offset : offset + 4])[0]
        start = offset + 4
        end = start + length
        if end > len(blob):
            raise RegulatoryEd25519Error("reviewer public key is truncated")
        return blob[start:end], end

    algorithm, offset = read_field(0)
    key_bytes, offset = read_field(offset)
    if algorithm != b"ssh-ed25519" or len(key_bytes) != 32 or offset != len(blob):
        raise RegulatoryEd25519Error("reviewer public key encoding is invalid")
    normalized = _PUBLIC_KEY_ALGORITHM + " " + parts[1]
    return normalized, hashlib.sha256(blob).hexdigest()


def _canonical_bytes(payload: Mapping[str, object]) -> bytes:
    return (
        json.dumps(
            dict(payload),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")


def _sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _hash_without(payload: Mapping[str, object], field: str) -> str:
    content = dict(payload)
    content.pop(field, None)
    return _sha256_bytes(_canonical_bytes(content))


def _strict_json_bytes(payload: bytes, field: str) -> dict[str, object]:
    if not payload or len(payload) > _MAX_EMBEDDED_BYTES:
        raise RegulatoryEd25519Error(f"{field} size invalid")

    def reject_duplicate(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise RegulatoryEd25519Error(f"{field} duplicate key")
            result[key] = value
        return result

    try:
        value = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=reject_duplicate,
            parse_constant=lambda value: (_ for _ in ()).throw(
                RegulatoryEd25519Error(f"{field} non-finite number")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RegulatoryEd25519Error(f"{field} invalid JSON") from exc
    if not isinstance(value, dict):
        raise RegulatoryEd25519Error(f"{field} must be an object")
    return value


def _exact_keys(
    payload: Mapping[str, object], expected: frozenset[str], field: str
) -> None:
    if frozenset(payload) != expected:
        raise RegulatoryEd25519Error(f"{field} fields invalid")


def _text(value: object, field: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise RegulatoryEd25519Error(f"{field} invalid")
    return value


def _identifier(value: object, field: str) -> str:
    text = _text(value, field).lower()
    if not _IDENTIFIER.fullmatch(text):
        raise RegulatoryEd25519Error(f"{field} invalid")
    return text


def _digest(value: object, field: str) -> str:
    text = _text(value, field).lower()
    if len(text) != 64 or any(char not in "0123456789abcdef" for char in text):
        raise RegulatoryEd25519Error(f"{field} invalid")
    return text


def _utc(value: object, field: str) -> datetime:
    text = _text(value, field)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise RegulatoryEd25519Error(f"{field} invalid") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise RegulatoryEd25519Error(f"{field} must be timezone-aware")
    return parsed.astimezone(timezone.utc)


def _utc_text(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise RegulatoryEd25519Error("trusted time must be timezone-aware")
    return value.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )


def _validate_evidence(evidence: Mapping[str, object]) -> dict[str, str]:
    if set(evidence) != set(_REGULATORY_EVIDENCE_FIELDS):
        raise RegulatoryEd25519Error("regulatory evidence fields invalid")
    if evidence.get("schema_version") != "regulatory-evidence-v1":
        raise RegulatoryEd25519Error("regulatory evidence schema invalid")
    if evidence.get("candidate_id") != "finex":
        raise RegulatoryEd25519Error("regulatory evidence candidate invalid")
    if evidence.get("operating_jurisdiction") != "ID":
        raise RegulatoryEd25519Error("regulatory jurisdiction invalid")
    if evidence.get("environment") != "DEMO":
        raise RegulatoryEd25519Error("regulatory environment invalid")
    if evidence.get("legal_eligible") is not True:
        raise RegulatoryEd25519Error("regulatory eligibility not established")
    if evidence.get("independent_registry_verification") is not True:
        raise RegulatoryEd25519Error("independent registry evidence missing")
    for field in (
        "execution_enabled",
        "live_allowed",
        "promotion_eligible",
        "safe_to_demo_auto_order",
    ):
        if evidence.get(field) is not False:
            raise RegulatoryEd25519Error(f"unsafe regulatory evidence field: {field}")
    return {
        "candidate_id": "finex",
        "evidence_bundle_sha256": _digest(
            evidence.get("evidence_bundle_sha256"), "evidence_bundle_sha256"
        ),
        "broker_legal_name": _text(
            evidence.get("broker_legal_name"), "broker_legal_name"
        ),
        "operating_jurisdiction": "ID",
    }


_REQUEST_KEYS = frozenset(
    {
        "schema_version",
        "candidate_id",
        "evidence_bundle_sha256",
        "broker_legal_name",
        "operating_jurisdiction",
        "approver_role",
        "approver_id",
        "reviewer_public_key",
        "reviewer_public_key_sha256",
        "review_scope",
        "request_sha256",
        "authorization_granted",
        "order_capability",
    }
)


def build_role_request(
    evidence: Mapping[str, object],
    *,
    approver_role: str,
    approver_id: str,
    public_key_text: str,
) -> dict[str, object]:
    binding = _validate_evidence(evidence)
    if approver_role not in ROLES:
        raise RegulatoryEd25519Error("approver role invalid")
    reviewer = _identifier(approver_id, "approver_id")
    normalized_key, public_key_sha256 = normalize_public_key(public_key_text)
    request: dict[str, object] = {
        "schema_version": REQUEST_SCHEMA,
        **binding,
        "approver_role": approver_role,
        "approver_id": reviewer,
        "reviewer_public_key": normalized_key,
        "reviewer_public_key_sha256": public_key_sha256,
        "review_scope": "REGULATORY_EVIDENCE_ONLY",
        "authorization_granted": False,
        "order_capability": "DISABLED",
    }
    request["request_sha256"] = _hash_without(request, "request_sha256")
    return request


def validate_role_request(
    request: Mapping[str, object], evidence: Mapping[str, object]
) -> dict[str, object]:
    _exact_keys(request, _REQUEST_KEYS, "request")
    binding = _validate_evidence(evidence)
    if request.get("schema_version") != REQUEST_SCHEMA:
        raise RegulatoryEd25519Error("request schema invalid")
    for field, expected in binding.items():
        if request.get(field) != expected:
            raise RegulatoryEd25519Error(f"request {field} binding mismatch")
    if request.get("approver_role") not in ROLES:
        raise RegulatoryEd25519Error("request role invalid")
    _identifier(request.get("approver_id"), "approver_id")
    normalized_key, key_hash = normalize_public_key(
        _text(request.get("reviewer_public_key"), "reviewer_public_key")
    )
    if request.get("reviewer_public_key") != normalized_key:
        raise RegulatoryEd25519Error("request public key not normalized")
    if request.get("reviewer_public_key_sha256") != key_hash:
        raise RegulatoryEd25519Error("request public key hash mismatch")
    if request.get("review_scope") != "REGULATORY_EVIDENCE_ONLY":
        raise RegulatoryEd25519Error("request scope invalid")
    if request.get("authorization_granted") is not False:
        raise RegulatoryEd25519Error("request must not authorize execution")
    if request.get("order_capability") != "DISABLED":
        raise RegulatoryEd25519Error("request order capability invalid")
    expected_hash = _hash_without(request, "request_sha256")
    if request.get("request_sha256") != expected_hash:
        raise RegulatoryEd25519Error("request hash mismatch")
    return dict(request)


_ATTESTATION_KEYS = frozenset(
    {
        "schema_version",
        "candidate_id",
        "evidence_bundle_sha256",
        "request_sha256",
        "approver_role",
        "approver_id",
        "reviewer_public_key_sha256",
        "decision",
        "independence_attested",
        "evidence_matches_sources_attested",
        "license_record_verified_attested",
        "reviewed_at_utc",
        "review_scope",
        "authorization_granted",
        "order_capability",
    }
)


def build_approved_attestation(
    request: Mapping[str, object],
    evidence: Mapping[str, object],
    *,
    independence_attested: bool,
    evidence_matches_sources_attested: bool,
    license_record_verified_attested: bool,
    now_provider: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
) -> dict[str, object]:
    validated = validate_role_request(request, evidence)
    if not all(
        (
            independence_attested,
            evidence_matches_sources_attested,
            license_record_verified_attested,
        )
    ):
        raise RegulatoryEd25519Error("all reviewer attestations are required")
    return {
        "schema_version": ATTESTATION_SCHEMA,
        "candidate_id": validated["candidate_id"],
        "evidence_bundle_sha256": validated["evidence_bundle_sha256"],
        "request_sha256": validated["request_sha256"],
        "approver_role": validated["approver_role"],
        "approver_id": validated["approver_id"],
        "reviewer_public_key_sha256": validated[
            "reviewer_public_key_sha256"
        ],
        "decision": "APPROVED_REGULATORY_EVIDENCE",
        "independence_attested": True,
        "evidence_matches_sources_attested": True,
        "license_record_verified_attested": True,
        "reviewed_at_utc": _utc_text(now_provider()),
        "review_scope": "REGULATORY_EVIDENCE_ONLY",
        "authorization_granted": False,
        "order_capability": "DISABLED",
    }


def _ssh_keygen() -> str:
    executable = shutil.which("ssh-keygen")
    if not executable:
        raise RegulatoryEd25519Error("ssh-keygen unavailable")
    return executable


def derive_public_key(private_key_path: Path) -> str:
    result = subprocess.run(
        [_ssh_keygen(), "-y", "-f", str(private_key_path)],
        capture_output=True,
        check=False,
        text=True,
        timeout=15,
    )
    if result.returncode != 0:
        raise RegulatoryEd25519Error("unable to derive reviewer public key")
    normalized, _ = normalize_public_key(result.stdout)
    return normalized


def sign_attestation(attestation_bytes: bytes, private_key_path: Path) -> bytes:
    if not attestation_bytes or len(attestation_bytes) > _MAX_EMBEDDED_BYTES:
        raise RegulatoryEd25519Error("attestation size invalid")
    with tempfile.TemporaryDirectory(prefix="regulatory-ed25519-sign-") as temp:
        payload_path = Path(temp) / "attestation.json"
        payload_path.write_bytes(attestation_bytes)
        result = subprocess.run(
            [
                _ssh_keygen(),
                "-Y",
                "sign",
                "-f",
                str(private_key_path),
                "-n",
                SIGNATURE_NAMESPACE,
                str(payload_path),
            ],
            capture_output=True,
            check=False,
            text=True,
            timeout=15,
        )
        signature_path = Path(str(payload_path) + ".sig")
        if result.returncode != 0 or not signature_path.is_file():
            raise RegulatoryEd25519Error("reviewer signature failed")
        signature = signature_path.read_bytes()
    if not signature or len(signature) > 64 * 1024:
        raise RegulatoryEd25519Error("reviewer signature size invalid")
    return signature


def _verify_sshsig(
    attestation_bytes: bytes, signature_bytes: bytes, public_key_text: str
) -> None:
    normalized_key, _ = normalize_public_key(public_key_text)
    if not signature_bytes or len(signature_bytes) > 64 * 1024:
        raise RegulatoryEd25519Error("reviewer signature size invalid")
    with tempfile.TemporaryDirectory(prefix="regulatory-ed25519-verify-") as temp:
        temp_path = Path(temp)
        allowed = temp_path / "allowed_signers"
        signature = temp_path / "attestation.sig"
        allowed.write_text("reviewer " + normalized_key + "\n", encoding="utf-8")
        signature.write_bytes(signature_bytes)
        result = subprocess.run(
            [
                _ssh_keygen(),
                "-Y",
                "verify",
                "-f",
                str(allowed),
                "-I",
                "reviewer",
                "-n",
                SIGNATURE_NAMESPACE,
                "-s",
                str(signature),
            ],
            input=attestation_bytes,
            capture_output=True,
            check=False,
            timeout=15,
        )
    if result.returncode != 0:
        raise RegulatoryEd25519Error("reviewer signature invalid")


def verify_attestation(
    request: Mapping[str, object],
    evidence: Mapping[str, object],
    attestation_bytes: bytes,
    signature_bytes: bytes,
    *,
    public_key_text: str,
    now_provider: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
) -> dict[str, object]:
    validated_request = validate_role_request(request, evidence)
    normalized_key, key_hash = normalize_public_key(public_key_text)
    if validated_request["reviewer_public_key"] != normalized_key:
        raise RegulatoryEd25519Error("attestation public key binding mismatch")
    attestation = _strict_json_bytes(attestation_bytes, "attestation")
    _exact_keys(attestation, _ATTESTATION_KEYS, "attestation")
    if attestation.get("schema_version") != ATTESTATION_SCHEMA:
        raise RegulatoryEd25519Error("attestation schema invalid")
    bindings = {
        "candidate_id": validated_request["candidate_id"],
        "evidence_bundle_sha256": validated_request[
            "evidence_bundle_sha256"
        ],
        "request_sha256": validated_request["request_sha256"],
        "approver_role": validated_request["approver_role"],
        "approver_id": validated_request["approver_id"],
        "reviewer_public_key_sha256": key_hash,
    }
    for field, expected in bindings.items():
        if attestation.get(field) != expected:
            raise RegulatoryEd25519Error(f"attestation {field} binding mismatch")
    if attestation.get("decision") != "APPROVED_REGULATORY_EVIDENCE":
        raise RegulatoryEd25519Error("attestation decision not approved")
    for field in (
        "independence_attested",
        "evidence_matches_sources_attested",
        "license_record_verified_attested",
    ):
        if attestation.get(field) is not True:
            raise RegulatoryEd25519Error(f"attestation {field} required")
    if attestation.get("review_scope") != "REGULATORY_EVIDENCE_ONLY":
        raise RegulatoryEd25519Error("attestation scope invalid")
    if attestation.get("authorization_granted") is not False:
        raise RegulatoryEd25519Error("attestation must not authorize execution")
    if attestation.get("order_capability") != "DISABLED":
        raise RegulatoryEd25519Error("attestation order capability invalid")
    reviewed_at = _utc(attestation.get("reviewed_at_utc"), "reviewed_at_utc")
    now = now_provider()
    if now.tzinfo is None or now.utcoffset() is None:
        raise RegulatoryEd25519Error("trusted time must be timezone-aware")
    if reviewed_at > now.astimezone(timezone.utc) + _MAX_CLOCK_SKEW:
        raise RegulatoryEd25519Error("attestation review time is in the future")
    _verify_sshsig(attestation_bytes, signature_bytes, normalized_key)
    request_bytes = _canonical_bytes(validated_request)
    receipt: dict[str, object] = {
        "schema_version": RECEIPT_SCHEMA,
        "candidate_id": validated_request["candidate_id"],
        "evidence_bundle_sha256": validated_request[
            "evidence_bundle_sha256"
        ],
        "broker_legal_name": validated_request["broker_legal_name"],
        "operating_jurisdiction": validated_request[
            "operating_jurisdiction"
        ],
        "approver_role": validated_request["approver_role"],
        "approver_id": validated_request["approver_id"],
        "reviewer_public_key": normalized_key,
        "reviewer_public_key_sha256": key_hash,
        "request_base64": base64.b64encode(request_bytes).decode("ascii"),
        "request_sha256": _sha256_bytes(request_bytes),
        "attestation_base64": base64.b64encode(attestation_bytes).decode("ascii"),
        "attestation_sha256": _sha256_bytes(attestation_bytes),
        "signature_base64": base64.b64encode(signature_bytes).decode("ascii"),
        "signature_sha256": _sha256_bytes(signature_bytes),
        "signed_at_utc": attestation["reviewed_at_utc"],
        "decision": "APPROVED_REGULATORY_EVIDENCE",
        "cryptographic_verification": True,
        "independence_attested": True,
        "authorization_granted": False,
        "order_capability": "DISABLED",
    }
    return receipt


def _decode(value: object, field: str) -> bytes:
    text = _text(value, field)
    try:
        decoded = base64.b64decode(text, validate=True)
    except ValueError as exc:
        raise RegulatoryEd25519Error(f"{field} invalid") from exc
    if not decoded or len(decoded) > _MAX_EMBEDDED_BYTES:
        raise RegulatoryEd25519Error(f"{field} size invalid")
    return decoded


def verify_receipt(
    evidence: Mapping[str, object],
    receipt: Mapping[str, object],
    *,
    now_provider: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
) -> dict[str, object]:
    request_bytes = _decode(receipt.get("request_base64"), "request_base64")
    attestation_bytes = _decode(
        receipt.get("attestation_base64"), "attestation_base64"
    )
    signature_bytes = _decode(
        receipt.get("signature_base64"), "signature_base64"
    )
    request = _strict_json_bytes(request_bytes, "embedded request")
    expected = verify_attestation(
        request,
        evidence,
        attestation_bytes,
        signature_bytes,
        public_key_text=_text(
            receipt.get("reviewer_public_key"), "reviewer_public_key"
        ),
        now_provider=now_provider,
    )
    if dict(receipt) != expected:
        raise RegulatoryEd25519Error("receipt content mismatch")
    return expected


def assemble_dual_review(
    evidence: Mapping[str, object],
    compliance_receipt: Mapping[str, object],
    legal_receipt: Mapping[str, object],
    *,
    now_provider: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
) -> dict[str, object]:
    binding = _validate_evidence(evidence)
    receipts = [
        verify_receipt(evidence, compliance_receipt, now_provider=now_provider),
        verify_receipt(evidence, legal_receipt, now_provider=now_provider),
    ]
    by_role = {str(receipt["approver_role"]): receipt for receipt in receipts}
    if frozenset(by_role) != ROLES or len(by_role) != 2:
        raise RegulatoryEd25519Error("both distinct approval roles are required")
    if len({str(receipt["approver_id"]) for receipt in receipts}) != 2:
        raise RegulatoryEd25519Error("reviewers must have distinct identities")
    if len({str(receipt["reviewer_public_key_sha256"]) for receipt in receipts}) != 2:
        raise RegulatoryEd25519Error("reviewers must have distinct public keys")
    ordered = [by_role["COMPLIANCE_REVIEW"], by_role["LEGAL_REVIEW"]]
    evidence_copy = deepcopy(dict(evidence))
    observation: dict[str, object] = {
        **evidence_copy,
        "schema_version": OBSERVATION_SCHEMA,
        **binding,
        "regulatory_evidence": evidence_copy,
        "regulatory_approvals": ordered,
        "independent_reviewers_verified": True,
        "verification_status": "VERIFIED_ELIGIBLE_ED25519_DUAL_REVIEW",
        "legal_eligible": True,
        "activation_eligible": False,
        "execution_enabled": False,
        "live_allowed": False,
        "promotion_eligible": False,
        "safe_to_demo_auto_order": False,
        "authorization_granted": False,
        "order_capability": "DISABLED",
    }
    observation["observation_sha256"] = _hash_without(
        observation, "observation_sha256"
    )
    return observation


def verify_dual_observation(
    observation: Mapping[str, object],
    *,
    now_provider: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
) -> dict[str, object]:
    """Reverify a self-contained dual-review observation from raw evidence."""

    if observation.get("schema_version") != OBSERVATION_SCHEMA:
        raise RegulatoryEd25519Error("dual review observation schema invalid")
    embedded = observation.get("regulatory_evidence")
    if not isinstance(embedded, Mapping):
        raise RegulatoryEd25519Error("embedded regulatory evidence missing")
    now = now_provider()
    if now.tzinfo is None or now.utcoffset() is None:
        raise RegulatoryEd25519Error("trusted time must be timezone-aware")
    try:
        from live_runtime.registration_review import (
            RegistrationReviewError,
            _validate_evidence as _validate_legacy_evidence,
        )

        _validate_legacy_evidence(embedded, now=now.astimezone(timezone.utc))
    except (RegistrationReviewError, TypeError, ValueError) as exc:
        raise RegulatoryEd25519Error(
            "embedded regulatory evidence invalid"
        ) from exc
    approvals = observation.get("regulatory_approvals")
    if not isinstance(approvals, list) or len(approvals) != 2:
        raise RegulatoryEd25519Error("two embedded approvals are required")
    by_role = {
        str(approval.get("approver_role") or ""): approval
        for approval in approvals
        if isinstance(approval, Mapping)
    }
    if frozenset(by_role) != ROLES:
        raise RegulatoryEd25519Error("embedded approval roles invalid")
    expected = assemble_dual_review(
        embedded,
        by_role["COMPLIANCE_REVIEW"],
        by_role["LEGAL_REVIEW"],
        now_provider=lambda: now,
    )
    if dict(observation) != expected:
        raise RegulatoryEd25519Error("dual review observation content mismatch")
    return expected


def canonical_bytes(payload: Mapping[str, object]) -> bytes:
    """Return the exact canonical JSON bytes used for reviewer signing."""

    return _canonical_bytes(payload)
