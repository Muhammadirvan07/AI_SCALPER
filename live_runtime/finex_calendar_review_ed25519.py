"""Asymmetric, request-bound, deny-only FINEX calendar review receipts."""

from __future__ import annotations

import base64
from datetime import datetime, timezone
import hashlib
import hmac
import json
from pathlib import Path
import re
import shutil
import struct
import subprocess
import tempfile
from typing import Callable, Mapping

from .contracts import canonical_sha256
from .finex_calendar_review_v2 import (
    CALENDAR_VERSION,
    DECISION,
    INDEPENDENCE_REQUIREMENT,
    INDEPENDENCE_STATEMENT,
    REVIEWER_ROLE,
    validate_request as validate_base_request,
)


REQUEST_SCHEMA_VERSION = "finex-calendar-review-request-v3-ed25519"
RECEIPT_SCHEMA_VERSION = "finex-calendar-review-receipt-v3-ed25519"
ASSEMBLED_SCHEMA_VERSION = "finex-prewindow-calendar-review-v3-ed25519"
DETACHED_ATTESTATION_SCHEMA_VERSION = "finex-calendar-review-attestation-v3-ed25519"
DETACHED_VALIDATION_SCHEMA_VERSION = "finex-calendar-review-detached-validation-v1"
SIGNATURE_NAMESPACE = "ai-scalper-finex-calendar-review-v3"
PUBLIC_KEY_ALGORITHM = "ssh-ed25519"

_HASH = re.compile(r"^[0-9a-f]{64}$")
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_REQUEST_FIELDS = frozenset(
    {
        "schema_version",
        "candidate_id",
        "calendar_version",
        "designated_reviewer_id",
        "reviewer_independence_attested",
        "independence_requirement",
        "required_reviewer_role",
        "public_key_algorithm",
        "reviewer_public_key_sha256",
        "signature_namespace",
        "base_request_sha256",
        "evidence_bundle_sha256",
        "schedule_claim_sha256",
        "official_sources",
        "observation_start_at_utc",
        "blind_until_utc",
        "current_special_hours_attested",
        "current_future_exception_completeness",
        "required_checks",
        "authorization_granted",
        "order_capability",
        "promotion_eligible",
        "safe_to_demo_auto_order",
        "live_allowed",
        "request_sha256",
    }
)
_RECEIPT_BODY_FIELDS = frozenset(
    {
        "schema_version",
        "candidate_id",
        "calendar_version",
        "request_sha256",
        "base_request_sha256",
        "evidence_bundle_sha256",
        "schedule_claim_sha256",
        "reviewer_id",
        "reviewer_role",
        "independence_attested",
        "independence_statement",
        "decision",
        "signed_at_utc",
        "public_key_algorithm",
        "reviewer_public_key_sha256",
        "signature_namespace",
        "future_exception_completeness",
        "special_hours_attested",
        "authorization_granted",
        "promotion_eligible",
        "safe_to_demo_auto_order",
        "live_allowed",
        "order_capability",
    }
)
_RECEIPT_FIELDS = _RECEIPT_BODY_FIELDS | {"signature_sshsig"}
_DETACHED_ATTESTATION_FIELDS = frozenset(
    {
        "schema_version",
        "candidate_id",
        "calendar_version",
        "request_sha256",
        "base_request_sha256",
        "evidence_bundle_sha256",
        "schedule_claim_sha256",
        "reviewer_id",
        "reviewer_role",
        "reviewer_public_key_sha256",
        "independence_attested",
        "independence_statement",
        "decision",
        "signature_namespace",
        "future_exception_completeness",
        "special_hours_attested",
        "authorization_granted",
        "promotion_eligible",
        "safe_to_demo_auto_order",
        "live_allowed",
        "order_capability",
    }
)


class FinexCalendarReviewEd25519Error(RuntimeError):
    """Raised when an asymmetric FINEX review artifact cannot be trusted."""


def _hash(value: object, field: str) -> str:
    normalized = str(value or "").strip().lower()
    if not _HASH.fullmatch(normalized):
        raise FinexCalendarReviewEd25519Error(f"{field} must be a SHA-256 digest")
    return normalized


def _identifier(value: object, field: str) -> str:
    normalized = str(value or "").strip().lower()
    if not _IDENTIFIER.fullmatch(normalized):
        raise FinexCalendarReviewEd25519Error(f"{field} is invalid")
    return normalized


def _utc_iso(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise FinexCalendarReviewEd25519Error("review timestamp must be timezone-aware")
    return value.astimezone(timezone.utc).isoformat(timespec="seconds").replace(
        "+00:00", "Z"
    )


def _canonical_bytes(payload: Mapping[str, object]) -> bytes:
    try:
        return json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError) as exc:
        raise FinexCalendarReviewEd25519Error("signing payload is invalid") from exc


def _strict_json_object(payload: bytes) -> dict[str, object]:
    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        value: dict[str, object] = {}
        for key, item in pairs:
            if key in value:
                raise FinexCalendarReviewEd25519Error(
                    "detached attestation contains duplicate fields"
                )
            value[key] = item
        return value

    try:
        decoded = payload.decode("utf-8")
        value = json.loads(decoded, object_pairs_hook=reject_duplicates)
    except FinexCalendarReviewEd25519Error:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise FinexCalendarReviewEd25519Error(
            "detached attestation is not strict UTF-8 JSON"
        ) from exc
    if not isinstance(value, dict):
        raise FinexCalendarReviewEd25519Error(
            "detached attestation must contain one JSON object"
        )
    return value


def _ssh_keygen() -> str:
    executable = shutil.which("ssh-keygen")
    if not executable:
        raise FinexCalendarReviewEd25519Error("OpenSSH ssh-keygen is unavailable")
    return executable


def normalize_public_key(public_key_text: str) -> tuple[str, str]:
    parts = str(public_key_text or "").strip().split()
    if len(parts) < 2 or parts[0] != PUBLIC_KEY_ALGORITHM:
        raise FinexCalendarReviewEd25519Error("reviewer public key must be ssh-ed25519")
    try:
        blob = base64.b64decode(parts[1], validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise FinexCalendarReviewEd25519Error("reviewer public key is malformed") from exc

    def read_field(offset: int) -> tuple[bytes, int]:
        if offset + 4 > len(blob):
            raise FinexCalendarReviewEd25519Error("reviewer public key is truncated")
        length = struct.unpack(">I", blob[offset : offset + 4])[0]
        start = offset + 4
        end = start + length
        if end > len(blob):
            raise FinexCalendarReviewEd25519Error("reviewer public key is truncated")
        return blob[start:end], end

    algorithm, offset = read_field(0)
    key_bytes, offset = read_field(offset)
    if algorithm != b"ssh-ed25519" or len(key_bytes) != 32 or offset != len(blob):
        raise FinexCalendarReviewEd25519Error("reviewer public key encoding is invalid")
    normalized = PUBLIC_KEY_ALGORITHM + " " + parts[1]
    return normalized, hashlib.sha256(blob).hexdigest()


def build_request(
    base_request: Mapping[str, object], public_key_text: str
) -> dict[str, object]:
    base = validate_base_request(base_request)
    _, fingerprint = normalize_public_key(public_key_text)
    body: dict[str, object] = {
        "schema_version": REQUEST_SCHEMA_VERSION,
        "candidate_id": "finex",
        "calendar_version": CALENDAR_VERSION,
        "designated_reviewer_id": base["designated_reviewer_id"],
        "reviewer_independence_attested": False,
        "independence_requirement": INDEPENDENCE_REQUIREMENT,
        "required_reviewer_role": REVIEWER_ROLE,
        "public_key_algorithm": PUBLIC_KEY_ALGORITHM,
        "reviewer_public_key_sha256": fingerprint,
        "signature_namespace": SIGNATURE_NAMESPACE,
        "base_request_sha256": base["request_sha256"],
        "evidence_bundle_sha256": base["evidence_bundle_sha256"],
        "schedule_claim_sha256": base["schedule_claim_sha256"],
        "official_sources": base["official_sources"],
        "observation_start_at_utc": base["observation_start_at_utc"],
        "blind_until_utc": base["blind_until_utc"],
        "current_special_hours_attested": False,
        "current_future_exception_completeness": False,
        "required_checks": [
            *base["required_checks"],
            "VERIFY_REVIEWER_ED25519_PUBLIC_KEY_OUT_OF_BAND",
        ],
        "authorization_granted": False,
        "order_capability": "DISABLED",
        "promotion_eligible": False,
        "safe_to_demo_auto_order": False,
        "live_allowed": False,
    }
    return {**body, "request_sha256": canonical_sha256(body)}


def validate_request(
    request: Mapping[str, object], public_key_text: str
) -> dict[str, object]:
    if set(request) != set(_REQUEST_FIELDS):
        raise FinexCalendarReviewEd25519Error("calendar request fields are invalid")
    if (
        request.get("schema_version") != REQUEST_SCHEMA_VERSION
        or request.get("candidate_id") != "finex"
        or request.get("calendar_version") != CALENDAR_VERSION
        or request.get("independence_requirement") != INDEPENDENCE_REQUIREMENT
        or request.get("required_reviewer_role") != REVIEWER_ROLE
        or request.get("public_key_algorithm") != PUBLIC_KEY_ALGORITHM
        or request.get("signature_namespace") != SIGNATURE_NAMESPACE
    ):
        raise FinexCalendarReviewEd25519Error("calendar request contract mismatch")
    reviewer = _identifier(request.get("designated_reviewer_id"), "reviewer_id")
    _, fingerprint = normalize_public_key(public_key_text)
    if not hmac.compare_digest(
        _hash(request.get("reviewer_public_key_sha256"), "public key fingerprint"),
        fingerprint,
    ):
        raise FinexCalendarReviewEd25519Error("reviewer public key binding mismatch")
    for field in (
        "base_request_sha256",
        "evidence_bundle_sha256",
        "schedule_claim_sha256",
        "request_sha256",
    ):
        _hash(request.get(field), field)
    if (
        request.get("reviewer_independence_attested") is not False
        or request.get("current_special_hours_attested") is not False
        or request.get("current_future_exception_completeness") is not False
        or request.get("authorization_granted") is not False
        or request.get("promotion_eligible") is not False
        or request.get("safe_to_demo_auto_order") is not False
        or request.get("live_allowed") is not False
        or request.get("order_capability") != "DISABLED"
    ):
        raise FinexCalendarReviewEd25519Error("calendar request safety locks are invalid")
    body = {key: request[key] for key in request if key != "request_sha256"}
    if not hmac.compare_digest(
        str(request["request_sha256"]), canonical_sha256(body)
    ):
        raise FinexCalendarReviewEd25519Error("calendar request hash mismatch")
    return {**dict(request), "designated_reviewer_id": reviewer}


def _validate_evidence(
    request: Mapping[str, object], evidence: Mapping[str, object]
) -> None:
    if (
        evidence.get("candidate_id") != "finex"
        or evidence.get("calendar_version") != CALENDAR_VERSION
        or evidence.get("evidence_bundle_sha256")
        != request.get("evidence_bundle_sha256")
        or evidence.get("schedule_claim_sha256")
        != request.get("schedule_claim_sha256")
    ):
        raise FinexCalendarReviewEd25519Error("request and evidence binding mismatch")
    if any(
        evidence.get(field) is not False
        for field in (
            "future_exception_completeness",
            "special_hours_attested",
            "execution_enabled",
            "promotion_eligible",
            "safe_to_demo_auto_order",
            "live_allowed",
        )
    ):
        raise FinexCalendarReviewEd25519Error("evidence safety locks are invalid")


def _derive_public_key(private_key_path: Path) -> str:
    result = subprocess.run(
        [_ssh_keygen(), "-y", "-f", str(private_key_path)],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise FinexCalendarReviewEd25519Error(
            "private key could not be opened by ssh-keygen"
        )
    normalized, _ = normalize_public_key(result.stdout)
    return normalized


def _sign_payload(payload: bytes, private_key_path: Path) -> str:
    with tempfile.TemporaryDirectory(prefix="finex-review-sign-") as directory:
        message_path = Path(directory) / "payload.json"
        message_path.write_bytes(payload)
        result = subprocess.run(
            [
                _ssh_keygen(),
                "-Y",
                "sign",
                "-f",
                str(private_key_path),
                "-n",
                SIGNATURE_NAMESPACE,
                str(message_path),
            ],
            check=False,
        )
        signature_path = Path(str(message_path) + ".sig")
        if result.returncode != 0 or not signature_path.is_file():
            raise FinexCalendarReviewEd25519Error("Ed25519 signing failed")
        signature = signature_path.read_text(encoding="ascii")
    if not signature.startswith("-----BEGIN SSH SIGNATURE-----"):
        raise FinexCalendarReviewEd25519Error("SSHSIG output is invalid")
    return signature


def sign_incomplete_review(
    request: Mapping[str, object],
    evidence: Mapping[str, object],
    *,
    reviewer_id: str,
    public_key_text: str,
    private_key_path: Path,
    independence_attested: bool,
    now_provider: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
) -> dict[str, object]:
    validated = validate_request(request, public_key_text)
    _validate_evidence(validated, evidence)
    reviewer = _identifier(reviewer_id, "reviewer_id")
    if reviewer != validated["designated_reviewer_id"]:
        raise FinexCalendarReviewEd25519Error("designated reviewer mismatch")
    if independence_attested is not True:
        raise FinexCalendarReviewEd25519Error("explicit independence is required")
    private_path = Path(private_key_path).expanduser().resolve(strict=True)
    derived_public = _derive_public_key(private_path)
    _, derived_fingerprint = normalize_public_key(derived_public)
    if not hmac.compare_digest(
        derived_fingerprint, str(validated["reviewer_public_key_sha256"])
    ):
        raise FinexCalendarReviewEd25519Error("private key does not match request")
    body: dict[str, object] = {
        "schema_version": RECEIPT_SCHEMA_VERSION,
        "candidate_id": "finex",
        "calendar_version": CALENDAR_VERSION,
        "request_sha256": validated["request_sha256"],
        "base_request_sha256": validated["base_request_sha256"],
        "evidence_bundle_sha256": validated["evidence_bundle_sha256"],
        "schedule_claim_sha256": validated["schedule_claim_sha256"],
        "reviewer_id": reviewer,
        "reviewer_role": REVIEWER_ROLE,
        "independence_attested": True,
        "independence_statement": INDEPENDENCE_STATEMENT,
        "decision": DECISION,
        "signed_at_utc": _utc_iso(now_provider()),
        "public_key_algorithm": PUBLIC_KEY_ALGORITHM,
        "reviewer_public_key_sha256": validated["reviewer_public_key_sha256"],
        "signature_namespace": SIGNATURE_NAMESPACE,
        "future_exception_completeness": False,
        "special_hours_attested": False,
        "authorization_granted": False,
        "promotion_eligible": False,
        "safe_to_demo_auto_order": False,
        "live_allowed": False,
        "order_capability": "DISABLED",
    }
    return {**body, "signature_sshsig": _sign_payload(_canonical_bytes(body), private_path)}


def verify_incomplete_review(
    request: Mapping[str, object],
    evidence: Mapping[str, object],
    receipt: Mapping[str, object],
    *,
    public_key_text: str,
) -> dict[str, object]:
    validated = validate_request(request, public_key_text)
    _validate_evidence(validated, evidence)
    if set(receipt) != set(_RECEIPT_FIELDS):
        raise FinexCalendarReviewEd25519Error("calendar receipt fields are invalid")
    expected = {
        "schema_version": RECEIPT_SCHEMA_VERSION,
        "candidate_id": "finex",
        "calendar_version": CALENDAR_VERSION,
        "request_sha256": validated["request_sha256"],
        "base_request_sha256": validated["base_request_sha256"],
        "evidence_bundle_sha256": validated["evidence_bundle_sha256"],
        "schedule_claim_sha256": validated["schedule_claim_sha256"],
        "reviewer_id": validated["designated_reviewer_id"],
        "reviewer_role": REVIEWER_ROLE,
        "independence_attested": True,
        "independence_statement": INDEPENDENCE_STATEMENT,
        "decision": DECISION,
        "public_key_algorithm": PUBLIC_KEY_ALGORITHM,
        "reviewer_public_key_sha256": validated["reviewer_public_key_sha256"],
        "signature_namespace": SIGNATURE_NAMESPACE,
        "future_exception_completeness": False,
        "special_hours_attested": False,
        "authorization_granted": False,
        "promotion_eligible": False,
        "safe_to_demo_auto_order": False,
        "live_allowed": False,
        "order_capability": "DISABLED",
    }
    for field, value in expected.items():
        if receipt.get(field) != value:
            raise FinexCalendarReviewEd25519Error(f"calendar receipt mismatch: {field}")
    signed_at = str(receipt.get("signed_at_utc") or "")
    try:
        parsed = datetime.fromisoformat(signed_at.replace("Z", "+00:00"))
    except ValueError as exc:
        raise FinexCalendarReviewEd25519Error("receipt timestamp is invalid") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise FinexCalendarReviewEd25519Error("receipt timestamp must be timezone-aware")
    signature = str(receipt.get("signature_sshsig") or "")
    if not signature.startswith("-----BEGIN SSH SIGNATURE-----"):
        raise FinexCalendarReviewEd25519Error("receipt signature is invalid")
    public_key, _ = normalize_public_key(public_key_text)
    body = {field: receipt[field] for field in _RECEIPT_BODY_FIELDS}
    with tempfile.TemporaryDirectory(prefix="finex-review-verify-") as directory:
        allowed = Path(directory) / "allowed_signers"
        signature_path = Path(directory) / "receipt.sig"
        allowed.write_text(
            str(validated["designated_reviewer_id"]) + " " + public_key + "\n",
            encoding="ascii",
        )
        signature_path.write_text(signature, encoding="ascii")
        result = subprocess.run(
            [
                _ssh_keygen(),
                "-Y",
                "verify",
                "-f",
                str(allowed),
                "-I",
                str(validated["designated_reviewer_id"]),
                "-n",
                SIGNATURE_NAMESPACE,
                "-s",
                str(signature_path),
            ],
            input=_canonical_bytes(body),
            check=False,
            capture_output=True,
        )
    if result.returncode != 0:
        raise FinexCalendarReviewEd25519Error("Ed25519 signature verification failed")
    return dict(receipt)


def verify_detached_incomplete_attestation(
    request: Mapping[str, object],
    evidence: Mapping[str, object],
    attestation_bytes: bytes,
    signature_bytes: bytes,
    *,
    public_key_text: str,
) -> dict[str, object]:
    """Verify an independently transported SSHSIG attestation as deny-only evidence."""

    if not isinstance(attestation_bytes, bytes) or not attestation_bytes:
        raise FinexCalendarReviewEd25519Error("detached attestation bytes are required")
    if not isinstance(signature_bytes, bytes) or not signature_bytes:
        raise FinexCalendarReviewEd25519Error("detached SSHSIG bytes are required")
    validated = validate_request(request, public_key_text)
    _validate_evidence(validated, evidence)
    attestation = _strict_json_object(attestation_bytes)
    if set(attestation) != set(_DETACHED_ATTESTATION_FIELDS):
        raise FinexCalendarReviewEd25519Error(
            "detached attestation fields are invalid"
        )
    expected = {
        "schema_version": DETACHED_ATTESTATION_SCHEMA_VERSION,
        "candidate_id": "finex",
        "calendar_version": CALENDAR_VERSION,
        "request_sha256": validated["request_sha256"],
        "base_request_sha256": validated["base_request_sha256"],
        "evidence_bundle_sha256": validated["evidence_bundle_sha256"],
        "schedule_claim_sha256": validated["schedule_claim_sha256"],
        "reviewer_id": validated["designated_reviewer_id"],
        "reviewer_role": REVIEWER_ROLE,
        "reviewer_public_key_sha256": validated["reviewer_public_key_sha256"],
        "independence_attested": True,
        "independence_statement": INDEPENDENCE_STATEMENT,
        "decision": DECISION,
        "signature_namespace": SIGNATURE_NAMESPACE,
        "future_exception_completeness": False,
        "special_hours_attested": False,
        "authorization_granted": False,
        "promotion_eligible": False,
        "safe_to_demo_auto_order": False,
        "live_allowed": False,
        "order_capability": "DISABLED",
    }
    for field, expected_value in expected.items():
        if attestation.get(field) != expected_value:
            raise FinexCalendarReviewEd25519Error(
                f"detached attestation mismatch: {field}"
            )
    try:
        signature_text = signature_bytes.decode("ascii")
    except UnicodeDecodeError as exc:
        raise FinexCalendarReviewEd25519Error("detached SSHSIG is not ASCII") from exc
    if not signature_text.startswith("-----BEGIN SSH SIGNATURE-----"):
        raise FinexCalendarReviewEd25519Error("detached SSHSIG format is invalid")
    public_key, _ = normalize_public_key(public_key_text)
    with tempfile.TemporaryDirectory(prefix="finex-review-detached-verify-") as directory:
        allowed = Path(directory) / "allowed_signers"
        signature_path = Path(directory) / "attestation.sig"
        allowed.write_text(
            str(validated["designated_reviewer_id"]) + " " + public_key + "\n",
            encoding="ascii",
        )
        signature_path.write_bytes(signature_bytes)
        result = subprocess.run(
            [
                _ssh_keygen(),
                "-Y",
                "verify",
                "-f",
                str(allowed),
                "-I",
                str(validated["designated_reviewer_id"]),
                "-n",
                SIGNATURE_NAMESPACE,
                "-s",
                str(signature_path),
            ],
            input=attestation_bytes,
            check=False,
            capture_output=True,
        )
    if result.returncode != 0:
        raise FinexCalendarReviewEd25519Error(
            "detached Ed25519 signature verification failed"
        )
    body: dict[str, object] = {
        "schema_version": DETACHED_VALIDATION_SCHEMA_VERSION,
        "candidate_id": "finex",
        "calendar_version": CALENDAR_VERSION,
        "request_sha256": validated["request_sha256"],
        "evidence_bundle_sha256": validated["evidence_bundle_sha256"],
        "schedule_claim_sha256": validated["schedule_claim_sha256"],
        "reviewer_id": validated["designated_reviewer_id"],
        "reviewer_public_key_sha256": validated["reviewer_public_key_sha256"],
        "attestation_sha256": hashlib.sha256(attestation_bytes).hexdigest(),
        "signature_sha256": hashlib.sha256(signature_bytes).hexdigest(),
        "signature_namespace": SIGNATURE_NAMESPACE,
        "signature_verified": True,
        "review_outcome": DECISION,
        "blocker_codes": [
            "FUTURE_EXCEPTION_COMPLETENESS_REQUIRED",
            "PREWINDOW_EMAIL_MONITORING_REQUIRED",
            "SPECIAL_HOURS_ATTESTATION_REQUIRED",
        ],
        "authorization_granted": False,
        "promotion_eligible": False,
        "safe_to_demo_auto_order": False,
        "live_allowed": False,
        "order_capability": "DISABLED",
    }
    return {**body, "validation_sha256": canonical_sha256(body)}


def assemble_incomplete_review(
    request: Mapping[str, object],
    evidence: Mapping[str, object],
    receipt: Mapping[str, object],
    *,
    public_key_text: str,
    now_provider: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
) -> dict[str, object]:
    verified = verify_incomplete_review(
        request, evidence, receipt, public_key_text=public_key_text
    )
    return {
        "schema_version": ASSEMBLED_SCHEMA_VERSION,
        "candidate_id": "finex",
        "calendar_version": CALENDAR_VERSION,
        "request_sha256": request["request_sha256"],
        "evidence_bundle_sha256": evidence["evidence_bundle_sha256"],
        "schedule_claim_sha256": evidence["schedule_claim_sha256"],
        "review_receipt_sha256": canonical_sha256(verified),
        "review_receipt": verified,
        "review_outcome": DECISION,
        "assembled_at_utc": _utc_iso(now_provider()),
        "future_exception_completeness": False,
        "special_hours_attested": False,
        "amendment_chain_required": True,
        "registered_email_monitoring_required": True,
        "authorization_granted": False,
        "promotion_eligible": False,
        "safe_to_demo_auto_order": False,
        "live_allowed": False,
        "order_capability": "DISABLED",
    }


__all__ = [
    "ASSEMBLED_SCHEMA_VERSION",
    "DETACHED_ATTESTATION_SCHEMA_VERSION",
    "DETACHED_VALIDATION_SCHEMA_VERSION",
    "FinexCalendarReviewEd25519Error",
    "PUBLIC_KEY_ALGORITHM",
    "RECEIPT_SCHEMA_VERSION",
    "REQUEST_SCHEMA_VERSION",
    "SIGNATURE_NAMESPACE",
    "assemble_incomplete_review",
    "build_request",
    "normalize_public_key",
    "sign_incomplete_review",
    "validate_request",
    "verify_detached_incomplete_attestation",
    "verify_incomplete_review",
]
