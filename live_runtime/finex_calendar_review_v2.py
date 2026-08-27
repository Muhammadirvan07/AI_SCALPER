"""Request-bound, deny-only FINEX calendar review receipts."""

from __future__ import annotations

from datetime import datetime, timezone
import hmac
import re
from typing import Callable, Mapping

from .account_identity import payload_hmac_sha256
from .contracts import canonical_sha256


REQUEST_SCHEMA_VERSION = "finex-calendar-review-request-v2"
RECEIPT_SCHEMA_VERSION = "finex-calendar-review-receipt-v2"
ASSEMBLED_SCHEMA_VERSION = "finex-prewindow-calendar-review-v2"
CALENDAR_VERSION = "finex-window-01-v2"
KEY_ID = "finex-prewindow-calendar-review-v2"
REVIEWER_ROLE = "CALENDAR_REVIEW"
INDEPENDENCE_REQUIREMENT = (
    "REVIEWER_MUST_NOT_BE_OPERATOR_DEVELOPER_OR_EVIDENCE_COLLECTOR"
)
INDEPENDENCE_STATEMENT = (
    "I attest that I am not the terminal operator, project developer, or evidence "
    "collector for this FINEX calendar review."
)
DECISION = "REVIEWED_INCOMPLETE_PENDING_EMAIL_MONITORING"
SIGNATURE_DOMAIN = b"AI_SCALPER/FINEX_CALENDAR_REVIEW_RECEIPT/V2"

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
        "required_key_id",
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
        "evidence_bundle_sha256",
        "schedule_claim_sha256",
        "reviewer_id",
        "reviewer_role",
        "independence_attested",
        "independence_statement",
        "decision",
        "signed_at_utc",
        "key_id",
        "future_exception_completeness",
        "special_hours_attested",
        "authorization_granted",
        "promotion_eligible",
        "safe_to_demo_auto_order",
        "live_allowed",
        "order_capability",
    }
)
_RECEIPT_FIELDS = _RECEIPT_BODY_FIELDS | {"signature_hmac_sha256"}


class FinexCalendarReviewV2Error(RuntimeError):
    """Raised when a FINEX v2 review artifact cannot be trusted."""


def _hash(value: object, field: str) -> str:
    normalized = str(value or "").strip().lower()
    if not _HASH.fullmatch(normalized):
        raise FinexCalendarReviewV2Error(f"{field} must be a SHA-256 digest")
    return normalized


def _identifier(value: object, field: str) -> str:
    normalized = str(value or "").strip().lower()
    if not _IDENTIFIER.fullmatch(normalized):
        raise FinexCalendarReviewV2Error(f"{field} is invalid")
    return normalized


def _utc_iso(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise FinexCalendarReviewV2Error("review timestamp must be timezone-aware")
    if value.utcoffset().total_seconds() != 0:
        value = value.astimezone(timezone.utc)
    return value.isoformat(timespec="seconds").replace("+00:00", "Z")


def _request_body(request: Mapping[str, object]) -> dict[str, object]:
    return {key: request[key] for key in request if key != "request_sha256"}


def validate_request(request: Mapping[str, object]) -> dict[str, object]:
    if set(request) != set(_REQUEST_FIELDS):
        raise FinexCalendarReviewV2Error("calendar review request fields are invalid")
    if request.get("schema_version") != REQUEST_SCHEMA_VERSION:
        raise FinexCalendarReviewV2Error("unsupported calendar review request")
    if request.get("candidate_id") != "finex":
        raise FinexCalendarReviewV2Error("calendar review candidate must be finex")
    if request.get("calendar_version") != CALENDAR_VERSION:
        raise FinexCalendarReviewV2Error("calendar review version mismatch")
    reviewer_id = _identifier(
        request.get("designated_reviewer_id"), "designated_reviewer_id"
    )
    if request.get("reviewer_independence_attested") is not False:
        raise FinexCalendarReviewV2Error(
            "unsigned request must not claim reviewer independence"
        )
    if request.get("independence_requirement") != INDEPENDENCE_REQUIREMENT:
        raise FinexCalendarReviewV2Error("reviewer independence contract mismatch")
    if request.get("required_reviewer_role") != REVIEWER_ROLE:
        raise FinexCalendarReviewV2Error("reviewer role mismatch")
    if request.get("required_key_id") != KEY_ID:
        raise FinexCalendarReviewV2Error("calendar review key must be v2")
    evidence_hash = _hash(request.get("evidence_bundle_sha256"), "evidence hash")
    schedule_hash = _hash(request.get("schedule_claim_sha256"), "schedule hash")
    checks = request.get("required_checks")
    if (
        not isinstance(checks, list)
        or not checks
        or any(not isinstance(item, str) or not item.strip() for item in checks)
    ):
        raise FinexCalendarReviewV2Error("required checks are invalid")
    sources = request.get("official_sources")
    if not isinstance(sources, list) or not sources:
        raise FinexCalendarReviewV2Error("official source binding is missing")
    if (
        request.get("current_special_hours_attested") is not False
        or request.get("current_future_exception_completeness") is not False
        or request.get("authorization_granted") is not False
        or request.get("promotion_eligible") is not False
        or request.get("safe_to_demo_auto_order") is not False
        or request.get("live_allowed") is not False
        or request.get("order_capability") != "DISABLED"
    ):
        raise FinexCalendarReviewV2Error("request safety locks are invalid")
    request_hash = _hash(request.get("request_sha256"), "request hash")
    if not hmac.compare_digest(request_hash, canonical_sha256(_request_body(request))):
        raise FinexCalendarReviewV2Error("calendar review request hash mismatch")
    return {
        **dict(request),
        "designated_reviewer_id": reviewer_id,
        "evidence_bundle_sha256": evidence_hash,
        "schedule_claim_sha256": schedule_hash,
        "request_sha256": request_hash,
    }


def _validate_evidence_binding(
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
        raise FinexCalendarReviewV2Error("request and evidence binding mismatch")
    if (
        evidence.get("future_exception_completeness") is not False
        or evidence.get("special_hours_attested") is not False
        or evidence.get("execution_enabled") is not False
        or evidence.get("promotion_eligible") is not False
        or evidence.get("safe_to_demo_auto_order") is not False
        or evidence.get("live_allowed") is not False
    ):
        raise FinexCalendarReviewV2Error("evidence safety locks are invalid")


def sign_incomplete_review(
    request: Mapping[str, object],
    evidence: Mapping[str, object],
    *,
    reviewer_id: str,
    key_id: str,
    signing_key: bytes,
    independence_attested: bool,
    now_provider: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
) -> dict[str, object]:
    validated = validate_request(request)
    _validate_evidence_binding(validated, evidence)
    reviewer = _identifier(reviewer_id, "reviewer_id")
    if reviewer != validated["designated_reviewer_id"]:
        raise FinexCalendarReviewV2Error("designated reviewer mismatch")
    if independence_attested is not True:
        raise FinexCalendarReviewV2Error("explicit reviewer independence is required")
    if key_id != KEY_ID:
        raise FinexCalendarReviewV2Error("calendar review signing key must be v2")
    if not isinstance(signing_key, bytes) or len(signing_key) < 32:
        raise FinexCalendarReviewV2Error("calendar review signing key is invalid")
    body: dict[str, object] = {
        "schema_version": RECEIPT_SCHEMA_VERSION,
        "candidate_id": "finex",
        "calendar_version": CALENDAR_VERSION,
        "request_sha256": validated["request_sha256"],
        "evidence_bundle_sha256": validated["evidence_bundle_sha256"],
        "schedule_claim_sha256": validated["schedule_claim_sha256"],
        "reviewer_id": reviewer,
        "reviewer_role": REVIEWER_ROLE,
        "independence_attested": True,
        "independence_statement": INDEPENDENCE_STATEMENT,
        "decision": DECISION,
        "signed_at_utc": _utc_iso(now_provider()),
        "key_id": KEY_ID,
        "future_exception_completeness": False,
        "special_hours_attested": False,
        "authorization_granted": False,
        "promotion_eligible": False,
        "safe_to_demo_auto_order": False,
        "live_allowed": False,
        "order_capability": "DISABLED",
    }
    return {
        **body,
        "signature_hmac_sha256": payload_hmac_sha256(
            body, signing_key, domain=SIGNATURE_DOMAIN
        ),
    }


def verify_incomplete_review(
    request: Mapping[str, object],
    evidence: Mapping[str, object],
    receipt: Mapping[str, object],
    *,
    key_provider: Callable[[str], bytes | None],
) -> dict[str, object]:
    validated = validate_request(request)
    _validate_evidence_binding(validated, evidence)
    if set(receipt) != set(_RECEIPT_FIELDS):
        raise FinexCalendarReviewV2Error("calendar review receipt fields are invalid")
    expected = {
        "schema_version": RECEIPT_SCHEMA_VERSION,
        "candidate_id": "finex",
        "calendar_version": CALENDAR_VERSION,
        "request_sha256": validated["request_sha256"],
        "evidence_bundle_sha256": validated["evidence_bundle_sha256"],
        "schedule_claim_sha256": validated["schedule_claim_sha256"],
        "reviewer_id": validated["designated_reviewer_id"],
        "reviewer_role": REVIEWER_ROLE,
        "independence_attested": True,
        "independence_statement": INDEPENDENCE_STATEMENT,
        "decision": DECISION,
        "key_id": KEY_ID,
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
            raise FinexCalendarReviewV2Error(f"calendar receipt mismatch: {field}")
    signed_at = str(receipt.get("signed_at_utc") or "")
    try:
        parsed = datetime.fromisoformat(signed_at.replace("Z", "+00:00"))
    except ValueError as exc:
        raise FinexCalendarReviewV2Error("receipt timestamp is invalid") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise FinexCalendarReviewV2Error("receipt timestamp must be timezone-aware")
    signature = _hash(receipt.get("signature_hmac_sha256"), "receipt signature")
    key = key_provider(KEY_ID)
    if not isinstance(key, bytes) or len(key) < 32:
        raise FinexCalendarReviewV2Error("calendar review verification key is unavailable")
    body = {field: receipt[field] for field in _RECEIPT_BODY_FIELDS}
    expected_signature = payload_hmac_sha256(body, key, domain=SIGNATURE_DOMAIN)
    if not hmac.compare_digest(signature, expected_signature):
        raise FinexCalendarReviewV2Error("calendar review signature mismatch")
    return dict(receipt)


def assemble_incomplete_review(
    request: Mapping[str, object],
    evidence: Mapping[str, object],
    receipt: Mapping[str, object],
    *,
    key_provider: Callable[[str], bytes | None],
    now_provider: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
) -> dict[str, object]:
    verified = verify_incomplete_review(
        request, evidence, receipt, key_provider=key_provider
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
    "DECISION",
    "FinexCalendarReviewV2Error",
    "KEY_ID",
    "RECEIPT_SCHEMA_VERSION",
    "REQUEST_SCHEMA_VERSION",
    "assemble_incomplete_review",
    "sign_incomplete_review",
    "validate_request",
    "verify_incomplete_review",
]
