"""Deny-only, independently signed broker eligibility for one LIVE canary.

The existing broker registration observation is diagnostic evidence.  This
module re-verifies that observation and then requires two new, role-scoped
approvals for the exact LIVE server and XAUUSD scope.  It has no broker,
credential-store, network, process, scheduler, or execution capability.
"""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
from pathlib import Path
import re
from typing import Callable, Iterable, Mapping

from .contracts import canonical_json, canonical_sha256, canonicalize, require_utc
from .live_canary_broker_eligibility import LiveCanaryBrokerEligibilityEvidence
from .registration_review import (
    RegistrationReviewError,
    assemble_regulatory_observation,
)
from .secure_files import SecureFileError, write_json_exclusive


UTC = timezone.utc
LIVE_CANARY_BROKER_ELIGIBILITY_REVIEW_BODY_SCHEMA_VERSION = (
    "live-canary-broker-eligibility-review-body-v1"
)
LIVE_CANARY_BROKER_ELIGIBILITY_APPROVAL_SCHEMA_VERSION = (
    "live-canary-broker-eligibility-approval-v1"
)
LIVE_CANARY_BROKER_ELIGIBILITY_REVIEW_SCHEMA_VERSION = (
    "live-canary-broker-eligibility-review-v1"
)
LIVE_CANARY_BROKER_ELIGIBILITY_APPROVAL_ROLES = frozenset(
    {
        "LIVE_CANARY_COMPLIANCE_REVIEW",
        "LIVE_CANARY_LEGAL_REVIEW",
    }
)
LIVE_CANARY_BROKER_ELIGIBILITY_MAX_TTL = timedelta(days=30)

_EXACT_CANDIDATE_ID = "phillip-commodity"
_EXACT_PARENT_BROKER_ID = "phillip"
_EXACT_BROKER_ID = "phillip-jp"
_EXACT_BROKER_LEGAL_NAME = "Phillip Securities Japan, Ltd."
_EXACT_JURISDICTION = "JP"
_EXACT_SYMBOL = "XAUUSD"
_EXACT_REGISTRATION_AUTHORITY = "JAPAN-FSA"
_EXACT_SOURCE_AUTHORITY = "Japan Financial Services Agency"
_EXACT_SOURCE_RESULT = "ENTITY_REGISTERED_FOR_JAPAN_RESIDENTS"
_PENDING_STATUS = "PENDING_INDEPENDENT_LIVE_CANARY_APPROVALS"
_PENDING_DECISION = "LIVE_CANARY_ELIGIBILITY_REVIEW_REQUIRED"
_APPROVAL_DECISION = "APPROVE_FIRST_XAUUSD_LIVE_CANARY_ELIGIBILITY"
_APPROVAL_HMAC_DOMAIN = (
    b"AI_SCALPER_LIVE_CANARY_BROKER_ELIGIBILITY_APPROVAL_V1\x00"
)

_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@+\-]{0,255}$")
_SERVER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._\-]{0,127}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")

_BODY_FIELDS = frozenset(
    {
        "schema_version",
        "candidate_id",
        "broker_id",
        "broker_legal_name",
        "operating_jurisdiction",
        "registration_authority",
        "registration_identifier",
        "demo_server",
        "live_server",
        "symbol",
        "broker_symbol",
        "regulatory_observation_sha256",
        "regulatory_evidence_bundle_sha256",
        "diagnostic_compliance_approval_sha256",
        "diagnostic_legal_approval_sha256",
        "reviewed_at_utc",
        "expires_at_utc",
        "status",
        "decision",
        "live_allowed",
        "execution_authorized",
        "order_capability",
        "content_sha256",
    }
)
_APPROVAL_FIELDS = frozenset(
    {
        "schema_version",
        "review_body_sha256",
        "candidate_id",
        "broker_id",
        "broker_legal_name",
        "operating_jurisdiction",
        "registration_authority",
        "registration_identifier",
        "live_server",
        "symbol",
        "broker_symbol",
        "reviewed_at_utc",
        "expires_at_utc",
        "approver_id",
        "approver_role",
        "decision",
        "key_id",
        "key_fingerprint_sha256",
        "signed_at_utc",
        "live_allowed",
        "execution_authorized",
        "order_capability",
        "signature_hmac_sha256",
    }
)
_REVIEW_FIELDS = frozenset(
    {
        "schema_version",
        "review_body",
        "approvals",
        "eligibility_evidence",
        "assembled_at_utc",
        "legal_compliance_activation_gate_required",
        "live_allowed",
        "execution_authorized",
        "order_capability",
        "content_sha256",
    }
)
_ELIGIBILITY_FIELDS = frozenset(
    LiveCanaryBrokerEligibilityEvidence.__dataclass_fields__
)


class LiveCanaryBrokerEligibilityReviewError(RuntimeError):
    """Raised when broker eligibility review validation fails closed."""


def utc_now() -> datetime:
    return datetime.now(UTC)


def _error(code: str, detail: str) -> LiveCanaryBrokerEligibilityReviewError:
    return LiveCanaryBrokerEligibilityReviewError(f"{code}: {detail}")


def _trusted_now(provider: Callable[[], datetime]) -> datetime:
    if not callable(provider):
        raise _error("LIVE_CANARY_ELIGIBILITY_CLOCK_INVALID", "clock is unavailable")
    try:
        now = provider()
        require_utc("live-canary eligibility clock", now)
    except (TypeError, ValueError) as exc:
        raise _error(
            "LIVE_CANARY_ELIGIBILITY_CLOCK_INVALID",
            "clock must be timezone-aware UTC",
        ) from exc
    return now


def _iso(value: datetime) -> str:
    try:
        require_utc("live-canary eligibility timestamp", value)
    except (TypeError, ValueError) as exc:
        raise _error(
            "LIVE_CANARY_ELIGIBILITY_TIME_INVALID", "timestamp must use UTC"
        ) from exc
    return value.isoformat(timespec="microseconds").replace("+00:00", "Z")


def _utc_text(value: object, field: str) -> datetime:
    if type(value) is not str or not value.endswith("Z"):
        raise _error(
            "LIVE_CANARY_ELIGIBILITY_TIME_INVALID", f"{field} must be canonical UTC"
        )
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        require_utc(field, parsed)
    except (TypeError, ValueError) as exc:
        raise _error(
            "LIVE_CANARY_ELIGIBILITY_TIME_INVALID", f"{field} must be canonical UTC"
        ) from exc
    if value != _iso(parsed):
        raise _error(
            "LIVE_CANARY_ELIGIBILITY_TIME_INVALID", f"{field} is not canonical"
        )
    return parsed


def _identifier(value: object, field: str) -> str:
    if type(value) is not str or _IDENTIFIER_RE.fullmatch(value) is None:
        raise _error(
            "LIVE_CANARY_ELIGIBILITY_IDENTITY_INVALID", f"{field} is invalid"
        )
    return value


def _server(value: object, field: str) -> str:
    if type(value) is not str or _SERVER_RE.fullmatch(value) is None:
        raise _error(
            "LIVE_CANARY_ELIGIBILITY_SCOPE_INVALID", f"{field} is invalid"
        )
    return value


def _sha256(value: object, field: str) -> str:
    if (
        type(value) is not str
        or _SHA256_RE.fullmatch(value) is None
        or value == "0" * 64
    ):
        raise _error(
            "LIVE_CANARY_ELIGIBILITY_HASH_INVALID", f"{field} is invalid"
        )
    return value


def _exact_dict(
    value: object,
    fields: frozenset[str],
    *,
    label: str,
    code: str,
) -> dict[str, object]:
    if type(value) is not dict or set(value) != set(fields):
        raise _error(code, f"{label} fields are invalid")
    return value


def _load_key(
    provider: Callable[[str], bytes | None],
    key_id: str,
    *,
    code: str,
) -> bytes:
    if not callable(provider):
        raise _error(code, "key provider is unavailable")
    try:
        value = provider(key_id)
    except (KeyError, OSError, RuntimeError, TypeError, ValueError) as exc:
        raise _error(code, "required key is unavailable") from exc
    if type(value) is not bytes or len(value) < 32:
        raise _error(code, "required key is invalid")
    return value


def _fingerprint(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _require_exact_values(
    actual: Mapping[str, object],
    expected: Mapping[str, object],
    *,
    code: str,
    detail: str,
) -> None:
    mismatches = [
        field for field, value in expected.items() if actual.get(field) != value
    ]
    if mismatches:
        raise _error(code, f"{detail}: {mismatches[0]}")


def _candidate(
    candidate_config: Mapping[str, object],
) -> Mapping[str, object]:
    if not isinstance(candidate_config, Mapping):
        raise _error(
            "LIVE_CANARY_ELIGIBILITY_SOURCE_INVALID",
            "candidate configuration is invalid",
        )
    candidates = candidate_config.get("candidates")
    if type(candidates) is not list:
        raise _error(
            "LIVE_CANARY_ELIGIBILITY_SOURCE_INVALID",
            "candidate configuration is incomplete",
        )
    matches = [
        item
        for item in candidates
        if type(item) is dict and item.get("candidate_id") == _EXACT_CANDIDATE_ID
    ]
    if len(matches) != 1:
        raise _error(
            "LIVE_CANARY_ELIGIBILITY_SOURCE_INVALID",
            "candidate must exist exactly once",
        )
    candidate = matches[0]
    _require_exact_values(
        candidate,
        {
            "parent_broker_id": _EXACT_PARENT_BROKER_ID,
            "broker_legal_name_observed": _EXACT_BROKER_LEGAL_NAME,
            "environment": "DEMO",
            "binding_scope": "COMMODITY",
        },
        code="LIVE_CANARY_ELIGIBILITY_SOURCE_INVALID",
        detail="candidate identity or scope differs",
    )
    execution_enabled = candidate.get("execution_enabled")
    if execution_enabled is not None and execution_enabled is not False:
        raise _error(
            "LIVE_CANARY_ELIGIBILITY_SOURCE_INVALID",
            "candidate execution safety binding is invalid",
        )
    return candidate


def _diagnostic_approval(
    value: object,
    key_provider: Callable[[str], bytes | None],
) -> tuple[str, Mapping[str, object], str, bytes]:
    if type(value) is not dict:
        raise _error(
            "LIVE_CANARY_ELIGIBILITY_SOURCE_INVALID",
            "diagnostic approval is invalid",
        )
    role = value.get("approver_role")
    if role not in {"COMPLIANCE_REVIEW", "LEGAL_REVIEW"}:
        raise _error(
            "LIVE_CANARY_ELIGIBILITY_SOURCE_INVALID",
            "diagnostic approval role is invalid",
        )
    key_id = _identifier(value.get("key_id"), "diagnostic key_id")
    key = _load_key(
        key_provider,
        key_id,
        code="LIVE_CANARY_ELIGIBILITY_DIAGNOSTIC_KEY_INVALID",
    )
    return str(role), value, key_id, key


def _diagnostic_approval_items(
    observation: Mapping[str, object],
) -> list[object]:
    approvals = observation.get("regulatory_approvals")
    if type(approvals) is not list or len(approvals) != 2:
        raise _error(
            "LIVE_CANARY_ELIGIBILITY_SOURCE_INVALID",
            "diagnostic approvals are incomplete",
        )
    return approvals


def _validate_diagnostic_authority_independence(
    approvals_by_role: Mapping[str, Mapping[str, object]],
    keys: Mapping[str, bytes],
) -> None:
    if set(approvals_by_role) != {"COMPLIANCE_REVIEW", "LEGAL_REVIEW"}:
        raise _error(
            "LIVE_CANARY_ELIGIBILITY_SOURCE_INVALID",
            "diagnostic approval roles must be exact and distinct",
        )
    if len(keys) != 2 or len(set(keys.values())) != 2:
        raise _error(
            "LIVE_CANARY_ELIGIBILITY_DIAGNOSTIC_KEY_INVALID",
            "diagnostic review keys must be distinct",
        )
    reviewers = {
        str(item.get("approver_id") or "")
        for item in approvals_by_role.values()
    }
    if len(reviewers) != 2 or "" in reviewers:
        raise _error(
            "LIVE_CANARY_ELIGIBILITY_SOURCE_INVALID",
            "diagnostic reviewers must be distinct",
        )


def _diagnostic_approval_context(
    observation: Mapping[str, object],
    key_provider: Callable[[str], bytes | None],
) -> tuple[dict[str, Mapping[str, object]], dict[str, bytes]]:
    validated = [
        _diagnostic_approval(item, key_provider)
        for item in _diagnostic_approval_items(observation)
    ]
    by_role = {role: approval for role, approval, _, _ in validated}
    keys = {key_id: key for _, _, key_id, key in validated}
    _validate_diagnostic_authority_independence(by_role, keys)
    return by_role, keys


def _assemble_verified_diagnostic_observation(
    observation: Mapping[str, object],
    candidate_config: Mapping[str, object],
    template: Mapping[str, object],
    *,
    approvals_by_role: Mapping[str, Mapping[str, object]],
    diagnostic_key_provider: Callable[[str], bytes | None],
    now: datetime,
) -> None:
    evidence = {
        key: deepcopy(value)
        for key, value in observation.items()
        if key != "regulatory_approvals"
    }
    try:
        verified = assemble_regulatory_observation(
            evidence,
            [
                approvals_by_role["COMPLIANCE_REVIEW"],
                approvals_by_role["LEGAL_REVIEW"],
            ],
            candidate_config,
            approval_key_provider=diagnostic_key_provider,
            now_provider=lambda: now,
            template=template,
        )
    except (RegistrationReviewError, TypeError, ValueError) as exc:
        raise _error(
            "LIVE_CANARY_ELIGIBILITY_SOURCE_INVALID",
            "signed diagnostic observation did not verify",
        ) from exc
    if canonical_json(verified) != canonical_json(observation):
        raise _error(
            "LIVE_CANARY_ELIGIBILITY_SOURCE_INVALID",
            "diagnostic observation canonical bytes differ",
        )


def _observation_scope(
    observation: Mapping[str, object],
    candidate: Mapping[str, object],
) -> tuple[str, str]:
    expected = {
        "candidate_id": _EXACT_CANDIDATE_ID,
        "broker_legal_name": _EXACT_BROKER_LEGAL_NAME,
        "entity": _EXACT_BROKER_LEGAL_NAME,
        "operating_jurisdiction": _EXACT_JURISDICTION,
        "environment": "DEMO",
        "binding_scope": "COMMODITY",
        "broker_server": candidate.get("server"),
        "decision": "DIAGNOSTIC_EVIDENCE_REGISTRATION_REVIEW_ONLY",
        "legal_eligible": True,
        "execution_enabled": False,
        "live_allowed": False,
        "safe_to_demo_auto_order": False,
        "promotion_eligible": False,
    }
    _require_exact_values(
        observation,
        expected,
        code="LIVE_CANARY_ELIGIBILITY_SOURCE_INVALID",
        detail="diagnostic observation identity, scope, or safety differs",
    )
    broker_symbols = observation.get("broker_symbols")
    candidate_symbols = candidate.get("broker_symbols_observed")
    if type(broker_symbols) is not dict or type(candidate_symbols) is not dict:
        raise _error(
            "LIVE_CANARY_ELIGIBILITY_SOURCE_INVALID",
            "diagnostic symbol mapping is invalid",
        )
    expected_symbols = {_EXACT_SYMBOL: candidate_symbols.get(_EXACT_SYMBOL)}
    if broker_symbols != expected_symbols or not expected_symbols[_EXACT_SYMBOL]:
        raise _error(
            "LIVE_CANARY_ELIGIBILITY_SOURCE_INVALID",
            "diagnostic symbol mapping differs",
        )
    return str(observation["broker_server"]), str(broker_symbols[_EXACT_SYMBOL])


def _fresh_source_verification_time(
    observation: Mapping[str, object], now: datetime
) -> datetime:
    verified_at = _parse_source_utc(
        observation.get("verified_at_utc"), "verified_at_utc"
    )
    age = now - verified_at
    if verified_at > now or age > LIVE_CANARY_BROKER_ELIGIBILITY_MAX_TTL:
        raise _error(
            "LIVE_CANARY_ELIGIBILITY_SOURCE_STALE",
            "diagnostic observation is outside its review lifetime",
        )
    return verified_at


def _reverify_diagnostic_observation(
    observation: Mapping[str, object],
    candidate_config: Mapping[str, object],
    template: Mapping[str, object],
    *,
    diagnostic_key_provider: Callable[[str], bytes | None],
    now: datetime,
) -> dict[str, object]:
    if type(observation) is not dict:
        raise _error(
            "LIVE_CANARY_ELIGIBILITY_SOURCE_INVALID",
            "regulatory observation must be an exact object",
        )
    candidate = _candidate(candidate_config)
    approvals_by_role, diagnostic_keys = _diagnostic_approval_context(
        observation, diagnostic_key_provider
    )
    _assemble_verified_diagnostic_observation(
        observation,
        candidate_config,
        template,
        approvals_by_role=approvals_by_role,
        diagnostic_key_provider=diagnostic_key_provider,
        now=now,
    )
    demo_server, broker_symbol = _observation_scope(observation, candidate)
    verified_at = _fresh_source_verification_time(observation, now)
    return {
        "approvals_by_role": approvals_by_role,
        "diagnostic_keys": diagnostic_keys,
        "verified_at": verified_at,
        "demo_server": demo_server,
        "broker_symbol": broker_symbol,
        "regulatory_observation_sha256": canonical_sha256(observation),
        "regulatory_evidence_bundle_sha256": _sha256(
            observation.get("evidence_bundle_sha256"),
            "evidence_bundle_sha256",
        ),
    }


def _parse_source_utc(value: object, field: str) -> datetime:
    if type(value) is not str or not value.endswith("Z"):
        raise _error(
            "LIVE_CANARY_ELIGIBILITY_SOURCE_INVALID", f"{field} is invalid"
        )
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        require_utc(field, parsed)
    except (TypeError, ValueError) as exc:
        raise _error(
            "LIVE_CANARY_ELIGIBILITY_SOURCE_INVALID", f"{field} is invalid"
        ) from exc
    return parsed


def _registry_source(
    observation: Mapping[str, object],
    *,
    registration_authority: str,
    registration_identifier: str,
) -> Mapping[str, object]:
    sources = observation.get("independent_registry_sources")
    if type(sources) is not list:
        raise _error(
            "LIVE_CANARY_ELIGIBILITY_REGISTRY_INVALID",
            "registry sources are invalid",
        )
    matches = [
        source
        for source in sources
        if type(source) is dict
        and source.get("authority") == _EXACT_SOURCE_AUTHORITY
        and registration_authority == _EXACT_REGISTRATION_AUTHORITY
        and source.get("registry_record_id") == registration_identifier
    ]
    if len(matches) != 1:
        raise _error(
            "LIVE_CANARY_ELIGIBILITY_REGISTRY_INVALID",
            "registration record must match exactly once",
        )
    source = matches[0]
    if (
        source.get("entity") != _EXACT_BROKER_LEGAL_NAME
        or source.get("result") != _EXACT_SOURCE_RESULT
    ):
        raise _error(
            "LIVE_CANARY_ELIGIBILITY_REGISTRY_INVALID",
            "registration source eligibility is invalid",
        )
    return source


def live_canary_broker_eligibility_key_name(
    candidate_id: str,
    approver_role: str,
) -> str:
    if candidate_id != _EXACT_CANDIDATE_ID:
        raise _error(
            "LIVE_CANARY_ELIGIBILITY_IDENTITY_INVALID", "candidate_id is invalid"
        )
    suffix = {
        "LIVE_CANARY_COMPLIANCE_REVIEW": (
            "live-canary-compliance-eligibility-v1"
        ),
        "LIVE_CANARY_LEGAL_REVIEW": "live-canary-legal-eligibility-v1",
    }.get(approver_role)
    if suffix is None:
        raise _error(
            "LIVE_CANARY_ELIGIBILITY_APPROVAL_INVALID",
            "approver_role is invalid",
        )
    result = f"{candidate_id}-{suffix}"
    if len(result) > 128:
        raise _error(
            "LIVE_CANARY_ELIGIBILITY_APPROVAL_INVALID", "key name is too long"
        )
    return result


def _review_window(body: Mapping[str, object]) -> tuple[datetime, datetime]:
    reviewed_at = _utc_text(body.get("reviewed_at_utc"), "reviewed_at_utc")
    expires_at = _utc_text(body.get("expires_at_utc"), "expires_at_utc")
    lifetime = expires_at - reviewed_at
    if lifetime <= timedelta(0) or lifetime > LIVE_CANARY_BROKER_ELIGIBILITY_MAX_TTL:
        raise _error(
            "LIVE_CANARY_ELIGIBILITY_TIME_INVALID", "review window is invalid"
        )
    return reviewed_at, expires_at


def _validate_body_content_hash(body: Mapping[str, object]) -> None:
    content = {key: value for key, value in body.items() if key != "content_sha256"}
    digest = _sha256(body.get("content_sha256"), "review body content_sha256")
    if not hmac.compare_digest(canonical_sha256(content), digest):
        raise _error(
            "LIVE_CANARY_ELIGIBILITY_BODY_INVALID", "review body hash mismatch"
        )


def _validate_body_constants(body: Mapping[str, object]) -> None:
    _require_exact_values(
        body,
        {
            "schema_version": (
                LIVE_CANARY_BROKER_ELIGIBILITY_REVIEW_BODY_SCHEMA_VERSION
            ),
            "candidate_id": _EXACT_CANDIDATE_ID,
            "broker_id": _EXACT_BROKER_ID,
            "broker_legal_name": _EXACT_BROKER_LEGAL_NAME,
            "operating_jurisdiction": _EXACT_JURISDICTION,
            "registration_authority": _EXACT_REGISTRATION_AUTHORITY,
            "symbol": _EXACT_SYMBOL,
            "status": _PENDING_STATUS,
            "decision": _PENDING_DECISION,
            "live_allowed": False,
            "execution_authorized": False,
            "order_capability": "DISABLED",
        },
        code="LIVE_CANARY_ELIGIBILITY_BODY_INVALID",
        detail="review body identity, decision, or safety differs",
    )


def _validate_body_scope_and_hashes(body: Mapping[str, object]) -> None:
    _identifier(body.get("registration_identifier"), "registration_identifier")
    demo_server = _server(body.get("demo_server"), "demo_server")
    live_server = _server(body.get("live_server"), "live_server")
    if demo_server == live_server:
        raise _error(
            "LIVE_CANARY_ELIGIBILITY_SCOPE_INVALID",
            "LIVE server must differ from DEMO server",
        )
    _server(body.get("broker_symbol"), "broker_symbol")
    for field in (
        "regulatory_observation_sha256",
        "regulatory_evidence_bundle_sha256",
        "diagnostic_compliance_approval_sha256",
        "diagnostic_legal_approval_sha256",
    ):
        _sha256(body.get(field), field)


def _validate_body_shape(body: object) -> dict[str, object]:
    result = _exact_dict(
        body,
        _BODY_FIELDS,
        label="review body",
        code="LIVE_CANARY_ELIGIBILITY_BODY_INVALID",
    )
    _validate_body_constants(result)
    _validate_body_content_hash(result)
    _review_window(result)
    _validate_body_scope_and_hashes(result)
    return result


def _source_bound_body_values(
    context: Mapping[str, object],
) -> dict[str, object]:
    approvals = context.get("approvals_by_role")
    if not isinstance(approvals, Mapping):
        raise _error(
            "LIVE_CANARY_ELIGIBILITY_SOURCE_INVALID", "approval context is invalid"
        )
    return {
        "candidate_id": _EXACT_CANDIDATE_ID,
        "broker_id": _EXACT_BROKER_ID,
        "broker_legal_name": _EXACT_BROKER_LEGAL_NAME,
        "operating_jurisdiction": _EXACT_JURISDICTION,
        "registration_authority": _EXACT_REGISTRATION_AUTHORITY,
        "demo_server": context["demo_server"],
        "symbol": _EXACT_SYMBOL,
        "broker_symbol": context["broker_symbol"],
        "regulatory_observation_sha256": context[
            "regulatory_observation_sha256"
        ],
        "regulatory_evidence_bundle_sha256": context[
            "regulatory_evidence_bundle_sha256"
        ],
        "diagnostic_compliance_approval_sha256": canonical_sha256(
            approvals["COMPLIANCE_REVIEW"]
        ),
        "diagnostic_legal_approval_sha256": canonical_sha256(
            approvals["LEGAL_REVIEW"]
        ),
    }


def _validate_source_bounded_window(
    body: Mapping[str, object], context: Mapping[str, object], now: datetime
) -> None:
    reviewed_at, expires_at = _review_window(body)
    source_verified_at = context.get("verified_at")
    if not isinstance(source_verified_at, datetime):
        raise _error(
            "LIVE_CANARY_ELIGIBILITY_SOURCE_INVALID",
            "source verification timestamp is invalid",
        )
    valid = (
        reviewed_at >= source_verified_at
        and reviewed_at <= now < expires_at
        and expires_at
        <= source_verified_at + LIVE_CANARY_BROKER_ELIGIBILITY_MAX_TTL
    )
    if not valid:
        raise _error(
            "LIVE_CANARY_ELIGIBILITY_TIME_INVALID",
            "review is outside the source-bounded validity window",
        )


def _validate_body_source_binding(
    body: dict[str, object],
    observation: Mapping[str, object],
    context: Mapping[str, object],
    *,
    now: datetime,
) -> None:
    _validate_source_bounded_window(body, context, now)
    _require_exact_values(
        body,
        _source_bound_body_values(context),
        code="LIVE_CANARY_ELIGIBILITY_SOURCE_BINDING_MISMATCH",
        detail="review body differs from signed source",
    )
    _registry_source(
        observation,
        registration_authority=str(body["registration_authority"]),
        registration_identifier=str(body["registration_identifier"]),
    )


def _validate_prepare_scope(
    candidate_id: str,
    broker_id: str,
    live_server: str,
    symbol: str,
    registration_authority: str,
    registration_identifier: str,
) -> str:
    if candidate_id != _EXACT_CANDIDATE_ID or broker_id != _EXACT_BROKER_ID:
        raise _error(
            "LIVE_CANARY_ELIGIBILITY_IDENTITY_INVALID",
            "candidate_id or broker_id is invalid",
        )
    if symbol != _EXACT_SYMBOL:
        raise _error(
            "LIVE_CANARY_ELIGIBILITY_SCOPE_INVALID", "symbol must be XAUUSD"
        )
    if registration_authority != _EXACT_REGISTRATION_AUTHORITY:
        raise _error(
            "LIVE_CANARY_ELIGIBILITY_REGISTRY_INVALID",
            "registration authority is invalid",
        )
    _identifier(registration_identifier, "registration_identifier")
    return _server(live_server, "live_server")


def _validate_prepare_expiry(
    expires_at: datetime,
    *,
    now: datetime,
    source_verified_at: object,
) -> None:
    try:
        require_utc("eligibility expires_at", expires_at)
    except (TypeError, ValueError) as exc:
        raise _error(
            "LIVE_CANARY_ELIGIBILITY_TIME_INVALID", "expires_at must use UTC"
        ) from exc
    if not isinstance(source_verified_at, datetime):
        raise _error(
            "LIVE_CANARY_ELIGIBILITY_SOURCE_INVALID", "source time is invalid"
        )
    lifetime = expires_at - now
    if (
        lifetime <= timedelta(0)
        or lifetime > LIVE_CANARY_BROKER_ELIGIBILITY_MAX_TTL
        or expires_at
        > source_verified_at + LIVE_CANARY_BROKER_ELIGIBILITY_MAX_TTL
    ):
        raise _error(
            "LIVE_CANARY_ELIGIBILITY_TIME_INVALID", "review window is invalid"
        )


def _pending_review_body(
    context: Mapping[str, object],
    *,
    registration_identifier: str,
    live_server: str,
    reviewed_at: datetime,
    expires_at: datetime,
) -> dict[str, object]:
    return {
        "schema_version": (
            LIVE_CANARY_BROKER_ELIGIBILITY_REVIEW_BODY_SCHEMA_VERSION
        ),
        **_source_bound_body_values(context),
        "registration_identifier": registration_identifier,
        "live_server": live_server,
        "reviewed_at_utc": _iso(reviewed_at),
        "expires_at_utc": _iso(expires_at),
        "status": _PENDING_STATUS,
        "decision": _PENDING_DECISION,
        "live_allowed": False,
        "execution_authorized": False,
        "order_capability": "DISABLED",
    }


def prepare_live_canary_broker_eligibility_review_body(
    candidate_config: Mapping[str, object],
    template: Mapping[str, object],
    regulatory_observation: Mapping[str, object],
    *,
    candidate_id: str,
    broker_id: str,
    live_server: str,
    symbol: str,
    registration_authority: str,
    registration_identifier: str,
    expires_at: datetime,
    diagnostic_key_provider: Callable[[str], bytes | None],
    now_provider: Callable[[], datetime] = utc_now,
) -> dict[str, object]:
    selected_live_server = _validate_prepare_scope(
        candidate_id,
        broker_id,
        live_server,
        symbol,
        registration_authority,
        registration_identifier,
    )
    now = _trusted_now(now_provider)
    context = _reverify_diagnostic_observation(
        regulatory_observation,
        candidate_config,
        template,
        diagnostic_key_provider=diagnostic_key_provider,
        now=now,
    )
    _registry_source(
        regulatory_observation,
        registration_authority=registration_authority,
        registration_identifier=registration_identifier,
    )
    _validate_prepare_expiry(
        expires_at,
        now=now,
        source_verified_at=context.get("verified_at"),
    )
    demo_server = str(context["demo_server"])
    if selected_live_server == demo_server:
        raise _error(
            "LIVE_CANARY_ELIGIBILITY_SCOPE_INVALID",
            "LIVE server must differ from DEMO server",
        )
    body = _pending_review_body(
        context,
        registration_identifier=registration_identifier,
        live_server=selected_live_server,
        reviewed_at=now,
        expires_at=expires_at,
    )
    result = {**body, "content_sha256": canonical_sha256(body)}
    _validate_body_shape(result)
    return result


def _approval_signing_payload(approval: Mapping[str, object]) -> dict[str, object]:
    return {
        str(key): value
        for key, value in approval.items()
        if key != "signature_hmac_sha256"
    }


def _approval_hmac(key: bytes, approval: Mapping[str, object]) -> str:
    return hmac.new(
        key,
        _APPROVAL_HMAC_DOMAIN
        + canonical_json(_approval_signing_payload(approval)).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def _diagnostic_authorities(
    context: Mapping[str, object],
) -> tuple[set[str], set[str], set[bytes]]:
    approvals = context.get("approvals_by_role")
    keys = context.get("diagnostic_keys")
    if not isinstance(approvals, Mapping) or not isinstance(keys, Mapping):
        raise _error(
            "LIVE_CANARY_ELIGIBILITY_SOURCE_INVALID",
            "diagnostic authority context is invalid",
        )
    return (
        {str(item.get("approver_id")) for item in approvals.values()},
        {str(item.get("key_id")) for item in approvals.values()},
        {bytes(item) for item in keys.values()},
    )


def _validate_live_signer_authority(
    *,
    approver_id: str,
    approver_role: str,
    key_id: str,
    signing_key: bytes,
    diagnostic_context: Mapping[str, object],
) -> str:
    if approver_role not in LIVE_CANARY_BROKER_ELIGIBILITY_APPROVAL_ROLES:
        raise _error(
            "LIVE_CANARY_ELIGIBILITY_APPROVAL_INVALID",
            "approver_role is invalid",
        )
    reviewer = _identifier(approver_id, "approver_id")
    expected_key_id = live_canary_broker_eligibility_key_name(
        _EXACT_CANDIDATE_ID, approver_role
    )
    if key_id != expected_key_id:
        raise _error(
            "LIVE_CANARY_ELIGIBILITY_APPROVAL_INVALID",
            "approval key ID is not role-scoped",
        )
    if type(signing_key) is not bytes or len(signing_key) < 32:
        raise _error(
            "LIVE_CANARY_ELIGIBILITY_APPROVAL_INVALID",
            "approval key is invalid",
        )
    diagnostic_reviewers, diagnostic_key_ids, diagnostic_key_values = (
        _diagnostic_authorities(diagnostic_context)
    )
    if reviewer in diagnostic_reviewers:
        raise _error(
            "LIVE_CANARY_ELIGIBILITY_APPROVAL_INVALID",
            "LIVE reviewer must differ from diagnostic reviewers",
        )
    if key_id in diagnostic_key_ids or signing_key in diagnostic_key_values:
        raise _error(
            "LIVE_CANARY_ELIGIBILITY_APPROVAL_INVALID",
            "LIVE approval key reuses diagnostic authority",
        )
    return reviewer


def _require_time_in_review_window(
    body: Mapping[str, object], observed_at: datetime, *, label: str
) -> None:
    reviewed_at = _utc_text(body["reviewed_at_utc"], "reviewed_at_utc")
    expires_at = _utc_text(body["expires_at_utc"], "expires_at_utc")
    if observed_at < reviewed_at or observed_at >= expires_at:
        raise _error(
            "LIVE_CANARY_ELIGIBILITY_TIME_INVALID",
            f"{label} is outside the review window",
        )


def _approval_payload(
    body: Mapping[str, object],
    *,
    reviewer: str,
    approver_role: str,
    key_id: str,
    signing_key: bytes,
    signed_at: datetime,
) -> dict[str, object]:
    return {
        "schema_version": (
            LIVE_CANARY_BROKER_ELIGIBILITY_APPROVAL_SCHEMA_VERSION
        ),
        "review_body_sha256": body["content_sha256"],
        "candidate_id": body["candidate_id"],
        "broker_id": body["broker_id"],
        "broker_legal_name": body["broker_legal_name"],
        "operating_jurisdiction": body["operating_jurisdiction"],
        "registration_authority": body["registration_authority"],
        "registration_identifier": body["registration_identifier"],
        "live_server": body["live_server"],
        "symbol": body["symbol"],
        "broker_symbol": body["broker_symbol"],
        "reviewed_at_utc": body["reviewed_at_utc"],
        "expires_at_utc": body["expires_at_utc"],
        "approver_id": reviewer,
        "approver_role": approver_role,
        "decision": _APPROVAL_DECISION,
        "key_id": key_id,
        "key_fingerprint_sha256": _fingerprint(signing_key),
        "signed_at_utc": _iso(signed_at),
        "live_allowed": False,
        "execution_authorized": False,
        "order_capability": "DISABLED",
    }


def sign_live_canary_broker_eligibility_approval(
    review_body: Mapping[str, object],
    regulatory_observation: Mapping[str, object],
    candidate_config: Mapping[str, object],
    template: Mapping[str, object],
    *,
    approver_id: str,
    approver_role: str,
    key_id: str,
    signing_key: bytes,
    diagnostic_key_provider: Callable[[str], bytes | None],
    now_provider: Callable[[], datetime] = utc_now,
) -> dict[str, object]:
    body = _validate_body_shape(review_body)
    now = _trusted_now(now_provider)
    context = _reverify_diagnostic_observation(
        regulatory_observation,
        candidate_config,
        template,
        diagnostic_key_provider=diagnostic_key_provider,
        now=now,
    )
    _validate_body_source_binding(
        body, regulatory_observation, context, now=now
    )
    reviewer = _validate_live_signer_authority(
        approver_id=approver_id,
        approver_role=approver_role,
        key_id=key_id,
        signing_key=signing_key,
        diagnostic_context=context,
    )
    _require_time_in_review_window(body, now, label="approval time")
    approval = _approval_payload(
        body,
        reviewer=reviewer,
        approver_role=approver_role,
        key_id=key_id,
        signing_key=signing_key,
        signed_at=now,
    )
    return {
        **approval,
        "signature_hmac_sha256": _approval_hmac(signing_key, approval),
    }


def _approval_expected_bindings(
    body: Mapping[str, object],
) -> dict[str, object]:
    return {
        "review_body_sha256": body["content_sha256"],
        "candidate_id": body["candidate_id"],
        "broker_id": body["broker_id"],
        "broker_legal_name": body["broker_legal_name"],
        "operating_jurisdiction": body["operating_jurisdiction"],
        "registration_authority": body["registration_authority"],
        "registration_identifier": body["registration_identifier"],
        "live_server": body["live_server"],
        "symbol": body["symbol"],
        "broker_symbol": body["broker_symbol"],
        "reviewed_at_utc": body["reviewed_at_utc"],
        "expires_at_utc": body["expires_at_utc"],
        "decision": _APPROVAL_DECISION,
        "live_allowed": False,
        "execution_authorized": False,
        "order_capability": "DISABLED",
    }


def _validate_verified_approval_authority(
    result: Mapping[str, object],
    *,
    role: str,
    live_key_provider: Callable[[str], bytes | None],
    diagnostic_reviewers: set[str],
    diagnostic_key_ids: set[str],
    diagnostic_key_values: set[bytes],
) -> bytes:
    reviewer = _identifier(result.get("approver_id"), "approver_id")
    if reviewer in diagnostic_reviewers:
        raise _error(
            "LIVE_CANARY_ELIGIBILITY_APPROVAL_INVALID",
            "LIVE reviewer reuses diagnostic authority",
        )
    key_id = _identifier(result.get("key_id"), "key_id")
    if key_id != live_canary_broker_eligibility_key_name(
        _EXACT_CANDIDATE_ID, str(role)
    ) or key_id in diagnostic_key_ids:
        raise _error(
            "LIVE_CANARY_ELIGIBILITY_APPROVAL_INVALID",
            "LIVE approval key ID is invalid",
        )
    key = _load_key(
        live_key_provider,
        key_id,
        code="LIVE_CANARY_ELIGIBILITY_APPROVAL_INVALID",
    )
    if key in diagnostic_key_values:
        raise _error(
            "LIVE_CANARY_ELIGIBILITY_APPROVAL_INVALID",
            "LIVE approval key reuses diagnostic key material",
        )
    fingerprint = _sha256(
        result.get("key_fingerprint_sha256"), "key_fingerprint_sha256"
    )
    if not hmac.compare_digest(_fingerprint(key), fingerprint):
        raise _error(
            "LIVE_CANARY_ELIGIBILITY_APPROVAL_INVALID",
            "LIVE approval key fingerprint mismatch",
        )
    return key


def _verify_approval_time_and_signature(
    result: Mapping[str, object],
    body: Mapping[str, object],
    key: bytes,
) -> None:
    signed_at = _utc_text(result.get("signed_at_utc"), "signed_at_utc")
    _require_time_in_review_window(
        body, signed_at, label="LIVE approval time"
    )
    observed_signature = _sha256(
        result.get("signature_hmac_sha256"), "signature_hmac_sha256"
    )
    expected_signature = _approval_hmac(key, result)
    if not hmac.compare_digest(expected_signature, observed_signature):
        raise _error(
            "LIVE_CANARY_ELIGIBILITY_APPROVAL_INVALID",
            "LIVE approval signature mismatch",
        )


def _verify_approval(
    approval: object,
    body: Mapping[str, object],
    *,
    live_key_provider: Callable[[str], bytes | None],
    diagnostic_reviewers: set[str],
    diagnostic_key_ids: set[str],
    diagnostic_key_values: set[bytes],
) -> tuple[dict[str, object], bytes]:
    result = _exact_dict(
        approval,
        _APPROVAL_FIELDS,
        label="LIVE approval",
        code="LIVE_CANARY_ELIGIBILITY_APPROVAL_INVALID",
    )
    if result.get("schema_version") != (
        LIVE_CANARY_BROKER_ELIGIBILITY_APPROVAL_SCHEMA_VERSION
    ):
        raise _error(
            "LIVE_CANARY_ELIGIBILITY_APPROVAL_INVALID",
            "LIVE approval schema is invalid",
        )
    role = result.get("approver_role")
    if role not in LIVE_CANARY_BROKER_ELIGIBILITY_APPROVAL_ROLES:
        raise _error(
            "LIVE_CANARY_ELIGIBILITY_APPROVAL_INVALID",
            "LIVE approval role is invalid",
        )
    _require_exact_values(
        result,
        _approval_expected_bindings(body),
        code="LIVE_CANARY_ELIGIBILITY_APPROVAL_INVALID",
        detail="LIVE approval body or safety binding differs",
    )
    key = _validate_verified_approval_authority(
        result,
        role=str(role),
        live_key_provider=live_key_provider,
        diagnostic_reviewers=diagnostic_reviewers,
        diagnostic_key_ids=diagnostic_key_ids,
        diagnostic_key_values=diagnostic_key_values,
    )
    _verify_approval_time_and_signature(result, body, key)
    return result, key


def _assembly_window(
    body: Mapping[str, object],
    *,
    assembled_at: datetime,
    trusted_now: datetime,
) -> tuple[datetime, datetime]:
    reviewed_at = _utc_text(body["reviewed_at_utc"], "reviewed_at_utc")
    expires_at = _utc_text(body["expires_at_utc"], "expires_at_utc")
    if (
        assembled_at < reviewed_at
        or assembled_at >= expires_at
        or assembled_at > trusted_now
    ):
        raise _error(
            "LIVE_CANARY_ELIGIBILITY_TIME_INVALID",
            "assembly time is outside review window",
        )
    return reviewed_at, expires_at


def _approval_items(
    approvals: Iterable[Mapping[str, object]],
) -> list[Mapping[str, object]]:
    try:
        approval_items = list(approvals)
    except TypeError as exc:
        raise _error(
            "LIVE_CANARY_ELIGIBILITY_APPROVAL_INVALID",
            "LIVE approvals are not iterable",
        ) from exc
    if len(approval_items) != 2:
        raise _error(
            "LIVE_CANARY_ELIGIBILITY_APPROVAL_INVALID",
            "exactly two LIVE approvals are required",
        )
    return approval_items


def _ordered_verified_approvals(
    verified: list[tuple[dict[str, object], bytes]],
) -> list[dict[str, object]]:
    verified.sort(key=lambda item: str(item[0]["approver_role"]))
    roles = {str(item[0]["approver_role"]) for item in verified}
    if roles != set(LIVE_CANARY_BROKER_ELIGIBILITY_APPROVAL_ROLES):
        raise _error(
            "LIVE_CANARY_ELIGIBILITY_APPROVAL_INVALID",
            "LIVE approval roles must be exact and distinct",
        )
    return [item[0] for item in verified]


def _validate_live_authority_independence(
    verified: list[tuple[dict[str, object], bytes]],
    approval_dicts: list[dict[str, object]],
) -> None:
    authority_sets = (
        {str(item["approver_id"]) for item in approval_dicts},
        {str(item["key_id"]) for item in approval_dicts},
        {str(item["key_fingerprint_sha256"]) for item in approval_dicts},
        {item[1] for item in verified},
    )
    if any(len(values) != 2 for values in authority_sets):
        raise _error(
            "LIVE_CANARY_ELIGIBILITY_APPROVAL_INVALID",
            "LIVE approval authorities must be independent",
        )


def _verified_approval_set(
    approval_items: Iterable[Mapping[str, object]],
    body: Mapping[str, object],
    context: Mapping[str, object],
    *,
    live_key_provider: Callable[[str], bytes | None],
) -> list[dict[str, object]]:
    diagnostic_reviewers, diagnostic_key_ids, diagnostic_key_values = (
        _diagnostic_authorities(context)
    )
    verified: list[tuple[dict[str, object], bytes]] = [
        _verify_approval(
            item,
            body,
            live_key_provider=live_key_provider,
            diagnostic_reviewers=diagnostic_reviewers,
            diagnostic_key_ids=diagnostic_key_ids,
            diagnostic_key_values=diagnostic_key_values,
        )
        for item in approval_items
    ]
    approval_dicts = _ordered_verified_approvals(verified)
    _validate_live_authority_independence(verified, approval_dicts)
    return approval_dicts


def _build_eligibility_evidence(
    body: Mapping[str, object],
    approval_dicts: list[dict[str, object]],
    regulatory_observation: Mapping[str, object],
    *,
    reviewed_at: datetime,
    expires_at: datetime,
) -> LiveCanaryBrokerEligibilityEvidence:
    compliance = next(
        item
        for item in approval_dicts
        if item["approver_role"] == "LIVE_CANARY_COMPLIANCE_REVIEW"
    )
    legal = next(
        item
        for item in approval_dicts
        if item["approver_role"] == "LIVE_CANARY_LEGAL_REVIEW"
    )
    try:
        evidence = LiveCanaryBrokerEligibilityEvidence(
            broker_id=str(body["broker_id"]),
            broker_legal_name=str(body["broker_legal_name"]),
            operating_jurisdiction=str(body["operating_jurisdiction"]),
            registration_authority=str(body["registration_authority"]),
            registration_identifier=str(body["registration_identifier"]),
            live_server=str(body["live_server"]),
            symbol=str(body["symbol"]),
            regulatory_evidence_sha256=canonical_sha256(
                regulatory_observation
            ),
            compliance_approval_sha256=canonical_sha256(compliance),
            legal_approval_sha256=canonical_sha256(legal),
            reviewed_at=reviewed_at,
            expires_at=expires_at,
        )
    except (TypeError, ValueError) as exc:
        raise _error(
            "LIVE_CANARY_ELIGIBILITY_EVIDENCE_INVALID",
            "activation eligibility evidence construction failed",
        ) from exc
    return evidence


def _assembled_review_payload(
    body: Mapping[str, object],
    approval_dicts: list[dict[str, object]],
    evidence: LiveCanaryBrokerEligibilityEvidence,
    *,
    assembled_at: datetime,
) -> dict[str, object]:
    return {
        "schema_version": LIVE_CANARY_BROKER_ELIGIBILITY_REVIEW_SCHEMA_VERSION,
        "review_body": deepcopy(body),
        "approvals": deepcopy(approval_dicts),
        "eligibility_evidence": evidence,
        "assembled_at_utc": _iso(assembled_at),
        "legal_compliance_activation_gate_required": True,
        "live_allowed": False,
        "execution_authorized": False,
        "order_capability": "DISABLED",
    }


def _assemble_review(
    review_body: Mapping[str, object],
    approvals: Iterable[Mapping[str, object]],
    regulatory_observation: Mapping[str, object],
    candidate_config: Mapping[str, object],
    template: Mapping[str, object],
    *,
    diagnostic_key_provider: Callable[[str], bytes | None],
    live_key_provider: Callable[[str], bytes | None],
    trusted_now: datetime,
    assembled_at: datetime,
) -> dict[str, object]:
    body = _validate_body_shape(review_body)
    context = _reverify_diagnostic_observation(
        regulatory_observation,
        candidate_config,
        template,
        diagnostic_key_provider=diagnostic_key_provider,
        now=trusted_now,
    )
    _validate_body_source_binding(
        body, regulatory_observation, context, now=trusted_now
    )
    reviewed_at, expires_at = _assembly_window(
        body, assembled_at=assembled_at, trusted_now=trusted_now
    )
    approval_dicts = _verified_approval_set(
        _approval_items(approvals),
        body,
        context,
        live_key_provider=live_key_provider,
    )
    evidence = _build_eligibility_evidence(
        body,
        approval_dicts,
        regulatory_observation,
        reviewed_at=reviewed_at,
        expires_at=expires_at,
    )
    review = _assembled_review_payload(
        body, approval_dicts, evidence, assembled_at=assembled_at
    )
    return {**review, "content_sha256": canonical_sha256(review)}


def assemble_live_canary_broker_eligibility_review(
    review_body: Mapping[str, object],
    approvals: Iterable[Mapping[str, object]],
    regulatory_observation: Mapping[str, object],
    candidate_config: Mapping[str, object],
    template: Mapping[str, object],
    *,
    diagnostic_key_provider: Callable[[str], bytes | None],
    live_key_provider: Callable[[str], bytes | None],
    now_provider: Callable[[], datetime] = utc_now,
) -> dict[str, object]:
    now = _trusted_now(now_provider)
    return _assemble_review(
        review_body,
        approvals,
        regulatory_observation,
        candidate_config,
        template,
        diagnostic_key_provider=diagnostic_key_provider,
        live_key_provider=live_key_provider,
        trusted_now=now,
        assembled_at=now,
    )


def _eligibility_dict(value: object) -> dict[str, object]:
    if type(value) is not dict or set(value) != set(_ELIGIBILITY_FIELDS):
        raise _error(
            "LIVE_CANARY_ELIGIBILITY_REVIEW_INVALID",
            "eligibility evidence fields are invalid",
        )
    return value


def _validate_review_safety_and_hash(
    persisted: Mapping[str, object],
) -> None:
    _require_exact_values(
        persisted,
        {
            "legal_compliance_activation_gate_required": True,
            "live_allowed": False,
            "execution_authorized": False,
            "order_capability": "DISABLED",
        },
        code="LIVE_CANARY_ELIGIBILITY_REVIEW_INVALID",
        detail="review safety boundary is invalid",
    )
    observed_content = _sha256(
        persisted.get("content_sha256"), "review content_sha256"
    )
    content = {
        key: value for key, value in persisted.items() if key != "content_sha256"
    }
    if not hmac.compare_digest(canonical_sha256(content), observed_content):
        raise _error(
            "LIVE_CANARY_ELIGIBILITY_REVIEW_INVALID", "review hash mismatch"
        )


def _validate_review_envelope(
    review: Mapping[str, object],
) -> tuple[
    dict[str, object],
    object,
    list[object],
    dict[str, object],
    datetime,
]:
    persisted = _exact_dict(
        review,
        _REVIEW_FIELDS,
        label="assembled review",
        code="LIVE_CANARY_ELIGIBILITY_REVIEW_INVALID",
    )
    if persisted.get("schema_version") != (
        LIVE_CANARY_BROKER_ELIGIBILITY_REVIEW_SCHEMA_VERSION
    ):
        raise _error(
            "LIVE_CANARY_ELIGIBILITY_REVIEW_INVALID", "review schema is invalid"
        )
    _validate_review_safety_and_hash(persisted)
    approvals = persisted.get("approvals")
    if type(approvals) is not list:
        raise _error(
            "LIVE_CANARY_ELIGIBILITY_REVIEW_INVALID",
            "review approvals are invalid",
        )
    eligibility = _eligibility_dict(persisted.get("eligibility_evidence"))
    assembled_at = _utc_text(
        persisted.get("assembled_at_utc"), "assembled_at_utc"
    )
    return (
        persisted,
        persisted.get("review_body"),
        approvals,
        eligibility,
        assembled_at,
    )


def _verified_reconstructed_evidence(
    persisted: Mapping[str, object],
    eligibility: Mapping[str, object],
    expected: Mapping[str, object],
) -> LiveCanaryBrokerEligibilityEvidence:
    expected_evidence = expected.get("eligibility_evidence")
    if type(expected_evidence) is not LiveCanaryBrokerEligibilityEvidence:
        raise _error(
            "LIVE_CANARY_ELIGIBILITY_EVIDENCE_INVALID",
            "reconstructed evidence type is invalid",
        )
    expected_persisted = {
        **expected,
        "eligibility_evidence": expected_evidence.to_canonical_dict(),
    }
    if (
        canonical_json(eligibility)
        != canonical_json(expected_evidence.to_canonical_dict())
        or canonical_json(persisted) != canonical_json(expected_persisted)
    ):
        raise _error(
            "LIVE_CANARY_ELIGIBILITY_REVIEW_INVALID",
            "persisted review differs from independently reconstructed review",
        )
    return expected_evidence


def verify_live_canary_broker_eligibility_review(
    review: Mapping[str, object],
    regulatory_observation: Mapping[str, object],
    candidate_config: Mapping[str, object],
    template: Mapping[str, object],
    *,
    diagnostic_key_provider: Callable[[str], bytes | None],
    live_key_provider: Callable[[str], bytes | None],
    now_provider: Callable[[], datetime] = utc_now,
) -> LiveCanaryBrokerEligibilityEvidence:
    persisted, body, approvals, eligibility, assembled_at = (
        _validate_review_envelope(review)
    )
    trusted = _trusted_now(now_provider)
    expected = _assemble_review(
        body,
        approvals,
        regulatory_observation,
        candidate_config,
        template,
        diagnostic_key_provider=diagnostic_key_provider,
        live_key_provider=live_key_provider,
        trusted_now=trusted,
        assembled_at=assembled_at,
    )
    return _verified_reconstructed_evidence(persisted, eligibility, expected)


def _reject_constant(_: str) -> None:
    raise _error(
        "LIVE_CANARY_ELIGIBILITY_FILE_INVALID",
        "non-finite JSON values are forbidden",
    )


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise _error(
                "LIVE_CANARY_ELIGIBILITY_FILE_INVALID",
                "duplicate JSON keys are forbidden",
            )
        result[key] = value
    return result


def _load_exact_json(path: str | Path) -> dict[str, object]:
    source = Path(path)
    if source.is_symlink() or not source.is_file():
        raise _error(
            "LIVE_CANARY_ELIGIBILITY_FILE_INVALID",
            "input must be a regular non-symlink file",
        )
    try:
        with source.open("r", encoding="utf-8") as handle:
            value = json.load(
                handle,
                object_pairs_hook=_unique_object,
                parse_constant=_reject_constant,
            )
    except LiveCanaryBrokerEligibilityReviewError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise _error(
            "LIVE_CANARY_ELIGIBILITY_FILE_INVALID", "input JSON is invalid"
        ) from exc
    if type(value) is not dict:
        raise _error(
            "LIVE_CANARY_ELIGIBILITY_FILE_INVALID", "input must be an object"
        )
    return value


def load_live_canary_broker_eligibility_review_body(
    path: str | Path,
) -> dict[str, object]:
    payload = _load_exact_json(path)
    _validate_body_shape(payload)
    return payload


def load_live_canary_broker_eligibility_approval(
    path: str | Path,
) -> dict[str, object]:
    payload = _load_exact_json(path)
    _exact_dict(
        payload,
        _APPROVAL_FIELDS,
        label="LIVE approval",
        code="LIVE_CANARY_ELIGIBILITY_APPROVAL_INVALID",
    )
    if payload.get("schema_version") != (
        LIVE_CANARY_BROKER_ELIGIBILITY_APPROVAL_SCHEMA_VERSION
    ):
        raise _error(
            "LIVE_CANARY_ELIGIBILITY_APPROVAL_INVALID",
            "LIVE approval schema is invalid",
        )
    _sha256(payload.get("signature_hmac_sha256"), "signature_hmac_sha256")
    return payload


def load_live_canary_broker_eligibility_review(
    path: str | Path,
) -> dict[str, object]:
    payload = _load_exact_json(path)
    _exact_dict(
        payload,
        _REVIEW_FIELDS,
        label="assembled review",
        code="LIVE_CANARY_ELIGIBILITY_REVIEW_INVALID",
    )
    if payload.get("schema_version") != (
        LIVE_CANARY_BROKER_ELIGIBILITY_REVIEW_SCHEMA_VERSION
    ):
        raise _error(
            "LIVE_CANARY_ELIGIBILITY_REVIEW_INVALID", "review schema is invalid"
        )
    return payload


def write_live_canary_broker_eligibility_artifact_exclusive(
    path: str | Path,
    payload: Mapping[str, object],
) -> Path:
    try:
        normalized = canonicalize(payload)
        if type(normalized) is not dict:
            raise TypeError("eligibility artifact must be an object")
        return write_json_exclusive(path, normalized)
    except FileExistsError:
        raise
    except (OSError, SecureFileError, TypeError, ValueError) as exc:
        raise _error(
            "LIVE_CANARY_ELIGIBILITY_FILE_INVALID",
            "artifact write failed",
        ) from exc


__all__ = [
    "LIVE_CANARY_BROKER_ELIGIBILITY_APPROVAL_ROLES",
    "LIVE_CANARY_BROKER_ELIGIBILITY_APPROVAL_SCHEMA_VERSION",
    "LIVE_CANARY_BROKER_ELIGIBILITY_REVIEW_BODY_SCHEMA_VERSION",
    "LIVE_CANARY_BROKER_ELIGIBILITY_REVIEW_SCHEMA_VERSION",
    "LiveCanaryBrokerEligibilityReviewError",
    "assemble_live_canary_broker_eligibility_review",
    "live_canary_broker_eligibility_key_name",
    "load_live_canary_broker_eligibility_approval",
    "load_live_canary_broker_eligibility_review",
    "load_live_canary_broker_eligibility_review_body",
    "prepare_live_canary_broker_eligibility_review_body",
    "sign_live_canary_broker_eligibility_approval",
    "verify_live_canary_broker_eligibility_review",
    "write_live_canary_broker_eligibility_artifact_exclusive",
]
