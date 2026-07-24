"""Broker-neutral immutable calendar-plan preparation for phase-3 evidence."""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import json
from pathlib import Path
import re
from typing import Callable, Mapping
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from .benchmark import REQUIRED_SYMBOLS
from .calendar_review import (
    CalendarReviewError,
    verify_prewindow_calendar_review,
    verify_prewindow_calendar_review_shape,
)
from .contracts import canonical_sha256, require_utc
from .secure_files import write_json_exclusive
from .session_calendar import (
    SessionCalendarError,
    validate_weekly_m15_sessions,
)
from .xm_window_plan import verify_candidate_legal_binding


TEMPLATE_SCHEMA_VERSION = "broker-calendar-plan-template-v1"
PLAN_SCHEMA_VERSION = "broker-calendar-plan-v1"
AMENDABLE_TEMPLATE_SCHEMA_VERSION = "broker-calendar-plan-template-v2"
AMENDABLE_PLAN_SCHEMA_VERSION = "broker-calendar-plan-v2"
SIGNED_REVIEW_TEMPLATE_SCHEMA_VERSION = "broker-calendar-plan-template-v3"
SIGNED_REVIEW_PLAN_SCHEMA_VERSION = "broker-calendar-plan-v3"
MAX_LOT = 0.01
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9._-]{2,127}$")
_TEMPLATE_FIELDS = frozenset(
    {
        "schema_version",
        "candidate_id",
        "broker_legal_name",
        "broker_server",
        "operating_jurisdiction",
        "broker_symbols",
        "server_timezone",
        "calendar_version",
        "observation_start_at_utc",
        "blind_until_utc",
        "expected_complete_sessions",
        "validation_profile",
        "execution_enabled",
        "live_allowed",
        "safe_to_demo_auto_order",
        "max_lot",
        "weekly_m15_sessions",
        "special_hours_review",
    }
)
_AMENDABLE_TEMPLATE_FIELDS = frozenset(
    set(_TEMPLATE_FIELDS) | {"calendar_amendment_policy"}
)
_SIGNED_REVIEW_TEMPLATE_FIELDS = frozenset(
    set(_AMENDABLE_TEMPLATE_FIELDS) | {"prewindow_calendar_review"}
)
_PLAN_FIELDS = frozenset(
    (_TEMPLATE_FIELDS - {"schema_version"})
    | {
        "schema_version",
        "captured_at_utc",
        "discovery_receipt_sha256",
        "source_instance_id",
        "plan_template_sha256",
        "regulatory_observation_sha256",
        "plan_payload_sha256",
    }
)
_AMENDABLE_PLAN_FIELDS = frozenset(
    (_AMENDABLE_TEMPLATE_FIELDS - {"schema_version"})
    | {
        "schema_version",
        "captured_at_utc",
        "discovery_receipt_sha256",
        "source_instance_id",
        "plan_template_sha256",
        "regulatory_observation_sha256",
        "plan_payload_sha256",
    }
)
_SIGNED_REVIEW_PLAN_FIELDS = frozenset(
    (_SIGNED_REVIEW_TEMPLATE_FIELDS - {"schema_version"})
    | {
        "schema_version",
        "captured_at_utc",
        "discovery_receipt_sha256",
        "source_instance_id",
        "plan_template_sha256",
        "regulatory_observation_sha256",
        "plan_payload_sha256",
    }
)


class BrokerWindowPlanError(RuntimeError):
    pass


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _mapping(value: object, field: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise BrokerWindowPlanError(f"{field} must be an object")
    return value


def _utc(value: object, field: str, *, m15: bool = False) -> datetime:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        require_utc(field, parsed)
    except (TypeError, ValueError) as exc:
        raise BrokerWindowPlanError(f"{field} must be timezone-aware UTC") from exc
    if m15 and (parsed.minute % 15 or parsed.second or parsed.microsecond):
        raise BrokerWindowPlanError(f"{field} must align to M15")
    return parsed


def _iso(value: datetime) -> str:
    return value.isoformat(timespec="seconds").replace("+00:00", "Z")


def _floor_m15(value: datetime) -> datetime:
    require_utc("now", value)
    return value.replace(
        minute=(value.minute // 15) * 15,
        second=0,
        microsecond=0,
    )


def _candidate(
    config: Mapping[str, object],
    candidate_id: str,
) -> Mapping[str, object]:
    if (
        config.get("execution_enabled") is not False
        or config.get("credentials_allowed") is not False
    ):
        raise BrokerWindowPlanError("candidate configuration safety locks are invalid")
    candidates = config.get("candidates")
    if not isinstance(candidates, list):
        raise BrokerWindowPlanError("candidate configuration is incomplete")
    matches = [
        item
        for item in candidates
        if isinstance(item, Mapping) and item.get("candidate_id") == candidate_id
    ]
    if len(matches) != 1:
        raise BrokerWindowPlanError("candidate must exist exactly once")
    return matches[0]


def verify_broker_calendar_template(template: Mapping[str, object]) -> None:
    schema_version = template.get("schema_version")
    expected_fields = (
        _SIGNED_REVIEW_TEMPLATE_FIELDS
        if schema_version == SIGNED_REVIEW_TEMPLATE_SCHEMA_VERSION
        else (
            _AMENDABLE_TEMPLATE_FIELDS
            if schema_version == AMENDABLE_TEMPLATE_SCHEMA_VERSION
            else _TEMPLATE_FIELDS
        )
    )
    if set(template) != set(expected_fields):
        raise BrokerWindowPlanError("broker calendar template fields are invalid")
    if schema_version not in {
        TEMPLATE_SCHEMA_VERSION,
        AMENDABLE_TEMPLATE_SCHEMA_VERSION,
        SIGNED_REVIEW_TEMPLATE_SCHEMA_VERSION,
    }:
        raise BrokerWindowPlanError("unsupported broker calendar template schema")
    amendment_enabled = schema_version in {
        AMENDABLE_TEMPLATE_SCHEMA_VERSION,
        SIGNED_REVIEW_TEMPLATE_SCHEMA_VERSION,
    }
    if amendment_enabled:
        policy = _mapping(
            template.get("calendar_amendment_policy"),
            "calendar_amendment_policy",
        )
        if set(policy) != {
            "mode",
            "minimum_lead_seconds",
            "completeness_attestation_required",
            "source_document_required",
        }:
            raise BrokerWindowPlanError("calendar amendment policy fields are invalid")
        lead = policy.get("minimum_lead_seconds")
        if (
            policy.get("mode") != "CLOSURE_ONLY_PROSPECTIVE_V1"
            or not isinstance(lead, int)
            or isinstance(lead, bool)
            or lead < 900
            or lead % 900
            or policy.get("completeness_attestation_required") is not True
            or policy.get("source_document_required") is not True
        ):
            raise BrokerWindowPlanError("calendar amendment policy is invalid")
    candidate_id = str(template.get("candidate_id") or "").lower()
    calendar_version = str(template.get("calendar_version") or "").lower()
    if (
        _IDENTIFIER.fullmatch(candidate_id) is None
        or _IDENTIFIER.fullmatch(calendar_version) is None
        or not calendar_version.startswith(candidate_id + "-")
    ):
        raise BrokerWindowPlanError("calendar identity must be candidate-namespaced")
    if template.get("operating_jurisdiction") not in {"JP", "ID"}:
        raise BrokerWindowPlanError("operating jurisdiction is invalid")
    try:
        ZoneInfo(str(template.get("server_timezone") or ""))
    except (ValueError, ZoneInfoNotFoundError) as exc:
        raise BrokerWindowPlanError("server timezone is invalid") from exc
    symbols = template.get("broker_symbols")
    if (
        not isinstance(symbols, Mapping)
        or not symbols
        or not set(symbols) <= set(REQUIRED_SYMBOLS)
        or any(not str(value or "").strip() for value in symbols.values())
    ):
        raise BrokerWindowPlanError("broker symbol map is outside the v1 lane allowlist")
    if type(template.get("expected_complete_sessions")) is not int or int(
        template["expected_complete_sessions"]
    ) < 20:
        raise BrokerWindowPlanError("at least 20 expected sessions are required")
    if (
        template.get("validation_profile") != "DIAGNOSTIC"
        or template.get("execution_enabled") is not False
        or template.get("live_allowed") is not False
        or template.get("safe_to_demo_auto_order") is not False
        or template.get("max_lot") != MAX_LOT
    ):
        raise BrokerWindowPlanError("broker calendar template violates safety locks")
    start = _utc(
        template.get("observation_start_at_utc"),
        "observation_start_at_utc",
        m15=True,
    )
    blind = _utc(template.get("blind_until_utc"), "blind_until_utc", m15=True)
    if start >= blind:
        raise BrokerWindowPlanError("broker calendar window is empty")
    try:
        validate_weekly_m15_sessions(
            template.get("weekly_m15_sessions"),
            required_symbols=tuple(symbols),
        )
    except SessionCalendarError as exc:
        raise BrokerWindowPlanError("weekly session schedule is invalid") from exc
    review = _mapping(template.get("special_hours_review"), "special_hours_review")
    review_attested = review.get("attested")
    if type(review_attested) is not bool or (
        not amendment_enabled and review_attested is not True
    ):
        raise BrokerWindowPlanError("special-hours review is not attested")
    if review_attested is True and not str(
        review.get("source") or ""
    ).startswith("https://"):
        raise BrokerWindowPlanError("special-hours review requires an HTTPS source")
    if "registered_closures" not in review:
        raise BrokerWindowPlanError("special-hours review must register closures")
    if schema_version == SIGNED_REVIEW_TEMPLATE_SCHEMA_VERSION:
        try:
            verify_prewindow_calendar_review_shape(
                _mapping(
                    template.get("prewindow_calendar_review"),
                    "prewindow_calendar_review",
                ),
                template=template,
            )
        except CalendarReviewError as exc:
            raise BrokerWindowPlanError(
                "signed pre-window calendar review is invalid"
            ) from exc


def _verify_bindings(
    template: Mapping[str, object],
    discovery: Mapping[str, object],
    candidate_config: Mapping[str, object],
    *,
    now_provider: Callable[[], datetime],
    regulatory_approval_key_provider: Callable[[str], bytes | None] | None,
    legal_binding_verifier: Callable[..., None],
) -> Mapping[str, object]:
    candidate_id = str(template["candidate_id"])
    if discovery.get("candidate_id") != candidate_id:
        raise BrokerWindowPlanError("discovery candidate binding mismatch")
    candidate = _candidate(candidate_config, candidate_id)
    if candidate.get("read_only_discovery_allowed") is not True:
        raise BrokerWindowPlanError("full read-only discovery gate is not approved")
    account = _mapping(discovery.get("account"), "discovery account")
    if (
        account.get("environment") != "DEMO"
        or candidate.get("environment") != "DEMO"
        or account.get("company") != template.get("broker_legal_name")
        or candidate.get("broker_legal_name_observed")
        != template.get("broker_legal_name")
        or account.get("server") != template.get("broker_server")
        or candidate.get("server") != template.get("broker_server")
    ):
        raise BrokerWindowPlanError("broker account binding mismatch")
    expected_symbols = dict(_mapping(template["broker_symbols"], "broker symbols"))
    if candidate.get("broker_symbols_observed") != expected_symbols:
        raise BrokerWindowPlanError("candidate symbol map binding mismatch")
    discovered_symbols = _mapping(discovery.get("symbols"), "discovery symbols")
    if set(discovered_symbols) != set(expected_symbols):
        raise BrokerWindowPlanError("discovery symbol set does not match the lane")
    for canonical, broker_symbol in expected_symbols.items():
        facts = _mapping(discovered_symbols[canonical], f"{canonical} facts")
        if facts.get("name") != broker_symbol:
            raise BrokerWindowPlanError(f"broker symbol drift: {canonical}")

    regulatory = _mapping(
        candidate.get("regulatory_observation"),
        "candidate regulatory_observation",
    )
    legal_payload = {
        "candidate_id": candidate_id,
        "operating_jurisdiction": template["operating_jurisdiction"],
        "regulatory_observation_sha256": canonical_sha256(regulatory),
    }
    try:
        legal_binding_verifier(
            legal_payload,
            candidate_config,
            now_provider=now_provider,
            regulatory_approval_key_provider=regulatory_approval_key_provider,
        )
    except Exception as exc:
        raise BrokerWindowPlanError("regulatory eligibility binding failed") from exc
    return candidate


def _source_instance_id(
    candidate_id: str,
    receipt_sha256: str,
    calendar_version: str,
) -> str:
    suffix = calendar_version.removeprefix(candidate_id + "-")
    return f"{candidate_id}-{receipt_sha256[:32]}-{suffix}"


def prepare_broker_calendar_plan(
    template: Mapping[str, object],
    discovery: Mapping[str, object],
    candidate_config: Mapping[str, object],
    signing_key: bytes,
    *,
    now_provider: Callable[[], datetime] = utc_now,
    regulatory_approval_key_provider: Callable[[str], bytes | None] | None = None,
    calendar_review_key_provider: Callable[[str], bytes | None] | None = None,
    legal_binding_verifier: Callable[..., None] = verify_candidate_legal_binding,
) -> dict[str, object]:
    verify_broker_calendar_template(template)
    from .evidence_bootstrap import (  # avoids an import cycle
        EvidenceBootstrapError,
        verify_discovery_receipt,
    )

    try:
        verify_discovery_receipt(
            discovery,
            signing_key,
            required_symbols=tuple(template["broker_symbols"]),
        )
    except EvidenceBootstrapError as exc:
        raise BrokerWindowPlanError("discovery receipt verification failed") from exc
    now = now_provider()
    try:
        require_utc("now", now)
    except (TypeError, ValueError) as exc:
        raise BrokerWindowPlanError("plan clock must be timezone-aware UTC") from exc
    if template.get("schema_version") == SIGNED_REVIEW_TEMPLATE_SCHEMA_VERSION:
        try:
            verify_prewindow_calendar_review(
                _mapping(
                    template.get("prewindow_calendar_review"),
                    "prewindow_calendar_review",
                ),
                template=template,
                approval_key_provider=calendar_review_key_provider,
                now_provider=lambda: now,
            )
        except CalendarReviewError as exc:
            raise BrokerWindowPlanError(
                "signed pre-window calendar review verification failed"
            ) from exc
    candidate = _verify_bindings(
        template,
        discovery,
        candidate_config,
        now_provider=now_provider,
        regulatory_approval_key_provider=regulatory_approval_key_provider,
        legal_binding_verifier=legal_binding_verifier,
    )
    captured = _floor_m15(now)
    start = _utc(template["observation_start_at_utc"], "observation start", m15=True)
    blind = _utc(template["blind_until_utc"], "blind until", m15=True)
    discovery_captured = _utc(discovery.get("captured_at_utc"), "discovery capture")
    if discovery_captured > captured or not captured < start < blind:
        raise BrokerWindowPlanError("plan must bind a completed discovery to a future window")

    receipt_hash = str(discovery.get("payload_sha256") or "")
    regulatory_hash = canonical_sha256(
        _mapping(candidate.get("regulatory_observation"), "regulatory observation")
    )
    template_body = deepcopy(dict(template))
    body = {
        **{key: value for key, value in template_body.items() if key != "schema_version"},
        "schema_version": (
            SIGNED_REVIEW_PLAN_SCHEMA_VERSION
            if template.get("schema_version")
            == SIGNED_REVIEW_TEMPLATE_SCHEMA_VERSION
            else (
                AMENDABLE_PLAN_SCHEMA_VERSION
                if template.get("schema_version")
                == AMENDABLE_TEMPLATE_SCHEMA_VERSION
                else PLAN_SCHEMA_VERSION
            )
        ),
        "captured_at_utc": _iso(captured),
        "discovery_receipt_sha256": receipt_hash,
        "source_instance_id": _source_instance_id(
            str(template["candidate_id"]),
            receipt_hash,
            str(template["calendar_version"]),
        ),
        "plan_template_sha256": canonical_sha256(template_body),
        "regulatory_observation_sha256": regulatory_hash,
    }
    return {**body, "plan_payload_sha256": canonical_sha256(body)}


def verify_prepared_broker_calendar_plan(
    payload: Mapping[str, object],
    *,
    template: Mapping[str, object] | None = None,
    calendar_review_key_provider: Callable[[str], bytes | None] | None = None,
    now_provider: Callable[[], datetime] = utc_now,
) -> None:
    schema_version = payload.get("schema_version")
    expected_fields = (
        _SIGNED_REVIEW_PLAN_FIELDS
        if schema_version == SIGNED_REVIEW_PLAN_SCHEMA_VERSION
        else (
            _AMENDABLE_PLAN_FIELDS
            if schema_version == AMENDABLE_PLAN_SCHEMA_VERSION
            else _PLAN_FIELDS
        )
    )
    if set(payload) != set(expected_fields):
        raise BrokerWindowPlanError("prepared broker plan fields are invalid")
    if schema_version not in {
        PLAN_SCHEMA_VERSION,
        AMENDABLE_PLAN_SCHEMA_VERSION,
        SIGNED_REVIEW_PLAN_SCHEMA_VERSION,
    }:
        raise BrokerWindowPlanError("unsupported prepared broker plan schema")
    if schema_version in {
        AMENDABLE_PLAN_SCHEMA_VERSION,
        SIGNED_REVIEW_PLAN_SCHEMA_VERSION,
    }:
        policy = payload.get("calendar_amendment_policy")
        if (
            not isinstance(policy, Mapping)
            or set(policy)
            != {
                "mode",
                "minimum_lead_seconds",
                "completeness_attestation_required",
                "source_document_required",
            }
            or policy.get("mode") != "CLOSURE_ONLY_PROSPECTIVE_V1"
            or not isinstance(policy.get("minimum_lead_seconds"), int)
            or isinstance(policy.get("minimum_lead_seconds"), bool)
            or int(policy["minimum_lead_seconds"]) < 900
            or int(policy["minimum_lead_seconds"]) % 900
            or policy.get("completeness_attestation_required") is not True
            or policy.get("source_document_required") is not True
        ):
            raise BrokerWindowPlanError("prepared calendar amendment policy is invalid")
    body = {key: value for key, value in payload.items() if key != "plan_payload_sha256"}
    if canonical_sha256(body) != payload.get("plan_payload_sha256"):
        raise BrokerWindowPlanError("prepared broker plan hash mismatch")
    if (
        payload.get("validation_profile") != "DIAGNOSTIC"
        or payload.get("execution_enabled") is not False
        or payload.get("live_allowed") is not False
        or payload.get("safe_to_demo_auto_order") is not False
        or payload.get("max_lot") != MAX_LOT
    ):
        raise BrokerWindowPlanError("prepared broker plan violates safety locks")
    for field in (
        "discovery_receipt_sha256",
        "plan_template_sha256",
        "regulatory_observation_sha256",
    ):
        if _SHA256.fullmatch(str(payload.get(field) or "")) is None:
            raise BrokerWindowPlanError(f"prepared broker plan {field} is invalid")
    candidate_id = str(payload.get("candidate_id") or "")
    expected_source = _source_instance_id(
        candidate_id,
        str(payload["discovery_receipt_sha256"]),
        str(payload.get("calendar_version") or ""),
    )
    if payload.get("source_instance_id") != expected_source:
        raise BrokerWindowPlanError("prepared broker plan cohort binding mismatch")
    captured = _utc(payload.get("captured_at_utc"), "captured_at_utc", m15=True)
    start = _utc(payload.get("observation_start_at_utc"), "observation start", m15=True)
    blind = _utc(payload.get("blind_until_utc"), "blind until", m15=True)
    if not captured < start < blind:
        raise BrokerWindowPlanError("prepared broker plan window is invalid")
    if schema_version == SIGNED_REVIEW_PLAN_SCHEMA_VERSION:
        try:
            verify_prewindow_calendar_review(
                _mapping(
                    payload.get("prewindow_calendar_review"),
                    "prewindow_calendar_review",
                ),
                template=payload,
                approval_key_provider=calendar_review_key_provider,
                now_provider=now_provider,
            )
        except CalendarReviewError as exc:
            raise BrokerWindowPlanError(
                "signed pre-window calendar review verification failed"
            ) from exc
    if template is not None:
        verify_broker_calendar_template(template)
        if payload.get("plan_template_sha256") != canonical_sha256(template):
            raise BrokerWindowPlanError("prepared broker plan template hash mismatch")
        for field, value in template.items():
            if field != "schema_version" and payload.get(field) != value:
                raise BrokerWindowPlanError(
                    f"prepared broker plan drifted from template: {field}"
                )


def read_json_object(path: str | Path) -> dict[str, object]:
    source = Path(path)
    if source.is_symlink() or not source.is_file():
        raise BrokerWindowPlanError(f"JSON input must be a regular file: {source}")
    try:
        payload = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise BrokerWindowPlanError(f"invalid JSON input: {source}") from exc
    if not isinstance(payload, dict):
        raise BrokerWindowPlanError(f"JSON input must be an object: {source}")
    return payload


def write_broker_calendar_plan_exclusive(
    path: str | Path,
    payload: Mapping[str, object],
    *,
    calendar_review_key_provider: Callable[[str], bytes | None] | None = None,
    now_provider: Callable[[], datetime] = utc_now,
) -> Path:
    verify_prepared_broker_calendar_plan(
        payload,
        calendar_review_key_provider=calendar_review_key_provider,
        now_provider=now_provider,
    )
    return write_json_exclusive(path, payload)


__all__ = [
    "AMENDABLE_PLAN_SCHEMA_VERSION",
    "AMENDABLE_TEMPLATE_SCHEMA_VERSION",
    "BrokerWindowPlanError",
    "PLAN_SCHEMA_VERSION",
    "SIGNED_REVIEW_PLAN_SCHEMA_VERSION",
    "SIGNED_REVIEW_TEMPLATE_SCHEMA_VERSION",
    "TEMPLATE_SCHEMA_VERSION",
    "prepare_broker_calendar_plan",
    "read_json_object",
    "verify_broker_calendar_template",
    "verify_prepared_broker_calendar_plan",
    "write_broker_calendar_plan_exclusive",
]
