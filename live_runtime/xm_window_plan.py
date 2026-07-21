"""Prepare one immutable XM diagnostic calendar plan from a signed discovery.

The tracked template deliberately contains no discovery receipt hash, account
identity, capture timestamp, or terminal cohort identifier.  Those values are
derived only after the Windows discovery receipt has passed its HMAC and
read-only checks.
"""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
from pathlib import Path
import re
from typing import Callable, Mapping
from urllib.parse import urlsplit

from .account_identity import AccountIdentityError, payload_hmac_sha256
from .benchmark import REQUIRED_SYMBOLS
from .contracts import canonical_sha256, require_utc
from .secure_files import write_json_exclusive


TEMPLATE_SCHEMA_VERSION = "xm-calendar-plan-template-v1"
PLAN_SCHEMA_VERSION = "xm-calendar-plan-v1"
WINDOW_CALENDAR_VERSION = "xm-window-02-v3"
M15 = timedelta(minutes=15)
LIVE_ALLOWED = False
SAFE_TO_DEMO_AUTO_ORDER = False
MAX_LOT = 0.01
MAX_REGULATORY_EVIDENCE_AGE = timedelta(days=30)
REGULATORY_APPROVAL_DOMAIN = b"AI_SCALPER/REGULATORY_APPROVAL/V1"
REGULATORY_APPROVAL_SCHEMA_VERSION = "regulatory-approval-v1"
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_REGULATORY_AUTHORITIES = {
    "JP": {
        "japan financial services agency": frozenset(
            {"fsa.go.jp", "www.fsa.go.jp"}
        ),
    },
    "ID": {
        "bappebti": frozenset(
            {
                "bappebti.go.id",
                "www.bappebti.go.id",
                "ceklegalitas.bappebti.go.id",
            }
        ),
        "badan pengawas perdagangan berjangka komoditi": frozenset(
            {
                "bappebti.go.id",
                "www.bappebti.go.id",
                "ceklegalitas.bappebti.go.id",
            }
        ),
    },
}
_ELIGIBLE_REGISTRY_RESULTS = {
    "JP": frozenset({"ENTITY_REGISTERED_FOR_JAPAN_RESIDENTS"}),
    "ID": frozenset(
        {
            "REGISTERED_INDONESIAN_FUTURES_BROKER",
            "ENTITY_AUTHORIZED_FOR_INDONESIAN_RESIDENTS",
        }
    ),
}
_REQUIRED_APPROVAL_ROLES = frozenset({"COMPLIANCE_REVIEW", "LEGAL_REVIEW"})
_HARD_DENIED_JP_CANDIDATES = frozenset({"xm"})
_HARD_DENIED_JP_ENTITIES = frozenset({"tradexfin limited"})

_DYNAMIC_FIELDS = frozenset({
    "captured_at_utc",
    "discovery_receipt_sha256",
    "source_instance_id",
    "plan_template_sha256",
    "plan_payload_sha256",
    "account",
    "account_identity_sha256",
    "account_identity_scheme",
    "account_identity_key_id",
    "regulatory_observation_sha256",
    "login",
})
_TEMPLATE_FIELDS = frozenset({
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
    "special_hours_review",
})
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


class XMWindowPlanError(RuntimeError):
    pass


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _mapping(value: object, field: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise XMWindowPlanError(f"{field} must be an object")
    return value


def _utc(value: object, field: str, *, m15: bool = False) -> datetime:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        require_utc(field, parsed)
    except (TypeError, ValueError) as exc:
        raise XMWindowPlanError(f"{field} must be timezone-aware UTC") from exc
    if m15 and (parsed.minute % 15 or parsed.second or parsed.microsecond):
        raise XMWindowPlanError(f"{field} must align to M15")
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
    candidate_config: Mapping[str, object],
    candidate_id: str,
) -> Mapping[str, object]:
    if candidate_config.get("execution_enabled") is not False:
        raise XMWindowPlanError("candidate configuration must disable execution")
    required = candidate_config.get("required_symbols")
    if not isinstance(required, list) or set(required) != set(REQUIRED_SYMBOLS):
        raise XMWindowPlanError("candidate configuration symbol set is incomplete")
    candidates = candidate_config.get("candidates")
    if not isinstance(candidates, list):
        raise XMWindowPlanError("candidate configuration is incomplete")
    matches = [
        item
        for item in candidates
        if isinstance(item, Mapping) and item.get("candidate_id") == candidate_id
    ]
    if len(matches) != 1:
        raise XMWindowPlanError("candidate must exist exactly once")
    return matches[0]


def _regulatory_evidence_body(
    observation: Mapping[str, object],
) -> dict[str, object]:
    return {
        str(key): value
        for key, value in observation.items()
        if key not in {"evidence_bundle_sha256", "regulatory_approvals"}
    }


def _approval_body(approval: Mapping[str, object]) -> dict[str, object]:
    return {
        str(key): value
        for key, value in approval.items()
        if key != "signature_hmac_sha256"
    }


def _fresh_regulatory_timestamp(
    value: object,
    field: str,
    *,
    now: datetime,
) -> datetime:
    observed = _utc(value, field)
    if observed > now:
        raise XMWindowPlanError(f"{field} must not be in the future")
    if now - observed > MAX_REGULATORY_EVIDENCE_AGE:
        raise XMWindowPlanError(f"{field} is stale")
    return observed


def _verify_regulatory_sources(
    sources: object,
    *,
    jurisdiction: str,
    broker_legal_name: str,
    verified_at: datetime,
    now: datetime,
) -> None:
    if not isinstance(sources, list) or not sources:
        raise XMWindowPlanError(
            "independent regulatory source evidence is incomplete"
        )
    authority_allowlist = _REGULATORY_AUTHORITIES[jurisdiction]
    eligible_results = _ELIGIBLE_REGISTRY_RESULTS[jurisdiction]
    for index, raw_source in enumerate(sources):
        source = _mapping(raw_source, f"regulatory source {index}")
        authority = str(source.get("authority") or "").strip()
        authority_key = authority.casefold()
        allowed_hosts = authority_allowlist.get(authority_key)
        if allowed_hosts is None:
            raise XMWindowPlanError(
                "regulatory source authority is not allowlisted"
            )
        parsed = urlsplit(str(source.get("url") or ""))
        if (
            parsed.scheme != "https"
            or parsed.username is not None
            or parsed.password is not None
            or parsed.port is not None
            or (parsed.hostname or "").casefold() not in allowed_hosts
            or not parsed.path.startswith("/")
        ):
            raise XMWindowPlanError(
                "regulatory source URL is not an allowlisted authority domain"
            )
        if source.get("entity") != broker_legal_name:
            raise XMWindowPlanError(
                "regulatory source entity binding mismatch"
            )
        if str(source.get("result") or "") not in eligible_results:
            raise XMWindowPlanError(
                "regulatory source result does not prove operating eligibility"
            )
        if not str(source.get("registry_record_id") or "").strip():
            raise XMWindowPlanError(
                "regulatory source registry record ID is missing"
            )
        if _SHA256_RE.fullmatch(
            str(source.get("captured_content_sha256") or "").lower()
        ) is None:
            raise XMWindowPlanError(
                "regulatory source captured-content hash is invalid"
            )
        observed_at = _fresh_regulatory_timestamp(
            source.get("observed_at_utc"),
            f"regulatory source {index} observed_at_utc",
            now=now,
        )
        if observed_at > verified_at:
            raise XMWindowPlanError(
                "regulatory source observation postdates verification"
            )


def _verify_dual_regulatory_approvals(
    observation: Mapping[str, object],
    *,
    candidate_id: str,
    broker_legal_name: str,
    jurisdiction: str,
    verified_at: datetime,
    now: datetime,
    approval_key_provider: Callable[[str], bytes | None] | None,
) -> None:
    evidence_sha256 = str(
        observation.get("evidence_bundle_sha256") or ""
    ).lower()
    if _SHA256_RE.fullmatch(evidence_sha256) is None:
        raise XMWindowPlanError("regulatory evidence bundle hash is invalid")
    if canonical_sha256(_regulatory_evidence_body(observation)) != evidence_sha256:
        raise XMWindowPlanError("regulatory evidence bundle hash mismatch")
    approvals = observation.get("regulatory_approvals")
    if (
        approval_key_provider is None
        or not isinstance(approvals, list)
        or len(approvals) != 2
    ):
        raise XMWindowPlanError(
            "two independent regulatory approvals are required"
        )

    approver_ids: set[str] = set()
    key_ids: set[str] = set()
    key_fingerprints: set[str] = set()
    roles: set[str] = set()
    expected_fields = {
        "schema_version",
        "candidate_id",
        "broker_legal_name",
        "operating_jurisdiction",
        "evidence_bundle_sha256",
        "approver_id",
        "approver_role",
        "key_id",
        "signed_at_utc",
        "signature_hmac_sha256",
    }
    for index, raw_approval in enumerate(approvals):
        approval = _mapping(raw_approval, f"regulatory approval {index}")
        if set(approval) != expected_fields:
            raise XMWindowPlanError("regulatory approval fields are invalid")
        if (
            approval.get("schema_version")
            != REGULATORY_APPROVAL_SCHEMA_VERSION
            or approval.get("candidate_id") != candidate_id
            or approval.get("broker_legal_name") != broker_legal_name
            or approval.get("operating_jurisdiction") != jurisdiction
            or approval.get("evidence_bundle_sha256") != evidence_sha256
        ):
            raise XMWindowPlanError(
                "regulatory approval evidence binding mismatch"
            )
        approver_id = str(approval.get("approver_id") or "").strip()
        key_id = str(approval.get("key_id") or "").strip()
        role = str(approval.get("approver_role") or "").strip().upper()
        if not approver_id or not key_id or role not in _REQUIRED_APPROVAL_ROLES:
            raise XMWindowPlanError("regulatory approval identity is invalid")
        signed_at = _fresh_regulatory_timestamp(
            approval.get("signed_at_utc"),
            f"regulatory approval {index} signed_at_utc",
            now=now,
        )
        if signed_at < verified_at:
            raise XMWindowPlanError(
                "regulatory approval predates source verification"
            )
        try:
            key = approval_key_provider(key_id)
        except Exception as exc:
            raise XMWindowPlanError(
                "regulatory approval key is unavailable"
            ) from exc
        if not isinstance(key, bytes) or len(key) < 32:
            raise XMWindowPlanError(
                "regulatory approval key is unavailable"
            )
        try:
            expected_signature = payload_hmac_sha256(
                _approval_body(approval),
                key,
                domain=REGULATORY_APPROVAL_DOMAIN,
            )
        except AccountIdentityError as exc:
            raise XMWindowPlanError(
                "regulatory approval key is invalid"
            ) from exc
        if not hmac.compare_digest(
            str(approval.get("signature_hmac_sha256") or ""),
            expected_signature,
        ):
            raise XMWindowPlanError(
                "regulatory approval signature is invalid"
            )
        approver_ids.add(approver_id)
        key_ids.add(key_id)
        key_fingerprints.add(hashlib.sha256(key).hexdigest())
        roles.add(role)
    if (
        len(approver_ids) != 2
        or len(key_ids) != 2
        or len(key_fingerprints) != 2
        or roles != _REQUIRED_APPROVAL_ROLES
    ):
        raise XMWindowPlanError(
            "regulatory approvals are not independently controlled"
        )


def _verified_regulatory_observation(
    candidate: Mapping[str, object],
    jurisdiction: object,
    *,
    now: datetime,
    approval_key_provider: Callable[[str], bytes | None] | None,
) -> Mapping[str, object]:
    normalized_jurisdiction = str(jurisdiction or "").upper()
    eligibility_field = {
        "JP": "japan_residency_eligibility",
        "ID": "indonesia_return_eligibility",
    }.get(normalized_jurisdiction)
    if eligibility_field is None:
        raise XMWindowPlanError("unsupported operating jurisdiction")
    observation = _mapping(
        candidate.get("regulatory_observation"),
        "candidate regulatory_observation",
    )
    candidate_id = str(candidate.get("candidate_id") or "").strip().lower()
    broker_legal_name = str(
        candidate.get("broker_legal_name_observed") or ""
    ).strip()
    entity = str(observation.get("entity") or "").strip()
    if (
        normalized_jurisdiction == "JP"
        and (
            candidate_id in _HARD_DENIED_JP_CANDIDATES
            or broker_legal_name.casefold() in _HARD_DENIED_JP_ENTITIES
            or entity.casefold() in _HARD_DENIED_JP_ENTITIES
        )
    ):
        raise XMWindowPlanError(
            "XM/Tradexfin is hard-denied for the Japan operating jurisdiction"
        )
    if not candidate_id or not broker_legal_name or entity != broker_legal_name:
        raise XMWindowPlanError("regulatory observation entity binding mismatch")
    verified_at = _fresh_regulatory_timestamp(
        observation.get("verified_at_utc"),
        "regulatory verified_at_utc",
        now=now,
    )
    eligibility = observation.get(eligibility_field)
    if eligibility == "VERIFIED_INELIGIBLE":
        raise XMWindowPlanError(
            "broker is verified ineligible for the operating jurisdiction"
        )
    if (
        observation.get("broker_claim_observed") is not True
        or observation.get("independent_registry_verification") is not True
        or observation.get("legal_eligible") is not True
        or eligibility != "VERIFIED_ELIGIBLE"
    ):
        raise XMWindowPlanError(
            "independent legal and regulatory eligibility is not verified"
        )
    _verify_regulatory_sources(
        observation.get("independent_registry_sources"),
        jurisdiction=normalized_jurisdiction,
        broker_legal_name=broker_legal_name,
        verified_at=verified_at,
        now=now,
    )
    _verify_dual_regulatory_approvals(
        observation,
        candidate_id=candidate_id,
        broker_legal_name=broker_legal_name,
        jurisdiction=normalized_jurisdiction,
        verified_at=verified_at,
        now=now,
        approval_key_provider=approval_key_provider,
    )
    return observation


def _validate_template(template: Mapping[str, object]) -> None:
    if set(template) != set(_TEMPLATE_FIELDS):
        unexpected = sorted(set(template) - set(_TEMPLATE_FIELDS))
        missing = sorted(set(_TEMPLATE_FIELDS) - set(template))
        raise XMWindowPlanError(
            f"template fields are invalid; unexpected={unexpected}, missing={missing}"
        )
    if _DYNAMIC_FIELDS & set(template):
        raise XMWindowPlanError("template must not contain runtime-derived identity fields")
    pending: list[object] = list(template.values())
    while pending:
        value = pending.pop()
        if isinstance(value, Mapping):
            forbidden = _DYNAMIC_FIELDS & {str(key) for key in value}
            if forbidden:
                raise XMWindowPlanError(
                    "template must not contain discovery or account identity data"
                )
            pending.extend(value.values())
        elif isinstance(value, (list, tuple)):
            pending.extend(value)
    if template.get("schema_version") != TEMPLATE_SCHEMA_VERSION:
        raise XMWindowPlanError("unsupported XM calendar template schema")
    if template.get("calendar_version") != WINDOW_CALENDAR_VERSION:
        raise XMWindowPlanError("template is not the Window 02 v3 calendar")
    if template.get("operating_jurisdiction") not in {"JP", "ID"}:
        raise XMWindowPlanError("template operating jurisdiction is invalid")
    if template.get("validation_profile") != "DIAGNOSTIC":
        raise XMWindowPlanError("Window 02 must remain DIAGNOSTIC")
    if (
        template.get("execution_enabled") is not False
        or template.get("live_allowed") is not False
        or template.get("safe_to_demo_auto_order") is not False
        or template.get("max_lot") != MAX_LOT
    ):
        raise XMWindowPlanError("template violates the read-only safety lock")


def _validate_bindings(
    template: Mapping[str, object],
    discovery: Mapping[str, object],
    candidate_config: Mapping[str, object],
    *,
    now: datetime,
    regulatory_approval_key_provider: Callable[[str], bytes | None] | None,
) -> Mapping[str, object]:
    candidate_id = str(template.get("candidate_id") or "")
    if not candidate_id or discovery.get("candidate_id") != candidate_id:
        raise XMWindowPlanError("candidate binding mismatch")
    candidate = _candidate(candidate_config, candidate_id)
    account = _mapping(discovery.get("account"), "discovery account")
    if account.get("environment") != "DEMO" or candidate.get("environment") != "DEMO":
        raise XMWindowPlanError("Window 02 requires the bound XM demo environment")

    expected_legal_name = template.get("broker_legal_name")
    expected_server = template.get("broker_server")
    if (
        account.get("company") != expected_legal_name
        or candidate.get("broker_legal_name_observed") != expected_legal_name
    ):
        raise XMWindowPlanError("broker legal-name binding mismatch")
    if account.get("server") != expected_server or candidate.get("server") != expected_server:
        raise XMWindowPlanError("broker server binding mismatch")

    symbols = _mapping(template.get("broker_symbols"), "template broker_symbols")
    candidate_symbols = candidate.get("broker_symbols_observed")
    discovery_symbols = _mapping(discovery.get("symbols"), "discovery symbols")
    if (
        set(symbols) != set(REQUIRED_SYMBOLS)
        or not isinstance(candidate_symbols, Mapping)
        or dict(candidate_symbols) != dict(symbols)
        or set(discovery_symbols) != set(REQUIRED_SYMBOLS)
    ):
        raise XMWindowPlanError("broker symbol map binding mismatch")
    for canonical_symbol, broker_symbol in symbols.items():
        facts = _mapping(discovery_symbols[canonical_symbol], f"{canonical_symbol} facts")
        if facts.get("name") != broker_symbol:
            raise XMWindowPlanError(
                f"broker symbol map binding mismatch: {canonical_symbol}"
            )
    _verified_regulatory_observation(
        candidate,
        template.get("operating_jurisdiction"),
        now=now,
        approval_key_provider=regulatory_approval_key_provider,
    )
    return candidate


def _source_instance_id(candidate_id: str, receipt_sha256: str) -> str:
    suffix = WINDOW_CALENDAR_VERSION.removeprefix(f"{candidate_id}-")
    return f"{candidate_id}-{receipt_sha256[:32]}-{suffix}"


def prepare_xm_calendar_plan(
    template: Mapping[str, object],
    discovery: Mapping[str, object],
    candidate_config: Mapping[str, object],
    signing_key: bytes,
    *,
    now_provider: Callable[[], datetime] = utc_now,
    regulatory_approval_key_provider: (
        Callable[[str], bytes | None] | None
    ) = None,
) -> dict[str, object]:
    """Return a content-addressed Window 02 plan without writing it."""

    _validate_template(template)
    # Kept local so evidence_bootstrap can validate prepared plans without a
    # module-import cycle.
    from .evidence_bootstrap import (  # pylint: disable=import-outside-toplevel
        EvidenceBootstrapError,
        verify_discovery_receipt,
    )

    try:
        verify_discovery_receipt(discovery, signing_key)
    except EvidenceBootstrapError as exc:
        raise XMWindowPlanError("discovery receipt verification failed") from exc

    now = now_provider()
    try:
        require_utc("now", now)
    except (TypeError, ValueError) as exc:
        raise XMWindowPlanError("plan preparation clock must be timezone-aware UTC") from exc
    candidate = _validate_bindings(
        template,
        discovery,
        candidate_config,
        now=now,
        regulatory_approval_key_provider=regulatory_approval_key_provider,
    )
    captured = _floor_m15(now)
    start = _utc(
        template.get("observation_start_at_utc"),
        "observation_start_at_utc",
        m15=True,
    )
    blind = _utc(template.get("blind_until_utc"), "blind_until_utc", m15=True)
    discovery_captured = _utc(
        discovery.get("captured_at_utc"),
        "discovery captured_at_utc",
    )
    if discovery_captured > captured:
        raise XMWindowPlanError(
            "wait until the first UTC M15 boundary after discovery capture"
        )
    if not captured < start < blind:
        raise XMWindowPlanError(
            "M15 plan capture must precede the future observation window"
        )

    receipt_sha256 = str(discovery.get("payload_sha256") or "")
    template_body = deepcopy(dict(template))
    plan_body = {
        **{key: value for key, value in template_body.items() if key != "schema_version"},
        "schema_version": PLAN_SCHEMA_VERSION,
        "discovery_receipt_sha256": receipt_sha256,
        "source_instance_id": _source_instance_id(
            str(template["candidate_id"]),
            receipt_sha256,
        ),
        "captured_at_utc": _iso(captured),
        "plan_template_sha256": canonical_sha256(template_body),
        "regulatory_observation_sha256": canonical_sha256(
            _mapping(
                candidate.get("regulatory_observation"),
                "candidate regulatory_observation",
            )
        ),
    }
    return {
        **plan_body,
        "plan_payload_sha256": canonical_sha256(plan_body),
    }


def verify_prepared_xm_calendar_plan(
    payload: Mapping[str, object],
    *,
    template: Mapping[str, object] | None = None,
) -> None:
    if set(payload) != set(_PLAN_FIELDS):
        raise XMWindowPlanError("prepared plan fields are invalid")
    if payload.get("schema_version") != PLAN_SCHEMA_VERSION:
        raise XMWindowPlanError("unsupported prepared plan schema")
    body = {
        key: value
        for key, value in payload.items()
        if key != "plan_payload_sha256"
    }
    if canonical_sha256(body) != payload.get("plan_payload_sha256"):
        raise XMWindowPlanError("prepared plan SHA-256 mismatch")
    if payload.get("calendar_version") != WINDOW_CALENDAR_VERSION:
        raise XMWindowPlanError("prepared plan is not Window 02 v3")
    if (
        payload.get("validation_profile") != "DIAGNOSTIC"
        or payload.get("execution_enabled") is not False
        or payload.get("live_allowed") is not False
        or payload.get("safe_to_demo_auto_order") is not False
        or payload.get("max_lot") != MAX_LOT
    ):
        raise XMWindowPlanError("prepared plan violates the read-only safety lock")
    receipt_sha256 = str(payload.get("discovery_receipt_sha256") or "")
    if _SHA256_RE.fullmatch(receipt_sha256) is None:
        raise XMWindowPlanError("prepared plan discovery receipt hash is invalid")
    if _SHA256_RE.fullmatch(str(payload.get("plan_template_sha256") or "")) is None:
        raise XMWindowPlanError("prepared plan template hash is invalid")
    if _SHA256_RE.fullmatch(
        str(payload.get("regulatory_observation_sha256") or "")
    ) is None:
        raise XMWindowPlanError("prepared plan regulatory hash is invalid")
    expected_source = _source_instance_id(
        str(payload.get("candidate_id") or ""),
        receipt_sha256,
    )
    if payload.get("source_instance_id") != expected_source:
        raise XMWindowPlanError("prepared plan terminal cohort binding mismatch")
    captured = _utc(payload.get("captured_at_utc"), "captured_at_utc", m15=True)
    start = _utc(
        payload.get("observation_start_at_utc"),
        "observation_start_at_utc",
        m15=True,
    )
    blind = _utc(payload.get("blind_until_utc"), "blind_until_utc", m15=True)
    if not captured < start < blind:
        raise XMWindowPlanError("prepared plan does not describe a future window")
    if template is not None:
        _validate_template(template)
        template_body = deepcopy(dict(template))
        if payload.get("plan_template_sha256") != canonical_sha256(template_body):
            raise XMWindowPlanError("prepared plan does not bind the tracked template")
        for field, value in template_body.items():
            if field == "schema_version":
                continue
            if payload.get(field) != value:
                raise XMWindowPlanError(
                    f"prepared plan drifted from tracked template: {field}"
                )


def verify_candidate_legal_binding(
    payload: Mapping[str, object],
    candidate_config: Mapping[str, object],
    *,
    now_provider: Callable[[], datetime] = utc_now,
    regulatory_approval_key_provider: (
        Callable[[str], bytes | None] | None
    ) = None,
) -> None:
    candidate = _candidate(
        candidate_config,
        str(payload.get("candidate_id") or ""),
    )
    observation = _verified_regulatory_observation(
        candidate,
        payload.get("operating_jurisdiction"),
        now=now_provider(),
        approval_key_provider=regulatory_approval_key_provider,
    )
    if canonical_sha256(observation) != payload.get(
        "regulatory_observation_sha256"
    ):
        raise XMWindowPlanError(
            "prepared plan regulatory observation binding mismatch"
        )


def read_json_object(path: str | Path) -> dict[str, object]:
    source = Path(path)
    if source.is_symlink() or not source.is_file():
        raise XMWindowPlanError(f"JSON input must be a regular file: {source}")
    try:
        payload = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise XMWindowPlanError(f"invalid JSON input: {source}") from exc
    if not isinstance(payload, dict):
        raise XMWindowPlanError(f"JSON input must be an object: {source}")
    return payload


def write_xm_calendar_plan_exclusive(
    path: str | Path,
    payload: Mapping[str, object],
) -> Path:
    verify_prepared_xm_calendar_plan(payload)
    return write_json_exclusive(path, payload)


__all__ = [
    "PLAN_SCHEMA_VERSION",
    "REGULATORY_APPROVAL_DOMAIN",
    "REGULATORY_APPROVAL_SCHEMA_VERSION",
    "TEMPLATE_SCHEMA_VERSION",
    "WINDOW_CALENDAR_VERSION",
    "XMWindowPlanError",
    "prepare_xm_calendar_plan",
    "read_json_object",
    "verify_candidate_legal_binding",
    "verify_prepared_xm_calendar_plan",
    "write_xm_calendar_plan_exclusive",
]
