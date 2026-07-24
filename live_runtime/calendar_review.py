"""Fail-closed signed pre-window broker calendar review artifacts.

This bounded context proves that one human-reviewed set of official source
bytes supports one regular base schedule as of a pre-window cutoff.  It never
claims that future exceptional hours are complete; prospective amendments and
post-window completeness remain separate controls.
"""

from __future__ import annotations

from copy import deepcopy
from datetime import date, datetime, timedelta, timezone
import hashlib
import hmac
import json
import os
from pathlib import Path, PurePath
import re
import stat
from typing import Callable, Iterable, Mapping
from urllib.parse import urlsplit
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from .account_identity import AccountIdentityError, payload_hmac_sha256
from .contracts import canonical_sha256, require_utc
from .secure_files import SecureFileError, write_json_exclusive
from .session_calendar import SessionCalendarError, validate_weekly_m15_sessions


SOURCE_MANIFEST_SCHEMA_VERSION = "prewindow-calendar-source-manifest-v1"
EVIDENCE_SCHEMA_VERSION = "prewindow-calendar-evidence-v1"
APPROVAL_SCHEMA_VERSION = "prewindow-calendar-approval-v1"
REVIEW_SCHEMA_VERSION = "prewindow-calendar-review-v1"
APPROVAL_DOMAIN = b"AI_SCALPER/PREWINDOW_CALENDAR_REVIEW/V1"
MAX_REVIEW_AGE = timedelta(days=30)
MAX_SOURCE_BYTES = 64 * 1024 * 1024
MAX_LOT = 0.01

_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_MANIFEST_FIELDS = frozenset(
    {"schema_version", "candidate_id", "future_exception_completeness", "sources"}
)
_SOURCE_INPUT_FIELDS = frozenset(
    {
        "source_id",
        "source_role",
        "url",
        "published_on",
        "observed_at_utc",
        "source_file",
    }
)
_SOURCE_EVIDENCE_FIELDS = frozenset(
    (_SOURCE_INPUT_FIELDS - {"source_file"})
    | {"captured_content_sha256", "captured_content_bytes"}
)
_SCHEDULE_FIELDS = (
    "candidate_id",
    "broker_legal_name",
    "broker_server",
    "operating_jurisdiction",
    "broker_symbols",
    "server_timezone",
    "calendar_version",
    "observation_start_at_utc",
    "blind_until_utc",
    "calendar_amendment_policy",
    "weekly_m15_sessions",
    "special_hours_review",
)
_EVIDENCE_FIELDS = frozenset(
    {
        "schema_version",
        *_SCHEDULE_FIELDS,
        "schedule_claim_sha256",
        "official_sources",
        "verified_at_utc",
        "special_hours_attested",
        "future_exception_completeness",
        "execution_enabled",
        "live_allowed",
        "safe_to_demo_auto_order",
        "promotion_eligible",
        "max_lot",
        "evidence_bundle_sha256",
    }
)
_APPROVAL_FIELDS = frozenset(
    {
        "schema_version",
        "candidate_id",
        "evidence_bundle_sha256",
        "schedule_claim_sha256",
        "reviewer_id",
        "reviewer_role",
        "key_id",
        "signed_at_utc",
        "signature_hmac_sha256",
    }
)
_REVIEW_FIELDS = frozenset(
    (_EVIDENCE_FIELDS - {"schema_version"})
    | {
        "schema_version",
        "calendar_review_approval",
        "amendment_chain_required",
        "post_window_completeness_required",
        "review_artifact_sha256",
    }
)
_SOURCE_ROLES = frozenset(
    {
        "REGULAR_FX_SESSION_SCHEDULE",
        "DST_TRANSITION_NOTICE",
        "COMMODITY_XAU_SESSION_SCHEDULE",
        "KNOWN_SPECIAL_HOURS_NOTICE",
    }
)
_REQUIRED_ROLES = {
    "phillip-fx": frozenset(
        {"REGULAR_FX_SESSION_SCHEDULE", "DST_TRANSITION_NOTICE"}
    ),
    "phillip-commodity": frozenset({"COMMODITY_XAU_SESSION_SCHEDULE"}),
}


class CalendarReviewError(RuntimeError):
    """Raised when calendar review evidence cannot be trusted."""


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _reject_constant(_: str) -> None:
    raise CalendarReviewError("non-finite JSON values are not allowed")


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise CalendarReviewError("duplicate JSON keys are not allowed")
        result[key] = value
    return result


def _strict_json_object(path: str | Path) -> dict[str, object]:
    source = Path(path)
    if source.is_symlink() or not source.is_file():
        raise CalendarReviewError("calendar review input must be a regular file")
    try:
        with source.open("r", encoding="utf-8") as handle:
            payload = json.load(
                handle,
                object_pairs_hook=_unique_object,
                parse_constant=_reject_constant,
            )
    except CalendarReviewError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise CalendarReviewError("calendar review input is invalid JSON") from exc
    if not isinstance(payload, dict):
        raise CalendarReviewError("calendar review input must be a JSON object")
    return payload


def load_calendar_review_artifact(
    path: str | Path,
    *,
    expected_fields: Iterable[str],
) -> dict[str, object]:
    payload = _strict_json_object(path)
    if set(payload) != {str(field) for field in expected_fields}:
        raise CalendarReviewError("calendar review artifact fields are invalid")
    return payload


def load_calendar_source_manifest(path: str | Path) -> dict[str, object]:
    payload = load_calendar_review_artifact(path, expected_fields=_MANIFEST_FIELDS)
    _validate_manifest_shape(payload)
    return payload


def load_calendar_review_evidence(path: str | Path) -> dict[str, object]:
    payload = load_calendar_review_artifact(path, expected_fields=_EVIDENCE_FIELDS)
    if payload.get("schema_version") != EVIDENCE_SCHEMA_VERSION:
        raise CalendarReviewError("unsupported calendar review evidence schema")
    return payload


def load_calendar_review_approval(path: str | Path) -> dict[str, object]:
    payload = load_calendar_review_artifact(path, expected_fields=_APPROVAL_FIELDS)
    if payload.get("schema_version") != APPROVAL_SCHEMA_VERSION:
        raise CalendarReviewError("unsupported calendar review approval schema")
    return payload


def load_prewindow_calendar_review(path: str | Path) -> dict[str, object]:
    payload = load_calendar_review_artifact(path, expected_fields=_REVIEW_FIELDS)
    if payload.get("schema_version") != REVIEW_SCHEMA_VERSION:
        raise CalendarReviewError("unsupported pre-window calendar review schema")
    return payload


def _identifier(value: object, field: str, *, lower: bool = False) -> str:
    normalized = str(value or "").strip()
    if _IDENTIFIER.fullmatch(normalized) is None:
        raise CalendarReviewError(f"{field} is invalid")
    return normalized.lower() if lower else normalized


def _mapping(value: object, field: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise CalendarReviewError(f"{field} must be an object")
    return value


def _utc(value: object, field: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        require_utc(field, parsed)
    except (TypeError, ValueError) as exc:
        raise CalendarReviewError(f"{field} must be timezone-aware UTC") from exc
    return parsed


def _trusted_now(now_provider: Callable[[], datetime]) -> datetime:
    try:
        now = now_provider()
        require_utc("calendar review clock", now)
    except (TypeError, ValueError) as exc:
        raise CalendarReviewError(
            "calendar review clock must be timezone-aware UTC"
        ) from exc
    return now


def _iso(value: datetime) -> str:
    return value.isoformat(timespec="seconds").replace("+00:00", "Z")


def _fresh_before_start(
    value: object,
    field: str,
    *,
    now: datetime,
    observation_start: datetime,
) -> datetime:
    observed = _utc(value, field)
    if observed > now:
        raise CalendarReviewError(f"{field} must not be in the future")
    if now - observed > MAX_REVIEW_AGE:
        raise CalendarReviewError(f"{field} is stale")
    if observed >= observation_start or now >= observation_start:
        raise CalendarReviewError("calendar review must complete before observation start")
    return observed


def calendar_review_key_name(candidate_id: str) -> str:
    candidate = _identifier(candidate_id, "candidate_id", lower=True)
    key_name = f"{candidate}-prewindow-calendar-review-v1"
    if len(key_name) > 128:
        raise CalendarReviewError("derived calendar review key name is too long")
    return key_name


def _validate_manifest_shape(payload: Mapping[str, object]) -> None:
    if set(payload) != set(_MANIFEST_FIELDS):
        raise CalendarReviewError("calendar source manifest fields are invalid")
    if payload.get("schema_version") != SOURCE_MANIFEST_SCHEMA_VERSION:
        raise CalendarReviewError("unsupported calendar source manifest")
    candidate_id = _identifier(payload.get("candidate_id"), "candidate_id", lower=True)
    if candidate_id not in _REQUIRED_ROLES:
        raise CalendarReviewError("calendar source manifest candidate is unsupported")
    if payload.get("future_exception_completeness") is not False:
        raise CalendarReviewError("future exception completeness must remain false")
    sources = payload.get("sources")
    if not isinstance(sources, list) or not sources:
        raise CalendarReviewError("calendar source manifest must contain sources")
    for source in sources:
        if not isinstance(source, Mapping) or set(source) != set(_SOURCE_INPUT_FIELDS):
            raise CalendarReviewError("calendar source manifest source fields are invalid")


def _candidate(
    candidate_config: Mapping[str, object],
    candidate_id: str,
) -> Mapping[str, object]:
    if (
        candidate_config.get("execution_enabled") is not False
        or candidate_config.get("credentials_allowed") is not False
    ):
        raise CalendarReviewError("candidate configuration safety locks are invalid")
    candidates = candidate_config.get("candidates")
    if not isinstance(candidates, list):
        raise CalendarReviewError("candidate configuration is incomplete")
    matches = [
        item
        for item in candidates
        if isinstance(item, Mapping) and item.get("candidate_id") == candidate_id
    ]
    if len(matches) != 1:
        raise CalendarReviewError("candidate must exist exactly once")
    return matches[0]


def _validate_template_safety_and_lane(
    candidate_config: Mapping[str, object],
    template: Mapping[str, object],
    candidate_id: str,
) -> None:
    candidate = _candidate(candidate_config, candidate_id)
    symbols = _mapping(template.get("broker_symbols"), "template broker_symbols")
    if (
        template.get("candidate_id") != candidate_id
        or candidate.get("environment") != "DEMO"
        or template.get("broker_legal_name")
        != candidate.get("broker_legal_name_observed")
        or template.get("broker_server") != candidate.get("server")
        or candidate.get("broker_symbols_observed") != dict(symbols)
        or template.get("operating_jurisdiction") != "JP"
    ):
        raise CalendarReviewError("candidate and template lane binding mismatch")
    if (
        template.get("validation_profile") != "DIAGNOSTIC"
        or template.get("execution_enabled") is not False
        or template.get("live_allowed") is not False
        or template.get("safe_to_demo_auto_order") is not False
        or template.get("max_lot") != MAX_LOT
    ):
        raise CalendarReviewError("calendar template safety locks are invalid")
    review = _mapping(template.get("special_hours_review"), "special_hours_review")
    if review.get("attested") is not False:
        raise CalendarReviewError("special-hours attestation must remain false")
    policy = _mapping(
        template.get("calendar_amendment_policy"), "calendar_amendment_policy"
    )
    if (
        policy.get("mode") != "CLOSURE_ONLY_PROSPECTIVE_V1"
        or policy.get("completeness_attestation_required") is not True
        or policy.get("source_document_required") is not True
        or not isinstance(policy.get("minimum_lead_seconds"), int)
        or isinstance(policy.get("minimum_lead_seconds"), bool)
        or int(policy["minimum_lead_seconds"]) < 900
        or int(policy["minimum_lead_seconds"]) % 900
    ):
        raise CalendarReviewError("calendar amendment policy is invalid")
    try:
        ZoneInfo(str(template.get("server_timezone") or ""))
        validate_weekly_m15_sessions(
            template.get("weekly_m15_sessions"), required_symbols=tuple(symbols)
        )
    except (ValueError, ZoneInfoNotFoundError, SessionCalendarError) as exc:
        raise CalendarReviewError("calendar schedule is invalid") from exc
    start = _utc(template.get("observation_start_at_utc"), "observation_start_at_utc")
    blind = _utc(template.get("blind_until_utc"), "blind_until_utc")
    if start >= blind:
        raise CalendarReviewError("calendar observation window is invalid")


def schedule_claim_body(template: Mapping[str, object]) -> dict[str, object]:
    missing = [field for field in _SCHEDULE_FIELDS if field not in template]
    if missing:
        raise CalendarReviewError("calendar schedule claim fields are missing")
    return {field: deepcopy(template[field]) for field in _SCHEDULE_FIELDS}


def schedule_claim_sha256(template: Mapping[str, object]) -> str:
    return canonical_sha256(schedule_claim_body(template))


def _source_path(source_root: str | Path, value: object) -> Path:
    root = Path(source_root)
    if root.is_symlink() or not root.is_dir():
        raise CalendarReviewError("calendar source root must be a real directory")
    raw = str(value or "").strip()
    if not raw:
        raise CalendarReviewError("calendar source file is required")
    requested = Path(raw)
    if requested.is_absolute():
        raise CalendarReviewError("calendar source path must be relative to source root")
    pure = PurePath(raw)
    if "." in pure.parts or ".." in pure.parts:
        raise CalendarReviewError("calendar source path traversal is forbidden")
    current = root
    for part in pure.parts:
        current = current / part
        if current.is_symlink():
            raise CalendarReviewError("calendar source path contains a symlink")
    return current


def _stable_regular_bytes(path: Path) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor: int | None = None
    try:
        descriptor = os.open(path, flags)
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise CalendarReviewError("calendar source must be a regular file")
        if before.st_size <= 0 or before.st_size > MAX_SOURCE_BYTES:
            raise CalendarReviewError("calendar source size is invalid")
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        after = os.fstat(descriptor)
        path_after = os.lstat(path)
        before_id = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
        after_id = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
        path_id = (
            path_after.st_dev,
            path_after.st_ino,
            path_after.st_size,
            path_after.st_mtime_ns,
        )
        if before_id != after_id or before_id != path_id or len(data) != before.st_size:
            raise CalendarReviewError("calendar source changed while being read")
        return data
    except CalendarReviewError:
        raise
    except (OSError, OverflowError) as exc:
        raise CalendarReviewError("calendar source is unavailable") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _validate_source_url(value: object) -> str:
    try:
        parsed = urlsplit(str(value or ""))
        port = parsed.port
    except ValueError as exc:
        raise CalendarReviewError("calendar source URL is invalid") from exc
    host = (parsed.hostname or "").casefold()
    if (
        parsed.scheme != "https"
        or parsed.username is not None
        or parsed.password is not None
        or port is not None
        or parsed.fragment
        or not (host == "phillip.co.jp" or host.endswith(".phillip.co.jp"))
        or not parsed.path.startswith("/")
        or parsed.path == "/"
    ):
        raise CalendarReviewError("calendar source URL is not allowlisted")
    return parsed.geturl()


def _published_date(value: object, *, observed_at: datetime) -> str | None:
    if value is None:
        return None
    try:
        published = date.fromisoformat(str(value))
    except ValueError as exc:
        raise CalendarReviewError("calendar source published_on is invalid") from exc
    if published > observed_at.date():
        raise CalendarReviewError("calendar source publication postdates observation")
    return published.isoformat()


def _validate_sources(
    sources: object,
    *,
    candidate_id: str,
    verified_at: datetime,
    now: datetime,
    observation_start: datetime,
) -> None:
    if not isinstance(sources, list) or not sources:
        raise CalendarReviewError("calendar review evidence has no sources")
    seen_ids: set[str] = set()
    seen_roles: set[str] = set()
    for source in sources:
        if not isinstance(source, Mapping) or set(source) != set(_SOURCE_EVIDENCE_FIELDS):
            raise CalendarReviewError("calendar review source fields are invalid")
        source_id = _identifier(source.get("source_id"), "source_id", lower=True)
        role = str(source.get("source_role") or "").strip().upper()
        if role not in _SOURCE_ROLES:
            raise CalendarReviewError("calendar source role is invalid")
        if source_id in seen_ids:
            raise CalendarReviewError("calendar source ID is duplicated")
        if role in seen_roles:
            raise CalendarReviewError("calendar source role is duplicated")
        seen_ids.add(source_id)
        seen_roles.add(role)
        _validate_source_url(source.get("url"))
        observed = _fresh_before_start(
            source.get("observed_at_utc"), "source observed_at_utc",
            now=now, observation_start=observation_start,
        )
        if observed > verified_at:
            raise CalendarReviewError("source observation postdates evidence verification")
        _published_date(source.get("published_on"), observed_at=observed)
        digest = str(source.get("captured_content_sha256") or "").lower()
        length = source.get("captured_content_bytes")
        if (
            _SHA256.fullmatch(digest) is None
            or type(length) is not int
            or int(length) <= 0
            or int(length) > MAX_SOURCE_BYTES
        ):
            raise CalendarReviewError("calendar source byte evidence is invalid")
    if not _REQUIRED_ROLES[candidate_id] <= seen_roles:
        raise CalendarReviewError("required source roles are missing")


def prepare_calendar_review_evidence(
    candidate_config: Mapping[str, object],
    template: Mapping[str, object],
    source_manifest: Mapping[str, object],
    *,
    source_root: str | Path,
    now_provider: Callable[[], datetime] = utc_now,
) -> dict[str, object]:
    _validate_manifest_shape(source_manifest)
    candidate_id = _identifier(
        source_manifest.get("candidate_id"), "candidate_id", lower=True
    )
    _validate_template_safety_and_lane(
        candidate_config, template, candidate_id
    )
    now = _trusted_now(now_provider)
    start = _utc(template["observation_start_at_utc"], "observation_start_at_utc")
    if now >= start:
        raise CalendarReviewError("calendar review must complete before observation start")
    source_evidence: list[dict[str, object]] = []
    seen_ids: set[str] = set()
    seen_roles: set[str] = set()
    for raw_source in source_manifest["sources"]:
        source = _mapping(raw_source, "calendar source")
        source_id = _identifier(source.get("source_id"), "source_id", lower=True)
        role = str(source.get("source_role") or "").strip().upper()
        if role not in _SOURCE_ROLES:
            raise CalendarReviewError("calendar source role is invalid")
        if source_id in seen_ids:
            raise CalendarReviewError("calendar source ID is duplicated")
        if role in seen_roles:
            raise CalendarReviewError("calendar source role is duplicated")
        seen_ids.add(source_id)
        seen_roles.add(role)
        url = _validate_source_url(source.get("url"))
        observed = _fresh_before_start(
            source.get("observed_at_utc"), "source observed_at_utc",
            now=now, observation_start=start,
        )
        published = _published_date(source.get("published_on"), observed_at=observed)
        data = _stable_regular_bytes(
            _source_path(source_root, source.get("source_file"))
        )
        source_evidence.append(
            {
                "source_id": source_id,
                "source_role": role,
                "url": url,
                "published_on": published,
                "observed_at_utc": _iso(observed),
                "captured_content_sha256": hashlib.sha256(data).hexdigest(),
                "captured_content_bytes": len(data),
            }
        )
    if not _REQUIRED_ROLES[candidate_id] <= seen_roles:
        raise CalendarReviewError("required source roles are missing")
    schedule = schedule_claim_body(template)
    body = {
        "schema_version": EVIDENCE_SCHEMA_VERSION,
        **schedule,
        "schedule_claim_sha256": canonical_sha256(schedule),
        "official_sources": source_evidence,
        "verified_at_utc": _iso(now),
        "special_hours_attested": False,
        "future_exception_completeness": False,
        "execution_enabled": False,
        "live_allowed": False,
        "safe_to_demo_auto_order": False,
        "promotion_eligible": False,
        "max_lot": MAX_LOT,
    }
    return {**body, "evidence_bundle_sha256": canonical_sha256(body)}


def _evidence_from_review(review: Mapping[str, object]) -> dict[str, object]:
    return {
        **{
            key: deepcopy(review[key])
            for key in _EVIDENCE_FIELDS
            if key != "schema_version"
        },
        "schema_version": EVIDENCE_SCHEMA_VERSION,
    }


def _validate_evidence(
    evidence: Mapping[str, object],
    *,
    now: datetime,
    template: Mapping[str, object] | None = None,
) -> None:
    if set(evidence) != set(_EVIDENCE_FIELDS):
        raise CalendarReviewError("calendar review evidence fields are invalid")
    if evidence.get("schema_version") != EVIDENCE_SCHEMA_VERSION:
        raise CalendarReviewError("unsupported calendar review evidence schema")
    candidate_id = _identifier(evidence.get("candidate_id"), "candidate_id", lower=True)
    if candidate_id not in _REQUIRED_ROLES:
        raise CalendarReviewError("calendar review candidate is unsupported")
    start = _utc(evidence.get("observation_start_at_utc"), "observation_start_at_utc")
    verified = _fresh_before_start(
        evidence.get("verified_at_utc"), "verified_at_utc",
        now=now, observation_start=start,
    )
    body = {key: deepcopy(value) for key, value in evidence.items() if key != "evidence_bundle_sha256"}
    if canonical_sha256(body) != evidence.get("evidence_bundle_sha256"):
        raise CalendarReviewError("calendar review evidence hash mismatch")
    schedule = {field: deepcopy(evidence[field]) for field in _SCHEDULE_FIELDS}
    if canonical_sha256(schedule) != evidence.get("schedule_claim_sha256"):
        raise CalendarReviewError("calendar review schedule claim mismatch")
    if (
        evidence.get("special_hours_attested") is not False
        or evidence.get("future_exception_completeness") is not False
        or evidence.get("execution_enabled") is not False
        or evidence.get("live_allowed") is not False
        or evidence.get("safe_to_demo_auto_order") is not False
        or evidence.get("promotion_eligible") is not False
        or evidence.get("max_lot") != MAX_LOT
        or _mapping(evidence.get("special_hours_review"), "special_hours_review").get("attested") is not False
    ):
        raise CalendarReviewError("calendar review safety or completeness locks are invalid")
    _validate_sources(
        evidence.get("official_sources"), candidate_id=candidate_id,
        verified_at=verified, now=now, observation_start=start,
    )
    if template is not None:
        if template.get("candidate_id") != candidate_id:
            raise CalendarReviewError("calendar review lane binding mismatch")
        if schedule_claim_sha256(template) != evidence.get("schedule_claim_sha256"):
            raise CalendarReviewError("calendar review schedule claim mismatch")


def sign_calendar_review_approval(
    evidence: Mapping[str, object],
    *,
    reviewer_id: str,
    key_id: str,
    signing_key: bytes,
    now_provider: Callable[[], datetime] = utc_now,
) -> dict[str, object]:
    now = _trusted_now(now_provider)
    _validate_evidence(evidence, now=now)
    candidate_id = str(evidence["candidate_id"])
    reviewer = _identifier(reviewer_id, "reviewer_id")
    expected_key_id = calendar_review_key_name(candidate_id)
    if key_id != expected_key_id:
        raise CalendarReviewError("calendar review key ID is invalid")
    if not isinstance(signing_key, bytes) or len(signing_key) < 32:
        raise CalendarReviewError("calendar review key must contain at least 32 bytes")
    start = _utc(evidence["observation_start_at_utc"], "observation_start_at_utc")
    if now >= start:
        raise CalendarReviewError("calendar review approval must precede observation start")
    body = {
        "schema_version": APPROVAL_SCHEMA_VERSION,
        "candidate_id": candidate_id,
        "evidence_bundle_sha256": evidence["evidence_bundle_sha256"],
        "schedule_claim_sha256": evidence["schedule_claim_sha256"],
        "reviewer_id": reviewer,
        "reviewer_role": "CALENDAR_REVIEW",
        "key_id": key_id,
        "signed_at_utc": _iso(now),
    }
    try:
        signature = payload_hmac_sha256(body, signing_key, domain=APPROVAL_DOMAIN)
    except AccountIdentityError as exc:
        raise CalendarReviewError("calendar review approval signing failed") from exc
    return {**body, "signature_hmac_sha256": signature}


def _verify_approval(
    approval: Mapping[str, object],
    evidence: Mapping[str, object],
    *,
    approval_key_provider: Callable[[str], bytes | None] | None,
    now: datetime,
) -> None:
    if set(approval) != set(_APPROVAL_FIELDS):
        raise CalendarReviewError("calendar review approval fields are invalid")
    if (
        approval.get("schema_version") != APPROVAL_SCHEMA_VERSION
        or approval.get("reviewer_role") != "CALENDAR_REVIEW"
        or approval.get("candidate_id") != evidence.get("candidate_id")
        or approval.get("evidence_bundle_sha256") != evidence.get("evidence_bundle_sha256")
        or approval.get("schedule_claim_sha256") != evidence.get("schedule_claim_sha256")
    ):
        raise CalendarReviewError("calendar review approval binding mismatch")
    _identifier(approval.get("reviewer_id"), "reviewer_id")
    key_id = str(approval.get("key_id") or "")
    if key_id != calendar_review_key_name(str(evidence["candidate_id"])):
        raise CalendarReviewError("calendar review approval key ID mismatch")
    start = _utc(evidence["observation_start_at_utc"], "observation_start_at_utc")
    signed = _fresh_before_start(
        approval.get("signed_at_utc"), "signed_at_utc",
        now=now, observation_start=start,
    )
    verified = _utc(evidence["verified_at_utc"], "verified_at_utc")
    if signed < verified:
        raise CalendarReviewError("calendar review approval predates evidence")
    if approval_key_provider is None:
        raise CalendarReviewError("calendar review approval key provider is required")
    try:
        key = approval_key_provider(key_id)
    except Exception as exc:
        raise CalendarReviewError("calendar review approval key is unavailable") from exc
    if not isinstance(key, bytes) or len(key) < 32:
        raise CalendarReviewError("calendar review approval key is unavailable")
    body = {key_name: value for key_name, value in approval.items() if key_name != "signature_hmac_sha256"}
    try:
        expected = payload_hmac_sha256(body, key, domain=APPROVAL_DOMAIN)
    except AccountIdentityError as exc:
        raise CalendarReviewError("calendar review approval verification failed") from exc
    signature = str(approval.get("signature_hmac_sha256") or "").lower()
    if _SHA256.fullmatch(signature) is None or not hmac.compare_digest(signature, expected):
        raise CalendarReviewError("calendar review approval signature mismatch")


def assemble_prewindow_calendar_review(
    evidence: Mapping[str, object],
    approval: Mapping[str, object],
    *,
    template: Mapping[str, object],
    approval_key_provider: Callable[[str], bytes | None] | None,
    now_provider: Callable[[], datetime] = utc_now,
) -> dict[str, object]:
    now = _trusted_now(now_provider)
    _validate_evidence(evidence, now=now, template=template)
    _verify_approval(
        approval, evidence, approval_key_provider=approval_key_provider, now=now
    )
    body = {
        **{
            key: deepcopy(value)
            for key, value in evidence.items()
            if key != "schema_version"
        },
        "schema_version": REVIEW_SCHEMA_VERSION,
        "calendar_review_approval": deepcopy(dict(approval)),
        "amendment_chain_required": True,
        "post_window_completeness_required": True,
    }
    return {**body, "review_artifact_sha256": canonical_sha256(body)}


def verify_prewindow_calendar_review(
    review: Mapping[str, object],
    *,
    template: Mapping[str, object],
    approval_key_provider: Callable[[str], bytes | None] | None,
    now_provider: Callable[[], datetime] = utc_now,
) -> None:
    if set(review) != set(_REVIEW_FIELDS):
        raise CalendarReviewError("pre-window calendar review fields are invalid")
    if review.get("schema_version") != REVIEW_SCHEMA_VERSION:
        raise CalendarReviewError("unsupported pre-window calendar review schema")
    body = {key: deepcopy(value) for key, value in review.items() if key != "review_artifact_sha256"}
    if canonical_sha256(body) != review.get("review_artifact_sha256"):
        raise CalendarReviewError("pre-window calendar review hash mismatch")
    if (
        review.get("amendment_chain_required") is not True
        or review.get("post_window_completeness_required") is not True
        or review.get("future_exception_completeness") is not False
        or review.get("special_hours_attested") is not False
    ):
        raise CalendarReviewError("pre-window review completeness claims are invalid")
    now = _trusted_now(now_provider)
    evidence = _evidence_from_review(review)
    _validate_evidence(evidence, now=now, template=template)
    _verify_approval(
        _mapping(review.get("calendar_review_approval"), "calendar_review_approval"),
        evidence,
        approval_key_provider=approval_key_provider,
        now=now,
    )


def verify_prewindow_calendar_review_shape(
    review: Mapping[str, object],
    *,
    template: Mapping[str, object],
) -> None:
    """Verify deterministic binding without treating a signature as trusted."""

    if set(review) != set(_REVIEW_FIELDS):
        raise CalendarReviewError("pre-window calendar review fields are invalid")
    if review.get("schema_version") != REVIEW_SCHEMA_VERSION:
        raise CalendarReviewError("unsupported pre-window calendar review schema")
    body = {key: deepcopy(value) for key, value in review.items() if key != "review_artifact_sha256"}
    if canonical_sha256(body) != review.get("review_artifact_sha256"):
        raise CalendarReviewError("pre-window calendar review hash mismatch")
    evidence = _evidence_from_review(review)
    evidence_body = {
        key: deepcopy(value)
        for key, value in evidence.items()
        if key != "evidence_bundle_sha256"
    }
    if canonical_sha256(evidence_body) != evidence.get("evidence_bundle_sha256"):
        raise CalendarReviewError("calendar review evidence hash mismatch")
    approval = _mapping(
        review.get("calendar_review_approval"), "calendar_review_approval"
    )
    candidate_id = _identifier(review.get("candidate_id"), "candidate_id", lower=True)
    signature = str(approval.get("signature_hmac_sha256") or "").lower()
    if (
        set(approval) != set(_APPROVAL_FIELDS)
        or approval.get("schema_version") != APPROVAL_SCHEMA_VERSION
        or approval.get("reviewer_role") != "CALENDAR_REVIEW"
        or approval.get("candidate_id") != candidate_id
        or approval.get("evidence_bundle_sha256")
        != review.get("evidence_bundle_sha256")
        or approval.get("schedule_claim_sha256")
        != review.get("schedule_claim_sha256")
        or approval.get("key_id") != calendar_review_key_name(candidate_id)
        or _SHA256.fullmatch(signature) is None
    ):
        raise CalendarReviewError("calendar review approval shape is invalid")
    _identifier(approval.get("reviewer_id"), "reviewer_id")
    _utc(approval.get("signed_at_utc"), "signed_at_utc")
    if (
        template.get("candidate_id") != candidate_id
        or schedule_claim_sha256(template) != review.get("schedule_claim_sha256")
        or review.get("future_exception_completeness") is not False
        or review.get("special_hours_attested") is not False
        or review.get("execution_enabled") is not False
        or review.get("live_allowed") is not False
        or review.get("safe_to_demo_auto_order") is not False
        or review.get("promotion_eligible") is not False
        or review.get("max_lot") != MAX_LOT
        or _mapping(
            review.get("special_hours_review"), "special_hours_review"
        ).get("attested")
        is not False
        or review.get("amendment_chain_required") is not True
        or review.get("post_window_completeness_required") is not True
    ):
        raise CalendarReviewError("pre-window calendar review binding mismatch")


def write_calendar_review_artifact_exclusive(
    path: str | Path,
    payload: Mapping[str, object],
) -> Path:
    try:
        return write_json_exclusive(path, payload)
    except SecureFileError as exc:
        raise CalendarReviewError("calendar review artifact write failed") from exc


__all__ = [
    "APPROVAL_SCHEMA_VERSION",
    "CalendarReviewError",
    "EVIDENCE_SCHEMA_VERSION",
    "REVIEW_SCHEMA_VERSION",
    "SOURCE_MANIFEST_SCHEMA_VERSION",
    "assemble_prewindow_calendar_review",
    "calendar_review_key_name",
    "load_calendar_review_approval",
    "load_calendar_review_artifact",
    "load_calendar_review_evidence",
    "load_calendar_source_manifest",
    "load_prewindow_calendar_review",
    "prepare_calendar_review_evidence",
    "schedule_claim_sha256",
    "sign_calendar_review_approval",
    "verify_prewindow_calendar_review",
    "verify_prewindow_calendar_review_shape",
    "write_calendar_review_artifact_exclusive",
]
