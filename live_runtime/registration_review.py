"""Fail-closed broker regulatory registration-review artifacts.

This module deliberately has no network or broker mutation capability.  It
turns operator-reviewed local source files into a content-addressed evidence
body, signs that body with independently controlled review keys, and asks the
existing legal-binding verifier to validate the assembled observation.
"""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePath
import re
import stat
from typing import Callable, Iterable, Mapping
from urllib.parse import urlsplit

from .account_identity import AccountIdentityError, payload_hmac_sha256
from .broker_window_plan import (
    BrokerWindowPlanError,
    verify_broker_calendar_template,
)
from .contracts import canonical_sha256, require_utc
from .secure_files import SecureFileError, write_json_exclusive
from .xm_window_plan import (
    MAX_REGULATORY_EVIDENCE_AGE,
    REGULATORY_APPROVAL_DOMAIN,
    REGULATORY_APPROVAL_SCHEMA_VERSION,
    XMWindowPlanError,
    verify_candidate_legal_binding,
)


REGULATORY_SOURCE_MANIFEST_SCHEMA_VERSION = "regulatory-source-manifest-v1"
REGULATORY_EVIDENCE_SCHEMA_VERSION = "regulatory-evidence-v1"
MAX_SOURCE_BYTES = 64 * 1024 * 1024
MAX_LOT = 0.01

_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_SOURCE_MANIFEST_FIELDS = frozenset(
    {"schema_version", "candidate_id", "operating_jurisdiction", "sources"}
)
_SOURCE_INPUT_FIELDS = frozenset(
    {
        "authority",
        "url",
        "entity",
        "result",
        "registry_record_id",
        "observed_at_utc",
        "source_file",
    }
)
_SOURCE_EVIDENCE_FIELDS = frozenset(
    (_SOURCE_INPUT_FIELDS - {"source_file"})
    | {"captured_content_sha256", "captured_content_bytes"}
)
_EVIDENCE_FIELDS = frozenset(
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
_APPROVAL_FIELDS = frozenset(
    {
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
)
_APPROVAL_ROLES = frozenset({"COMPLIANCE_REVIEW", "LEGAL_REVIEW"})
_AUTHORITY_HOSTS = {
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
_ELIGIBLE_RESULTS = {
    "JP": frozenset({"ENTITY_REGISTERED_FOR_JAPAN_RESIDENTS"}),
    "ID": frozenset(
        {
            "REGISTERED_INDONESIAN_FUTURES_BROKER",
            "ENTITY_AUTHORIZED_FOR_INDONESIAN_RESIDENTS",
        }
    ),
}


class RegistrationReviewError(RuntimeError):
    """Raised when a registration-review artifact fails closed."""


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _reject_constant(_: str) -> None:
    raise RegistrationReviewError("non-finite JSON values are not allowed")


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise RegistrationReviewError("duplicate JSON keys are not allowed")
        result[key] = value
    return result


def _strict_json_object(path: str | Path) -> dict[str, object]:
    source = Path(path)
    if source.is_symlink() or not source.is_file():
        raise RegistrationReviewError("review input must be a regular file")
    try:
        with source.open("r", encoding="utf-8") as handle:
            payload = json.load(
                handle,
                object_pairs_hook=_unique_object,
                parse_constant=_reject_constant,
            )
    except RegistrationReviewError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise RegistrationReviewError("review input is invalid JSON") from exc
    if not isinstance(payload, dict):
        raise RegistrationReviewError("review input must be a JSON object")
    return payload


def load_regulatory_artifact(
    path: str | Path,
    *,
    expected_fields: Iterable[str],
) -> dict[str, object]:
    payload = _strict_json_object(path)
    fields = frozenset(str(field) for field in expected_fields)
    if set(payload) != set(fields):
        raise RegistrationReviewError("review artifact fields are invalid")
    return payload


def load_regulatory_source_manifest(path: str | Path) -> dict[str, object]:
    payload = load_regulatory_artifact(
        path,
        expected_fields=_SOURCE_MANIFEST_FIELDS,
    )
    if payload.get("schema_version") != REGULATORY_SOURCE_MANIFEST_SCHEMA_VERSION:
        raise RegistrationReviewError("unsupported regulatory source manifest")
    candidate_id = str(payload.get("candidate_id") or "").strip().lower()
    jurisdiction = str(payload.get("operating_jurisdiction") or "").strip().upper()
    if _IDENTIFIER_RE.fullmatch(candidate_id) is None:
        raise RegistrationReviewError("source manifest candidate is invalid")
    if jurisdiction not in _AUTHORITY_HOSTS:
        raise RegistrationReviewError("source manifest jurisdiction is invalid")
    sources = payload.get("sources")
    if not isinstance(sources, list) or not sources:
        raise RegistrationReviewError("source manifest must contain sources")
    for source in sources:
        if not isinstance(source, Mapping) or set(source) != set(_SOURCE_INPUT_FIELDS):
            raise RegistrationReviewError("source manifest source fields are invalid")
    return payload


def load_regulatory_evidence(path: str | Path) -> dict[str, object]:
    payload = load_regulatory_artifact(path, expected_fields=_EVIDENCE_FIELDS)
    if payload.get("schema_version") != REGULATORY_EVIDENCE_SCHEMA_VERSION:
        raise RegistrationReviewError("unsupported regulatory evidence schema")
    return payload


def load_regulatory_approval(path: str | Path) -> dict[str, object]:
    payload = load_regulatory_artifact(path, expected_fields=_APPROVAL_FIELDS)
    _validate_approval_shape(payload)
    return payload


def _mapping(value: object, field: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise RegistrationReviewError(f"{field} must be an object")
    return value


def _identifier(value: object, field: str, *, lower: bool = False) -> str:
    normalized = str(value or "").strip()
    if _IDENTIFIER_RE.fullmatch(normalized) is None:
        raise RegistrationReviewError(f"{field} is invalid")
    return normalized.lower() if lower else normalized


def regulatory_review_key_name(candidate_id: str, approver_role: str) -> str:
    candidate = _identifier(candidate_id, "candidate_id", lower=True)
    role = str(approver_role or "").strip().upper()
    suffix = {
        "COMPLIANCE_REVIEW": "compliance-review-v1",
        "LEGAL_REVIEW": "legal-review-v1",
    }.get(role)
    if suffix is None:
        raise RegistrationReviewError("approver_role is invalid")
    key_name = f"{candidate}-{suffix}"
    if len(key_name) > 128:
        raise RegistrationReviewError("derived regulatory review key name is too long")
    return key_name


def _utc(value: object, field: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        require_utc(field, parsed)
    except (TypeError, ValueError) as exc:
        raise RegistrationReviewError(f"{field} must be timezone-aware UTC") from exc
    return parsed


def _trusted_now(now_provider: Callable[[], datetime]) -> datetime:
    try:
        now = now_provider()
        require_utc("registration review clock", now)
    except (TypeError, ValueError) as exc:
        raise RegistrationReviewError(
            "registration review clock must be timezone-aware UTC"
        ) from exc
    return now


def _iso(value: datetime) -> str:
    return value.isoformat(timespec="seconds").replace("+00:00", "Z")


def _fresh(value: object, field: str, *, now: datetime) -> datetime:
    observed = _utc(value, field)
    if observed > now:
        raise RegistrationReviewError(f"{field} must not be in the future")
    if now - observed > MAX_REGULATORY_EVIDENCE_AGE:
        raise RegistrationReviewError(f"{field} is stale")
    return observed


def _candidate(
    candidate_config: Mapping[str, object],
    candidate_id: str,
) -> Mapping[str, object]:
    if (
        candidate_config.get("execution_enabled") is not False
        or candidate_config.get("credentials_allowed") is not False
    ):
        raise RegistrationReviewError("candidate configuration safety locks are invalid")
    candidates = candidate_config.get("candidates")
    if not isinstance(candidates, list):
        raise RegistrationReviewError("candidate configuration is incomplete")
    matches = [
        item
        for item in candidates
        if isinstance(item, Mapping) and item.get("candidate_id") == candidate_id
    ]
    if len(matches) != 1:
        raise RegistrationReviewError("candidate must exist exactly once")
    return matches[0]


def _validate_lane_binding(
    candidate_config: Mapping[str, object],
    template: Mapping[str, object],
    *,
    candidate_id: str,
    jurisdiction: str,
) -> Mapping[str, object]:
    try:
        verify_broker_calendar_template(template)
    except BrokerWindowPlanError as exc:
        raise RegistrationReviewError("broker calendar template is invalid") from exc
    candidate = _candidate(candidate_config, candidate_id)
    symbols = _mapping(template.get("broker_symbols"), "template broker_symbols")
    scope = str(candidate.get("binding_scope") or "ALL").strip().upper()
    if scope not in {"FX", "COMMODITY", "ALL"}:
        raise RegistrationReviewError("candidate binding scope is invalid")
    if (
        template.get("candidate_id") != candidate_id
        or template.get("operating_jurisdiction") != jurisdiction
        or template.get("broker_legal_name")
        != candidate.get("broker_legal_name_observed")
        or template.get("broker_server") != candidate.get("server")
        or candidate.get("environment") != "DEMO"
        or candidate.get("broker_symbols_observed") != dict(symbols)
    ):
        raise RegistrationReviewError("candidate and template lane binding mismatch")
    return candidate


def _reject_symlink_components(path: Path, *, relative_to: Path | None) -> None:
    """Reject caller-controlled symlinks without rejecting OS path aliases.

    macOS commonly exposes ``/var`` as a system symlink to ``/private/var``.
    That ancestor is outside the operator-controlled source root.  Relative
    inputs are therefore checked from the already-attested root downward;
    absolute inputs still reject a substituted final file and are protected by
    ``O_NOFOLLOW`` during open.
    """

    if relative_to is None:
        if path.is_symlink():
            raise RegistrationReviewError("regulatory source path contains a symlink")
        return
    current = relative_to
    relative = path.relative_to(relative_to)
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            raise RegistrationReviewError("regulatory source path contains a symlink")


def _source_path(source_root: str | Path, value: object) -> Path:
    root = Path(source_root)
    if root.is_symlink() or not root.is_dir():
        raise RegistrationReviewError("regulatory source root must be a real directory")
    raw = str(value or "").strip()
    if not raw:
        raise RegistrationReviewError("regulatory source file is required")
    requested = Path(raw)
    if requested.is_absolute():
        target = requested
        controlled_root = None
    else:
        pure = PurePath(raw)
        if ".." in pure.parts or "." in pure.parts:
            raise RegistrationReviewError("regulatory source path traversal is forbidden")
        target = root / requested
        controlled_root = root
    _reject_symlink_components(target, relative_to=controlled_root)
    return target


def _stable_regular_bytes(path: Path) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor: int | None = None
    try:
        descriptor = os.open(path, flags)
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise RegistrationReviewError("regulatory source must be a regular file")
        if before.st_size <= 0 or before.st_size > MAX_SOURCE_BYTES:
            raise RegistrationReviewError("regulatory source size is invalid")
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
        before_identity = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
        after_identity = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
        path_identity = (
            path_after.st_dev,
            path_after.st_ino,
            path_after.st_size,
            path_after.st_mtime_ns,
        )
        if (
            before_identity != after_identity
            or before_identity != path_identity
            or len(data) != before.st_size
        ):
            raise RegistrationReviewError("regulatory source changed while being read")
        return data
    except RegistrationReviewError:
        raise
    except (OSError, OverflowError) as exc:
        raise RegistrationReviewError("regulatory source is unavailable") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _validate_source_claim(
    source: Mapping[str, object],
    *,
    jurisdiction: str,
    broker_legal_name: str,
    now: datetime,
) -> datetime:
    authority = str(source.get("authority") or "").strip()
    allowed_hosts = _AUTHORITY_HOSTS[jurisdiction].get(authority.casefold())
    if allowed_hosts is None:
        raise RegistrationReviewError("regulatory source authority is not allowlisted")
    try:
        parsed = urlsplit(str(source.get("url") or ""))
        port = parsed.port
    except ValueError as exc:
        raise RegistrationReviewError("regulatory source URL is invalid") from exc
    if (
        parsed.scheme != "https"
        or parsed.username is not None
        or parsed.password is not None
        or port is not None
        or parsed.fragment
        or (parsed.hostname or "").casefold() not in allowed_hosts
        or not parsed.path.startswith("/")
    ):
        raise RegistrationReviewError("regulatory source URL is not allowlisted")
    if source.get("entity") != broker_legal_name:
        raise RegistrationReviewError("regulatory source entity binding mismatch")
    if source.get("result") not in _ELIGIBLE_RESULTS[jurisdiction]:
        raise RegistrationReviewError("regulatory source result is not eligible")
    if not str(source.get("registry_record_id") or "").strip():
        raise RegistrationReviewError("regulatory source registry record is missing")
    return _fresh(source.get("observed_at_utc"), "source observed_at_utc", now=now)


def _validate_source_evidence(
    sources: object,
    *,
    jurisdiction: str,
    broker_legal_name: str,
    verified_at: datetime,
    now: datetime,
) -> None:
    if not isinstance(sources, list) or not sources:
        raise RegistrationReviewError("regulatory evidence has no sources")
    seen: set[tuple[str, str]] = set()
    for source in sources:
        if not isinstance(source, Mapping) or set(source) != set(_SOURCE_EVIDENCE_FIELDS):
            raise RegistrationReviewError("regulatory evidence source fields are invalid")
        observed = _validate_source_claim(
            source,
            jurisdiction=jurisdiction,
            broker_legal_name=broker_legal_name,
            now=now,
        )
        if observed > verified_at:
            raise RegistrationReviewError("source observation postdates verification")
        digest = str(source.get("captured_content_sha256") or "").lower()
        length = source.get("captured_content_bytes")
        if (
            _SHA256_RE.fullmatch(digest) is None
            or type(length) is not int
            or int(length) <= 0
            or int(length) > MAX_SOURCE_BYTES
        ):
            raise RegistrationReviewError("regulatory source byte evidence is invalid")
        identity = (
            str(source.get("authority") or "").casefold(),
            str(source.get("registry_record_id") or "").casefold(),
        )
        if identity in seen:
            raise RegistrationReviewError("regulatory source record is duplicated")
        seen.add(identity)


def prepare_regulatory_evidence(
    candidate_config: Mapping[str, object],
    template: Mapping[str, object],
    source_manifest: Mapping[str, object],
    *,
    source_root: str | Path,
    now_provider: Callable[[], datetime] = utc_now,
) -> dict[str, object]:
    if set(source_manifest) != set(_SOURCE_MANIFEST_FIELDS):
        raise RegistrationReviewError("source manifest fields are invalid")
    if source_manifest.get("schema_version") != REGULATORY_SOURCE_MANIFEST_SCHEMA_VERSION:
        raise RegistrationReviewError("unsupported regulatory source manifest")
    candidate_id = _identifier(
        source_manifest.get("candidate_id"), "candidate_id", lower=True
    )
    jurisdiction = str(
        source_manifest.get("operating_jurisdiction") or ""
    ).strip().upper()
    if jurisdiction not in _AUTHORITY_HOSTS:
        raise RegistrationReviewError("operating jurisdiction is invalid")
    candidate = _validate_lane_binding(
        candidate_config,
        template,
        candidate_id=candidate_id,
        jurisdiction=jurisdiction,
    )
    now = _trusted_now(now_provider)
    broker_legal_name = str(candidate.get("broker_legal_name_observed") or "").strip()
    raw_sources = source_manifest.get("sources")
    if not isinstance(raw_sources, list) or not raw_sources:
        raise RegistrationReviewError("source manifest must contain sources")
    captured_sources: list[dict[str, object]] = []
    seen: set[tuple[str, str]] = set()
    for raw_source in raw_sources:
        if not isinstance(raw_source, Mapping) or set(raw_source) != set(_SOURCE_INPUT_FIELDS):
            raise RegistrationReviewError("source manifest source fields are invalid")
        observed = _validate_source_claim(
            raw_source,
            jurisdiction=jurisdiction,
            broker_legal_name=broker_legal_name,
            now=now,
        )
        identity = (
            str(raw_source.get("authority") or "").casefold(),
            str(raw_source.get("registry_record_id") or "").casefold(),
        )
        if identity in seen:
            raise RegistrationReviewError("regulatory source record is duplicated")
        seen.add(identity)
        data = _stable_regular_bytes(
            _source_path(source_root, raw_source.get("source_file"))
        )
        captured_sources.append(
            {
                key: value
                for key, value in raw_source.items()
                if key != "source_file"
            }
            | {
                "observed_at_utc": _iso(observed),
                "captured_content_sha256": hashlib.sha256(data).hexdigest(),
                "captured_content_bytes": len(data),
            }
        )
    scope = str(candidate.get("binding_scope") or "ALL").strip().upper()
    body: dict[str, object] = {
        "schema_version": REGULATORY_EVIDENCE_SCHEMA_VERSION,
        "candidate_id": candidate_id,
        "entity": broker_legal_name,
        "broker_legal_name": broker_legal_name,
        "broker_server": str(candidate.get("server") or ""),
        "environment": "DEMO",
        "binding_scope": scope,
        "operating_jurisdiction": jurisdiction,
        "broker_symbols": deepcopy(dict(template["broker_symbols"])),
        "calendar_template_sha256": canonical_sha256(template),
        "broker_claim_observed": True,
        "independent_registry_verification": True,
        "verified_at_utc": _iso(now),
        "verification_status": "VERIFIED_ELIGIBLE_SIGNED_REVIEW",
        "independent_registry_sources": captured_sources,
        "japan_residency_eligibility": (
            "VERIFIED_ELIGIBLE" if jurisdiction == "JP" else "NOT_ASSESSED"
        ),
        "indonesia_return_eligibility": (
            "VERIFIED_ELIGIBLE" if jurisdiction == "ID" else "NOT_ASSESSED"
        ),
        "legal_eligible": True,
        "decision": "DIAGNOSTIC_EVIDENCE_REGISTRATION_REVIEW_ONLY",
        "execution_enabled": False,
        "live_allowed": False,
        "safe_to_demo_auto_order": False,
        "promotion_eligible": False,
        "max_lot": MAX_LOT,
    }
    return {**body, "evidence_bundle_sha256": canonical_sha256(body)}


def _validate_evidence(
    evidence: Mapping[str, object],
    *,
    now: datetime,
) -> datetime:
    if set(evidence) != set(_EVIDENCE_FIELDS):
        raise RegistrationReviewError("regulatory evidence fields are invalid")
    if evidence.get("schema_version") != REGULATORY_EVIDENCE_SCHEMA_VERSION:
        raise RegistrationReviewError("unsupported regulatory evidence schema")
    body = {
        str(key): value
        for key, value in evidence.items()
        if key != "evidence_bundle_sha256"
    }
    digest = str(evidence.get("evidence_bundle_sha256") or "").lower()
    if _SHA256_RE.fullmatch(digest) is None or canonical_sha256(body) != digest:
        raise RegistrationReviewError("regulatory evidence hash mismatch")
    candidate_id = _identifier(evidence.get("candidate_id"), "candidate_id", lower=True)
    if candidate_id != evidence.get("candidate_id"):
        raise RegistrationReviewError("regulatory evidence candidate is not canonical")
    jurisdiction = str(evidence.get("operating_jurisdiction") or "").upper()
    if jurisdiction not in _AUTHORITY_HOSTS:
        raise RegistrationReviewError("regulatory evidence jurisdiction is invalid")
    if (
        evidence.get("environment") != "DEMO"
        or evidence.get("binding_scope") not in {"FX", "COMMODITY", "ALL"}
        or evidence.get("broker_claim_observed") is not True
        or evidence.get("independent_registry_verification") is not True
        or evidence.get("legal_eligible") is not True
        or evidence.get("execution_enabled") is not False
        or evidence.get("live_allowed") is not False
        or evidence.get("safe_to_demo_auto_order") is not False
        or evidence.get("promotion_eligible") is not False
        or evidence.get("max_lot") != MAX_LOT
        or _SHA256_RE.fullmatch(
            str(evidence.get("calendar_template_sha256") or "").lower()
        ) is None
    ):
        raise RegistrationReviewError("regulatory evidence safety or binding is invalid")
    verified_at = _fresh(
        evidence.get("verified_at_utc"), "verified_at_utc", now=now
    )
    _validate_source_evidence(
        evidence.get("independent_registry_sources"),
        jurisdiction=jurisdiction,
        broker_legal_name=str(evidence.get("broker_legal_name") or ""),
        verified_at=verified_at,
        now=now,
    )
    return verified_at


def sign_regulatory_approval(
    evidence: Mapping[str, object],
    *,
    approver_id: str,
    approver_role: str,
    key_id: str,
    signing_key: bytes,
    now_provider: Callable[[], datetime] = utc_now,
) -> dict[str, object]:
    now = _trusted_now(now_provider)
    verified_at = _validate_evidence(evidence, now=now)
    reviewer = _identifier(approver_id, "approver_id")
    role = str(approver_role or "").strip().upper()
    if role not in _APPROVAL_ROLES:
        raise RegistrationReviewError("approver_role is invalid")
    normalized_key_id = _identifier(key_id, "key_id")
    if not isinstance(signing_key, bytes) or len(signing_key) < 32:
        raise RegistrationReviewError("regulatory approval key is invalid")
    if now < verified_at or now - verified_at > MAX_REGULATORY_EVIDENCE_AGE:
        raise RegistrationReviewError("approval time is outside evidence lifetime")
    body: dict[str, object] = {
        "schema_version": REGULATORY_APPROVAL_SCHEMA_VERSION,
        "candidate_id": evidence["candidate_id"],
        "broker_legal_name": evidence["broker_legal_name"],
        "operating_jurisdiction": evidence["operating_jurisdiction"],
        "evidence_bundle_sha256": evidence["evidence_bundle_sha256"],
        "approver_id": reviewer,
        "approver_role": role,
        "key_id": normalized_key_id,
        "signed_at_utc": _iso(now),
    }
    try:
        signature = payload_hmac_sha256(
            body,
            signing_key,
            domain=REGULATORY_APPROVAL_DOMAIN,
        )
    except AccountIdentityError as exc:
        raise RegistrationReviewError("regulatory approval key is invalid") from exc
    return {**body, "signature_hmac_sha256": signature}


def _validate_approval_shape(approval: Mapping[str, object]) -> None:
    if set(approval) != set(_APPROVAL_FIELDS):
        raise RegistrationReviewError("regulatory approval fields are invalid")
    if approval.get("schema_version") != REGULATORY_APPROVAL_SCHEMA_VERSION:
        raise RegistrationReviewError("unsupported regulatory approval schema")
    if _SHA256_RE.fullmatch(
        str(approval.get("signature_hmac_sha256") or "").lower()
    ) is None:
        raise RegistrationReviewError("regulatory approval signature is invalid")


def assemble_regulatory_observation(
    evidence: Mapping[str, object],
    approvals: Iterable[Mapping[str, object]],
    candidate_config: Mapping[str, object],
    *,
    approval_key_provider: Callable[[str], bytes | None],
    now_provider: Callable[[], datetime] = utc_now,
    template: Mapping[str, object] | None = None,
) -> dict[str, object]:
    now = _trusted_now(now_provider)
    _validate_evidence(evidence, now=now)
    approval_list = [deepcopy(dict(item)) for item in approvals]
    if len(approval_list) != 2:
        raise RegistrationReviewError("exactly two regulatory approvals are required")
    for approval in approval_list:
        _validate_approval_shape(approval)
    approval_list.sort(key=lambda item: str(item.get("approver_role") or ""))

    candidate_id = str(evidence.get("candidate_id") or "")
    candidate = _candidate(candidate_config, candidate_id)
    if (
        candidate.get("broker_legal_name_observed")
        != evidence.get("broker_legal_name")
        or candidate.get("server") != evidence.get("broker_server")
        or candidate.get("environment") != evidence.get("environment")
        or str(candidate.get("binding_scope") or "ALL").upper()
        != evidence.get("binding_scope")
        or candidate.get("broker_symbols_observed")
        != evidence.get("broker_symbols")
    ):
        raise RegistrationReviewError("regulatory evidence candidate binding mismatch")
    if template is not None:
        _validate_lane_binding(
            candidate_config,
            template,
            candidate_id=candidate_id,
            jurisdiction=str(evidence.get("operating_jurisdiction") or ""),
        )
        if (
            canonical_sha256(template) != evidence.get("calendar_template_sha256")
            or dict(_mapping(template.get("broker_symbols"), "template broker_symbols"))
            != evidence.get("broker_symbols")
        ):
            raise RegistrationReviewError("regulatory evidence template binding mismatch")
    observation = {**deepcopy(dict(evidence)), "regulatory_approvals": approval_list}
    config = deepcopy(dict(candidate_config))
    candidates = config.get("candidates")
    if not isinstance(candidates, list):
        raise RegistrationReviewError("candidate configuration is incomplete")
    replacement_count = 0
    for item in candidates:
        if isinstance(item, dict) and item.get("candidate_id") == candidate_id:
            item["regulatory_observation"] = observation
            replacement_count += 1
    if replacement_count != 1:
        raise RegistrationReviewError("candidate must exist exactly once")
    payload = {
        "candidate_id": candidate_id,
        "operating_jurisdiction": evidence["operating_jurisdiction"],
        "regulatory_observation_sha256": canonical_sha256(observation),
    }
    try:
        verify_candidate_legal_binding(
            payload,
            config,
            now_provider=lambda: now,
            regulatory_approval_key_provider=approval_key_provider,
        )
    except (XMWindowPlanError, TypeError, ValueError) as exc:
        raise RegistrationReviewError(
            "assembled regulatory observation failed legal verification"
        ) from exc
    return observation


def write_regulatory_artifact_exclusive(
    path: str | Path,
    payload: Mapping[str, object],
) -> Path:
    try:
        return write_json_exclusive(path, payload)
    except FileExistsError:
        raise
    except (OSError, SecureFileError, TypeError, ValueError) as exc:
        raise RegistrationReviewError("regulatory artifact write failed") from exc


__all__ = [
    "REGULATORY_EVIDENCE_SCHEMA_VERSION",
    "REGULATORY_SOURCE_MANIFEST_SCHEMA_VERSION",
    "RegistrationReviewError",
    "assemble_regulatory_observation",
    "load_regulatory_artifact",
    "load_regulatory_approval",
    "load_regulatory_evidence",
    "load_regulatory_source_manifest",
    "prepare_regulatory_evidence",
    "regulatory_review_key_name",
    "sign_regulatory_approval",
    "write_regulatory_artifact_exclusive",
]
