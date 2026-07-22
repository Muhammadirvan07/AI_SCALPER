"""HMAC-anchored, deny-only accounting for a broker demo-auto soak.

This module records observations and evaluates the numerical soak criteria.  It
has no broker adapter, no execution surface, and no authority to enable an
order.  A signed assessment exported to independent storage can be supplied on
reopen to detect a rolled-back, forked, or coherently rewritten local database.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import InitVar, dataclass, field
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
from pathlib import Path
import re
import sqlite3
from types import MappingProxyType
from typing import Any, Callable, Iterator, Mapping
import uuid

from .contracts import (
    CanonicalContract,
    canonical_json,
    canonical_sha256,
    require_finite,
    require_hash,
    require_int,
    require_text,
    require_utc,
)


UTC = timezone.utc
SCHEMA_VERSION = "demo-auto-soak-tracker-v1"
EVENT_SCHEMA_VERSION = "demo-auto-soak-event-v1"
ASSESSMENT_RECEIPT_SCHEMA_VERSION = "demo-auto-soak-assessment-receipt-v1"
SOURCE_RECEIPT_SCHEMA_VERSION = "demo-auto-soak-source-receipt-v1"
DUAL_REVIEW_RECEIPT_SCHEMA_VERSION = "demo-auto-soak-dual-review-receipt-v1"
ZERO_HMAC_SHA256 = "0" * 64
MINIMUM_CLEAN_DAYS = 30
MINIMUM_CLOSED_FILLS = 50
MINIMUM_XAUUSD_CLOSED_FILLS = 20
MAX_SOURCE_RECEIPT_LIFETIME_SECONDS = 5.0
MAX_SOURCE_OBSERVATION_DELAY_SECONDS = 30.0
MAX_SOURCE_FUTURE_DRIFT_SECONDS = 1.0

_IDENTITY_HMAC_DOMAIN = b"AI_SCALPER_DEMO_AUTO_SOAK_IDENTITY_V1\x00"
_EVENT_HMAC_DOMAIN = b"AI_SCALPER_DEMO_AUTO_SOAK_EVENT_V1\x00"
_STATE_HMAC_DOMAIN = b"AI_SCALPER_DEMO_AUTO_SOAK_STATE_V1\x00"
_ASSESSMENT_HMAC_DOMAIN = b"AI_SCALPER_DEMO_AUTO_SOAK_ASSESSMENT_V1\x00"
_SOURCE_HMAC_DOMAINS = {
    "DEMO_AUTO_ACTIVATION": b"AI_SCALPER_SOAK_DEMO_AUTO_ACTIVATION_V1\x00",
    "BROKER_CLOSED_DEAL": b"AI_SCALPER_SOAK_BROKER_CLOSED_DEAL_V1\x00",
    "CRITICAL_INCIDENT": b"AI_SCALPER_SOAK_CRITICAL_INCIDENT_V1\x00",
}
_DUAL_REVIEW_HMAC_DOMAIN = b"AI_SCALPER_SOAK_DUAL_REVIEW_V1\x00"
_RECEIPT_SEAL = object()
_SOURCE_RECEIPT_SEAL = object()
_DUAL_REVIEW_RECEIPT_SEAL = object()

_ALLOWED_EVENT_TYPES = frozenset(
    {
        "SOAK_STARTED",
        "SOAK_RESTARTED_AFTER_REVIEW",
        "CLOSED_FILL",
        "CRITICAL_INCIDENT",
    }
)
_HASH_RE = re.compile(r"^[0-9a-f]{64}$")
_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@+\-]{0,255}$")
_SYMBOL_RE = re.compile(r"^[A-Z][A-Z0-9._-]{1,31}$")
_REASON_RE = re.compile(r"^[A-Z][A-Z0-9_]{2,127}$")

_DENY_SAFETY = MappingProxyType(
    {
        "ready": False,
        "promotion_eligible": False,
        "execution_enabled": False,
        "safe_to_demo_auto_order": False,
        "live_allowed": False,
        "order_capability": "DISABLED",
    }
)

_EXPECTED_TABLE_COLUMNS = {
    "soak_identity": (
        "singleton",
        "schema_version",
        "tracker_id",
        "broker_id",
        "environment",
        "account_alias_sha256",
        "broker_server",
        "journal_sha256",
        "commit_sha",
        "config_sha256",
        "broker_spec_sha256",
        "model_artifact_sha256",
        "lane_id",
        "binding_sha256",
        "key_id",
        "key_fingerprint_sha256",
        "source_trust_sha256",
        "created_at_utc",
        "identity_hmac_sha256",
    ),
    "soak_events": (
        "sequence",
        "event_id",
        "dedup_key",
        "event_type",
        "observed_at_utc",
        "clean_generation",
        "payload_json",
        "previous_hmac_sha256",
        "event_hmac_sha256",
    ),
    "soak_head": (
        "singleton",
        "event_count",
        "head_sequence",
        "head_hmac_sha256",
        "clean_generation",
        "clean_started_at_utc",
        "latest_observed_at_utc",
        "critical_incident_count",
        "review_restart_count",
        "latest_incident_id",
        "demotion_latched",
        "state_hmac_sha256",
    ),
}

_TABLE_SQL = {
    "soak_identity": """CREATE TABLE soak_identity (
        singleton INTEGER PRIMARY KEY CHECK(singleton=1),
        schema_version TEXT NOT NULL,
        tracker_id TEXT NOT NULL UNIQUE,
        broker_id TEXT NOT NULL,
        environment TEXT NOT NULL CHECK(environment='DEMO'),
        account_alias_sha256 TEXT NOT NULL,
        broker_server TEXT NOT NULL,
        journal_sha256 TEXT NOT NULL,
        commit_sha TEXT NOT NULL,
        config_sha256 TEXT NOT NULL,
        broker_spec_sha256 TEXT NOT NULL,
        model_artifact_sha256 TEXT NOT NULL,
        lane_id TEXT NOT NULL,
        binding_sha256 TEXT NOT NULL,
        key_id TEXT NOT NULL,
        key_fingerprint_sha256 TEXT NOT NULL,
        source_trust_sha256 TEXT NOT NULL,
        created_at_utc TEXT NOT NULL,
        identity_hmac_sha256 TEXT NOT NULL
    )""",
    "soak_events": """CREATE TABLE soak_events (
        sequence INTEGER PRIMARY KEY CHECK(sequence > 0),
        event_id TEXT NOT NULL UNIQUE,
        dedup_key TEXT NOT NULL UNIQUE,
        event_type TEXT NOT NULL CHECK(
            event_type IN (
                'SOAK_STARTED','SOAK_RESTARTED_AFTER_REVIEW',
                'CLOSED_FILL','CRITICAL_INCIDENT'
            )
        ),
        observed_at_utc TEXT NOT NULL,
        clean_generation INTEGER NOT NULL CHECK(clean_generation > 0),
        payload_json TEXT NOT NULL,
        previous_hmac_sha256 TEXT NOT NULL,
        event_hmac_sha256 TEXT NOT NULL UNIQUE
    )""",
    "soak_head": """CREATE TABLE soak_head (
        singleton INTEGER PRIMARY KEY CHECK(singleton=1),
        event_count INTEGER NOT NULL CHECK(event_count >= 0),
        head_sequence INTEGER NOT NULL CHECK(head_sequence >= 0),
        head_hmac_sha256 TEXT NOT NULL,
        clean_generation INTEGER NOT NULL CHECK(clean_generation >= 0),
        clean_started_at_utc TEXT NOT NULL,
        latest_observed_at_utc TEXT NOT NULL,
        critical_incident_count INTEGER NOT NULL CHECK(critical_incident_count >= 0),
        review_restart_count INTEGER NOT NULL CHECK(review_restart_count >= 0),
        latest_incident_id TEXT NOT NULL,
        demotion_latched INTEGER NOT NULL CHECK(demotion_latched IN (0,1)),
        state_hmac_sha256 TEXT NOT NULL
    )""",
}

_TRIGGER_SQL = {
    "soak_identity_no_update": """CREATE TRIGGER soak_identity_no_update
        BEFORE UPDATE ON soak_identity
        BEGIN
            SELECT RAISE(ABORT, 'soak identity is immutable');
        END""",
    "soak_identity_no_delete": """CREATE TRIGGER soak_identity_no_delete
        BEFORE DELETE ON soak_identity
        BEGIN
            SELECT RAISE(ABORT, 'soak identity is immutable');
        END""",
    "soak_events_no_update": """CREATE TRIGGER soak_events_no_update
        BEFORE UPDATE ON soak_events
        BEGIN
            SELECT RAISE(ABORT, 'soak events are append-only');
        END""",
    "soak_events_no_delete": """CREATE TRIGGER soak_events_no_delete
        BEFORE DELETE ON soak_events
        BEGIN
            SELECT RAISE(ABORT, 'soak events are append-only');
        END""",
    "soak_head_no_delete": """CREATE TRIGGER soak_head_no_delete
        BEFORE DELETE ON soak_head
        BEGIN
            SELECT RAISE(ABORT, 'soak head is required');
        END""",
}


class SoakTrackerError(RuntimeError):
    """Base fail-closed tracker error."""


class SoakTrackerBindingError(SoakTrackerError):
    """The database or receipt belongs to another exact evidence domain."""


class SoakTrackerDuplicateError(SoakTrackerError):
    """An immutable event or source observation identifier was reused."""


class SoakTrackerIntegrityError(SoakTrackerError):
    """Stored state, HMAC identity, chain, schema, or receipt is invalid."""


class SoakTrackerRollbackError(SoakTrackerIntegrityError):
    """An external assessment proves local rollback, fork, or rewrite."""


class SoakTrackerSourceError(SoakTrackerIntegrityError):
    """An ingestion receipt is missing, forged, stale, or cross-bound."""


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _utc_text(name: str, value: datetime) -> str:
    try:
        normalized = require_utc(name, value)
    except (TypeError, ValueError) as exc:
        raise SoakTrackerError(str(exc)) from exc
    return normalized.isoformat(timespec="microseconds").replace("+00:00", "Z")


def _stored_utc(name: str, value: object) -> datetime:
    if not isinstance(value, str):
        raise SoakTrackerIntegrityError(f"{name} must be canonical UTC text")
    try:
        parsed = require_utc(name, datetime.fromisoformat(value.replace("Z", "+00:00")))
    except (TypeError, ValueError) as exc:
        raise SoakTrackerIntegrityError(f"{name} is not timezone-aware UTC") from exc
    if _utc_text(name, parsed) != value:
        raise SoakTrackerIntegrityError(f"{name} is not canonical UTC")
    return parsed


def _source_utc(name: str, value: object) -> datetime:
    if isinstance(value, datetime):
        try:
            return require_utc(name, value)
        except (TypeError, ValueError) as exc:
            raise SoakTrackerSourceError(f"{name} is not timezone-aware UTC") from exc
    return _stored_utc(name, value)


def _identifier(name: str, value: object) -> str:
    if (
        not isinstance(value, str)
        or value != value.strip()
        or _IDENTIFIER_RE.fullmatch(value) is None
    ):
        raise SoakTrackerError(f"{name} has an invalid format")
    return value


def _exact_text(name: str, value: object, *, maximum: int = 255) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > maximum
        or any(ord(character) < 32 for character in value)
    ):
        raise SoakTrackerError(f"{name} must be exact non-empty text")
    return value


def _strict_hash(name: str, value: object) -> str:
    try:
        return require_hash(name, value)
    except ValueError as exc:
        raise SoakTrackerError(str(exc)) from exc


def _secret(value: object) -> bytes:
    if isinstance(value, str):
        normalized = value.encode("utf-8")
    elif isinstance(value, bytes):
        normalized = value
    else:
        raise SoakTrackerIntegrityError("soak HMAC key must be str or bytes")
    if len(normalized) < 32:
        raise SoakTrackerIntegrityError("soak HMAC key must contain at least 32 bytes")
    return normalized


def _hmac_sha256(secret: bytes, domain: bytes, value: Mapping[str, Any]) -> str:
    return hmac.new(
        secret,
        domain + canonical_json(value).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def _canonical_object(text: object) -> dict[str, Any]:
    def reject_duplicate(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise SoakTrackerIntegrityError("event payload contains duplicate keys")
            result[key] = value
        return result

    if not isinstance(text, str):
        raise SoakTrackerIntegrityError("event payload must be JSON text")
    try:
        value = json.loads(text, object_pairs_hook=reject_duplicate)
    except SoakTrackerIntegrityError:
        raise
    except (TypeError, json.JSONDecodeError) as exc:
        raise SoakTrackerIntegrityError("event payload is not valid JSON") from exc
    if not isinstance(value, dict) or canonical_json(value) != text:
        raise SoakTrackerIntegrityError("event payload is not a canonical object")
    return value


def _normalized_sql(value: object) -> str:
    return " ".join(str(value).strip().rstrip(";").split()).lower()


def _source_details(value: object) -> tuple[tuple[str, object], ...]:
    if not isinstance(value, (tuple, list)):
        raise SoakTrackerSourceError("source receipt details must be key/value pairs")
    normalized: list[tuple[str, object]] = []
    seen: set[str] = set()
    for item in value:
        if not isinstance(item, (tuple, list)) or len(item) != 2:
            raise SoakTrackerSourceError("source receipt detail is invalid")
        key = _identifier("source detail key", item[0])
        raw = item[1]
        if isinstance(raw, bool) or not isinstance(raw, (str, int, float)):
            raise SoakTrackerSourceError("source receipt detail value is invalid")
        detail_value: object = raw
        if isinstance(raw, float):
            detail_value = require_finite("source detail value", raw)
        if key in seen:
            raise SoakTrackerSourceError("source receipt detail keys are duplicated")
        seen.add(key)
        normalized.append((key, detail_value))
    ordered = tuple(sorted(normalized))
    if tuple(normalized) != ordered:
        raise SoakTrackerSourceError("source receipt details must be sorted")
    return ordered


def _receipt_binding_fields(binding: "SoakBinding") -> dict[str, str]:
    return {
        "binding_sha256": binding.binding_sha256,
        "account_alias_sha256": binding.account_alias_sha256,
        "broker_server": binding.broker_server,
        "environment": binding.environment,
        "journal_sha256": binding.journal_sha256,
    }


@dataclass(frozen=True)
class SoakBinding(CanonicalContract):
    """Exact non-secret identity of one soak evidence domain."""

    broker_id: str
    environment: str
    account_alias_sha256: str
    broker_server: str
    journal_sha256: str
    commit_sha: str
    config_sha256: str
    broker_spec_sha256: str
    model_artifact_sha256: str
    lane_id: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "broker_id", _identifier("broker_id", self.broker_id))
        environment = require_text("environment", self.environment, upper=True)
        if environment != "DEMO":
            raise ValueError("soak binding environment must be DEMO")
        object.__setattr__(self, "environment", environment)
        for name in (
            "account_alias_sha256",
            "journal_sha256",
            "config_sha256",
            "broker_spec_sha256",
            "model_artifact_sha256",
        ):
            object.__setattr__(self, name, require_hash(name, getattr(self, name)))
        object.__setattr__(
            self,
            "commit_sha",
            require_hash("commit_sha", self.commit_sha, minimum_length=7),
        )
        object.__setattr__(self, "broker_server", _exact_text("broker_server", self.broker_server))
        object.__setattr__(self, "lane_id", _identifier("lane_id", self.lane_id))

    @property
    def binding_sha256(self) -> str:
        return canonical_sha256(self)


@dataclass(frozen=True)
class SoakSourceReceipt(CanonicalContract):
    """Sealed, signed activation, broker-deal, or incident source fact."""

    source_receipt_id: str
    source_kind: str
    issuer_id: str
    key_id: str
    binding_sha256: str
    account_alias_sha256: str
    broker_server: str
    environment: str
    journal_sha256: str
    subject_id: str
    upstream_receipt_sha256: str
    occurred_at_utc: datetime
    observed_at_utc: datetime
    valid_until_utc: datetime
    details: tuple[tuple[str, object], ...]
    receipt_hmac_sha256: str
    schema_version: str = SOURCE_RECEIPT_SCHEMA_VERSION
    _seal: InitVar[object | None] = None

    def __post_init__(self, _seal: object | None) -> None:
        if _seal is not _SOURCE_RECEIPT_SEAL:
            raise TypeError(
                "SoakSourceReceipt can only be created by verify_soak_source_receipt"
            )
        object.__setattr__(
            self,
            "source_receipt_id",
            _identifier("source_receipt_id", self.source_receipt_id),
        )
        kind = require_text("source_kind", self.source_kind, upper=True)
        if kind not in _SOURCE_HMAC_DOMAINS:
            raise ValueError("source_kind is invalid")
        object.__setattr__(self, "source_kind", kind)
        object.__setattr__(self, "issuer_id", _identifier("issuer_id", self.issuer_id))
        object.__setattr__(self, "key_id", _identifier("key_id", self.key_id))
        for name in (
            "binding_sha256",
            "account_alias_sha256",
            "journal_sha256",
            "upstream_receipt_sha256",
            "receipt_hmac_sha256",
        ):
            object.__setattr__(self, name, _strict_hash(name, getattr(self, name)))
        object.__setattr__(
            self,
            "broker_server",
            _exact_text("broker_server", self.broker_server),
        )
        environment = require_text("environment", self.environment, upper=True)
        if environment != "DEMO":
            raise ValueError("soak source environment must be DEMO")
        object.__setattr__(self, "environment", environment)
        object.__setattr__(self, "subject_id", _identifier("subject_id", self.subject_id))
        occurred = require_utc("occurred_at_utc", self.occurred_at_utc)
        observed = require_utc("observed_at_utc", self.observed_at_utc)
        valid_until = require_utc("valid_until_utc", self.valid_until_utc)
        if observed < occurred:
            raise ValueError("source receipt observation predates source occurrence")
        if (observed - occurred).total_seconds() > MAX_SOURCE_OBSERVATION_DELAY_SECONDS:
            raise ValueError("source receipt observation delay exceeds maximum")
        if valid_until < observed:
            raise ValueError("source receipt validity is inverted")
        if (valid_until - observed).total_seconds() > MAX_SOURCE_RECEIPT_LIFETIME_SECONDS:
            raise ValueError("source receipt lifetime exceeds maximum")
        normalized_details = _source_details(self.details)
        object.__setattr__(self, "details", normalized_details)
        detail_map = dict(normalized_details)
        if kind == "DEMO_AUTO_ACTIVATION":
            if detail_map != {"mode": "DEMO_AUTO"}:
                raise ValueError("activation source details are invalid")
        elif kind == "BROKER_CLOSED_DEAL":
            if set(detail_map) != {
                "closed_volume",
                "intent_id",
                "symbol",
                "ticket",
            }:
                raise ValueError("closed-deal source details are invalid")
            _identifier("intent_id", detail_map["intent_id"])
            _identifier("ticket", detail_map["ticket"])
            volume = require_finite(
                "closed_volume", detail_map["closed_volume"], positive=True
            )
            symbol = require_text("symbol", detail_map["symbol"], upper=True)
            if _SYMBOL_RE.fullmatch(symbol) is None:
                raise ValueError("closed-deal symbol is invalid")
            object.__setattr__(
                self,
                "details",
                tuple(
                    sorted(
                        {
                            **detail_map,
                            "closed_volume": volume,
                            "symbol": symbol,
                        }.items()
                    )
                ),
            )
        else:
            if set(detail_map) != {"reason_code"}:
                raise ValueError("incident source details are invalid")
            reason = require_text("reason_code", detail_map["reason_code"], upper=True)
            if _REASON_RE.fullmatch(reason) is None:
                raise ValueError("incident reason code is invalid")
            object.__setattr__(self, "details", (("reason_code", reason),))
        if self.schema_version != SOURCE_RECEIPT_SCHEMA_VERSION:
            raise ValueError("soak source receipt schema is invalid")

    @property
    def signing_payload(self) -> dict[str, Any]:
        payload = self.to_canonical_dict()
        payload.pop("receipt_hmac_sha256")
        return payload


@dataclass(frozen=True)
class DualReviewReceipt(CanonicalContract):
    """Two independently signed reviewer approvals for one latched incident."""

    review_receipt_id: str
    issuer_id: str
    binding_sha256: str
    account_alias_sha256: str
    broker_server: str
    environment: str
    journal_sha256: str
    incident_id: str
    review_evidence_sha256: str
    reviewer_one_id: str
    reviewer_one_key_id: str
    reviewer_two_id: str
    reviewer_two_key_id: str
    reviewed_at_utc: datetime
    observed_at_utc: datetime
    valid_until_utc: datetime
    reviewer_one_hmac_sha256: str
    reviewer_two_hmac_sha256: str
    schema_version: str = DUAL_REVIEW_RECEIPT_SCHEMA_VERSION
    _seal: InitVar[object | None] = None

    def __post_init__(self, _seal: object | None) -> None:
        if _seal is not _DUAL_REVIEW_RECEIPT_SEAL:
            raise TypeError(
                "DualReviewReceipt can only be created by verify_dual_review_receipt"
            )
        for name in (
            "review_receipt_id",
            "issuer_id",
            "incident_id",
            "reviewer_one_id",
            "reviewer_one_key_id",
            "reviewer_two_id",
            "reviewer_two_key_id",
        ):
            object.__setattr__(self, name, _identifier(name, getattr(self, name)))
        if self.reviewer_one_id == self.reviewer_two_id:
            raise ValueError("dual review requires distinct reviewer identities")
        if self.reviewer_one_key_id == self.reviewer_two_key_id:
            raise ValueError("dual review requires distinct signing keys")
        for name in (
            "binding_sha256",
            "account_alias_sha256",
            "journal_sha256",
            "review_evidence_sha256",
            "reviewer_one_hmac_sha256",
            "reviewer_two_hmac_sha256",
        ):
            object.__setattr__(self, name, _strict_hash(name, getattr(self, name)))
        object.__setattr__(
            self,
            "broker_server",
            _exact_text("broker_server", self.broker_server),
        )
        environment = require_text("environment", self.environment, upper=True)
        if environment != "DEMO":
            raise ValueError("dual-review environment must be DEMO")
        object.__setattr__(self, "environment", environment)
        reviewed = require_utc("reviewed_at_utc", self.reviewed_at_utc)
        observed = require_utc("observed_at_utc", self.observed_at_utc)
        valid_until = require_utc("valid_until_utc", self.valid_until_utc)
        if observed < reviewed:
            raise ValueError("dual-review observation predates review")
        if (observed - reviewed).total_seconds() > MAX_SOURCE_OBSERVATION_DELAY_SECONDS:
            raise ValueError("dual-review observation delay exceeds maximum")
        if valid_until < observed:
            raise ValueError("dual-review validity is inverted")
        if (valid_until - observed).total_seconds() > MAX_SOURCE_RECEIPT_LIFETIME_SECONDS:
            raise ValueError("dual-review lifetime exceeds maximum")
        if self.schema_version != DUAL_REVIEW_RECEIPT_SCHEMA_VERSION:
            raise ValueError("dual-review receipt schema is invalid")

    @property
    def signing_payload(self) -> dict[str, Any]:
        payload = self.to_canonical_dict()
        payload.pop("reviewer_one_hmac_sha256")
        payload.pop("reviewer_two_hmac_sha256")
        return payload


def _trusted_source_keys(
    trusted: Mapping[str, Mapping[str, tuple[str, ...] | list[str] | set[str] | frozenset[str]]],
    *,
    source_kind: str,
    issuer_id: str,
) -> frozenset[str]:
    by_issuer = trusted.get(source_kind)
    if not isinstance(by_issuer, Mapping):
        raise SoakTrackerSourceError("source kind has no trusted issuer allowlist")
    keys = by_issuer.get(issuer_id)
    if not isinstance(keys, (tuple, list, set, frozenset)) or isinstance(
        keys, (str, bytes)
    ):
        raise SoakTrackerSourceError("source issuer has no trusted key allowlist")
    normalized = frozenset(_identifier("trusted source key", key) for key in keys)
    if not normalized:
        raise SoakTrackerSourceError("source issuer key allowlist is empty")
    return normalized


def _verify_source_freshness(
    *,
    observed_at_utc: datetime,
    valid_until_utc: datetime,
    clock_provider: Callable[[], datetime],
) -> None:
    try:
        now = require_utc("trusted source clock", clock_provider())
    except (TypeError, ValueError) as exc:
        raise SoakTrackerSourceError("trusted source clock is invalid") from exc
    if observed_at_utc > now + timedelta(seconds=MAX_SOURCE_FUTURE_DRIFT_SECONDS):
        raise SoakTrackerSourceError("source receipt is from the future")
    if now > valid_until_utc:
        raise SoakTrackerSourceError("source receipt is stale")


def verify_soak_source_receipt(
    payload: Mapping[str, Any],
    *,
    expected_binding: SoakBinding,
    key_provider: Callable[[str], str | bytes],
    trusted_source_issuer_keys: Mapping[
        str,
        Mapping[str, tuple[str, ...] | list[str] | set[str] | frozenset[str]],
    ],
    clock_provider: Callable[[], datetime] = _utc_now,
    enforce_freshness: bool = True,
) -> SoakSourceReceipt:
    if type(expected_binding) is not SoakBinding:
        raise TypeError("expected_binding must be SoakBinding")
    if not isinstance(payload, Mapping):
        raise SoakTrackerSourceError("source receipt payload must be an object")
    if not callable(key_provider) or not callable(clock_provider):
        raise TypeError("source receipt key and clock providers must be callable")
    raw = dict(payload)
    expected_fields = {
        "source_receipt_id",
        "source_kind",
        "issuer_id",
        "key_id",
        "binding_sha256",
        "account_alias_sha256",
        "broker_server",
        "environment",
        "journal_sha256",
        "subject_id",
        "upstream_receipt_sha256",
        "occurred_at_utc",
        "observed_at_utc",
        "valid_until_utc",
        "details",
        "receipt_hmac_sha256",
        "schema_version",
    }
    if set(raw) != expected_fields:
        raise SoakTrackerSourceError("source receipt fields are invalid")
    try:
        receipt = SoakSourceReceipt(
            source_receipt_id=raw["source_receipt_id"],
            source_kind=raw["source_kind"],
            issuer_id=raw["issuer_id"],
            key_id=raw["key_id"],
            binding_sha256=raw["binding_sha256"],
            account_alias_sha256=raw["account_alias_sha256"],
            broker_server=raw["broker_server"],
            environment=raw["environment"],
            journal_sha256=raw["journal_sha256"],
            subject_id=raw["subject_id"],
            upstream_receipt_sha256=raw["upstream_receipt_sha256"],
            occurred_at_utc=_source_utc("occurred_at_utc", raw["occurred_at_utc"]),
            observed_at_utc=_source_utc("observed_at_utc", raw["observed_at_utc"]),
            valid_until_utc=_source_utc(
                "valid_until_utc", raw["valid_until_utc"]
            ),
            details=_source_details(raw["details"]),
            receipt_hmac_sha256=raw["receipt_hmac_sha256"],
            schema_version=raw["schema_version"],
            _seal=_SOURCE_RECEIPT_SEAL,
        )
    except SoakTrackerSourceError:
        raise
    except (KeyError, TypeError, ValueError, SoakTrackerError) as exc:
        raise SoakTrackerSourceError("source receipt is structurally invalid") from exc
    if canonical_json(raw) != receipt.canonical_json():
        raise SoakTrackerSourceError("source receipt is not canonical")
    expected_binding_fields = _receipt_binding_fields(expected_binding)
    if any(
        getattr(receipt, field) != expected
        for field, expected in expected_binding_fields.items()
    ):
        raise SoakTrackerBindingError("source receipt exact binding does not match")
    trusted_keys = _trusted_source_keys(
        trusted_source_issuer_keys,
        source_kind=receipt.source_kind,
        issuer_id=receipt.issuer_id,
    )
    if receipt.key_id not in trusted_keys:
        raise SoakTrackerSourceError("source receipt signing key is not trusted")
    try:
        source_secret = _secret(key_provider(receipt.key_id))
    except Exception as exc:
        raise SoakTrackerSourceError("source receipt key is unavailable") from exc
    expected_hmac = _hmac_sha256(
        source_secret,
        _SOURCE_HMAC_DOMAINS[receipt.source_kind],
        receipt.signing_payload,
    )
    if not hmac.compare_digest(receipt.receipt_hmac_sha256, expected_hmac):
        raise SoakTrackerSourceError("source receipt HMAC is invalid")
    if enforce_freshness:
        _verify_source_freshness(
            observed_at_utc=receipt.observed_at_utc,
            valid_until_utc=receipt.valid_until_utc,
            clock_provider=clock_provider,
        )
    return receipt


def verify_dual_review_receipt(
    payload: Mapping[str, Any],
    *,
    expected_binding: SoakBinding,
    key_provider: Callable[[str], str | bytes],
    trusted_source_issuer_keys: Mapping[
        str,
        Mapping[str, tuple[str, ...] | list[str] | set[str] | frozenset[str]],
    ],
    clock_provider: Callable[[], datetime] = _utc_now,
    enforce_freshness: bool = True,
) -> DualReviewReceipt:
    if type(expected_binding) is not SoakBinding:
        raise TypeError("expected_binding must be SoakBinding")
    if not isinstance(payload, Mapping):
        raise SoakTrackerSourceError("dual-review payload must be an object")
    if not callable(key_provider) or not callable(clock_provider):
        raise TypeError("dual-review key and clock providers must be callable")
    raw = dict(payload)
    expected_fields = {
        "review_receipt_id",
        "issuer_id",
        "binding_sha256",
        "account_alias_sha256",
        "broker_server",
        "environment",
        "journal_sha256",
        "incident_id",
        "review_evidence_sha256",
        "reviewer_one_id",
        "reviewer_one_key_id",
        "reviewer_two_id",
        "reviewer_two_key_id",
        "reviewed_at_utc",
        "observed_at_utc",
        "valid_until_utc",
        "reviewer_one_hmac_sha256",
        "reviewer_two_hmac_sha256",
        "schema_version",
    }
    if set(raw) != expected_fields:
        raise SoakTrackerSourceError("dual-review receipt fields are invalid")
    try:
        receipt = DualReviewReceipt(
            review_receipt_id=raw["review_receipt_id"],
            issuer_id=raw["issuer_id"],
            binding_sha256=raw["binding_sha256"],
            account_alias_sha256=raw["account_alias_sha256"],
            broker_server=raw["broker_server"],
            environment=raw["environment"],
            journal_sha256=raw["journal_sha256"],
            incident_id=raw["incident_id"],
            review_evidence_sha256=raw["review_evidence_sha256"],
            reviewer_one_id=raw["reviewer_one_id"],
            reviewer_one_key_id=raw["reviewer_one_key_id"],
            reviewer_two_id=raw["reviewer_two_id"],
            reviewer_two_key_id=raw["reviewer_two_key_id"],
            reviewed_at_utc=_source_utc("reviewed_at_utc", raw["reviewed_at_utc"]),
            observed_at_utc=_source_utc("observed_at_utc", raw["observed_at_utc"]),
            valid_until_utc=_source_utc(
                "valid_until_utc", raw["valid_until_utc"]
            ),
            reviewer_one_hmac_sha256=raw["reviewer_one_hmac_sha256"],
            reviewer_two_hmac_sha256=raw["reviewer_two_hmac_sha256"],
            schema_version=raw["schema_version"],
            _seal=_DUAL_REVIEW_RECEIPT_SEAL,
        )
    except SoakTrackerSourceError:
        raise
    except (KeyError, TypeError, ValueError, SoakTrackerError) as exc:
        raise SoakTrackerSourceError("dual-review receipt is structurally invalid") from exc
    if canonical_json(raw) != receipt.canonical_json():
        raise SoakTrackerSourceError("dual-review receipt is not canonical")
    expected_binding_fields = _receipt_binding_fields(expected_binding)
    if any(
        getattr(receipt, field) != expected
        for field, expected in expected_binding_fields.items()
    ):
        raise SoakTrackerBindingError("dual-review exact binding does not match")
    trusted_keys = _trusted_source_keys(
        trusted_source_issuer_keys,
        source_kind="DUAL_REVIEW",
        issuer_id=receipt.issuer_id,
    )
    reviewer_keys = (receipt.reviewer_one_key_id, receipt.reviewer_two_key_id)
    if any(key not in trusted_keys for key in reviewer_keys):
        raise SoakTrackerSourceError("dual-review signing key is not trusted")
    signatures = (
        receipt.reviewer_one_hmac_sha256,
        receipt.reviewer_two_hmac_sha256,
    )
    for key_id, signature in zip(reviewer_keys, signatures, strict=True):
        try:
            review_secret = _secret(key_provider(key_id))
        except Exception as exc:
            raise SoakTrackerSourceError("dual-review key is unavailable") from exc
        expected_hmac = _hmac_sha256(
            review_secret,
            _DUAL_REVIEW_HMAC_DOMAIN,
            receipt.signing_payload,
        )
        if not hmac.compare_digest(signature, expected_hmac):
            raise SoakTrackerSourceError("dual-review HMAC is invalid")
    if enforce_freshness:
        _verify_source_freshness(
            observed_at_utc=receipt.observed_at_utc,
            valid_until_utc=receipt.valid_until_utc,
            clock_provider=clock_provider,
        )
    return receipt


@dataclass(frozen=True)
class SoakEventReceipt(CanonicalContract):
    sequence: int
    event_id: str
    event_type: str
    observed_at_utc: datetime
    clean_generation: int
    previous_hmac_sha256: str
    event_hmac_sha256: str


@dataclass(frozen=True)
class SoakAssessment(CanonicalContract):
    clean_period_started_at_utc: datetime
    assessed_at_utc: datetime
    latest_event_at_utc: datetime
    clean_generation: int
    clean_duration_seconds: float
    clean_duration_days: float
    closed_fills: int
    xauusd_closed_fills: int
    duration_30_days_met: bool
    closed_fills_50_met: bool
    xauusd_fills_20_met: bool
    statistical_criteria_met: bool
    critical_incident_count: int
    review_restart_count: int
    demotion_latched: bool
    blocker_codes: tuple[str, ...]
    ready: bool = field(default=False, init=False)
    promotion_eligible: bool = field(default=False, init=False)
    execution_enabled: bool = field(default=False, init=False)
    safe_to_demo_auto_order: bool = field(default=False, init=False)
    live_allowed: bool = field(default=False, init=False)
    order_capability: str = field(default="DISABLED", init=False)


@dataclass(frozen=True)
class SoakAssessmentReceipt(CanonicalContract):
    """Sealed, HMAC-signed checkpoint suitable for independent custody."""

    tracker_id: str
    broker_id: str
    environment: str
    account_alias_sha256: str
    broker_server: str
    journal_sha256: str
    commit_sha: str
    config_sha256: str
    broker_spec_sha256: str
    model_artifact_sha256: str
    lane_id: str
    binding_sha256: str
    key_id: str
    event_count: int
    head_hmac_sha256: str
    clean_generation: int
    clean_period_started_at_utc: datetime
    latest_event_at_utc: datetime
    assessed_at_utc: datetime
    clean_duration_seconds: float
    clean_duration_days: float
    closed_fills: int
    xauusd_closed_fills: int
    duration_30_days_met: bool
    closed_fills_50_met: bool
    xauusd_fills_20_met: bool
    statistical_criteria_met: bool
    critical_incident_count: int
    review_restart_count: int
    demotion_latched: bool
    blocker_codes: tuple[str, ...]
    receipt_hmac_sha256: str
    schema_version: str = ASSESSMENT_RECEIPT_SCHEMA_VERSION
    ready: bool = field(default=False, init=False)
    promotion_eligible: bool = field(default=False, init=False)
    execution_enabled: bool = field(default=False, init=False)
    safe_to_demo_auto_order: bool = field(default=False, init=False)
    live_allowed: bool = field(default=False, init=False)
    order_capability: str = field(default="DISABLED", init=False)
    _seal: InitVar[object | None] = None

    def __post_init__(self, _seal: object | None) -> None:
        if _seal is not _RECEIPT_SEAL:
            raise TypeError("SoakAssessmentReceipt can only be created by the tracker")
        object.__setattr__(self, "tracker_id", _identifier("tracker_id", self.tracker_id))
        object.__setattr__(self, "broker_id", _identifier("broker_id", self.broker_id))
        environment = require_text("environment", self.environment, upper=True)
        if environment != "DEMO":
            raise ValueError("assessment receipt environment must be DEMO")
        object.__setattr__(self, "environment", environment)
        for name in (
            "account_alias_sha256",
            "journal_sha256",
            "config_sha256",
            "broker_spec_sha256",
            "model_artifact_sha256",
            "binding_sha256",
            "head_hmac_sha256",
            "receipt_hmac_sha256",
        ):
            object.__setattr__(self, name, require_hash(name, getattr(self, name)))
        object.__setattr__(
            self,
            "commit_sha",
            require_hash("commit_sha", self.commit_sha, minimum_length=7),
        )
        object.__setattr__(
            self,
            "broker_server",
            _exact_text("broker_server", self.broker_server),
        )
        for name in ("lane_id", "key_id"):
            object.__setattr__(self, name, _identifier(name, getattr(self, name)))
        require_int("event_count", self.event_count, minimum=1)
        require_int("clean_generation", self.clean_generation, minimum=1)
        require_int("closed_fills", self.closed_fills, minimum=0)
        require_int("xauusd_closed_fills", self.xauusd_closed_fills, minimum=0)
        require_int("critical_incident_count", self.critical_incident_count, minimum=0)
        require_int("review_restart_count", self.review_restart_count, minimum=0)
        for name in (
            "clean_period_started_at_utc",
            "latest_event_at_utc",
            "assessed_at_utc",
        ):
            require_utc(name, getattr(self, name))
        if self.assessed_at_utc < self.latest_event_at_utc:
            raise ValueError("assessment receipt predates its latest event")
        if self.clean_period_started_at_utc > self.latest_event_at_utc:
            raise ValueError("clean generation starts after the latest event")
        expected_seconds = (
            self.assessed_at_utc - self.clean_period_started_at_utc
        ).total_seconds()
        if self.clean_duration_seconds != expected_seconds:
            raise ValueError("receipt clean duration is inconsistent")
        if self.clean_duration_days != expected_seconds / 86400:
            raise ValueError("receipt clean duration days are inconsistent")
        if self.xauusd_closed_fills > self.closed_fills:
            raise ValueError("XAUUSD fills exceed total fills")
        if self.clean_generation != (
            self.critical_incident_count + self.review_restart_count + 1
        ):
            raise ValueError("receipt clean generation is inconsistent")
        if self.review_restart_count > self.critical_incident_count:
            raise ValueError("receipt review restart count exceeds incidents")
        if self.critical_incident_count == 0 and self.demotion_latched:
            raise ValueError("receipt demotion latch has no incident evidence")
        expected_statistical = (
            self.duration_30_days_met
            and self.closed_fills_50_met
            and self.xauusd_fills_20_met
        )
        if self.duration_30_days_met != (expected_seconds >= MINIMUM_CLEAN_DAYS * 86400):
            raise ValueError("receipt duration criterion is inconsistent")
        if self.closed_fills_50_met != (self.closed_fills >= MINIMUM_CLOSED_FILLS):
            raise ValueError("receipt fill criterion is inconsistent")
        if self.xauusd_fills_20_met != (
            self.xauusd_closed_fills >= MINIMUM_XAUUSD_CLOSED_FILLS
        ):
            raise ValueError("receipt XAUUSD criterion is inconsistent")
        if self.statistical_criteria_met != expected_statistical:
            raise ValueError("receipt criteria aggregate is inconsistent")
        blockers = tuple(sorted(set(self.blocker_codes)))
        expected_blockers = {"DENY_ONLY_TRACKER"}
        if not self.duration_30_days_met:
            expected_blockers.add("CLEAN_DURATION_30_DAYS_REQUIRED")
        if not self.closed_fills_50_met:
            expected_blockers.add("CLOSED_FILLS_50_REQUIRED")
        if not self.xauusd_fills_20_met:
            expected_blockers.add("XAUUSD_CLOSED_FILLS_20_REQUIRED")
        if self.demotion_latched:
            expected_blockers.add("CRITICAL_INCIDENT_DEMOTION_LATCHED")
        if blockers != self.blocker_codes or set(blockers) != expected_blockers:
            raise ValueError("receipt blocker codes are invalid")
        if self.schema_version != ASSESSMENT_RECEIPT_SCHEMA_VERSION:
            raise ValueError("assessment receipt schema is invalid")

    @property
    def signing_payload(self) -> dict[str, Any]:
        value = self.to_canonical_dict()
        value.pop("receipt_hmac_sha256")
        return value


@dataclass(frozen=True)
class _SoakState:
    event_count: int = 0
    head_hmac_sha256: str = ZERO_HMAC_SHA256
    clean_generation: int = 0
    clean_started_at_utc: datetime | None = None
    latest_observed_at_utc: datetime | None = None
    critical_incident_count: int = 0
    review_restart_count: int = 0
    latest_incident_id: str | None = None
    demotion_latched: bool = False
    closed_fills: int = 0
    xauusd_closed_fills: int = 0


class DemoAutoSoakTracker:
    """SQLite WAL/FULL HMAC journal whose public results always deny orders."""

    def __init__(
        self,
        path: str | Path,
        *,
        binding: SoakBinding,
        key_id: str,
        key_provider: Callable[[str], str | bytes],
        source_key_provider: Callable[[str], str | bytes],
        trusted_source_issuer_keys: Mapping[
            str,
            Mapping[str, tuple[str, ...] | list[str] | set[str] | frozenset[str]],
        ],
        clock_provider: Callable[[], datetime] = _utc_now,
        expected_receipt: SoakAssessmentReceipt | None = None,
    ) -> None:
        if type(binding) is not SoakBinding:
            raise TypeError("binding must be SoakBinding")
        if not callable(key_provider) or not callable(source_key_provider):
            raise TypeError("ledger and source key providers must be callable")
        if not callable(clock_provider):
            raise TypeError("clock_provider must be callable")
        if not isinstance(trusted_source_issuer_keys, Mapping):
            raise TypeError("trusted_source_issuer_keys must be a mapping")
        if expected_receipt is not None and type(expected_receipt) is not SoakAssessmentReceipt:
            raise TypeError("expected_receipt must be a sealed SoakAssessmentReceipt")
        self.path = Path(path)
        self.binding = binding
        self.key_id = _identifier("key_id", key_id)
        self._key_provider = key_provider
        self._source_key_provider = source_key_provider
        allowed_kinds = set(_SOURCE_HMAC_DOMAINS) | {"DUAL_REVIEW"}
        normalized_trust: dict[str, dict[str, tuple[str, ...]]] = {}
        if set(trusted_source_issuer_keys) != allowed_kinds:
            raise SoakTrackerSourceError("trusted source kinds are incomplete")
        for kind, issuers in trusted_source_issuer_keys.items():
            if not isinstance(issuers, Mapping) or not issuers:
                raise SoakTrackerSourceError("trusted source issuers are invalid")
            normalized_issuers: dict[str, tuple[str, ...]] = {}
            for issuer, keys in issuers.items():
                normalized_issuer = _identifier("trusted source issuer", issuer)
                if not isinstance(keys, (tuple, list, set, frozenset)) or isinstance(
                    keys, (str, bytes)
                ):
                    raise SoakTrackerSourceError("trusted source keys are invalid")
                normalized_keys = tuple(
                    sorted({_identifier("trusted source key", key) for key in keys})
                )
                if not normalized_keys or self.key_id in normalized_keys:
                    raise SoakTrackerSourceError(
                        "trusted source keys must be nonempty and separate"
                    )
                normalized_issuers[normalized_issuer] = normalized_keys
            normalized_trust[kind] = MappingProxyType(normalized_issuers)
        self._trusted_source_issuer_keys = MappingProxyType(normalized_trust)
        self._clock_provider = clock_provider
        ledger_fingerprint = hashlib.sha256(self._secret()).hexdigest()
        source_fingerprints: dict[str, str] = {}
        source_key_uses: dict[str, tuple[str, str]] = {}
        for kind, issuers in self._trusted_source_issuer_keys.items():
            for issuer, key_ids in issuers.items():
                for source_key_id in key_ids:
                    use = (kind, issuer)
                    previous_use = source_key_uses.setdefault(source_key_id, use)
                    if previous_use != use:
                        raise SoakTrackerSourceError(
                            "one source key cannot span trust domains"
                        )
                    fingerprint = hashlib.sha256(
                        self._source_secret(source_key_id)
                    ).hexdigest()
                    if fingerprint == ledger_fingerprint:
                        raise SoakTrackerSourceError(
                            "source and ledger keys must be cryptographically separate"
                        )
                    prior_key = source_fingerprints.setdefault(
                        fingerprint, source_key_id
                    )
                    if prior_key != source_key_id:
                        raise SoakTrackerSourceError(
                            "trusted source keys must use independent secret material"
                        )
        self._database_preexisted = self.path.exists()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.tracker_id = ""
        self.created_at_utc: datetime | None = None
        self._initialize_or_verify(expected_receipt=expected_receipt)

    def _now(self) -> datetime:
        try:
            return require_utc("trusted soak clock", self._clock_provider())
        except (TypeError, ValueError) as exc:
            raise SoakTrackerIntegrityError("trusted soak clock is invalid") from exc

    def _secret(self) -> bytes:
        try:
            return _secret(self._key_provider(self.key_id))
        except SoakTrackerIntegrityError:
            raise
        except Exception as exc:
            raise SoakTrackerIntegrityError("soak HMAC key is unavailable") from exc

    def _source_secret(self, key_id: str) -> bytes:
        try:
            return _secret(self._source_key_provider(key_id))
        except SoakTrackerIntegrityError:
            raise
        except Exception as exc:
            raise SoakTrackerSourceError("soak source key is unavailable") from exc

    def _source_trust_sha256(self) -> str:
        values = {
            kind: {
                issuer: {
                    key_id: hashlib.sha256(self._source_secret(key_id)).hexdigest()
                    for key_id in key_ids
                }
                for issuer, key_ids in issuers.items()
            }
            for kind, issuers in self._trusted_source_issuer_keys.items()
        }
        return canonical_sha256(values)

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(str(self.path), timeout=10.0, isolation_level=None)
        try:
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA busy_timeout=10000")
            connection.execute("PRAGMA foreign_keys=ON")
            mode = str(connection.execute("PRAGMA journal_mode=WAL").fetchone()[0]).lower()
            connection.execute("PRAGMA synchronous=FULL")
            if mode != "wal":
                raise SoakTrackerIntegrityError("SQLite WAL mode is unavailable")
            if int(connection.execute("PRAGMA synchronous").fetchone()[0]) != 2:
                raise SoakTrackerIntegrityError("SQLite FULL sync is unavailable")
            if int(connection.execute("PRAGMA foreign_keys").fetchone()[0]) != 1:
                raise SoakTrackerIntegrityError("SQLite foreign keys are unavailable")
            if int(connection.execute("PRAGMA busy_timeout").fetchone()[0]) != 10000:
                raise SoakTrackerIntegrityError("SQLite busy timeout is unavailable")
            return connection
        except Exception:
            connection.close()
            raise

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            yield connection
            connection.execute("COMMIT")
        except Exception:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()

    @contextmanager
    def _reader(self) -> Iterator[sqlite3.Connection]:
        connection = self._connect()
        try:
            yield connection
        finally:
            connection.close()

    def _identity_body(self, *, tracker_id: str, created_at_utc: str) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "tracker_id": tracker_id,
            "binding": self.binding.to_canonical_dict(),
            "binding_sha256": self.binding.binding_sha256,
            "key_id": self.key_id,
            "source_trust_sha256": self._source_trust_sha256(),
            "created_at_utc": created_at_utc,
        }

    def _empty_state_body(self) -> dict[str, Any]:
        return self._state_body(_SoakState())

    def _state_body(self, state: _SoakState) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "tracker_id": self.tracker_id,
            "binding_sha256": self.binding.binding_sha256,
            "event_count": state.event_count,
            "head_sequence": state.event_count,
            "head_hmac_sha256": state.head_hmac_sha256,
            "clean_generation": state.clean_generation,
            "clean_started_at_utc": (
                "" if state.clean_started_at_utc is None else _utc_text("clean start", state.clean_started_at_utc)
            ),
            "latest_observed_at_utc": (
                "" if state.latest_observed_at_utc is None else _utc_text("latest event", state.latest_observed_at_utc)
            ),
            "critical_incident_count": state.critical_incident_count,
            "review_restart_count": state.review_restart_count,
            "latest_incident_id": (
                "" if state.latest_incident_id is None else state.latest_incident_id
            ),
            "demotion_latched": state.demotion_latched,
        }

    def _initialize_or_verify(
        self, *, expected_receipt: SoakAssessmentReceipt | None
    ) -> None:
        secret = self._secret()
        now = self._now()
        with self._transaction() as connection:
            tables = {
                str(row[0])
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
                ).fetchall()
            }
            if not tables:
                if self._database_preexisted:
                    raise SoakTrackerIntegrityError("existing soak database is empty")
                self._create_schema(connection, secret=secret, now=now)
            elif tables != set(_EXPECTED_TABLE_COLUMNS):
                raise SoakTrackerIntegrityError("soak database is partial or unknown")
            state = self._verify_connection(connection, secret)
            if expected_receipt is not None:
                self._verify_external_receipt(
                    connection,
                    state=state,
                    receipt=expected_receipt,
                    secret=secret,
                    now=now,
                )

    def _create_schema(
        self,
        connection: sqlite3.Connection,
        *,
        secret: bytes,
        now: datetime,
    ) -> None:
        for sql in _TABLE_SQL.values():
            connection.execute(sql)
        for sql in _TRIGGER_SQL.values():
            connection.execute(sql)
        self.tracker_id = "soak-" + uuid.uuid4().hex
        created_at = _utc_text("created_at_utc", now)
        identity_body = self._identity_body(
            tracker_id=self.tracker_id,
            created_at_utc=created_at,
        )
        connection.execute(
            """INSERT INTO soak_identity(
                singleton, schema_version, tracker_id, broker_id, environment,
                account_alias_sha256, broker_server, journal_sha256, commit_sha,
                config_sha256, broker_spec_sha256, model_artifact_sha256,
                lane_id, binding_sha256, key_id, key_fingerprint_sha256,
                source_trust_sha256, created_at_utc, identity_hmac_sha256
            ) VALUES(1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                SCHEMA_VERSION,
                self.tracker_id,
                self.binding.broker_id,
                self.binding.environment,
                self.binding.account_alias_sha256,
                self.binding.broker_server,
                self.binding.journal_sha256,
                self.binding.commit_sha,
                self.binding.config_sha256,
                self.binding.broker_spec_sha256,
                self.binding.model_artifact_sha256,
                self.binding.lane_id,
                self.binding.binding_sha256,
                self.key_id,
                hashlib.sha256(secret).hexdigest(),
                self._source_trust_sha256(),
                created_at,
                _hmac_sha256(secret, _IDENTITY_HMAC_DOMAIN, identity_body),
            ),
        )
        empty = _SoakState()
        connection.execute(
            """INSERT INTO soak_head(
                singleton, event_count, head_sequence, head_hmac_sha256,
                clean_generation, clean_started_at_utc,
                latest_observed_at_utc, critical_incident_count,
                review_restart_count, latest_incident_id, demotion_latched,
                state_hmac_sha256
            ) VALUES(1, 0, 0, ?, 0, '', '', 0, 0, '', 0, ?)""",
            (
                ZERO_HMAC_SHA256,
                _hmac_sha256(secret, _STATE_HMAC_DOMAIN, self._state_body(empty)),
            ),
        )

    def _verify_schema(self, connection: sqlite3.Connection) -> None:
        tables = {
            str(row[0]): str(row[1])
            for row in connection.execute(
                "SELECT name, sql FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
            ).fetchall()
        }
        if set(tables) != set(_EXPECTED_TABLE_COLUMNS) or any(
            _normalized_sql(tables[name]) != _normalized_sql(expected)
            for name, expected in _TABLE_SQL.items()
        ):
            raise SoakTrackerIntegrityError("soak table definitions are invalid")
        for table, columns in _EXPECTED_TABLE_COLUMNS.items():
            actual = tuple(
                str(row[1])
                for row in connection.execute(f"PRAGMA table_info({table})").fetchall()
            )
            if actual != columns:
                raise SoakTrackerIntegrityError(f"{table} columns are invalid")
        triggers = {
            str(row[0]): str(row[1])
            for row in connection.execute(
                "SELECT name, sql FROM sqlite_master WHERE type='trigger'"
            ).fetchall()
        }
        if set(triggers) != set(_TRIGGER_SQL) or any(
            _normalized_sql(triggers[name]) != _normalized_sql(expected)
            for name, expected in _TRIGGER_SQL.items()
        ):
            raise SoakTrackerIntegrityError("soak trigger definitions are invalid")
        user_indexes = connection.execute(
            "SELECT name FROM sqlite_master WHERE type='index' AND sql IS NOT NULL"
        ).fetchall()
        if user_indexes:
            raise SoakTrackerIntegrityError("unexpected soak index exists")

    def _verify_identity(self, connection: sqlite3.Connection, secret: bytes) -> None:
        rows = connection.execute("SELECT * FROM soak_identity").fetchall()
        if len(rows) != 1 or int(rows[0]["singleton"]) != 1:
            raise SoakTrackerIntegrityError("soak identity singleton is invalid")
        row = rows[0]
        try:
            tracker_id = _identifier("stored tracker_id", row["tracker_id"])
            created_at = _stored_utc("stored created_at_utc", row["created_at_utc"])
        except SoakTrackerError as exc:
            raise SoakTrackerIntegrityError("stored soak identity is invalid") from exc
        try:
            observed = SoakBinding(
                broker_id=row["broker_id"],
                environment=row["environment"],
                account_alias_sha256=row["account_alias_sha256"],
                broker_server=row["broker_server"],
                journal_sha256=row["journal_sha256"],
                commit_sha=row["commit_sha"],
                config_sha256=row["config_sha256"],
                broker_spec_sha256=row["broker_spec_sha256"],
                model_artifact_sha256=row["model_artifact_sha256"],
                lane_id=row["lane_id"],
            )
        except (TypeError, ValueError, SoakTrackerError) as exc:
            raise SoakTrackerIntegrityError("stored soak binding is invalid") from exc
        if observed != self.binding or row["binding_sha256"] != self.binding.binding_sha256:
            raise SoakTrackerBindingError("soak exact binding does not match")
        if row["schema_version"] != SCHEMA_VERSION:
            raise SoakTrackerIntegrityError("soak schema version is invalid")
        if row["key_id"] != self.key_id:
            raise SoakTrackerBindingError("soak key identity does not match")
        if row["key_fingerprint_sha256"] != hashlib.sha256(secret).hexdigest():
            raise SoakTrackerIntegrityError("soak HMAC key does not match")
        if row["source_trust_sha256"] != self._source_trust_sha256():
            raise SoakTrackerBindingError("soak source trust binding does not match")
        body = self._identity_body(
            tracker_id=tracker_id,
            created_at_utc=_utc_text("created_at_utc", created_at),
        )
        expected = _hmac_sha256(secret, _IDENTITY_HMAC_DOMAIN, body)
        if not hmac.compare_digest(str(row["identity_hmac_sha256"]), expected):
            raise SoakTrackerIntegrityError("soak identity HMAC is invalid")
        if self.tracker_id and self.tracker_id != tracker_id:
            raise SoakTrackerIntegrityError("soak tracker identity changed")
        self.tracker_id = tracker_id
        if self.created_at_utc is not None and self.created_at_utc != created_at:
            raise SoakTrackerIntegrityError("soak tracker creation time changed")
        self.created_at_utc = created_at

    def _event_hmac_body(
        self,
        *,
        sequence: int,
        event_id: str,
        dedup_key: str,
        event_type: str,
        observed_at_utc: str,
        clean_generation: int,
        payload: Mapping[str, Any],
        previous_hmac_sha256: str,
    ) -> dict[str, Any]:
        return {
            "schema_version": EVENT_SCHEMA_VERSION,
            "tracker_id": self.tracker_id,
            "binding_sha256": self.binding.binding_sha256,
            "key_id": self.key_id,
            "sequence": sequence,
            "event_id": event_id,
            "dedup_key": dedup_key,
            "event_type": event_type,
            "observed_at_utc": observed_at_utc,
            "clean_generation": clean_generation,
            "payload": dict(payload),
            "previous_hmac_sha256": previous_hmac_sha256,
        }

    def _verify_ingestion_receipt(
        self,
        event_type: str,
        value: object,
        *,
        enforce_freshness: bool,
    ) -> SoakSourceReceipt | DualReviewReceipt:
        if not isinstance(value, Mapping):
            raise SoakTrackerSourceError("soak ingestion source must be an object")
        if event_type == "SOAK_RESTARTED_AFTER_REVIEW":
            receipt = verify_dual_review_receipt(
                value,
                expected_binding=self.binding,
                key_provider=self._source_key_provider,
                trusted_source_issuer_keys=self._trusted_source_issuer_keys,
                clock_provider=self._clock_provider,
                enforce_freshness=enforce_freshness,
            )
            return receipt
        expected_kind = {
            "SOAK_STARTED": "DEMO_AUTO_ACTIVATION",
            "CLOSED_FILL": "BROKER_CLOSED_DEAL",
            "CRITICAL_INCIDENT": "CRITICAL_INCIDENT",
        }.get(event_type)
        if expected_kind is None:
            raise SoakTrackerSourceError("soak event source kind is unsupported")
        receipt = verify_soak_source_receipt(
            value,
            expected_binding=self.binding,
            key_provider=self._source_key_provider,
            trusted_source_issuer_keys=self._trusted_source_issuer_keys,
            clock_provider=self._clock_provider,
            enforce_freshness=enforce_freshness,
        )
        if receipt.source_kind != expected_kind:
            raise SoakTrackerSourceError("source receipt kind does not match soak event")
        return receipt

    def _validate_payload(
        self,
        *,
        row: sqlite3.Row,
        payload: Mapping[str, Any],
        sequence: int,
        state: _SoakState,
    ) -> tuple[datetime, int, str, SoakSourceReceipt | DualReviewReceipt]:
        event_type = str(row["event_type"])
        if event_type not in _ALLOWED_EVENT_TYPES:
            raise SoakTrackerIntegrityError("unsupported soak event type")
        expected_keys = {
            "schema_version",
            "tracker_id",
            "binding_sha256",
            "event_id",
            "event_type",
            "observed_at_utc",
            "clean_generation",
            "safety",
        }
        expected_keys.add("source_receipt")
        if set(payload) != expected_keys:
            raise SoakTrackerIntegrityError("soak event payload fields are invalid")
        observed_text = str(row["observed_at_utc"])
        observed = _stored_utc("stored observed_at_utc", observed_text)
        if state.latest_observed_at_utc is not None and observed <= state.latest_observed_at_utc:
            raise SoakTrackerIntegrityError("soak timestamps are not strictly increasing")
        common_valid = (
            payload.get("schema_version") == EVENT_SCHEMA_VERSION
            and payload.get("tracker_id") == self.tracker_id
            and payload.get("binding_sha256") == self.binding.binding_sha256
            and payload.get("event_id") == row["event_id"]
            and payload.get("event_type") == event_type
            and payload.get("observed_at_utc") == observed_text
            and payload.get("clean_generation") == row["clean_generation"]
            and payload.get("safety") == _DENY_SAFETY
        )
        if not common_valid:
            raise SoakTrackerIntegrityError("soak event payload binding is invalid")
        event_id = _identifier("stored event_id", row["event_id"])
        generation = int(row["clean_generation"])
        source_receipt = self._verify_ingestion_receipt(
            event_type,
            payload.get("source_receipt"),
            enforce_freshness=False,
        )
        if event_type == "SOAK_STARTED":
            if sequence != 1 or state.event_count != 0 or generation != 1:
                raise SoakTrackerIntegrityError("soak start must be generation-one genesis")
            if type(source_receipt) is not SoakSourceReceipt:
                raise SoakTrackerIntegrityError("soak start source type is invalid")
            if _utc_text("activation time", source_receipt.occurred_at_utc) != observed_text:
                raise SoakTrackerIntegrityError("soak start timestamp is inconsistent")
            dedup_key = f"START:{source_receipt.subject_id}"
        elif event_type == "SOAK_RESTARTED_AFTER_REVIEW":
            if (
                state.event_count == 0
                or not state.demotion_latched
                or generation != state.clean_generation + 1
            ):
                raise SoakTrackerIntegrityError(
                    "reviewed restart requires an active incident demotion"
                )
            if type(source_receipt) is not DualReviewReceipt:
                raise SoakTrackerIntegrityError("reviewed restart source type is invalid")
            if (
                state.latest_incident_id is None
                or source_receipt.incident_id != state.latest_incident_id
            ):
                raise SoakTrackerIntegrityError(
                    "dual review does not bind the currently latched incident"
                )
            if _utc_text("reviewed_at_utc", source_receipt.reviewed_at_utc) != observed_text:
                raise SoakTrackerIntegrityError("reviewed restart timestamp is inconsistent")
            dedup_key = f"SOAK_RESTART:{source_receipt.review_receipt_id}"
        elif event_type == "CLOSED_FILL":
            if state.event_count == 0 or generation != state.clean_generation:
                raise SoakTrackerIntegrityError("closed fill generation is invalid")
            if type(source_receipt) is not SoakSourceReceipt:
                raise SoakTrackerIntegrityError("closed fill source type is invalid")
            symbol = str(dict(source_receipt.details).get("symbol", ""))
            if _SYMBOL_RE.fullmatch(symbol) is None:
                raise SoakTrackerIntegrityError("stored fill symbol is invalid")
            if _utc_text("broker_closed_at_utc", source_receipt.occurred_at_utc) != observed_text:
                raise SoakTrackerIntegrityError("closed fill timestamp is inconsistent")
            dedup_key = f"BROKER_DEAL:{source_receipt.subject_id}"
        else:
            if state.event_count == 0 or generation != state.clean_generation + 1:
                raise SoakTrackerIntegrityError("incident must advance the clean generation")
            if type(source_receipt) is not SoakSourceReceipt:
                raise SoakTrackerIntegrityError("incident source type is invalid")
            incident_id = source_receipt.subject_id
            reason = str(dict(source_receipt.details).get("reason_code", ""))
            if _REASON_RE.fullmatch(reason) is None:
                raise SoakTrackerIntegrityError("stored incident reason is invalid")
            if _utc_text("incident occurred_at_utc", source_receipt.occurred_at_utc) != observed_text:
                raise SoakTrackerIntegrityError("incident timestamp is inconsistent")
            dedup_key = f"CRITICAL_INCIDENT:{incident_id}"
        if row["dedup_key"] != dedup_key:
            raise SoakTrackerIntegrityError("soak deduplication binding is invalid")
        return observed, generation, dedup_key, source_receipt

    def _verify_connection(
        self, connection: sqlite3.Connection, secret: bytes
    ) -> _SoakState:
        integrity = connection.execute("PRAGMA integrity_check").fetchall()
        if not integrity or any(str(row[0]).lower() != "ok" for row in integrity):
            raise SoakTrackerIntegrityError("SQLite integrity check failed")
        self._verify_schema(connection)
        self._verify_identity(connection, secret)
        rows = connection.execute("SELECT * FROM soak_events ORDER BY sequence").fetchall()
        state = _SoakState()
        for sequence, row in enumerate(rows, start=1):
            if int(row["sequence"]) != sequence:
                raise SoakTrackerIntegrityError("soak sequence is not contiguous")
            if row["previous_hmac_sha256"] != state.head_hmac_sha256:
                raise SoakTrackerIntegrityError("soak predecessor HMAC is invalid")
            payload = _canonical_object(row["payload_json"])
            try:
                observed, generation, _dedup, source_receipt = self._validate_payload(
                    row=row,
                    payload=payload,
                    sequence=sequence,
                    state=state,
                )
            except SoakTrackerIntegrityError:
                raise
            except (SoakTrackerError, TypeError, ValueError) as exc:
                raise SoakTrackerIntegrityError("stored soak event semantics are invalid") from exc
            body = self._event_hmac_body(
                sequence=sequence,
                event_id=str(row["event_id"]),
                dedup_key=str(row["dedup_key"]),
                event_type=str(row["event_type"]),
                observed_at_utc=str(row["observed_at_utc"]),
                clean_generation=generation,
                payload=payload,
                previous_hmac_sha256=state.head_hmac_sha256,
            )
            expected_hmac = _hmac_sha256(secret, _EVENT_HMAC_DOMAIN, body)
            observed_hmac = str(row["event_hmac_sha256"])
            if _HASH_RE.fullmatch(observed_hmac) is None or not hmac.compare_digest(
                observed_hmac, expected_hmac
            ):
                raise SoakTrackerIntegrityError("soak event HMAC is invalid")
            if row["event_type"] == "SOAK_STARTED":
                state = _SoakState(
                    event_count=sequence,
                    head_hmac_sha256=observed_hmac,
                    clean_generation=1,
                    clean_started_at_utc=observed,
                    latest_observed_at_utc=observed,
                )
            elif row["event_type"] == "SOAK_RESTARTED_AFTER_REVIEW":
                state = _SoakState(
                    event_count=sequence,
                    head_hmac_sha256=observed_hmac,
                    clean_generation=generation,
                    clean_started_at_utc=observed,
                    latest_observed_at_utc=observed,
                    critical_incident_count=state.critical_incident_count,
                    review_restart_count=state.review_restart_count + 1,
                    latest_incident_id=state.latest_incident_id,
                    demotion_latched=False,
                )
            elif row["event_type"] == "CRITICAL_INCIDENT":
                state = _SoakState(
                    event_count=sequence,
                    head_hmac_sha256=observed_hmac,
                    clean_generation=generation,
                    clean_started_at_utc=observed,
                    latest_observed_at_utc=observed,
                    critical_incident_count=state.critical_incident_count + 1,
                    review_restart_count=state.review_restart_count,
                    latest_incident_id=(
                        source_receipt.subject_id
                        if type(source_receipt) is SoakSourceReceipt
                        else None
                    ),
                    demotion_latched=True,
                )
            else:
                state = _SoakState(
                    event_count=sequence,
                    head_hmac_sha256=observed_hmac,
                    clean_generation=state.clean_generation,
                    clean_started_at_utc=state.clean_started_at_utc,
                    latest_observed_at_utc=observed,
                    critical_incident_count=state.critical_incident_count,
                    review_restart_count=state.review_restart_count,
                    latest_incident_id=state.latest_incident_id,
                    demotion_latched=state.demotion_latched,
                    closed_fills=state.closed_fills + 1,
                    xauusd_closed_fills=(
                        state.xauusd_closed_fills
                        + (
                            1
                            if type(source_receipt) is SoakSourceReceipt
                            and dict(source_receipt.details)["symbol"] == "XAUUSD"
                            else 0
                        )
                    ),
                )
        heads = connection.execute("SELECT * FROM soak_head").fetchall()
        if len(heads) != 1 or int(heads[0]["singleton"]) != 1:
            raise SoakTrackerIntegrityError("soak head singleton is invalid")
        head = heads[0]
        body = self._state_body(state)
        actual = {
            "event_count": int(head["event_count"]),
            "head_sequence": int(head["head_sequence"]),
            "head_hmac_sha256": str(head["head_hmac_sha256"]),
            "clean_generation": int(head["clean_generation"]),
            "clean_started_at_utc": str(head["clean_started_at_utc"]),
            "latest_observed_at_utc": str(head["latest_observed_at_utc"]),
            "critical_incident_count": int(head["critical_incident_count"]),
            "review_restart_count": int(head["review_restart_count"]),
            "latest_incident_id": str(head["latest_incident_id"]),
            "demotion_latched": bool(head["demotion_latched"]),
        }
        expected = {key: body[key] for key in actual}
        if actual != expected:
            raise SoakTrackerIntegrityError("soak head projection is invalid")
        expected_state_hmac = _hmac_sha256(secret, _STATE_HMAC_DOMAIN, body)
        if not hmac.compare_digest(str(head["state_hmac_sha256"]), expected_state_hmac):
            raise SoakTrackerIntegrityError("soak state HMAC is invalid")
        return state

    def _persist_head(
        self,
        connection: sqlite3.Connection,
        *,
        state: _SoakState,
        secret: bytes,
    ) -> None:
        body = self._state_body(state)
        connection.execute(
            """UPDATE soak_head SET
                event_count=?, head_sequence=?, head_hmac_sha256=?,
                clean_generation=?, clean_started_at_utc=?,
                latest_observed_at_utc=?, critical_incident_count=?,
                review_restart_count=?, latest_incident_id=?, demotion_latched=?,
                state_hmac_sha256=?
            WHERE singleton=1""",
            (
                state.event_count,
                state.event_count,
                state.head_hmac_sha256,
                state.clean_generation,
                body["clean_started_at_utc"],
                body["latest_observed_at_utc"],
                state.critical_incident_count,
                state.review_restart_count,
                body["latest_incident_id"],
                int(state.demotion_latched),
                _hmac_sha256(secret, _STATE_HMAC_DOMAIN, body),
            ),
        )

    def _append(
        self,
        *,
        event_id: str,
        event_type: str,
        source_receipt: SoakSourceReceipt | DualReviewReceipt,
    ) -> SoakEventReceipt:
        normalized_event_id = _identifier("event_id", event_id)
        if type(source_receipt) not in {SoakSourceReceipt, DualReviewReceipt}:
            raise TypeError("source_receipt must be a verified sealed receipt")
        verified_source = self._verify_ingestion_receipt(
            event_type,
            source_receipt.to_canonical_dict(),
            enforce_freshness=True,
        )
        if verified_source != source_receipt:
            raise SoakTrackerSourceError("source receipt does not verify exactly")
        if type(verified_source) is DualReviewReceipt:
            observed_at_utc = verified_source.reviewed_at_utc
            dedup_key = f"SOAK_RESTART:{verified_source.review_receipt_id}"
        elif event_type == "SOAK_STARTED":
            observed_at_utc = verified_source.occurred_at_utc
            dedup_key = f"START:{verified_source.subject_id}"
        elif event_type == "CLOSED_FILL":
            observed_at_utc = verified_source.occurred_at_utc
            dedup_key = f"BROKER_DEAL:{verified_source.subject_id}"
        elif event_type == "CRITICAL_INCIDENT":
            observed_at_utc = verified_source.occurred_at_utc
            dedup_key = f"CRITICAL_INCIDENT:{verified_source.subject_id}"
        else:
            raise SoakTrackerSourceError("soak event type is unsupported")
        observed_text = _utc_text("observed_at_utc", observed_at_utc)
        secret = self._secret()
        with self._transaction() as connection:
            state = self._verify_connection(connection, secret)
            now = self._now()
            if observed_at_utc > now:
                raise SoakTrackerError("soak observation is in the future")
            if self.created_at_utc is None or observed_at_utc < self.created_at_utc:
                raise SoakTrackerError("soak observation predates tracker creation")
            if connection.execute(
                "SELECT 1 FROM soak_events WHERE event_id=? OR dedup_key=? LIMIT 1",
                (normalized_event_id, dedup_key),
            ).fetchone() is not None:
                raise SoakTrackerDuplicateError("soak observation already exists")
            if (
                state.latest_observed_at_utc is not None
                and observed_at_utc <= state.latest_observed_at_utc
            ):
                raise SoakTrackerError("soak observation is backdated or duplicates time")
            if event_type == "SOAK_STARTED":
                if state.event_count:
                    raise SoakTrackerError("soak has already started")
                generation = 1
            elif not state.event_count:
                raise SoakTrackerError("soak must start before observations")
            elif (
                event_type == "SOAK_RESTARTED_AFTER_REVIEW"
                and not state.demotion_latched
            ):
                raise SoakTrackerError(
                    "reviewed restart requires an active incident demotion"
                )
            elif (
                event_type == "SOAK_RESTARTED_AFTER_REVIEW"
                and (
                    type(verified_source) is not DualReviewReceipt
                    or state.latest_incident_id is None
                    or verified_source.incident_id != state.latest_incident_id
                )
            ):
                raise SoakTrackerSourceError(
                    "dual review does not bind the currently latched incident"
                )
            elif event_type in {
                "CRITICAL_INCIDENT",
                "SOAK_RESTARTED_AFTER_REVIEW",
            }:
                generation = state.clean_generation + 1
            else:
                generation = state.clean_generation
            sequence = state.event_count + 1
            payload: dict[str, object] = {
                "schema_version": EVENT_SCHEMA_VERSION,
                "tracker_id": self.tracker_id,
                "binding_sha256": self.binding.binding_sha256,
                "event_id": normalized_event_id,
                "event_type": event_type,
                "observed_at_utc": observed_text,
                "clean_generation": generation,
                "safety": dict(_DENY_SAFETY),
                "source_receipt": verified_source.to_canonical_dict(),
            }
            body = self._event_hmac_body(
                sequence=sequence,
                event_id=normalized_event_id,
                dedup_key=dedup_key,
                event_type=event_type,
                observed_at_utc=observed_text,
                clean_generation=generation,
                payload=payload,
                previous_hmac_sha256=state.head_hmac_sha256,
            )
            event_hmac = _hmac_sha256(secret, _EVENT_HMAC_DOMAIN, body)
            try:
                connection.execute(
                    """INSERT INTO soak_events(
                        sequence, event_id, dedup_key, event_type,
                        observed_at_utc, clean_generation, payload_json,
                        previous_hmac_sha256, event_hmac_sha256
                    ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        sequence,
                        normalized_event_id,
                        dedup_key,
                        event_type,
                        observed_text,
                        generation,
                        canonical_json(payload),
                        state.head_hmac_sha256,
                        event_hmac,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise SoakTrackerDuplicateError("soak observation already exists") from exc
            if event_type == "SOAK_STARTED":
                next_state = _SoakState(
                    event_count=sequence,
                    head_hmac_sha256=event_hmac,
                    clean_generation=1,
                    clean_started_at_utc=observed_at_utc,
                    latest_observed_at_utc=observed_at_utc,
                )
            elif event_type == "SOAK_RESTARTED_AFTER_REVIEW":
                next_state = _SoakState(
                    event_count=sequence,
                    head_hmac_sha256=event_hmac,
                    clean_generation=generation,
                    clean_started_at_utc=observed_at_utc,
                    latest_observed_at_utc=observed_at_utc,
                    critical_incident_count=state.critical_incident_count,
                    review_restart_count=state.review_restart_count + 1,
                    latest_incident_id=state.latest_incident_id,
                    demotion_latched=False,
                )
            elif event_type == "CRITICAL_INCIDENT":
                next_state = _SoakState(
                    event_count=sequence,
                    head_hmac_sha256=event_hmac,
                    clean_generation=generation,
                    clean_started_at_utc=observed_at_utc,
                    latest_observed_at_utc=observed_at_utc,
                    critical_incident_count=state.critical_incident_count + 1,
                    review_restart_count=state.review_restart_count,
                    latest_incident_id=(
                        verified_source.subject_id
                        if type(verified_source) is SoakSourceReceipt
                        else None
                    ),
                    demotion_latched=True,
                )
            else:
                next_state = _SoakState(
                    event_count=sequence,
                    head_hmac_sha256=event_hmac,
                    clean_generation=generation,
                    clean_started_at_utc=state.clean_started_at_utc,
                    latest_observed_at_utc=observed_at_utc,
                    critical_incident_count=state.critical_incident_count,
                    review_restart_count=state.review_restart_count,
                    latest_incident_id=state.latest_incident_id,
                    demotion_latched=state.demotion_latched,
                    closed_fills=state.closed_fills + 1,
                    xauusd_closed_fills=(
                        state.xauusd_closed_fills
                        + (
                            1
                            if type(verified_source) is SoakSourceReceipt
                            and dict(verified_source.details)["symbol"] == "XAUUSD"
                            else 0
                        )
                    ),
                )
            self._persist_head(connection, state=next_state, secret=secret)
            verified = self._verify_connection(connection, secret)
            if verified != next_state:
                raise SoakTrackerIntegrityError("appended soak state did not replay exactly")
        return SoakEventReceipt(
            sequence=sequence,
            event_id=normalized_event_id,
            event_type=event_type,
            observed_at_utc=observed_at_utc,
            clean_generation=generation,
            previous_hmac_sha256=state.head_hmac_sha256,
            event_hmac_sha256=event_hmac,
        )

    def start_soak(
        self,
        *,
        event_id: str,
        activation_receipt: SoakSourceReceipt,
    ) -> SoakEventReceipt:
        return self._append(
            event_id=event_id,
            event_type="SOAK_STARTED",
            source_receipt=activation_receipt,
        )

    def record_closed_fill(
        self,
        *,
        event_id: str,
        closed_deal_receipt: SoakSourceReceipt,
    ) -> SoakEventReceipt:
        return self._append(
            event_id=event_id,
            event_type="CLOSED_FILL",
            source_receipt=closed_deal_receipt,
        )

    def restart_after_review(
        self,
        *,
        event_id: str,
        review_receipt: DualReviewReceipt,
    ) -> SoakEventReceipt:
        return self._append(
            event_id=event_id,
            event_type="SOAK_RESTARTED_AFTER_REVIEW",
            source_receipt=review_receipt,
        )

    def record_critical_incident(
        self,
        *,
        event_id: str,
        incident_receipt: SoakSourceReceipt,
    ) -> SoakEventReceipt:
        return self._append(
            event_id=event_id,
            event_type="CRITICAL_INCIDENT",
            source_receipt=incident_receipt,
        )

    def _assessment(self, *, state: _SoakState, as_of_utc: datetime) -> SoakAssessment:
        if state.event_count == 0 or state.clean_started_at_utc is None or state.latest_observed_at_utc is None:
            raise SoakTrackerError("soak has not started")
        if as_of_utc < state.latest_observed_at_utc:
            raise SoakTrackerError("assessment timestamp precedes the latest event")
        seconds = (as_of_utc - state.clean_started_at_utc).total_seconds()
        duration_met = seconds >= MINIMUM_CLEAN_DAYS * 86400
        fills_met = state.closed_fills >= MINIMUM_CLOSED_FILLS
        xau_met = state.xauusd_closed_fills >= MINIMUM_XAUUSD_CLOSED_FILLS
        blockers = ["DENY_ONLY_TRACKER"]
        if not duration_met:
            blockers.append("CLEAN_DURATION_30_DAYS_REQUIRED")
        if not fills_met:
            blockers.append("CLOSED_FILLS_50_REQUIRED")
        if not xau_met:
            blockers.append("XAUUSD_CLOSED_FILLS_20_REQUIRED")
        if state.demotion_latched:
            blockers.append("CRITICAL_INCIDENT_DEMOTION_LATCHED")
        return SoakAssessment(
            clean_period_started_at_utc=state.clean_started_at_utc,
            assessed_at_utc=as_of_utc,
            latest_event_at_utc=state.latest_observed_at_utc,
            clean_generation=state.clean_generation,
            clean_duration_seconds=seconds,
            clean_duration_days=seconds / 86400,
            closed_fills=state.closed_fills,
            xauusd_closed_fills=state.xauusd_closed_fills,
            duration_30_days_met=duration_met,
            closed_fills_50_met=fills_met,
            xauusd_fills_20_met=xau_met,
            statistical_criteria_met=duration_met and fills_met and xau_met,
            critical_incident_count=state.critical_incident_count,
            review_restart_count=state.review_restart_count,
            demotion_latched=state.demotion_latched,
            blocker_codes=tuple(sorted(blockers)),
        )

    def _state_and_assessment(
        self, as_of_utc: datetime
    ) -> tuple[_SoakState, SoakAssessment, bytes]:
        _utc_text("as_of_utc", as_of_utc)
        now = self._now()
        if as_of_utc > now:
            raise SoakTrackerError("assessment timestamp is in the future")
        secret = self._secret()
        with self._reader() as connection:
            state = self._verify_connection(connection, secret)
        return state, self._assessment(state=state, as_of_utc=as_of_utc), secret

    def assessment(self, *, as_of_utc: datetime) -> SoakAssessment:
        return self._state_and_assessment(as_of_utc)[1]

    def assessment_receipt(self, *, as_of_utc: datetime) -> SoakAssessmentReceipt:
        state, report, secret = self._state_and_assessment(as_of_utc)
        values: dict[str, Any] = {
            "tracker_id": self.tracker_id,
            "broker_id": self.binding.broker_id,
            "environment": self.binding.environment,
            "account_alias_sha256": self.binding.account_alias_sha256,
            "broker_server": self.binding.broker_server,
            "journal_sha256": self.binding.journal_sha256,
            "commit_sha": self.binding.commit_sha,
            "config_sha256": self.binding.config_sha256,
            "broker_spec_sha256": self.binding.broker_spec_sha256,
            "model_artifact_sha256": self.binding.model_artifact_sha256,
            "lane_id": self.binding.lane_id,
            "binding_sha256": self.binding.binding_sha256,
            "key_id": self.key_id,
            "event_count": state.event_count,
            "head_hmac_sha256": state.head_hmac_sha256,
            "clean_generation": report.clean_generation,
            "clean_period_started_at_utc": report.clean_period_started_at_utc,
            "latest_event_at_utc": report.latest_event_at_utc,
            "assessed_at_utc": report.assessed_at_utc,
            "clean_duration_seconds": report.clean_duration_seconds,
            "clean_duration_days": report.clean_duration_days,
            "closed_fills": report.closed_fills,
            "xauusd_closed_fills": report.xauusd_closed_fills,
            "duration_30_days_met": report.duration_30_days_met,
            "closed_fills_50_met": report.closed_fills_50_met,
            "xauusd_fills_20_met": report.xauusd_fills_20_met,
            "statistical_criteria_met": report.statistical_criteria_met,
            "critical_incident_count": report.critical_incident_count,
            "review_restart_count": report.review_restart_count,
            "demotion_latched": report.demotion_latched,
            "blocker_codes": report.blocker_codes,
            "schema_version": ASSESSMENT_RECEIPT_SCHEMA_VERSION,
            "ready": False,
            "promotion_eligible": False,
            "execution_enabled": False,
            "safe_to_demo_auto_order": False,
            "live_allowed": False,
            "order_capability": "DISABLED",
        }
        signature = _hmac_sha256(secret, _ASSESSMENT_HMAC_DOMAIN, values)
        receipt_values = {
            key: value
            for key, value in values.items()
            if key not in _DENY_SAFETY
        }
        return SoakAssessmentReceipt(
            **receipt_values,
            receipt_hmac_sha256=signature,
            _seal=_RECEIPT_SEAL,
        )

    def _verify_external_receipt(
        self,
        connection: sqlite3.Connection,
        *,
        state: _SoakState,
        receipt: SoakAssessmentReceipt,
        secret: bytes,
        now: datetime,
    ) -> None:
        expected_signature = _hmac_sha256(
            secret,
            _ASSESSMENT_HMAC_DOMAIN,
            receipt.signing_payload,
        )
        if not hmac.compare_digest(
            receipt.receipt_hmac_sha256,
            expected_signature,
        ):
            raise SoakTrackerIntegrityError("external soak receipt signature is invalid")
        exact = (
            receipt.tracker_id == self.tracker_id
            and receipt.broker_id == self.binding.broker_id
            and receipt.environment == self.binding.environment
            and receipt.account_alias_sha256 == self.binding.account_alias_sha256
            and receipt.broker_server == self.binding.broker_server
            and receipt.journal_sha256 == self.binding.journal_sha256
            and receipt.commit_sha == self.binding.commit_sha
            and receipt.config_sha256 == self.binding.config_sha256
            and receipt.broker_spec_sha256 == self.binding.broker_spec_sha256
            and receipt.model_artifact_sha256 == self.binding.model_artifact_sha256
            and receipt.lane_id == self.binding.lane_id
            and receipt.binding_sha256 == self.binding.binding_sha256
            and receipt.key_id == self.key_id
        )
        if not exact:
            raise SoakTrackerBindingError("external soak receipt binding does not match")
        if receipt.assessed_at_utc > now:
            raise SoakTrackerRollbackError("external soak receipt is from the future")
        if state.event_count < receipt.event_count:
            raise SoakTrackerRollbackError("local soak event count regressed")
        prefix = connection.execute(
            "SELECT event_hmac_sha256, observed_at_utc FROM soak_events WHERE sequence=?",
            (receipt.event_count,),
        ).fetchone()
        if prefix is None:
            raise SoakTrackerRollbackError("external soak receipt event is missing")
        if not hmac.compare_digest(str(prefix["event_hmac_sha256"]), receipt.head_hmac_sha256):
            raise SoakTrackerRollbackError("local soak chain forked or was rewritten")
        if _stored_utc("receipt prefix event", prefix["observed_at_utc"]) != receipt.latest_event_at_utc:
            raise SoakTrackerRollbackError("local soak prefix time changed")
        if state.clean_generation < receipt.clean_generation:
            raise SoakTrackerRollbackError("clean generation regressed")
        if state.critical_incident_count < receipt.critical_incident_count:
            raise SoakTrackerRollbackError("critical incident history regressed")
        if state.review_restart_count < receipt.review_restart_count:
            raise SoakTrackerRollbackError("reviewed restart history regressed")
        if state.clean_generation == receipt.clean_generation:
            if (
                state.clean_started_at_utc != receipt.clean_period_started_at_utc
                or state.critical_incident_count != receipt.critical_incident_count
                or state.review_restart_count != receipt.review_restart_count
                or state.demotion_latched != receipt.demotion_latched
                or state.closed_fills < receipt.closed_fills
                or state.xauusd_closed_fills < receipt.xauusd_closed_fills
            ):
                raise SoakTrackerRollbackError("current clean generation regressed")
        elif (
            state.critical_incident_count + state.review_restart_count
            <= receipt.critical_incident_count + receipt.review_restart_count
        ):
            raise SoakTrackerRollbackError(
                "generation advanced without incident or reviewed-restart evidence"
            )
        elif (
            receipt.demotion_latched
            and not state.demotion_latched
            and state.review_restart_count <= receipt.review_restart_count
        ):
            raise SoakTrackerRollbackError(
                "demotion cleared without advanced reviewed-restart evidence"
            )

    def events(self) -> tuple[SoakEventReceipt, ...]:
        secret = self._secret()
        with self._reader() as connection:
            self._verify_connection(connection, secret)
            rows = connection.execute("SELECT * FROM soak_events ORDER BY sequence").fetchall()
        return tuple(
            SoakEventReceipt(
                sequence=int(row["sequence"]),
                event_id=str(row["event_id"]),
                event_type=str(row["event_type"]),
                observed_at_utc=_stored_utc("event timestamp", row["observed_at_utc"]),
                clean_generation=int(row["clean_generation"]),
                previous_hmac_sha256=str(row["previous_hmac_sha256"]),
                event_hmac_sha256=str(row["event_hmac_sha256"]),
            )
            for row in rows
        )

    def verify_integrity(
        self, *, expected_receipt: SoakAssessmentReceipt | None = None
    ) -> bool:
        if expected_receipt is not None and type(expected_receipt) is not SoakAssessmentReceipt:
            raise TypeError("expected_receipt must be a sealed SoakAssessmentReceipt")
        try:
            secret = self._secret()
            now = self._now()
            with self._reader() as connection:
                state = self._verify_connection(connection, secret)
                if expected_receipt is not None:
                    self._verify_external_receipt(
                        connection,
                        state=state,
                        receipt=expected_receipt,
                        secret=secret,
                        now=now,
                    )
        except (sqlite3.DatabaseError, SoakTrackerError, TypeError, ValueError):
            return False
        return True

    def storage_profile(self) -> Mapping[str, object]:
        secret = self._secret()
        with self._reader() as connection:
            self._verify_connection(connection, secret)
            profile = {
                "journal_mode": str(connection.execute("PRAGMA journal_mode").fetchone()[0]).upper(),
                "synchronous": (
                    "FULL" if int(connection.execute("PRAGMA synchronous").fetchone()[0]) == 2 else "INVALID"
                ),
                "foreign_keys": int(connection.execute("PRAGMA foreign_keys").fetchone()[0]) == 1,
                "busy_timeout_ms": int(connection.execute("PRAGMA busy_timeout").fetchone()[0]),
                "identity_hmac": True,
                "event_hmac_chain": True,
                "authenticated_source_receipts": True,
                "dual_independent_review_receipt": True,
                "raw_production_ingestion": False,
                "strict_schema": True,
                "key_id": self.key_id,
                "source_trust_sha256": self._source_trust_sha256(),
            }
        return MappingProxyType(profile)


def verify_soak_assessment_receipt(
    receipt: SoakAssessmentReceipt,
    key_provider: Callable[[str], str | bytes],
) -> bool:
    if type(receipt) is not SoakAssessmentReceipt or not callable(key_provider):
        return False
    try:
        secret = _secret(key_provider(receipt.key_id))
        expected = _hmac_sha256(
            secret,
            _ASSESSMENT_HMAC_DOMAIN,
            receipt.signing_payload,
        )
    except Exception:
        return False
    return hmac.compare_digest(receipt.receipt_hmac_sha256, expected)


__all__ = [
    "ASSESSMENT_RECEIPT_SCHEMA_VERSION",
    "DemoAutoSoakTracker",
    "DUAL_REVIEW_RECEIPT_SCHEMA_VERSION",
    "DualReviewReceipt",
    "MINIMUM_CLEAN_DAYS",
    "MINIMUM_CLOSED_FILLS",
    "MINIMUM_XAUUSD_CLOSED_FILLS",
    "SCHEMA_VERSION",
    "SOURCE_RECEIPT_SCHEMA_VERSION",
    "SoakAssessment",
    "SoakAssessmentReceipt",
    "SoakBinding",
    "SoakEventReceipt",
    "SoakSourceReceipt",
    "SoakTrackerBindingError",
    "SoakTrackerDuplicateError",
    "SoakTrackerError",
    "SoakTrackerIntegrityError",
    "SoakTrackerRollbackError",
    "SoakTrackerSourceError",
    "verify_dual_review_receipt",
    "verify_soak_assessment_receipt",
    "verify_soak_source_receipt",
]
