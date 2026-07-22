"""Durable deny-only accounting for controlled manual-demo acceptance.

This module consumes sealed observations that were produced elsewhere.  It has
no broker client and deliberately exposes no path that can authorize or mutate
an order.  Numerical acceptance progress therefore remains separate from every
execution permission.
"""

from __future__ import annotations

from dataclasses import InitVar, dataclass, field
from datetime import datetime, timezone
import hashlib
import hmac
import json
from pathlib import Path
import re
import sqlite3
from types import MappingProxyType
from typing import Any, Callable, Mapping
import uuid

from .contracts import (
    CanonicalContract,
    ExecutionReceipt,
    canonical_json,
    canonical_sha256,
    canonicalize,
    require_hash,
    require_text,
    require_utc,
)
from .journal import ALLOWED_TRANSITIONS
from .mt5_adapter import MT5Preflight, MT5SubmissionGuard
from .reconciliation import _BrokerReconciliationEvidence


SCHEMA_VERSION = "manual-demo-acceptance-tracker-v1"
ASSESSMENT_RECEIPT_SCHEMA_VERSION = "manual-demo-assessment-receipt-v1"
RECONCILIATION_CYCLE_SCHEMA_VERSION = "manual-demo-reconciliation-cycle-v1"
MANUAL_DEMO_CYCLE_HMAC_DOMAIN = (
    b"AI_SCALPER:MANUAL_DEMO_RECONCILIATION_CYCLE:v1\n"
)
MINIMUM_CLEAN_COMPLETED_ORDERS = 10
ZERO_HASH = "0" * 64

_IDENTITY_HMAC_DOMAIN = b"AI_SCALPER_MANUAL_DEMO_IDENTITY_V1\x00"
_EVENT_HMAC_DOMAIN = b"AI_SCALPER_MANUAL_DEMO_EVENT_V1\x00"
_STATE_HMAC_DOMAIN = b"AI_SCALPER_MANUAL_DEMO_STATE_V1\x00"
_ASSESSMENT_HMAC_DOMAIN = b"AI_SCALPER_MANUAL_DEMO_ASSESSMENT_V1\x00"

_VERIFIED_CYCLE_SEAL = object()
_ASSESSMENT_RECEIPT_SEAL = object()
_HASH_RE = re.compile(r"^[0-9a-f]{64}$")
_COMMIT_RE = re.compile(r"^[0-9a-f]{7,64}$")
_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$")
_REASON_RE = re.compile(r"^[A-Z][A-Z0-9_]{2,127}$")
_ALLOWED_EVENT_TYPES = frozenset(
    {"PREFLIGHT", "EXECUTION", "RECONCILIATION", "RECONCILIATION_CYCLE"}
)
_ALLOWED_EXECUTION_STATES = frozenset(
    {"ACKNOWLEDGED", "PARTIAL", "FILLED", "REJECTED", "UNCERTAIN"}
)

_DENY_SAFETY = MappingProxyType(
    {
        "ready": False,
        "promotion_eligible": False,
        "execution_enabled": False,
        "manual_demo_enabled": False,
        "safe_to_demo_auto_order": False,
        "live_allowed": False,
        "order_capability": "DISABLED",
    }
)

_EXPECTED_TABLE_COLUMNS = {
    "manual_demo_binding": (
        "singleton",
        "schema_version",
        "tracker_id",
        "account_alias_sha256",
        "broker_server",
        "journal_sha256",
        "commit_sha",
        "config_sha256",
        "lane_id",
        "binding_sha256",
        "key_id",
        "key_fingerprint_sha256",
        "created_at_utc",
        "identity_hmac_sha256",
    ),
    "manual_demo_events": (
        "sequence",
        "event_id",
        "observation_sha256",
        "stage_key",
        "event_type",
        "intent_id",
        "observed_at_utc",
        "critical",
        "payload_json",
        "previous_event_sha256",
        "event_sha256",
    ),
    "manual_demo_head": (
        "singleton",
        "event_count",
        "head_sequence",
        "head_sha256",
        "state_hmac_sha256",
    ),
}

_TABLE_SQL = {
    "manual_demo_binding": """CREATE TABLE manual_demo_binding (
        singleton INTEGER PRIMARY KEY CHECK(singleton=1),
        schema_version TEXT NOT NULL,
        tracker_id TEXT NOT NULL UNIQUE,
        account_alias_sha256 TEXT NOT NULL,
        broker_server TEXT NOT NULL,
        journal_sha256 TEXT NOT NULL,
        commit_sha TEXT NOT NULL,
        config_sha256 TEXT NOT NULL,
        lane_id TEXT NOT NULL,
        binding_sha256 TEXT NOT NULL,
        key_id TEXT NOT NULL,
        key_fingerprint_sha256 TEXT NOT NULL,
        created_at_utc TEXT NOT NULL,
        identity_hmac_sha256 TEXT NOT NULL
    )""",
    "manual_demo_events": """CREATE TABLE manual_demo_events (
        sequence INTEGER PRIMARY KEY AUTOINCREMENT,
        event_id TEXT NOT NULL UNIQUE,
        observation_sha256 TEXT NOT NULL UNIQUE,
        stage_key TEXT NOT NULL UNIQUE,
        event_type TEXT NOT NULL CHECK(event_type IN (
            'PREFLIGHT','EXECUTION','RECONCILIATION','RECONCILIATION_CYCLE'
        )),
        intent_id TEXT,
        observed_at_utc TEXT NOT NULL,
        critical INTEGER NOT NULL CHECK(critical IN (0,1)),
        payload_json TEXT NOT NULL,
        previous_event_sha256 TEXT NOT NULL,
        event_sha256 TEXT NOT NULL UNIQUE
    )""",
    "manual_demo_head": """CREATE TABLE manual_demo_head (
        singleton INTEGER PRIMARY KEY CHECK(singleton=1),
        event_count INTEGER NOT NULL CHECK(event_count >= 0),
        head_sequence INTEGER NOT NULL CHECK(head_sequence >= 0),
        head_sha256 TEXT NOT NULL,
        state_hmac_sha256 TEXT NOT NULL
    )""",
}

_TRIGGER_SQL = {
    "manual_demo_binding_no_update": """CREATE TRIGGER manual_demo_binding_no_update
        BEFORE UPDATE ON manual_demo_binding
        BEGIN
            SELECT RAISE(ABORT, 'manual demo binding is immutable');
        END""",
    "manual_demo_binding_no_delete": """CREATE TRIGGER manual_demo_binding_no_delete
        BEFORE DELETE ON manual_demo_binding
        BEGIN
            SELECT RAISE(ABORT, 'manual demo binding is immutable');
        END""",
    "manual_demo_events_no_update": """CREATE TRIGGER manual_demo_events_no_update
        BEFORE UPDATE ON manual_demo_events
        BEGIN
            SELECT RAISE(ABORT, 'manual demo events are append-only');
        END""",
    "manual_demo_events_no_delete": """CREATE TRIGGER manual_demo_events_no_delete
        BEFORE DELETE ON manual_demo_events
        BEGIN
            SELECT RAISE(ABORT, 'manual demo events are append-only');
        END""",
    "manual_demo_head_no_delete": """CREATE TRIGGER manual_demo_head_no_delete
        BEFORE DELETE ON manual_demo_head
        BEGIN
            SELECT RAISE(ABORT, 'manual demo head is required');
        END""",
}


class ManualDemoTrackerError(RuntimeError):
    """Base fail-closed tracker error."""


class ManualDemoTrackerBindingError(ManualDemoTrackerError):
    """The database or source receipt belongs to another binding."""


class ManualDemoDuplicateError(ManualDemoTrackerError):
    """A sealed observation or lifecycle stage has already been recorded."""


class ManualDemoIntegrityError(ManualDemoTrackerError):
    """Durable state cannot be proven intact."""


class ManualDemoRollbackError(ManualDemoIntegrityError):
    """An external signed checkpoint proves rollback, fork, or rewrite."""


class ReconciliationCycleVerificationError(ManualDemoTrackerError):
    """A signed reconciliation-cycle receipt could not be authenticated."""


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _utc_text(name: str, value: datetime) -> str:
    try:
        normalized = require_utc(name, value)
    except (TypeError, ValueError) as exc:
        raise ManualDemoTrackerError(str(exc)) from exc
    return normalized.isoformat(timespec="microseconds").replace("+00:00", "Z")


def _stored_utc(name: str, value: object) -> datetime:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        normalized = require_utc(name, parsed)
    except (TypeError, ValueError) as exc:
        raise ManualDemoIntegrityError(f"{name} is not canonical UTC") from exc
    if str(value) != normalized.isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    ):
        raise ManualDemoIntegrityError(f"{name} is not canonical UTC")
    return normalized


def _identifier(name: str, value: object) -> str:
    try:
        normalized = require_text(name, value)
    except ValueError as exc:
        raise ManualDemoTrackerError(str(exc)) from exc
    if _IDENTIFIER_RE.fullmatch(normalized) is None:
        raise ManualDemoTrackerError(f"{name} has an invalid format")
    return normalized


def _reason(name: str, value: object) -> str:
    try:
        normalized = require_text(name, value, upper=True)
    except ValueError as exc:
        raise ManualDemoTrackerError(str(exc)) from exc
    if _REASON_RE.fullmatch(normalized) is None:
        raise ManualDemoTrackerError(f"{name} has an invalid format")
    return normalized


def _strict_hash(name: str, value: object) -> str:
    normalized = str(value or "")
    if _HASH_RE.fullmatch(normalized) is None:
        raise ManualDemoTrackerError(f"{name} must be lowercase SHA-256")
    return normalized


def _account_alias_sha256(account_id: object) -> str:
    normalized = require_text("account_id", account_id)
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def _ticket_hash(value: object | None) -> str | None:
    if value in (None, "", 0, "0"):
        return None
    normalized = _identifier("broker ticket", value)
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def _secret(value: str | bytes) -> bytes:
    if isinstance(value, str):
        normalized = value.encode("utf-8")
    elif isinstance(value, bytes):
        normalized = value
    else:
        raise ManualDemoIntegrityError("manual-demo HMAC key is unavailable")
    if len(normalized) < 32:
        raise ManualDemoIntegrityError(
            "manual-demo HMAC key must contain at least 32 bytes"
        )
    return normalized


def _hmac_sha256(secret: bytes, domain: bytes, value: object) -> str:
    return hmac.new(
        secret,
        domain + canonical_json(value).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def _normalized_sql(value: object) -> str:
    return " ".join(str(value).strip().rstrip(";").split()).lower()


def _canonical_object(text: object) -> dict[str, Any]:
    def reject_duplicate(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ManualDemoIntegrityError("event payload contains duplicate keys")
            result[key] = value
        return result

    try:
        value = json.loads(str(text), object_pairs_hook=reject_duplicate)
    except ManualDemoIntegrityError:
        raise
    except (TypeError, json.JSONDecodeError) as exc:
        raise ManualDemoIntegrityError("event payload is not valid JSON") from exc
    if not isinstance(value, dict) or canonical_json(value) != str(text):
        raise ManualDemoIntegrityError("event payload is not a canonical object")
    return value


@dataclass(frozen=True)
class ManualDemoBinding:
    account_alias_sha256: str
    broker_server: str
    journal_sha256: str
    commit_sha: str
    config_sha256: str
    lane_id: str

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "account_alias_sha256",
            require_hash("account_alias_sha256", self.account_alias_sha256),
        )
        object.__setattr__(
            self, "broker_server", require_text("broker_server", self.broker_server)
        )
        object.__setattr__(
            self, "journal_sha256", require_hash("journal_sha256", self.journal_sha256)
        )
        commit = str(self.commit_sha or "").strip().lower()
        if _COMMIT_RE.fullmatch(commit) is None:
            raise ValueError("commit_sha must contain 7 through 64 hexadecimal characters")
        object.__setattr__(self, "commit_sha", commit)
        object.__setattr__(
            self, "config_sha256", require_hash("config_sha256", self.config_sha256)
        )
        object.__setattr__(self, "lane_id", require_text("lane_id", self.lane_id))

    @property
    def binding_sha256(self) -> str:
        return canonical_sha256(self)


@dataclass(frozen=True)
class ManualDemoEventReceipt:
    sequence: int
    event_id: str
    event_type: str
    intent_id: str | None
    observed_at_utc: datetime
    critical: bool
    previous_event_sha256: str
    event_sha256: str


@dataclass(frozen=True)
class ManualDemoAssessment:
    assessed_at_utc: datetime
    status: str
    clean_completed_orders: int
    criteria_observed: bool
    failed_latched: bool
    preflight_passed_orders: int
    broker_acknowledged_or_filled_orders: int
    rejected_orders: int
    sl_tp_confirmed_orders: int
    closed_reconciled_orders: int
    critical_incidents: int
    orphan_positions: int
    orphan_orders: int
    unexplained_positions: int
    total_events: int
    last_reset_sequence: int
    blocker_codes: tuple[str, ...]
    ready: bool = field(default=False, init=False)
    promotion_eligible: bool = field(default=False, init=False)
    execution_enabled: bool = field(default=False, init=False)
    manual_demo_enabled: bool = field(default=False, init=False)
    safe_to_demo_auto_order: bool = field(default=False, init=False)
    live_allowed: bool = field(default=False, init=False)
    order_capability: str = field(default="DISABLED", init=False)


@dataclass(frozen=True)
class ManualDemoAssessmentReceipt(CanonicalContract):
    """Sealed HMAC checkpoint for independent rollback/fork detection."""

    tracker_id: str
    account_alias_sha256: str
    broker_server: str
    journal_sha256: str
    commit_sha: str
    config_sha256: str
    lane_id: str
    binding_sha256: str
    key_id: str
    event_count: int
    head_sha256: str
    latest_event_at_utc: datetime | None
    created_at_utc: datetime
    assessed_at_utc: datetime
    status: str
    clean_completed_orders: int
    criteria_observed: bool
    failed_latched: bool
    preflight_passed_orders: int
    broker_acknowledged_or_filled_orders: int
    rejected_orders: int
    sl_tp_confirmed_orders: int
    closed_reconciled_orders: int
    critical_incidents: int
    orphan_positions: int
    orphan_orders: int
    unexplained_positions: int
    total_events: int
    last_reset_sequence: int
    blocker_codes: tuple[str, ...]
    receipt_hmac_sha256: str
    schema_version: str = ASSESSMENT_RECEIPT_SCHEMA_VERSION
    ready: bool = field(default=False, init=False)
    promotion_eligible: bool = field(default=False, init=False)
    execution_enabled: bool = field(default=False, init=False)
    manual_demo_enabled: bool = field(default=False, init=False)
    safe_to_demo_auto_order: bool = field(default=False, init=False)
    live_allowed: bool = field(default=False, init=False)
    order_capability: str = field(default="DISABLED", init=False)
    _seal: InitVar[object | None] = None

    def __post_init__(self, _seal: object | None) -> None:
        if _seal is not _ASSESSMENT_RECEIPT_SEAL:
            raise TypeError(
                "ManualDemoAssessmentReceipt can only be created by the tracker"
            )
        object.__setattr__(self, "tracker_id", _identifier("tracker_id", self.tracker_id))
        object.__setattr__(
            self,
            "account_alias_sha256",
            require_hash("account_alias_sha256", self.account_alias_sha256),
        )
        object.__setattr__(
            self, "broker_server", require_text("broker_server", self.broker_server)
        )
        object.__setattr__(
            self, "journal_sha256", require_hash("journal_sha256", self.journal_sha256)
        )
        commit = str(self.commit_sha or "").strip().lower()
        if _COMMIT_RE.fullmatch(commit) is None:
            raise ValueError("receipt commit hash is invalid")
        object.__setattr__(self, "commit_sha", commit)
        for name in (
            "config_sha256",
            "binding_sha256",
            "head_sha256",
            "receipt_hmac_sha256",
        ):
            object.__setattr__(self, name, require_hash(name, getattr(self, name)))
        object.__setattr__(self, "lane_id", _identifier("lane_id", self.lane_id))
        object.__setattr__(self, "key_id", _identifier("key_id", self.key_id))
        try:
            created = require_utc("created_at_utc", self.created_at_utc)
            assessed = require_utc("assessed_at_utc", self.assessed_at_utc)
            latest = (
                None
                if self.latest_event_at_utc is None
                else require_utc("latest_event_at_utc", self.latest_event_at_utc)
            )
        except (TypeError, ValueError) as exc:
            raise ValueError(str(exc)) from exc
        if assessed < created:
            raise ValueError("assessment receipt predates tracker creation")
        integer_fields = (
            "event_count",
            "clean_completed_orders",
            "preflight_passed_orders",
            "broker_acknowledged_or_filled_orders",
            "rejected_orders",
            "sl_tp_confirmed_orders",
            "closed_reconciled_orders",
            "critical_incidents",
            "orphan_positions",
            "orphan_orders",
            "unexplained_positions",
            "total_events",
            "last_reset_sequence",
        )
        for name in integer_fields:
            value = getattr(self, name)
            if type(value) is not int or value < 0:
                raise ValueError(f"{name} must be a non-negative integer")
        if self.event_count != self.total_events:
            raise ValueError("receipt event counts are inconsistent")
        if self.last_reset_sequence > self.total_events:
            raise ValueError("receipt reset sequence exceeds event count")
        if self.event_count == 0:
            if latest is not None or self.head_sha256 != ZERO_HASH:
                raise ValueError("empty receipt chain fields are inconsistent")
        elif latest is None or assessed < latest or self.head_sha256 == ZERO_HASH:
            raise ValueError("non-empty receipt chain fields are inconsistent")
        expected_criteria = (
            self.clean_completed_orders >= MINIMUM_CLEAN_COMPLETED_ORDERS
        )
        expected_failed = self.critical_incidents > 0
        expected_status = (
            "FAILED_LATCHED"
            if expected_failed
            else "CRITERIA_OBSERVED_LOCKED"
            if expected_criteria
            else "OBSERVING"
        )
        if (
            self.criteria_observed != expected_criteria
            or self.failed_latched != expected_failed
            or self.status != expected_status
        ):
            raise ValueError("receipt assessment status is inconsistent")
        if expected_failed != (self.last_reset_sequence > 0):
            raise ValueError("receipt critical reset state is inconsistent")
        expected_blockers = {"DENY_ONLY_TRACKER"}
        if not expected_criteria:
            expected_blockers.add("TEN_CLEAN_COMPLETED_ORDERS_REQUIRED")
        if expected_failed:
            expected_blockers.add("CRITICAL_INCIDENT_FAILED_LATCHED")
        blockers = tuple(sorted(set(self.blocker_codes)))
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
class _VerifiedReconciliationCycleReceipt:
    receipt_id: str
    binding_sha256: str
    observed_at_utc: datetime
    orphan_position_tickets: tuple[str, ...]
    orphan_order_tickets: tuple[str, ...]
    unexplained_position_tickets: tuple[str, ...]
    protection_failures: tuple[str, ...]
    volume_failures: tuple[str, ...]
    binding_failures: tuple[str, ...]
    critical_reason_codes: tuple[str, ...]
    kill_switch_latched: bool
    signing_key_id: str
    observation_sha256: str
    _seal: InitVar[object | None] = None

    def __post_init__(self, _seal: object | None) -> None:
        if _seal is not _VERIFIED_CYCLE_SEAL:
            raise TypeError("verified cycle receipt can only be created by its verifier")


@dataclass(frozen=True)
class _AppendPlan:
    event_type: str
    intent_id: str | None
    observed_at_utc: datetime
    observation_sha256: str
    stage_key: str
    critical: bool
    reason_codes: tuple[str, ...]
    details: Mapping[str, object]


@dataclass
class _Lifecycle:
    preflight_passed: bool = False
    guard_clean: bool = False
    symbol: str | None = None
    broker_spec_sha256: str | None = None
    execution_state: str | None = None
    broker_outcome: bool = False
    rejected: bool = False
    protected: bool = False
    closed: bool = False
    filled_volume: float = 0.0
    order_ticket_sha256: str | None = None


def _string_list(name: str, value: object, *, reasons: bool = False) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise ReconciliationCycleVerificationError(f"{name} must be a JSON array")
    try:
        normalized = tuple(
            _reason(name, item) if reasons else _identifier(name, item) for item in value
        )
    except ManualDemoTrackerError as exc:
        raise ReconciliationCycleVerificationError(str(exc)) from exc
    if tuple(sorted(set(normalized))) != normalized:
        raise ReconciliationCycleVerificationError(f"{name} must be sorted and unique")
    return normalized


def verify_reconciliation_cycle_receipt(
    payload: Mapping[str, object],
    *,
    key_provider: Callable[[str], bytes | None],
) -> _VerifiedReconciliationCycleReceipt:
    """Authenticate one aggregate broker-reconciliation observation."""

    if not isinstance(payload, Mapping) or not callable(key_provider):
        raise ReconciliationCycleVerificationError(
            "signed reconciliation-cycle payload and key provider are required"
        )
    expected = {
        "schema_version",
        "receipt_id",
        "binding_sha256",
        "observed_at_utc",
        "orphan_position_tickets",
        "orphan_order_tickets",
        "unexplained_position_tickets",
        "protection_failures",
        "volume_failures",
        "binding_failures",
        "critical_reason_codes",
        "kill_switch_latched",
        "signing_key_id",
        "signature_hmac_sha256",
    }
    if set(payload) != expected:
        raise ReconciliationCycleVerificationError("cycle receipt fields are invalid")
    if payload.get("schema_version") != RECONCILIATION_CYCLE_SCHEMA_VERSION:
        raise ReconciliationCycleVerificationError("cycle receipt schema is invalid")
    try:
        receipt_id = _identifier("receipt_id", payload["receipt_id"])
        binding_sha256 = _strict_hash("binding_sha256", payload["binding_sha256"])
        observed_text = str(payload["observed_at_utc"])
        observed = _stored_utc("cycle observed_at_utc", observed_text)
        signing_key_id = _identifier("signing_key_id", payload["signing_key_id"])
        signature = _strict_hash(
            "signature_hmac_sha256", payload["signature_hmac_sha256"]
        )
    except (ManualDemoTrackerError, ManualDemoIntegrityError) as exc:
        raise ReconciliationCycleVerificationError(str(exc)) from exc
    if type(payload["kill_switch_latched"]) is not bool:
        raise ReconciliationCycleVerificationError(
            "kill_switch_latched must be a boolean"
        )
    orphan_positions = _string_list(
        "orphan_position_tickets", payload["orphan_position_tickets"]
    )
    orphan_orders = _string_list(
        "orphan_order_tickets", payload["orphan_order_tickets"]
    )
    unexplained = _string_list(
        "unexplained_position_tickets", payload["unexplained_position_tickets"]
    )
    protection = _string_list("protection_failures", payload["protection_failures"])
    volume = _string_list("volume_failures", payload["volume_failures"])
    binding = _string_list("binding_failures", payload["binding_failures"])
    reasons = _string_list(
        "critical_reason_codes", payload["critical_reason_codes"], reasons=True
    )
    body = {key: canonicalize(payload[key]) for key in expected - {"signature_hmac_sha256"}}
    try:
        key = key_provider(signing_key_id)
    except Exception:
        raise ReconciliationCycleVerificationError(
            "trusted reconciliation-cycle key is unavailable"
        ) from None
    if not isinstance(key, (bytes, bytearray)) or len(key) < 32:
        raise ReconciliationCycleVerificationError(
            "trusted reconciliation-cycle key is unavailable or too short"
        )
    expected_signature = hmac.new(
        bytes(key),
        MANUAL_DEMO_CYCLE_HMAC_DOMAIN + canonical_json(body).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(signature, expected_signature):
        raise ReconciliationCycleVerificationError(
            "reconciliation-cycle signature is invalid"
        )
    full_payload = dict(body)
    full_payload["signature_hmac_sha256"] = signature
    return _VerifiedReconciliationCycleReceipt(
        receipt_id=receipt_id,
        binding_sha256=binding_sha256,
        observed_at_utc=observed,
        orphan_position_tickets=orphan_positions,
        orphan_order_tickets=orphan_orders,
        unexplained_position_tickets=unexplained,
        protection_failures=protection,
        volume_failures=volume,
        binding_failures=binding,
        critical_reason_codes=reasons,
        kill_switch_latched=bool(payload["kill_switch_latched"]),
        signing_key_id=signing_key_id,
        observation_sha256=canonical_sha256(full_payload),
        _seal=_VERIFIED_CYCLE_SEAL,
    )


def verify_manual_demo_assessment_receipt(
    receipt: ManualDemoAssessmentReceipt,
    key_provider: Callable[[str], str | bytes],
) -> bool:
    """Verify a sealed checkpoint without trusting local SQLite state."""

    if type(receipt) is not ManualDemoAssessmentReceipt or not callable(key_provider):
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


class ManualDemoAcceptanceTracker:
    """Restart-safe, append-only manual-demo acceptance accounting."""

    def __init__(
        self,
        path: str | Path,
        *,
        binding: ManualDemoBinding,
        key_id: str,
        key_provider: Callable[[str], str | bytes],
        clock_provider: Callable[[], datetime] = _utc_now,
        expected_receipt: ManualDemoAssessmentReceipt | None = None,
    ) -> None:
        if type(binding) is not ManualDemoBinding:
            raise TypeError("binding must be an exact ManualDemoBinding")
        if not callable(key_provider) or not callable(clock_provider):
            raise TypeError("key_provider and clock_provider must be callable")
        if (
            expected_receipt is not None
            and type(expected_receipt) is not ManualDemoAssessmentReceipt
        ):
            raise TypeError(
                "expected_receipt must be a sealed ManualDemoAssessmentReceipt"
            )
        self.path = Path(path)
        self.binding = binding
        self.key_id = _identifier("key_id", key_id)
        self._key_provider = key_provider
        self._clock_provider = clock_provider
        self._database_preexisted = self.path.exists()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.tracker_id = ""
        self.created_at_utc: datetime | None = None
        self._initialize_or_verify(expected_receipt=expected_receipt)

    def _now(self) -> datetime:
        try:
            return require_utc("trusted manual-demo clock", self._clock_provider())
        except (TypeError, ValueError) as exc:
            raise ManualDemoIntegrityError("trusted manual-demo clock is invalid") from exc

    def _secret(self) -> bytes:
        try:
            return _secret(self._key_provider(self.key_id))
        except ManualDemoIntegrityError:
            raise
        except Exception as exc:
            raise ManualDemoIntegrityError(
                "manual-demo HMAC key is unavailable"
            ) from exc

    @property
    def key_fingerprint_sha256(self) -> str:
        """Return the non-secret identity of the tracker signing key.

        External checkpoint custodians use this value to prove that their
        authority key is cryptographically distinct from the local tracker
        key.  No key material leaves the configured provider.
        """

        return hashlib.sha256(self._secret()).hexdigest()

    def _identity_body(self, *, tracker_id: str, created_at_utc: str) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "tracker_id": tracker_id,
            "binding": canonicalize(self.binding),
            "binding_sha256": self.binding.binding_sha256,
            "key_id": self.key_id,
            "created_at_utc": created_at_utc,
        }

    def _connect(self) -> sqlite3.Connection:
        try:
            connection = sqlite3.connect(
                str(self.path), timeout=10.0, isolation_level=None
            )
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA busy_timeout=10000")
            connection.execute("PRAGMA foreign_keys=ON")
            mode = connection.execute("PRAGMA journal_mode=WAL").fetchone()
            if mode is None or str(mode[0]).lower() != "wal":
                raise ManualDemoIntegrityError("SQLite WAL mode is unavailable")
            connection.execute("PRAGMA synchronous=FULL")
            synchronous = connection.execute("PRAGMA synchronous").fetchone()
            foreign_keys = connection.execute("PRAGMA foreign_keys").fetchone()
            timeout = connection.execute("PRAGMA busy_timeout").fetchone()
            if synchronous is None or int(synchronous[0]) != 2:
                raise ManualDemoIntegrityError("SQLite FULL sync is unavailable")
            if foreign_keys is None or int(foreign_keys[0]) != 1:
                raise ManualDemoIntegrityError("SQLite foreign keys are unavailable")
            if timeout is None or int(timeout[0]) != 10000:
                raise ManualDemoIntegrityError("SQLite busy timeout is unavailable")
            return connection
        except Exception:
            if "connection" in locals():
                connection.close()
            raise

    @staticmethod
    def _begin(connection: sqlite3.Connection) -> None:
        connection.execute("BEGIN IMMEDIATE")

    @staticmethod
    def _rollback(connection: sqlite3.Connection) -> None:
        if connection.in_transaction:
            connection.execute("ROLLBACK")

    def _initialize_or_verify(
        self, *, expected_receipt: ManualDemoAssessmentReceipt | None
    ) -> None:
        secret = self._secret()
        now = self._now()
        connection = self._connect()
        try:
            tables = {
                str(row[0])
                for row in connection.execute(
                    """SELECT name FROM sqlite_master
                    WHERE type='table' AND name NOT LIKE 'sqlite_%'"""
                ).fetchall()
            }
            if not tables:
                if self._database_preexisted:
                    raise ManualDemoIntegrityError(
                        "existing manual-demo tracker database is empty"
                    )
                self._create_schema(connection, secret=secret, now=now)
            elif tables != set(_EXPECTED_TABLE_COLUMNS):
                raise ManualDemoIntegrityError(
                    "manual-demo database is partial or has an unknown schema"
                )
            verified = self._verified_events(connection, secret=secret)
            if expected_receipt is not None:
                self._verify_external_receipt(
                    connection,
                    verified=verified,
                    receipt=expected_receipt,
                    secret=secret,
                    now=now,
                )
        except sqlite3.DatabaseError as exc:
            raise ManualDemoIntegrityError("manual-demo database is invalid") from exc
        finally:
            connection.close()

    def _create_schema(
        self,
        connection: sqlite3.Connection,
        *,
        secret: bytes,
        now: datetime,
    ) -> None:
        self._begin(connection)
        try:
            for sql in _TABLE_SQL.values():
                connection.execute(sql)
            for sql in _TRIGGER_SQL.values():
                connection.execute(sql)
            self.tracker_id = "manual-demo-" + uuid.uuid4().hex
            created_at = _utc_text("created_at_utc", now)
            identity_body = self._identity_body(
                tracker_id=self.tracker_id,
                created_at_utc=created_at,
            )
            connection.execute(
                """INSERT INTO manual_demo_binding(
                    singleton, schema_version, tracker_id, account_alias_sha256,
                    broker_server, journal_sha256, commit_sha, config_sha256,
                    lane_id, binding_sha256, key_id, key_fingerprint_sha256,
                    created_at_utc, identity_hmac_sha256
                ) VALUES(1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    SCHEMA_VERSION,
                    self.tracker_id,
                    self.binding.account_alias_sha256,
                    self.binding.broker_server,
                    self.binding.journal_sha256,
                    self.binding.commit_sha,
                    self.binding.config_sha256,
                    self.binding.lane_id,
                    self.binding.binding_sha256,
                    self.key_id,
                    hashlib.sha256(secret).hexdigest(),
                    created_at,
                    _hmac_sha256(secret, _IDENTITY_HMAC_DOMAIN, identity_body),
                ),
            )
            empty_state = self._state_body(())
            connection.execute(
                """INSERT INTO manual_demo_head(
                    singleton, event_count, head_sequence, head_sha256,
                    state_hmac_sha256
                ) VALUES(1, 0, 0, ?, ?)""",
                (
                    ZERO_HASH,
                    _hmac_sha256(secret, _STATE_HMAC_DOMAIN, empty_state),
                ),
            )
            connection.execute("COMMIT")
        except Exception:
            self._rollback(connection)
            raise

    def _verify_schema(self, connection: sqlite3.Connection) -> None:
        tables = {
            str(row[0]): str(row[1])
            for row in connection.execute(
                """SELECT name, sql FROM sqlite_master
                WHERE type='table' AND name NOT LIKE 'sqlite_%'"""
            ).fetchall()
        }
        if set(tables) != set(_EXPECTED_TABLE_COLUMNS):
            raise ManualDemoIntegrityError("manual-demo table set is invalid")
        for name, sql in _TABLE_SQL.items():
            if _normalized_sql(tables[name]) != _normalized_sql(sql):
                raise ManualDemoIntegrityError(
                    "manual-demo table definitions are invalid"
                )
        for table, expected in _EXPECTED_TABLE_COLUMNS.items():
            actual = tuple(
                str(row[1])
                for row in connection.execute(
                    f"PRAGMA table_info({table})"
                ).fetchall()
            )
            if actual != expected:
                raise ManualDemoIntegrityError(f"{table} schema is invalid")
        triggers = {
            str(row[0]): str(row[1])
            for row in connection.execute(
                "SELECT name, sql FROM sqlite_master WHERE type='trigger'"
            ).fetchall()
        }
        if set(triggers) != set(_TRIGGER_SQL):
            raise ManualDemoIntegrityError("manual-demo trigger set is invalid")
        for name, sql in _TRIGGER_SQL.items():
            if _normalized_sql(triggers[name]) != _normalized_sql(sql):
                raise ManualDemoIntegrityError(
                    "manual-demo trigger definitions are invalid"
                )

        user_indexes = connection.execute(
            "SELECT name FROM sqlite_master WHERE type='index' AND sql IS NOT NULL"
        ).fetchall()
        if user_indexes:
            raise ManualDemoIntegrityError("unexpected manual-demo index exists")

    def _verify_binding(
        self, connection: sqlite3.Connection, *, secret: bytes
    ) -> None:
        rows = connection.execute("SELECT * FROM manual_demo_binding").fetchall()
        if len(rows) != 1 or int(rows[0]["singleton"]) != 1:
            raise ManualDemoIntegrityError("manual-demo binding singleton is invalid")
        row = rows[0]
        try:
            tracker_id = _identifier("stored tracker_id", row["tracker_id"])
            created_at = _stored_utc("stored created_at_utc", row["created_at_utc"])
        except ManualDemoTrackerError as exc:
            raise ManualDemoIntegrityError(
                "stored manual-demo identity is invalid"
            ) from exc
        actual = {
            "schema_version": str(row["schema_version"]),
            "account_alias_sha256": str(row["account_alias_sha256"]),
            "broker_server": str(row["broker_server"]),
            "journal_sha256": str(row["journal_sha256"]),
            "commit_sha": str(row["commit_sha"]),
            "config_sha256": str(row["config_sha256"]),
            "lane_id": str(row["lane_id"]),
            "binding_sha256": str(row["binding_sha256"]),
            "key_id": str(row["key_id"]),
            "key_fingerprint_sha256": str(row["key_fingerprint_sha256"]),
        }
        expected = {
            "schema_version": SCHEMA_VERSION,
            "account_alias_sha256": self.binding.account_alias_sha256,
            "broker_server": self.binding.broker_server,
            "journal_sha256": self.binding.journal_sha256,
            "commit_sha": self.binding.commit_sha,
            "config_sha256": self.binding.config_sha256,
            "lane_id": self.binding.lane_id,
            "binding_sha256": self.binding.binding_sha256,
            "key_id": self.key_id,
            "key_fingerprint_sha256": hashlib.sha256(secret).hexdigest(),
        }
        if actual != expected:
            binding_fields = {key for key in actual if key not in {"key_fingerprint_sha256"}}
            if any(actual[key] != expected[key] for key in binding_fields):
                raise ManualDemoTrackerBindingError(
                    "manual-demo database binding does not match the requested domain"
                )
            raise ManualDemoIntegrityError("manual-demo HMAC key does not match")
        body = self._identity_body(
            tracker_id=tracker_id,
            created_at_utc=_utc_text("created_at_utc", created_at),
        )
        expected_hmac = _hmac_sha256(secret, _IDENTITY_HMAC_DOMAIN, body)
        observed_hmac = str(row["identity_hmac_sha256"])
        if _HASH_RE.fullmatch(observed_hmac) is None or not hmac.compare_digest(
            observed_hmac, expected_hmac
        ):
            raise ManualDemoIntegrityError("manual-demo identity HMAC is invalid")
        if self.tracker_id and self.tracker_id != tracker_id:
            raise ManualDemoIntegrityError("manual-demo tracker identity changed")
        if self.created_at_utc is not None and self.created_at_utc != created_at:
            raise ManualDemoIntegrityError("manual-demo tracker creation time changed")
        self.tracker_id = tracker_id
        self.created_at_utc = created_at

    def _event_hmac_body(
        self,
        *,
        sequence: int,
        event_id: str,
        observation_sha256: str,
        stage_key: str,
        event_type: str,
        intent_id: str | None,
        observed_at_utc: str,
        critical: bool,
        payload: Mapping[str, Any],
        previous_event_sha256: str,
    ) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "tracker_id": self.tracker_id,
            "binding_sha256": self.binding.binding_sha256,
            "key_id": self.key_id,
            "sequence": sequence,
            "event_id": event_id,
            "observation_sha256": observation_sha256,
            "stage_key": stage_key,
            "event_type": event_type,
            "intent_id": intent_id,
            "observed_at_utc": observed_at_utc,
            "critical": critical,
            "payload": canonicalize(payload),
            "previous_event_sha256": previous_event_sha256,
        }

    @classmethod
    def _assessment_values(
        cls,
        verified: list[tuple[sqlite3.Row, dict[str, Any], datetime]]
        | tuple[tuple[sqlite3.Row, dict[str, Any], datetime], ...],
    ) -> dict[str, Any]:
        rows = list(verified)
        states, last_critical = cls._clean_states(rows)
        completed = sum(
            1
            for state in states.values()
            if state.preflight_passed
            and state.guard_clean
            and state.broker_outcome
            and state.protected
            and state.closed
            and not state.rejected
        )
        preflight_passed = sum(
            1
            for state in states.values()
            if state.preflight_passed and state.guard_clean
        )
        broker_outcomes = sum(1 for state in states.values() if state.broker_outcome)
        protected = sum(1 for state in states.values() if state.protected)
        closed = sum(1 for state in states.values() if state.closed)
        rejected_intents = {
            str(row["intent_id"])
            for row, payload, _at in rows
            if row["intent_id"] is not None
            and (
                (row["event_type"] == "PREFLIGHT" and not payload["passed"])
                or (
                    row["event_type"] == "EXECUTION"
                    and payload["state"] == "REJECTED"
                )
            )
        }
        critical = sum(1 for row, _payload, _at in rows if row["critical"])
        orphan_positions = sum(
            int(payload["orphan_position_count"])
            for row, payload, _at in rows
            if row["event_type"] == "RECONCILIATION_CYCLE"
        )
        orphan_orders = sum(
            int(payload["orphan_order_count"])
            for row, payload, _at in rows
            if row["event_type"] == "RECONCILIATION_CYCLE"
        )
        unexplained = sum(
            int(payload["unexplained_position_count"])
            for row, payload, _at in rows
            if row["event_type"] == "RECONCILIATION_CYCLE"
        )
        criteria = completed >= MINIMUM_CLEAN_COMPLETED_ORDERS
        failed = critical > 0
        status = (
            "FAILED_LATCHED"
            if failed
            else "CRITERIA_OBSERVED_LOCKED"
            if criteria
            else "OBSERVING"
        )
        blockers = ["DENY_ONLY_TRACKER"]
        if not criteria:
            blockers.append("TEN_CLEAN_COMPLETED_ORDERS_REQUIRED")
        if failed:
            blockers.append("CRITICAL_INCIDENT_FAILED_LATCHED")
        return {
            "status": status,
            "clean_completed_orders": completed,
            "criteria_observed": criteria,
            "failed_latched": failed,
            "preflight_passed_orders": preflight_passed,
            "broker_acknowledged_or_filled_orders": broker_outcomes,
            "rejected_orders": len(rejected_intents),
            "sl_tp_confirmed_orders": protected,
            "closed_reconciled_orders": closed,
            "critical_incidents": critical,
            "orphan_positions": orphan_positions,
            "orphan_orders": orphan_orders,
            "unexplained_positions": unexplained,
            "total_events": len(rows),
            "last_reset_sequence": last_critical,
            "blocker_codes": tuple(sorted(blockers)),
        }

    def _state_body(
        self,
        verified: list[tuple[sqlite3.Row, dict[str, Any], datetime]]
        | tuple[tuple[sqlite3.Row, dict[str, Any], datetime], ...],
    ) -> dict[str, Any]:
        rows = list(verified)
        metrics = self._assessment_values(rows)
        return {
            "schema_version": SCHEMA_VERSION,
            "tracker_id": self.tracker_id,
            "binding_sha256": self.binding.binding_sha256,
            "key_id": self.key_id,
            "event_count": len(rows),
            "head_sequence": len(rows),
            "head_sha256": (
                ZERO_HASH if not rows else str(rows[-1][0]["event_sha256"])
            ),
            "latest_event_at_utc": (
                "" if not rows else _utc_text("latest event", rows[-1][2])
            ),
            "assessment_projection": canonicalize(metrics),
        }

    @staticmethod
    def _common_payload_keys() -> set[str]:
        return {
            "schema_version",
            "binding_sha256",
            "sequence",
            "event_id",
            "observation_sha256",
            "stage_key",
            "event_type",
            "intent_id",
            "observed_at_utc",
            "critical",
            "reason_codes",
            "previous_event_sha256",
            "safety",
        }

    @staticmethod
    def _detail_keys(event_type: str) -> set[str]:
        return {
            "PREFLIGHT": {
                "preflight_sha256",
                "guard_sha256",
                "passed",
                "guard_clean",
                "active_order_count",
                "active_position_count",
                "canonical_symbol",
                "broker_symbol",
                "broker_spec_sha256",
            },
            "EXECUTION": {
                "execution_receipt_id",
                "state",
                "broker_retcode",
                "requested_volume",
                "filled_volume",
                "server_protection_fields_present",
                "order_ticket_sha256",
                "deal_ticket_sha256",
            },
            "RECONCILIATION": {
                "expected_state",
                "target_state",
                "source",
                "filled_volume",
                "protection_confirmed",
                "close_reconciled",
                "order_ticket_sha256",
                "position_ticket_sha256",
            },
            "RECONCILIATION_CYCLE": {
                "receipt_id",
                "signing_key_id",
                "orphan_position_count",
                "orphan_order_count",
                "unexplained_position_count",
                "protection_failure_count",
                "volume_failure_count",
                "binding_failure_count",
                "signed_critical_reason_codes",
                "kill_switch_latched",
            },
        }[event_type]

    @staticmethod
    def _expected_reasons(
        event_type: str,
        payload: Mapping[str, object],
        prior: list[tuple[sqlite3.Row, dict[str, Any], datetime]],
    ) -> tuple[str, ...]:
        reasons: set[str] = set()
        if event_type == "PREFLIGHT":
            if (
                int(payload["active_order_count"]) > 0
                or int(payload["active_position_count"]) > 0
            ):
                reasons.add("EXISTING_BROKER_EXPOSURE")
        elif event_type == "EXECUTION":
            if payload["state"] == "UNCERTAIN":
                reasons.add("SUBMISSION_UNCERTAIN")
            if payload["state"] in {"PARTIAL", "FILLED"} and not payload[
                "server_protection_fields_present"
            ]:
                reasons.add("MISSING_SERVER_SL_TP")
        elif event_type == "RECONCILIATION":
            if payload["target_state"] == "UNCERTAIN":
                reasons.add("RECONCILIATION_UNCERTAIN")
            if payload["target_state"] in {"PARTIAL", "FILLED"} and payload[
                "protection_confirmed"
            ] is not True:
                reasons.add("MISSING_SERVER_SL_TP")
            if payload["target_state"] == "CLOSED":
                states, _ = ManualDemoAcceptanceTracker._clean_states(prior)
                state = states.get(str(payload["intent_id"]))
                if state is None or not state.protected:
                    reasons.add("CLOSE_WITHOUT_CONFIRMED_PROTECTION")
        else:
            if int(payload["orphan_position_count"]) > 0:
                reasons.add("ORPHAN_POSITION")
            if int(payload["orphan_order_count"]) > 0:
                reasons.add("ORPHAN_ORDER")
            if int(payload["unexplained_position_count"]) > 0:
                reasons.add("UNEXPLAINED_POSITION")
            if int(payload["protection_failure_count"]) > 0:
                reasons.add("PROTECTION_FAILURE")
            if int(payload["volume_failure_count"]) > 0:
                reasons.add("VOLUME_FAILURE")
            if int(payload["binding_failure_count"]) > 0:
                reasons.add("BINDING_FAILURE")
            if payload["kill_switch_latched"]:
                reasons.add("KILL_SWITCH_LATCHED")
            reasons.update(str(item) for item in payload["signed_critical_reason_codes"])
        return tuple(sorted(reasons))

    @staticmethod
    def _validate_number(
        payload: Mapping[str, object], name: str, *, positive: bool = False
    ) -> float:
        value = payload[name]
        if isinstance(value, bool):
            raise ManualDemoIntegrityError(f"{name} is invalid")
        try:
            number = float(value)
        except (TypeError, ValueError) as exc:
            raise ManualDemoIntegrityError(f"{name} is invalid") from exc
        if number < 0 or (positive and number <= 0):
            raise ManualDemoIntegrityError(f"{name} is invalid")
        return number

    def _validate_event_semantics(
        self,
        *,
        row: sqlite3.Row,
        payload: Mapping[str, object],
        expected_sequence: int,
        previous_hash: str,
        last_observed: datetime | None,
        prior: list[tuple[sqlite3.Row, dict[str, Any], datetime]],
    ) -> datetime:
        event_type = str(row["event_type"])
        if event_type not in _ALLOWED_EVENT_TYPES:
            raise ManualDemoIntegrityError("manual-demo event type is invalid")
        expected_keys = self._common_payload_keys() | self._detail_keys(event_type)
        if set(payload) != expected_keys:
            raise ManualDemoIntegrityError("manual-demo payload fields are invalid")
        observed = _stored_utc("stored event timestamp", row["observed_at_utc"])
        if last_observed is not None and observed < last_observed:
            raise ManualDemoIntegrityError("manual-demo timestamps are decreasing")
        observation = str(row["observation_sha256"])
        event_id = f"manual-demo-{event_type.lower()}-{observation[:24]}"
        intent = row["intent_id"]
        if intent is not None:
            try:
                intent = _identifier("stored intent_id", intent)
            except ManualDemoTrackerError as exc:
                raise ManualDemoIntegrityError(str(exc)) from exc
        try:
            _strict_hash("observation_sha256", observation)
        except ManualDemoTrackerError as exc:
            raise ManualDemoIntegrityError(str(exc)) from exc
        common_matches = (
            payload["schema_version"] == SCHEMA_VERSION
            and payload["binding_sha256"] == self.binding.binding_sha256
            and payload["sequence"] == expected_sequence
            and payload["event_id"] == event_id == row["event_id"]
            and payload["observation_sha256"] == observation
            and payload["stage_key"] == row["stage_key"]
            and payload["event_type"] == event_type
            and payload["intent_id"] == intent
            and payload["observed_at_utc"] == row["observed_at_utc"]
            and payload["critical"] == bool(row["critical"])
            and payload["previous_event_sha256"] == previous_hash
            and row["previous_event_sha256"] == previous_hash
            and payload["safety"] == _DENY_SAFETY
        )
        if not common_matches:
            raise ManualDemoIntegrityError("manual-demo row binding is invalid")
        reasons = payload["reason_codes"]
        if (
            not isinstance(reasons, list)
            or reasons != sorted(set(reasons))
            or any(_REASON_RE.fullmatch(str(reason)) is None for reason in reasons)
        ):
            raise ManualDemoIntegrityError("manual-demo reason codes are invalid")

        if event_type == "PREFLIGHT":
            if intent is None or row["stage_key"] != f"PREFLIGHT:{intent}":
                raise ManualDemoIntegrityError("preflight stage binding is invalid")
            if type(payload["passed"]) is not bool or type(payload["guard_clean"]) is not bool:
                raise ManualDemoIntegrityError("preflight boolean facts are invalid")
            for name in ("active_order_count", "active_position_count"):
                if isinstance(payload[name], bool) or not isinstance(payload[name], int) or payload[name] < 0:
                    raise ManualDemoIntegrityError("preflight exposure facts are invalid")
            if payload["guard_clean"] != (
                payload["active_order_count"] == 0
                and payload["active_position_count"] == 0
            ):
                raise ManualDemoIntegrityError("preflight guard fact is inconsistent")
            for name in ("preflight_sha256", "guard_sha256", "broker_spec_sha256"):
                try:
                    _strict_hash(name, payload[name])
                except ManualDemoTrackerError as exc:
                    raise ManualDemoIntegrityError(str(exc)) from exc
            _identifier("canonical_symbol", payload["canonical_symbol"])
            _identifier("broker_symbol", payload["broker_symbol"])
            expected_observation = canonical_sha256(
                {
                    "schema_version": "sealed-manual-demo-preflight-observation-v1",
                    "preflight_sha256": payload["preflight_sha256"],
                    "guard_sha256": payload["guard_sha256"],
                }
            )
            if observation != expected_observation or any(
                prior_row["intent_id"] == intent
                and prior_row["event_type"] == "PREFLIGHT"
                for prior_row, _prior_payload, _prior_at in prior
            ):
                raise ManualDemoIntegrityError(
                    "preflight source or lifecycle ordering is invalid"
                )
        elif event_type == "EXECUTION":
            if intent is None or row["stage_key"] != f"EXECUTION:{intent}":
                raise ManualDemoIntegrityError("execution stage binding is invalid")
            if payload["state"] not in _ALLOWED_EXECUTION_STATES:
                raise ManualDemoIntegrityError("execution state is invalid")
            if type(payload["server_protection_fields_present"]) is not bool:
                raise ManualDemoIntegrityError("execution protection fact is invalid")
            requested = self._validate_number(payload, "requested_volume", positive=True)
            filled = self._validate_number(payload, "filled_volume")
            if filled > requested:
                raise ManualDemoIntegrityError("execution volume is invalid")
            for name in ("order_ticket_sha256", "deal_ticket_sha256"):
                if payload[name] is not None:
                    try:
                        _strict_hash(name, payload[name])
                    except ManualDemoTrackerError as exc:
                        raise ManualDemoIntegrityError(str(exc)) from exc
            if payload["state"] == "ACKNOWLEDGED" and payload["order_ticket_sha256"] is None:
                raise ManualDemoIntegrityError("acknowledgement ticket is missing")
            if payload["state"] in {"PARTIAL", "FILLED"} and (
                filled <= 0
                or (
                    payload["order_ticket_sha256"] is None
                    and payload["deal_ticket_sha256"] is None
                )
            ):
                raise ManualDemoIntegrityError("filled execution facts are invalid")
            if payload["state"] == "REJECTED" and filled != 0:
                raise ManualDemoIntegrityError("rejected execution has a fill")
            _identifier("execution_receipt_id", payload["execution_receipt_id"])
            _identifier("broker_retcode", payload["broker_retcode"])
            if payload["execution_receipt_id"] != f"receipt_{observation[:32]}":
                raise ManualDemoIntegrityError(
                    "execution receipt identity is inconsistent"
                )
            prior_preflights = [
                prior_payload
                for prior_row, prior_payload, _prior_at in prior
                if prior_row["intent_id"] == intent
                and prior_row["event_type"] == "PREFLIGHT"
            ]
            prior_executions = [
                prior_row
                for prior_row, _prior_payload, _prior_at in prior
                if prior_row["intent_id"] == intent
                and prior_row["event_type"] == "EXECUTION"
            ]
            if (
                len(prior_preflights) != 1
                or not prior_preflights[0]["passed"]
                or prior_executions
            ):
                raise ManualDemoIntegrityError(
                    "execution lifecycle ordering is invalid"
                )
        elif event_type == "RECONCILIATION":
            if intent is None or row["stage_key"] != f"RECONCILIATION:{observation}":
                raise ManualDemoIntegrityError("reconciliation stage binding is invalid")
            expected_state = str(payload["expected_state"])
            target_state = str(payload["target_state"])
            if expected_state not in ALLOWED_TRANSITIONS or (
                target_state != expected_state
                and target_state not in ALLOWED_TRANSITIONS[expected_state]
            ):
                raise ManualDemoIntegrityError("reconciliation transition is invalid")
            source = str(payload["source"])
            if not source.startswith("BROKER_"):
                raise ManualDemoIntegrityError("reconciliation source is invalid")
            if type(payload["close_reconciled"]) is not bool or payload[
                "protection_confirmed"
            ] not in (True, False, None):
                raise ManualDemoIntegrityError("reconciliation facts are invalid")
            filled = self._validate_number(payload, "filled_volume")
            if target_state in {"PARTIAL", "FILLED"} and (
                filled <= 0 or payload["position_ticket_sha256"] is None
            ):
                raise ManualDemoIntegrityError("position reconciliation is invalid")
            if target_state == "CLOSED":
                if source != "BROKER_EXIT_DEAL_RECONCILIATION" or not payload[
                    "close_reconciled"
                ]:
                    raise ManualDemoIntegrityError("close reconciliation is invalid")
            elif payload["close_reconciled"]:
                raise ManualDemoIntegrityError("non-close event claims closure")
            for name in ("order_ticket_sha256", "position_ticket_sha256"):
                if payload[name] is not None:
                    try:
                        _strict_hash(name, payload[name])
                    except ManualDemoTrackerError as exc:
                        raise ManualDemoIntegrityError(str(exc)) from exc
            prior_executions = [
                prior_payload
                for prior_row, prior_payload, _prior_at in prior
                if prior_row["intent_id"] == intent
                and prior_row["event_type"] == "EXECUTION"
            ]
            if len(prior_executions) != 1 or prior_executions[0]["state"] == "REJECTED":
                raise ManualDemoIntegrityError(
                    "reconciliation lifecycle ordering is invalid"
                )
            current_state = str(prior_executions[0]["state"])
            known_filled_volume = float(prior_executions[0]["filled_volume"])
            execution_order_sha = prior_executions[0]["order_ticket_sha256"]
            for prior_row, prior_payload, _prior_at in prior:
                if (
                    prior_row["intent_id"] == intent
                    and prior_row["event_type"] == "RECONCILIATION"
                ):
                    current_state = str(prior_payload["target_state"])
                    if float(prior_payload["filled_volume"]) > 0:
                        known_filled_volume = float(prior_payload["filled_volume"])
            if expected_state != current_state:
                raise ManualDemoIntegrityError(
                    "reconciliation expected state is not current"
                )
            if (
                execution_order_sha is not None
                and payload["order_ticket_sha256"] is not None
                and execution_order_sha != payload["order_ticket_sha256"]
            ):
                raise ManualDemoIntegrityError(
                    "reconciliation ticket binding is invalid"
                )
            if target_state == "CLOSED" and (
                known_filled_volume <= 0
                or abs(float(payload["filled_volume"]) - known_filled_volume) > 1e-12
            ):
                raise ManualDemoIntegrityError(
                    "close volume does not match the controlled fill"
                )
        else:
            if intent is not None:
                raise ManualDemoIntegrityError("cycle event cannot bind one intent")
            receipt_id = _identifier("receipt_id", payload["receipt_id"])
            if row["stage_key"] != f"CYCLE:{receipt_id}":
                raise ManualDemoIntegrityError("cycle stage binding is invalid")
            for name in (
                "orphan_position_count",
                "orphan_order_count",
                "unexplained_position_count",
                "protection_failure_count",
                "volume_failure_count",
                "binding_failure_count",
            ):
                if isinstance(payload[name], bool) or not isinstance(payload[name], int) or payload[name] < 0:
                    raise ManualDemoIntegrityError("cycle count is invalid")
            if type(payload["kill_switch_latched"]) is not bool:
                raise ManualDemoIntegrityError("cycle latch fact is invalid")
            signed = payload["signed_critical_reason_codes"]
            if not isinstance(signed, list) or signed != sorted(set(signed)):
                raise ManualDemoIntegrityError("signed cycle reasons are invalid")
            for item in signed:
                if _REASON_RE.fullmatch(str(item)) is None:
                    raise ManualDemoIntegrityError("signed cycle reason is invalid")
            _identifier("signing_key_id", payload["signing_key_id"])

        expected_reasons = self._expected_reasons(event_type, payload, prior)
        if tuple(reasons) != expected_reasons or bool(row["critical"]) != bool(
            expected_reasons
        ):
            raise ManualDemoIntegrityError("manual-demo critical facts are inconsistent")
        return observed

    def _verified_events(
        self,
        connection: sqlite3.Connection,
        *,
        secret: bytes,
        verify_head: bool = True,
    ) -> list[tuple[sqlite3.Row, dict[str, Any], datetime]]:
        integrity = connection.execute("PRAGMA integrity_check").fetchall()
        if not integrity or any(str(row[0]).lower() != "ok" for row in integrity):
            raise ManualDemoIntegrityError("SQLite integrity check failed")
        self._verify_schema(connection)
        self._verify_binding(connection, secret=secret)
        rows = connection.execute(
            "SELECT * FROM manual_demo_events ORDER BY sequence"
        ).fetchall()
        previous = ZERO_HASH
        last_observed: datetime | None = None
        verified: list[tuple[sqlite3.Row, dict[str, Any], datetime]] = []
        for sequence, row in enumerate(rows, start=1):
            if int(row["sequence"]) != sequence:
                raise ManualDemoIntegrityError("manual-demo sequence is not contiguous")
            payload = _canonical_object(row["payload_json"])
            try:
                observed = self._validate_event_semantics(
                    row=row,
                    payload=payload,
                    expected_sequence=sequence,
                    previous_hash=previous,
                    last_observed=last_observed,
                    prior=verified,
                )
            except ManualDemoIntegrityError:
                raise
            except (ManualDemoTrackerError, TypeError, ValueError, KeyError) as exc:
                raise ManualDemoIntegrityError(
                    "stored manual-demo event semantics are invalid"
                ) from exc
            event_hash = str(row["event_sha256"])
            body = self._event_hmac_body(
                sequence=sequence,
                event_id=str(row["event_id"]),
                observation_sha256=str(row["observation_sha256"]),
                stage_key=str(row["stage_key"]),
                event_type=str(row["event_type"]),
                intent_id=(
                    None if row["intent_id"] is None else str(row["intent_id"])
                ),
                observed_at_utc=str(row["observed_at_utc"]),
                critical=bool(row["critical"]),
                payload=payload,
                previous_event_sha256=previous,
            )
            expected_hmac = _hmac_sha256(secret, _EVENT_HMAC_DOMAIN, body)
            if _HASH_RE.fullmatch(event_hash) is None or not hmac.compare_digest(
                event_hash, expected_hmac
            ):
                raise ManualDemoIntegrityError("manual-demo event HMAC is invalid")
            previous = event_hash
            last_observed = observed
            verified.append((row, payload, observed))
        if not verify_head:
            return verified
        heads = connection.execute("SELECT * FROM manual_demo_head").fetchall()
        if len(heads) != 1 or int(heads[0]["singleton"]) != 1:
            raise ManualDemoIntegrityError("manual-demo head singleton is invalid")
        head = heads[0]
        if (
            int(head["event_count"]) != len(rows)
            or int(head["head_sequence"]) != len(rows)
            or str(head["head_sha256"]) != previous
            or _HASH_RE.fullmatch(str(head["head_sha256"])) is None
        ):
            raise ManualDemoIntegrityError("manual-demo durable head is invalid")
        state_body = self._state_body(verified)
        expected_state_hmac = _hmac_sha256(
            secret,
            _STATE_HMAC_DOMAIN,
            state_body,
        )
        observed_state_hmac = str(head["state_hmac_sha256"])
        if _HASH_RE.fullmatch(observed_state_hmac) is None or not hmac.compare_digest(
            observed_state_hmac,
            expected_state_hmac,
        ):
            raise ManualDemoIntegrityError("manual-demo state HMAC is invalid")
        return verified

    @staticmethod
    def _clean_states(
        verified: list[tuple[sqlite3.Row, dict[str, Any], datetime]],
    ) -> tuple[dict[str, _Lifecycle], int]:
        last_critical = max(
            (int(row["sequence"]) for row, _payload, _at in verified if row["critical"]),
            default=0,
        )
        states: dict[str, _Lifecycle] = {}
        for row, payload, _at in verified:
            if int(row["sequence"]) <= last_critical:
                continue
            intent = row["intent_id"]
            if intent is None:
                continue
            state = states.setdefault(str(intent), _Lifecycle())
            event_type = row["event_type"]
            if event_type == "PREFLIGHT":
                state.preflight_passed = bool(payload["passed"])
                state.guard_clean = bool(payload["guard_clean"])
                state.symbol = str(payload["canonical_symbol"])
                state.broker_spec_sha256 = str(payload["broker_spec_sha256"])
                state.rejected = not state.preflight_passed
            elif event_type == "EXECUTION":
                state.execution_state = str(payload["state"])
                state.broker_outcome = state.execution_state in {
                    "ACKNOWLEDGED",
                    "PARTIAL",
                    "FILLED",
                }
                state.rejected = state.execution_state == "REJECTED"
                state.filled_volume = float(payload["filled_volume"])
                state.order_ticket_sha256 = payload["order_ticket_sha256"]
            elif event_type == "RECONCILIATION":
                target = str(payload["target_state"])
                if target in {"PARTIAL", "FILLED"}:
                    state.filled_volume = float(payload["filled_volume"])
                    if payload["protection_confirmed"] is True:
                        state.protected = True
                if target == "CLOSED" and bool(payload["close_reconciled"]):
                    state.closed = True
        return states, last_critical

    def _append(
        self,
        build_plan: Callable[
            [list[tuple[sqlite3.Row, dict[str, Any], datetime]]], _AppendPlan
        ],
    ) -> ManualDemoEventReceipt:
        secret = self._secret()
        connection = self._connect()
        try:
            self._begin(connection)
            verified = self._verified_events(connection, secret=secret)
            plan = build_plan(verified)
            if type(plan) is not _AppendPlan:
                raise ManualDemoTrackerError("internal append plan is invalid")
            if plan.event_type not in _ALLOWED_EVENT_TYPES:
                raise ManualDemoTrackerError("unsupported manual-demo event type")
            observed_text = _utc_text("observed_at_utc", plan.observed_at_utc)
            observation = _strict_hash(
                "observation_sha256", plan.observation_sha256
            )
            stage_key = _identifier("stage_key", plan.stage_key)
            duplicate = connection.execute(
                """SELECT 1 FROM manual_demo_events
                WHERE observation_sha256=? OR stage_key=? LIMIT 1""",
                (observation, stage_key),
            ).fetchone()
            if duplicate is not None:
                raise ManualDemoDuplicateError(
                    "manual-demo observation or lifecycle stage already exists"
                )
            now = self._now()
            if plan.observed_at_utc > now:
                raise ManualDemoTrackerError(
                    "manual-demo observation timestamp is in the future"
                )
            if (
                self.created_at_utc is None
                or plan.observed_at_utc < self.created_at_utc
            ):
                raise ManualDemoTrackerError(
                    "manual-demo observation predates tracker creation"
                )
            if verified and plan.observed_at_utc < verified[-1][2]:
                raise ManualDemoTrackerError(
                    "manual-demo observation timestamp is backdated"
                )
            sequence = len(verified) + 1
            previous = ZERO_HASH if not verified else str(
                verified[-1][0]["event_sha256"]
            )
            event_id = (
                f"manual-demo-{plan.event_type.lower()}-{observation[:24]}"
            )
            intent = (
                None
                if plan.intent_id is None
                else _identifier("intent_id", plan.intent_id)
            )
            reasons = tuple(sorted({_reason("reason_code", item) for item in plan.reason_codes}))
            if bool(reasons) != plan.critical:
                raise ManualDemoTrackerError("critical plan facts are inconsistent")
            payload: dict[str, object] = {
                "schema_version": SCHEMA_VERSION,
                "binding_sha256": self.binding.binding_sha256,
                "sequence": sequence,
                "event_id": event_id,
                "observation_sha256": observation,
                "stage_key": stage_key,
                "event_type": plan.event_type,
                "intent_id": intent,
                "observed_at_utc": observed_text,
                "critical": plan.critical,
                "reason_codes": list(reasons),
                "previous_event_sha256": previous,
                "safety": dict(_DENY_SAFETY),
            }
            payload.update(dict(plan.details))
            payload_json = canonical_json(payload)
            event_sha256 = _hmac_sha256(
                secret,
                _EVENT_HMAC_DOMAIN,
                self._event_hmac_body(
                    sequence=sequence,
                    event_id=event_id,
                    observation_sha256=observation,
                    stage_key=stage_key,
                    event_type=plan.event_type,
                    intent_id=intent,
                    observed_at_utc=observed_text,
                    critical=plan.critical,
                    payload=payload,
                    previous_event_sha256=previous,
                ),
            )
            try:
                connection.execute(
                    """INSERT INTO manual_demo_events(
                        event_id, observation_sha256, stage_key, event_type,
                        intent_id, observed_at_utc, critical, payload_json,
                        previous_event_sha256, event_sha256
                    ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        event_id,
                        observation,
                        stage_key,
                        plan.event_type,
                        intent,
                        observed_text,
                        int(plan.critical),
                        payload_json,
                        previous,
                        event_sha256,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise ManualDemoDuplicateError(
                    "manual-demo observation or lifecycle stage already exists"
                ) from exc
            post_verified = self._verified_events(
                connection,
                secret=secret,
                verify_head=False,
            )
            state_body = self._state_body(post_verified)
            connection.execute(
                """UPDATE manual_demo_head SET
                    event_count=?, head_sequence=?, head_sha256=?,
                    state_hmac_sha256=?
                WHERE singleton=1""",
                (
                    sequence,
                    sequence,
                    event_sha256,
                    _hmac_sha256(secret, _STATE_HMAC_DOMAIN, state_body),
                ),
            )
            self._verified_events(connection, secret=secret)
            connection.execute("COMMIT")
        except Exception:
            self._rollback(connection)
            raise
        finally:
            connection.close()
        return ManualDemoEventReceipt(
            sequence=sequence,
            event_id=event_id,
            event_type=plan.event_type,
            intent_id=intent,
            observed_at_utc=plan.observed_at_utc,
            critical=plan.critical,
            previous_event_sha256=previous,
            event_sha256=event_sha256,
        )

    def record_preflight(
        self,
        *,
        preflight: MT5Preflight,
        submission_guard: MT5SubmissionGuard,
    ) -> ManualDemoEventReceipt:
        if type(preflight) is not MT5Preflight or type(
            submission_guard
        ) is not MT5SubmissionGuard:
            raise TypeError(
                "exact sealed MT5Preflight and MT5SubmissionGuard are required"
            )
        try:
            checked = require_utc("preflight checked_at_utc", preflight.checked_at_utc)
            guard_checked = require_utc(
                "submission guard checked_at_utc", submission_guard.checked_at_utc
            )
            require_utc("preflight valid_until_utc", preflight.valid_until_utc)
            require_utc("preflight tick_time_utc", preflight.tick_time_utc)
            if type(preflight.passed) is not bool:
                raise ValueError("preflight passed must be boolean")
            intent = _identifier("preflight intent_id", preflight.intent_id)
            guard_intent = _identifier(
                "submission guard intent_id", submission_guard.intent_id
            )
            preflight_spec = _strict_hash(
                "preflight broker_spec_sha256", preflight.broker_spec_sha256
            )
            guard_spec = _strict_hash(
                "guard broker_spec_sha256", submission_guard.broker_spec_sha256
            )
            if intent != guard_intent or preflight_spec != guard_spec:
                raise ManualDemoTrackerError(
                    "preflight and submission guard binding do not match"
                )
            if (
                _account_alias_sha256(submission_guard.account_id)
                != self.binding.account_alias_sha256
                or submission_guard.server != self.binding.broker_server
            ):
                raise ManualDemoTrackerBindingError(
                    "submission guard account/server binding does not match"
                )
            canonical_symbol = _identifier(
                "submission guard symbol", submission_guard.symbol
            ).upper()
            broker_symbol = _identifier(
                "preflight broker_symbol", preflight.broker_symbol
            ).upper()
            if (
                isinstance(submission_guard.active_order_count, bool)
                or isinstance(submission_guard.active_position_count, bool)
                or submission_guard.active_order_count < 0
                or submission_guard.active_position_count < 0
            ):
                raise ValueError("submission guard exposure is invalid")
            preflight_sha = _strict_hash(
                "preflight content_sha256", preflight.content_sha256
            )
            guard_sha = _strict_hash(
                "guard content_sha256", submission_guard.content_sha256
            )
        except ManualDemoTrackerError:
            raise
        except (TypeError, ValueError) as exc:
            raise ManualDemoTrackerError(str(exc)) from exc
        observed = max(checked, guard_checked)
        observation = canonical_sha256(
            {
                "schema_version": "sealed-manual-demo-preflight-observation-v1",
                "preflight_sha256": preflight_sha,
                "guard_sha256": guard_sha,
            }
        )
        guard_clean = (
            submission_guard.active_order_count == 0
            and submission_guard.active_position_count == 0
        )
        reasons = () if guard_clean else ("EXISTING_BROKER_EXPOSURE",)

        def plan(
            _verified: list[tuple[sqlite3.Row, dict[str, Any], datetime]],
        ) -> _AppendPlan:
            return _AppendPlan(
                event_type="PREFLIGHT",
                intent_id=intent,
                observed_at_utc=observed,
                observation_sha256=observation,
                stage_key=f"PREFLIGHT:{intent}",
                critical=bool(reasons),
                reason_codes=reasons,
                details={
                    "preflight_sha256": preflight_sha,
                    "guard_sha256": guard_sha,
                    "passed": preflight.passed,
                    "guard_clean": guard_clean,
                    "active_order_count": submission_guard.active_order_count,
                    "active_position_count": submission_guard.active_position_count,
                    "canonical_symbol": canonical_symbol,
                    "broker_symbol": broker_symbol,
                    "broker_spec_sha256": preflight_spec,
                },
            )

        return self._append(plan)

    def record_execution(
        self, *, receipt: ExecutionReceipt
    ) -> ManualDemoEventReceipt:
        if type(receipt) is not ExecutionReceipt:
            raise TypeError("exact sealed ExecutionReceipt is required")
        try:
            observed = require_utc("execution received_at", receipt.received_at)
            intent = _identifier("execution intent_id", receipt.intent_id)
            state = require_text("execution state", receipt.state, upper=True)
            if state not in _ALLOWED_EXECUTION_STATES:
                raise ManualDemoTrackerError(
                    "execution receipt state is outside manual-demo acceptance"
                )
            if (
                _account_alias_sha256(receipt.account_id)
                != self.binding.account_alias_sha256
                or receipt.server != self.binding.broker_server
                or receipt.journal_sha256 != self.binding.journal_sha256
            ):
                raise ManualDemoTrackerBindingError(
                    "execution receipt account/server/journal binding does not match"
                )
            symbol = _identifier("execution symbol", receipt.symbol).upper()
            requested_volume = float(receipt.requested_volume)
            filled_volume = float(receipt.filled_volume)
            if requested_volume <= 0 or filled_volume < 0 or filled_volume > requested_volume:
                raise ValueError("execution volume is invalid")
            order_ticket_sha = _ticket_hash(receipt.order_ticket)
            deal_ticket_sha = _ticket_hash(receipt.deal_ticket)
            if state == "ACKNOWLEDGED" and order_ticket_sha is None:
                raise ManualDemoTrackerError(
                    "broker acknowledgement requires an order ticket"
                )
            if state in {"PARTIAL", "FILLED"} and (
                filled_volume <= 0
                or (order_ticket_sha is None and deal_ticket_sha is None)
            ):
                raise ManualDemoTrackerError("broker fill evidence is incomplete")
            if state == "REJECTED" and filled_volume != 0:
                raise ManualDemoTrackerError("rejected execution cannot contain a fill")
            protection_fields = (
                receipt.stop_loss is not None
                and float(receipt.stop_loss) > 0
                and receipt.take_profit is not None
                and float(receipt.take_profit) > 0
            )
            observation = _strict_hash(
                "execution receipt content_sha256", receipt.content_sha256
            )
            receipt_id = _identifier("execution receipt_id", receipt.receipt_id)
            broker_retcode = _identifier("broker_retcode", receipt.broker_retcode)
        except ManualDemoTrackerError:
            raise
        except (TypeError, ValueError) as exc:
            raise ManualDemoTrackerError(str(exc)) from exc
        reasons: list[str] = []
        if state == "UNCERTAIN":
            reasons.append("SUBMISSION_UNCERTAIN")
        if state in {"PARTIAL", "FILLED"} and not protection_fields:
            reasons.append("MISSING_SERVER_SL_TP")

        def plan(
            verified: list[tuple[sqlite3.Row, dict[str, Any], datetime]],
        ) -> _AppendPlan:
            histories = [
                payload
                for row, payload, _at in verified
                if row["intent_id"] == intent and row["event_type"] == "PREFLIGHT"
            ]
            if len(histories) != 1:
                raise ManualDemoTrackerError(
                    "execution receipt has no unique controlled preflight"
                )
            preflight_payload = histories[0]
            if not preflight_payload["passed"]:
                raise ManualDemoTrackerError(
                    "execution cannot follow a rejected preflight"
                )
            if symbol != preflight_payload["canonical_symbol"]:
                raise ManualDemoTrackerBindingError(
                    "execution receipt symbol does not match controlled preflight"
                )
            return _AppendPlan(
                event_type="EXECUTION",
                intent_id=intent,
                observed_at_utc=observed,
                observation_sha256=observation,
                stage_key=f"EXECUTION:{intent}",
                critical=bool(reasons),
                reason_codes=tuple(reasons),
                details={
                    "execution_receipt_id": receipt_id,
                    "state": state,
                    "broker_retcode": broker_retcode,
                    "requested_volume": requested_volume,
                    "filled_volume": filled_volume,
                    "server_protection_fields_present": protection_fields,
                    "order_ticket_sha256": order_ticket_sha,
                    "deal_ticket_sha256": deal_ticket_sha,
                },
            )

        return self._append(plan)

    def record_reconciliation(
        self, *, evidence: _BrokerReconciliationEvidence
    ) -> ManualDemoEventReceipt:
        if type(evidence) is not _BrokerReconciliationEvidence:
            raise TypeError("exact sealed broker reconciliation evidence is required")
        try:
            observed = require_utc(
                "reconciliation observed_at", evidence.observed_at
            )
            intent = _identifier("reconciliation intent_id", evidence.intent_id)
            expected_state = require_text(
                "reconciliation expected_state", evidence.expected_state, upper=True
            )
            target_state = require_text(
                "reconciliation target_state", evidence.target_state, upper=True
            )
            if expected_state not in ALLOWED_TRANSITIONS or (
                target_state != expected_state
                and target_state not in ALLOWED_TRANSITIONS[expected_state]
            ):
                raise ManualDemoTrackerError(
                    "reconciliation transition is invalid"
                )
            if target_state not in {
                "ACKNOWLEDGED",
                "PARTIAL",
                "FILLED",
                "UNCERTAIN",
                "CLOSED",
            }:
                raise ManualDemoTrackerError(
                    "reconciliation target is outside manual-demo acceptance"
                )
            details = canonicalize(dict(evidence.details))
            if not isinstance(details, dict):
                raise TypeError("reconciliation details are invalid")
            source = require_text(
                "reconciliation source", details.get("source"), upper=True
            )
            if not source.startswith("BROKER_"):
                raise ManualDemoTrackerError(
                    "reconciliation evidence is not broker-derived"
                )
            filled_volume = (
                0.0 if evidence.filled_volume is None else float(evidence.filled_volume)
            )
            if filled_volume < 0:
                raise ValueError("reconciliation filled_volume is invalid")
            order_ticket_sha = _ticket_hash(evidence.broker_order_ticket)
            position_ticket_sha = _ticket_hash(evidence.broker_position_ticket)
            if target_state in {"PARTIAL", "FILLED"} and (
                filled_volume <= 0 or position_ticket_sha is None
            ):
                raise ManualDemoTrackerError(
                    "position reconciliation requires ticket and positive volume"
                )
            close_reconciled = target_state == "CLOSED"
            if close_reconciled:
                if source != "BROKER_EXIT_DEAL_RECONCILIATION":
                    raise ManualDemoTrackerError(
                        "close requires broker exit-deal reconciliation"
                    )
                closed_volume = details.get("closed_volume")
                if isinstance(closed_volume, bool):
                    raise ManualDemoTrackerError("broker close volume is invalid")
                try:
                    normalized_closed = float(closed_volume)
                except (TypeError, ValueError) as exc:
                    raise ManualDemoTrackerError(
                        "broker close volume is invalid"
                    ) from exc
                if normalized_closed <= 0 or abs(normalized_closed - filled_volume) > 1e-12:
                    raise ManualDemoTrackerError(
                        "broker close volume does not match reconciled volume"
                    )
            snapshot = {
                "intent_id": intent,
                "expected_state": expected_state,
                "target_state": target_state,
                "observed_at": _utc_text("observed_at", observed),
                "details": details,
                "broker_order_ticket_sha256": order_ticket_sha,
                "broker_position_ticket_sha256": position_ticket_sha,
                "filled_volume": filled_volume,
                "protective_sl_tp_confirmed": evidence.protective_sl_tp_confirmed,
                "last_error": None
                if evidence.last_error is None
                else str(evidence.last_error),
            }
            observation = canonical_sha256(snapshot)
        except ManualDemoTrackerError:
            raise
        except (TypeError, ValueError) as exc:
            raise ManualDemoTrackerError(str(exc)) from exc

        def plan(
            verified: list[tuple[sqlite3.Row, dict[str, Any], datetime]],
        ) -> _AppendPlan:
            preflights = [
                payload
                for row, payload, _at in verified
                if row["intent_id"] == intent and row["event_type"] == "PREFLIGHT"
            ]
            executions = [
                payload
                for row, payload, _at in verified
                if row["intent_id"] == intent and row["event_type"] == "EXECUTION"
            ]
            if len(preflights) != 1 or len(executions) != 1:
                raise ManualDemoTrackerError(
                    "reconciliation has no unique controlled execution"
                )
            if not preflights[0]["passed"] or executions[0]["state"] == "REJECTED":
                raise ManualDemoTrackerError(
                    "reconciliation cannot follow a rejected controlled order"
                )
            execution_order_sha = executions[0]["order_ticket_sha256"]
            if (
                execution_order_sha is not None
                and order_ticket_sha is not None
                and execution_order_sha != order_ticket_sha
            ):
                raise ManualDemoTrackerBindingError(
                    "reconciliation order ticket does not match execution receipt"
                )
            states, _last_critical = self._clean_states(verified)
            clean_state = states.get(intent)
            reasons: list[str] = []
            if target_state == "UNCERTAIN":
                reasons.append("RECONCILIATION_UNCERTAIN")
            if target_state in {"PARTIAL", "FILLED"} and evidence.protective_sl_tp_confirmed is not True:
                reasons.append("MISSING_SERVER_SL_TP")
            if target_state == "CLOSED" and (
                clean_state is None or not clean_state.protected
            ):
                reasons.append("CLOSE_WITHOUT_CONFIRMED_PROTECTION")
            return _AppendPlan(
                event_type="RECONCILIATION",
                intent_id=intent,
                observed_at_utc=observed,
                observation_sha256=observation,
                stage_key=f"RECONCILIATION:{observation}",
                critical=bool(reasons),
                reason_codes=tuple(reasons),
                details={
                    "expected_state": expected_state,
                    "target_state": target_state,
                    "source": source,
                    "filled_volume": filled_volume,
                    "protection_confirmed": evidence.protective_sl_tp_confirmed,
                    "close_reconciled": close_reconciled,
                    "order_ticket_sha256": order_ticket_sha,
                    "position_ticket_sha256": position_ticket_sha,
                },
            )

        return self._append(plan)

    def record_reconciliation_cycle(
        self, *, receipt: _VerifiedReconciliationCycleReceipt
    ) -> ManualDemoEventReceipt:
        if type(receipt) is not _VerifiedReconciliationCycleReceipt:
            raise TypeError("exact verified reconciliation-cycle receipt is required")
        if receipt.binding_sha256 != self.binding.binding_sha256:
            raise ReconciliationCycleVerificationError(
                "reconciliation-cycle receipt binding does not match"
            )
        reasons: set[str] = set(receipt.critical_reason_codes)
        if receipt.orphan_position_tickets:
            reasons.add("ORPHAN_POSITION")
        if receipt.orphan_order_tickets:
            reasons.add("ORPHAN_ORDER")
        if receipt.unexplained_position_tickets:
            reasons.add("UNEXPLAINED_POSITION")
        if receipt.protection_failures:
            reasons.add("PROTECTION_FAILURE")
        if receipt.volume_failures:
            reasons.add("VOLUME_FAILURE")
        if receipt.binding_failures:
            reasons.add("BINDING_FAILURE")
        if receipt.kill_switch_latched:
            reasons.add("KILL_SWITCH_LATCHED")

        def plan(
            _verified: list[tuple[sqlite3.Row, dict[str, Any], datetime]],
        ) -> _AppendPlan:
            return _AppendPlan(
                event_type="RECONCILIATION_CYCLE",
                intent_id=None,
                observed_at_utc=receipt.observed_at_utc,
                observation_sha256=receipt.observation_sha256,
                stage_key=f"CYCLE:{receipt.receipt_id}",
                critical=bool(reasons),
                reason_codes=tuple(sorted(reasons)),
                details={
                    "receipt_id": receipt.receipt_id,
                    "signing_key_id": receipt.signing_key_id,
                    "orphan_position_count": len(receipt.orphan_position_tickets),
                    "orphan_order_count": len(receipt.orphan_order_tickets),
                    "unexplained_position_count": len(
                        receipt.unexplained_position_tickets
                    ),
                    "protection_failure_count": len(receipt.protection_failures),
                    "volume_failure_count": len(receipt.volume_failures),
                    "binding_failure_count": len(receipt.binding_failures),
                    "signed_critical_reason_codes": list(
                        receipt.critical_reason_codes
                    ),
                    "kill_switch_latched": receipt.kill_switch_latched,
                },
            )

        return self._append(plan)

    def events(self) -> tuple[ManualDemoEventReceipt, ...]:
        secret = self._secret()
        connection = self._connect()
        try:
            verified = self._verified_events(connection, secret=secret)
            return tuple(
                ManualDemoEventReceipt(
                    sequence=int(row["sequence"]),
                    event_id=str(row["event_id"]),
                    event_type=str(row["event_type"]),
                    intent_id=None
                    if row["intent_id"] is None
                    else str(row["intent_id"]),
                    observed_at_utc=observed,
                    critical=bool(row["critical"]),
                    previous_event_sha256=str(row["previous_event_sha256"]),
                    event_sha256=str(row["event_sha256"]),
                )
                for row, _payload, observed in verified
            )
        except sqlite3.DatabaseError as exc:
            raise ManualDemoIntegrityError("manual-demo database is invalid") from exc
        finally:
            connection.close()

    def verify_integrity(
        self,
        *,
        expected_receipt: ManualDemoAssessmentReceipt | None = None,
    ) -> bool:
        if (
            expected_receipt is not None
            and type(expected_receipt) is not ManualDemoAssessmentReceipt
        ):
            raise TypeError(
                "expected_receipt must be a sealed ManualDemoAssessmentReceipt"
            )
        try:
            secret = self._secret()
            now = self._now()
            connection = self._connect()
            try:
                verified = self._verified_events(connection, secret=secret)
                if expected_receipt is not None:
                    self._verify_external_receipt(
                        connection,
                        verified=verified,
                        receipt=expected_receipt,
                        secret=secret,
                        now=now,
                    )
            finally:
                connection.close()
        except (sqlite3.DatabaseError, ManualDemoTrackerError, TypeError, ValueError):
            return False
        return True

    def storage_profile(self) -> dict[str, object]:
        secret = self._secret()
        connection = self._connect()
        try:
            self._verified_events(connection, secret=secret)
            triggers = {
                str(row[0])
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='trigger'"
                ).fetchall()
            }
            synchronous = int(connection.execute("PRAGMA synchronous").fetchone()[0])
            return {
                "journal_mode": str(
                    connection.execute("PRAGMA journal_mode").fetchone()[0]
                ).lower(),
                "synchronous": "FULL" if synchronous == 2 else str(synchronous),
                "foreign_keys": bool(
                    connection.execute("PRAGMA foreign_keys").fetchone()[0]
                ),
                "busy_timeout_ms": int(
                    connection.execute("PRAGMA busy_timeout").fetchone()[0]
                ),
                "event_update_trigger": "manual_demo_events_no_update" in triggers,
                "event_delete_trigger": "manual_demo_events_no_delete" in triggers,
                "binding_update_trigger": "manual_demo_binding_no_update" in triggers,
                "binding_delete_trigger": "manual_demo_binding_no_delete" in triggers,
                "head_delete_trigger": "manual_demo_head_no_delete" in triggers,
                "identity_hmac": True,
                "event_hmac_chain": True,
                "state_hmac": True,
                "strict_schema": True,
                "key_id": self.key_id,
            }
        finally:
            connection.close()

    def _build_assessment(
        self,
        *,
        verified: list[tuple[sqlite3.Row, dict[str, Any], datetime]],
        as_of: datetime,
    ) -> ManualDemoAssessment:
        values = self._assessment_values(verified)
        return ManualDemoAssessment(assessed_at_utc=as_of, **values)

    def _state_and_assessment(
        self, *, as_of_utc: datetime
    ) -> tuple[
        list[tuple[sqlite3.Row, dict[str, Any], datetime]],
        ManualDemoAssessment,
        bytes,
    ]:
        try:
            as_of = require_utc("as_of_utc", as_of_utc)
        except (TypeError, ValueError) as exc:
            raise ManualDemoTrackerError(str(exc)) from exc
        now = self._now()
        if as_of > now:
            raise ManualDemoTrackerError("assessment timestamp is in the future")
        if self.created_at_utc is None or as_of < self.created_at_utc:
            raise ManualDemoTrackerError("assessment predates tracker creation")
        secret = self._secret()
        connection = self._connect()
        try:
            verified = self._verified_events(connection, secret=secret)
        except sqlite3.DatabaseError as exc:
            raise ManualDemoIntegrityError("manual-demo database is invalid") from exc
        finally:
            connection.close()
        if verified and as_of < verified[-1][2]:
            raise ManualDemoTrackerError(
                "assessment timestamp precedes the latest observation"
            )
        return verified, self._build_assessment(verified=verified, as_of=as_of), secret

    def assessment(self, *, as_of_utc: datetime) -> ManualDemoAssessment:
        return self._state_and_assessment(as_of_utc=as_of_utc)[1]

    def assessment_receipt(
        self, *, as_of_utc: datetime
    ) -> ManualDemoAssessmentReceipt:
        verified, report, secret = self._state_and_assessment(as_of_utc=as_of_utc)
        if self.created_at_utc is None:
            raise ManualDemoIntegrityError("manual-demo tracker creation time is missing")
        values: dict[str, Any] = {
            "tracker_id": self.tracker_id,
            "account_alias_sha256": self.binding.account_alias_sha256,
            "broker_server": self.binding.broker_server,
            "journal_sha256": self.binding.journal_sha256,
            "commit_sha": self.binding.commit_sha,
            "config_sha256": self.binding.config_sha256,
            "lane_id": self.binding.lane_id,
            "binding_sha256": self.binding.binding_sha256,
            "key_id": self.key_id,
            "event_count": report.total_events,
            "head_sha256": (
                ZERO_HASH if not verified else str(verified[-1][0]["event_sha256"])
            ),
            "latest_event_at_utc": None if not verified else verified[-1][2],
            "created_at_utc": self.created_at_utc,
            "assessed_at_utc": report.assessed_at_utc,
            "status": report.status,
            "clean_completed_orders": report.clean_completed_orders,
            "criteria_observed": report.criteria_observed,
            "failed_latched": report.failed_latched,
            "preflight_passed_orders": report.preflight_passed_orders,
            "broker_acknowledged_or_filled_orders": report.broker_acknowledged_or_filled_orders,
            "rejected_orders": report.rejected_orders,
            "sl_tp_confirmed_orders": report.sl_tp_confirmed_orders,
            "closed_reconciled_orders": report.closed_reconciled_orders,
            "critical_incidents": report.critical_incidents,
            "orphan_positions": report.orphan_positions,
            "orphan_orders": report.orphan_orders,
            "unexplained_positions": report.unexplained_positions,
            "total_events": report.total_events,
            "last_reset_sequence": report.last_reset_sequence,
            "blocker_codes": report.blocker_codes,
            "schema_version": ASSESSMENT_RECEIPT_SCHEMA_VERSION,
            **dict(_DENY_SAFETY),
        }
        signature = _hmac_sha256(secret, _ASSESSMENT_HMAC_DOMAIN, values)
        init_values = {
            key: value for key, value in values.items() if key not in _DENY_SAFETY
        }
        return ManualDemoAssessmentReceipt(
            **init_values,
            receipt_hmac_sha256=signature,
            _seal=_ASSESSMENT_RECEIPT_SEAL,
        )

    def _verify_external_receipt(
        self,
        connection: sqlite3.Connection,
        *,
        verified: list[tuple[sqlite3.Row, dict[str, Any], datetime]],
        receipt: ManualDemoAssessmentReceipt,
        secret: bytes,
        now: datetime,
    ) -> None:
        expected_signature = _hmac_sha256(
            secret,
            _ASSESSMENT_HMAC_DOMAIN,
            receipt.signing_payload,
        )
        if not hmac.compare_digest(receipt.receipt_hmac_sha256, expected_signature):
            raise ManualDemoIntegrityError(
                "external manual-demo receipt signature is invalid"
            )
        exact = (
            receipt.tracker_id == self.tracker_id
            and receipt.account_alias_sha256 == self.binding.account_alias_sha256
            and receipt.broker_server == self.binding.broker_server
            and receipt.journal_sha256 == self.binding.journal_sha256
            and receipt.commit_sha == self.binding.commit_sha
            and receipt.config_sha256 == self.binding.config_sha256
            and receipt.lane_id == self.binding.lane_id
            and receipt.binding_sha256 == self.binding.binding_sha256
            and receipt.key_id == self.key_id
            and receipt.created_at_utc == self.created_at_utc
        )
        if not exact:
            raise ManualDemoTrackerBindingError(
                "external manual-demo receipt binding does not match"
            )
        if receipt.assessed_at_utc > now:
            raise ManualDemoRollbackError(
                "external manual-demo receipt is from the future"
            )
        if len(verified) < receipt.event_count:
            raise ManualDemoRollbackError("local manual-demo event count regressed")
        if receipt.event_count == 0:
            if receipt.head_sha256 != ZERO_HASH or receipt.latest_event_at_utc is not None:
                raise ManualDemoRollbackError("empty external receipt is inconsistent")
        else:
            prefix = verified[receipt.event_count - 1]
            if not hmac.compare_digest(
                str(prefix[0]["event_sha256"]), receipt.head_sha256
            ):
                raise ManualDemoRollbackError(
                    "local manual-demo chain forked or was rewritten"
                )
            if prefix[2] != receipt.latest_event_at_utc:
                raise ManualDemoRollbackError(
                    "local manual-demo prefix time changed"
                )
        current = self._build_assessment(verified=verified, as_of=now)
        if current.critical_incidents < receipt.critical_incidents:
            raise ManualDemoRollbackError("critical incident history regressed")
        if current.rejected_orders < receipt.rejected_orders:
            raise ManualDemoRollbackError("rejection history regressed")
        if current.orphan_positions < receipt.orphan_positions:
            raise ManualDemoRollbackError("orphan-position history regressed")
        if current.orphan_orders < receipt.orphan_orders:
            raise ManualDemoRollbackError("orphan-order history regressed")
        if current.unexplained_positions < receipt.unexplained_positions:
            raise ManualDemoRollbackError("unexplained-position history regressed")
        if receipt.failed_latched and not current.failed_latched:
            raise ManualDemoRollbackError("permanent failure latch regressed")
        if len(verified) == receipt.event_count:
            comparable = (
                "status",
                "clean_completed_orders",
                "criteria_observed",
                "failed_latched",
                "preflight_passed_orders",
                "broker_acknowledged_or_filled_orders",
                "rejected_orders",
                "sl_tp_confirmed_orders",
                "closed_reconciled_orders",
                "critical_incidents",
                "orphan_positions",
                "orphan_orders",
                "unexplained_positions",
                "total_events",
                "last_reset_sequence",
                "blocker_codes",
            )
            if any(getattr(current, name) != getattr(receipt, name) for name in comparable):
                raise ManualDemoRollbackError(
                    "same-head manual-demo assessment was rewritten"
                )
        elif current.last_reset_sequence == receipt.last_reset_sequence:
            monotonic = (
                "clean_completed_orders",
                "preflight_passed_orders",
                "broker_acknowledged_or_filled_orders",
                "sl_tp_confirmed_orders",
                "closed_reconciled_orders",
            )
            if any(getattr(current, name) < getattr(receipt, name) for name in monotonic):
                raise ManualDemoRollbackError(
                    "current clean manual-demo lifecycle counters regressed"
                )
        elif current.critical_incidents <= receipt.critical_incidents:
            raise ManualDemoRollbackError(
                "manual-demo reset advanced without critical evidence"
            )


__all__ = [
    "ASSESSMENT_RECEIPT_SCHEMA_VERSION",
    "MANUAL_DEMO_CYCLE_HMAC_DOMAIN",
    "MINIMUM_CLEAN_COMPLETED_ORDERS",
    "ManualDemoAcceptanceTracker",
    "ManualDemoAssessment",
    "ManualDemoAssessmentReceipt",
    "ManualDemoBinding",
    "ManualDemoDuplicateError",
    "ManualDemoEventReceipt",
    "ManualDemoIntegrityError",
    "ManualDemoRollbackError",
    "ManualDemoTrackerBindingError",
    "ManualDemoTrackerError",
    "ReconciliationCycleVerificationError",
    "SCHEMA_VERSION",
    "verify_manual_demo_assessment_receipt",
    "verify_reconciliation_cycle_receipt",
]
