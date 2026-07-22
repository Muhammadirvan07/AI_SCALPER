"""Durable broker-derived risk state without execution authority.

The ledger is an append-only, HMAC chained record of immutable broker account
snapshots, entries, and closed trades.  It materializes only the state needed by
a future trusted risk-context collector.  It never creates ``RiskContext`` and
contains no broker mutation, permit, demo-auto, or live-trading capability.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import InitVar, dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
import re
from pathlib import Path
import sqlite3
from types import MappingProxyType
from typing import Any, Callable, Iterator, Mapping
import uuid

from .contracts import (
    CanonicalContract,
    canonical_json,
    require_currency,
    require_finite,
    require_hash,
    require_int,
    require_text,
    require_utc,
)


UTC = timezone.utc
LEDGER_SCHEMA_VERSION = "durable-risk-ledger-v1"
EVENT_SCHEMA_VERSION = "durable-risk-event-v1"
RECEIPT_SCHEMA_VERSION = "durable-risk-state-receipt-v1"
CHECKPOINT_CAS_ACK_SCHEMA_VERSION = "durable-risk-checkpoint-cas-ack-v1"
SOURCE_RECEIPT_SCHEMA_VERSION = "durable-risk-source-receipt-v1"
ZERO_HMAC_SHA256 = "0" * 64
LOSS_LATCH_COUNT = 2
MAX_FUTURE_CLOCK_DRIFT_SECONDS = 1.0
MAX_SOURCE_RECEIPT_LIFETIME_SECONDS = 5.0

_EVENT_HMAC_DOMAIN = b"AI_SCALPER_DURABLE_RISK_EVENT_V1\x00"
_IDENTITY_HMAC_DOMAIN = b"AI_SCALPER_DURABLE_RISK_IDENTITY_V1\x00"
_STATE_HMAC_DOMAIN = b"AI_SCALPER_DURABLE_RISK_STATE_V1\x00"
_RECEIPT_HMAC_DOMAIN = b"AI_SCALPER_DURABLE_RISK_RECEIPT_V1\x00"
_SOURCE_HMAC_DOMAIN = b"AI_SCALPER_DURABLE_RISK_SOURCE_V1\x00"
_RECEIPT_SEAL = object()
_SOURCE_RECEIPT_SEAL = object()
_EXACT_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@+\-]{0,127}$")
_SYMBOL = re.compile(r"^[A-Z0-9][A-Z0-9._\-]{0,31}$")


class RiskLedgerError(RuntimeError):
    """Base fail-closed risk-ledger error."""


class RiskLedgerBindingError(RiskLedgerError):
    """Raised when a caller or database does not match the exact binding."""


class RiskLedgerIntegrityError(RiskLedgerError):
    """Raised for structural, semantic, HMAC, or materialized-state tamper."""


class RiskLedgerDuplicateError(RiskLedgerError):
    """Raised when an immutable event or closed entry is repeated."""


class RiskLedgerRollbackError(RiskLedgerIntegrityError):
    """Raised when time, session, sequence, or an external checkpoint regresses."""


class RiskLedgerSourceError(RiskLedgerIntegrityError):
    """Raised when upstream source evidence is missing, forged, or mismatched."""


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _exact_id(name: str, value: object) -> str:
    if not isinstance(value, str) or _EXACT_ID.fullmatch(value) is None:
        raise ValueError(f"{name} must be an exact session-safe identifier")
    return value


def _exact_text(name: str, value: object, *, maximum: int = 255) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > maximum
        or any(ord(character) < 32 for character in value)
    ):
        raise ValueError(f"{name} must be exact non-empty text")
    return value


def _symbol(value: object) -> str:
    normalized = require_text("symbol", value, upper=True)
    if _SYMBOL.fullmatch(normalized) is None:
        raise ValueError("symbol is invalid")
    return normalized


def _iso(value: datetime) -> str:
    return require_utc("timestamp", value).isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )


def _parse_utc(value: object) -> datetime:
    if not isinstance(value, str):
        raise RiskLedgerIntegrityError("stored timestamp must be text")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        parsed = require_utc("stored timestamp", parsed)
    except (TypeError, ValueError) as exc:
        raise RiskLedgerIntegrityError("stored timestamp is not aware UTC") from exc
    if _iso(parsed) != value:
        raise RiskLedgerIntegrityError("stored timestamp is not canonical UTC")
    return parsed


def _source_utc(value: object) -> datetime:
    if isinstance(value, datetime):
        try:
            return require_utc("risk source timestamp", value)
        except ValueError as exc:
            raise RiskLedgerSourceError("risk source timestamp is not aware UTC") from exc
    return _parse_utc(value)


def _key(value: object) -> bytes:
    if isinstance(value, str):
        normalized = value.encode("utf-8")
    elif isinstance(value, bytes):
        normalized = value
    else:
        raise RiskLedgerIntegrityError("risk-ledger HMAC key must be str or bytes")
    if len(normalized) < 32:
        raise RiskLedgerIntegrityError("risk-ledger HMAC key must contain 32 bytes")
    return normalized


def _hmac_sha256(secret: bytes, domain: bytes, value: Mapping[str, Any]) -> str:
    payload = canonical_json(value).encode("utf-8")
    return hmac.new(secret, domain + payload, hashlib.sha256).hexdigest()


def _strict_object(value: object, field: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise RiskLedgerIntegrityError(f"{field} must be an object")
    return {str(key): item for key, item in value.items()}


def _exact_fields(value: Mapping[str, Any], expected: set[str], field: str) -> None:
    observed = set(value)
    if observed != expected:
        raise RiskLedgerIntegrityError(f"{field} fields are invalid")


@dataclass(frozen=True)
class RiskLedgerBinding(CanonicalContract):
    account_id_sha256: str
    server: str
    environment: str
    journal_sha256: str
    broker_spec_sha256: str
    account_currency: str

    def __post_init__(self) -> None:
        account_identity = require_hash("account_id_sha256", self.account_id_sha256)
        if account_identity == ZERO_HMAC_SHA256:
            raise ValueError("account_id_sha256 cannot be the zero hash")
        object.__setattr__(self, "account_id_sha256", account_identity)
        object.__setattr__(self, "server", _exact_text("server", self.server))
        environment = require_text("environment", self.environment, upper=True)
        if environment not in {"DEMO", "LIVE"}:
            raise ValueError("environment must be DEMO or LIVE")
        object.__setattr__(self, "environment", environment)
        object.__setattr__(
            self,
            "journal_sha256",
            require_hash("journal_sha256", self.journal_sha256),
        )
        object.__setattr__(
            self,
            "broker_spec_sha256",
            require_hash("broker_spec_sha256", self.broker_spec_sha256),
        )
        object.__setattr__(
            self,
            "account_currency",
            require_currency("account_currency", self.account_currency),
        )


@dataclass(frozen=True)
class RiskSourceReceipt(CanonicalContract):
    """Short-lived, signed provenance envelope for one exact risk event.

    The receipt is sealed by :func:`verify_risk_source_receipt`.  The trusted
    upstream verifier remains responsible for validating the exact sealed
    ``RuntimeFactReceipt``, ``ExecutionReceipt``, or reconciliation/deal
    receipt whose hash is bound here.
    """

    source_receipt_id: str
    source_kind: str
    issuer_id: str
    key_id: str
    binding: RiskLedgerBinding
    event_sha256: str
    upstream_receipt_type: str
    upstream_receipt_sha256: str
    observed_at_utc: datetime
    valid_until_utc: datetime
    signature_hmac_sha256: str
    schema_version: str = SOURCE_RECEIPT_SCHEMA_VERSION
    _seal: InitVar[object | None] = None

    def __post_init__(self, _seal: object | None) -> None:
        if _seal is not _SOURCE_RECEIPT_SEAL:
            raise TypeError(
                "RiskSourceReceipt can only be created by verify_risk_source_receipt"
            )
        object.__setattr__(
            self,
            "source_receipt_id",
            _exact_id("source_receipt_id", self.source_receipt_id),
        )
        kind = require_text("source_kind", self.source_kind, upper=True)
        if kind not in {"ACCOUNT_SNAPSHOT", "ENTRY", "CLOSED_TRADE"}:
            raise ValueError("risk source kind is invalid")
        object.__setattr__(self, "source_kind", kind)
        object.__setattr__(self, "issuer_id", _exact_id("issuer_id", self.issuer_id))
        object.__setattr__(self, "key_id", _exact_id("key_id", self.key_id))
        if type(self.binding) is not RiskLedgerBinding:
            raise TypeError("binding must be a RiskLedgerBinding")
        object.__setattr__(
            self, "event_sha256", require_hash("event_sha256", self.event_sha256)
        )
        upstream_type = require_text(
            "upstream_receipt_type", self.upstream_receipt_type, upper=True
        )
        allowed_upstream = {
            "ACCOUNT_SNAPSHOT": {"RUNTIME_FACT_RECEIPT"},
            "ENTRY": {"EXECUTION_RECEIPT"},
            "CLOSED_TRADE": {
                "BROKER_DEAL_RECEIPT",
                "BROKER_RECONCILIATION_RECEIPT",
                "BROKER_CLOSED_TRADE_RECEIPT",
            },
        }
        if upstream_type not in allowed_upstream[kind]:
            raise ValueError("upstream receipt type is invalid for risk source kind")
        object.__setattr__(self, "upstream_receipt_type", upstream_type)
        object.__setattr__(
            self,
            "upstream_receipt_sha256",
            require_hash("upstream_receipt_sha256", self.upstream_receipt_sha256),
        )
        observed = require_utc("observed_at_utc", self.observed_at_utc)
        valid_until = require_utc("valid_until_utc", self.valid_until_utc)
        if valid_until < observed:
            raise ValueError("risk source receipt validity is inverted")
        if (valid_until - observed).total_seconds() > MAX_SOURCE_RECEIPT_LIFETIME_SECONDS:
            raise ValueError("risk source receipt lifetime exceeds the maximum")
        object.__setattr__(
            self,
            "signature_hmac_sha256",
            require_hash("signature_hmac_sha256", self.signature_hmac_sha256),
        )
        if self.schema_version != SOURCE_RECEIPT_SCHEMA_VERSION:
            raise ValueError("risk source receipt schema is invalid")

    @property
    def signing_payload(self) -> dict[str, Any]:
        payload = self.to_canonical_dict()
        payload.pop("signature_hmac_sha256")
        return payload

    @property
    def source_verified(self) -> bool:
        return True


@dataclass(frozen=True)
class AccountRiskSnapshot(CanonicalContract):
    snapshot_id: str
    binding: RiskLedgerBinding
    observed_at_utc: datetime
    daily_baseline_id: str
    weekly_baseline_id: str
    equity: float
    schema_version: str = EVENT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        object.__setattr__(self, "snapshot_id", _exact_id("snapshot_id", self.snapshot_id))
        if type(self.binding) is not RiskLedgerBinding:
            raise TypeError("binding must be a RiskLedgerBinding")
        require_utc("observed_at_utc", self.observed_at_utc)
        object.__setattr__(
            self,
            "daily_baseline_id",
            _exact_id("daily_baseline_id", self.daily_baseline_id),
        )
        object.__setattr__(
            self,
            "weekly_baseline_id",
            _exact_id("weekly_baseline_id", self.weekly_baseline_id),
        )
        object.__setattr__(self, "equity", require_finite("equity", self.equity, positive=True))
        if self.schema_version != EVENT_SCHEMA_VERSION:
            raise ValueError("snapshot schema version is invalid")


@dataclass(frozen=True)
class EntryRiskEvent(CanonicalContract):
    entry_id: str
    binding: RiskLedgerBinding
    occurred_at_utc: datetime
    daily_baseline_id: str
    weekly_baseline_id: str
    symbol: str
    schema_version: str = EVENT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        object.__setattr__(self, "entry_id", _exact_id("entry_id", self.entry_id))
        if type(self.binding) is not RiskLedgerBinding:
            raise TypeError("binding must be a RiskLedgerBinding")
        require_utc("occurred_at_utc", self.occurred_at_utc)
        object.__setattr__(
            self,
            "daily_baseline_id",
            _exact_id("daily_baseline_id", self.daily_baseline_id),
        )
        object.__setattr__(
            self,
            "weekly_baseline_id",
            _exact_id("weekly_baseline_id", self.weekly_baseline_id),
        )
        object.__setattr__(self, "symbol", _symbol(self.symbol))
        if self.schema_version != EVENT_SCHEMA_VERSION:
            raise ValueError("entry schema version is invalid")


@dataclass(frozen=True)
class ClosedTradeRiskEvent(CanonicalContract):
    trade_id: str
    entry_id: str
    binding: RiskLedgerBinding
    occurred_at_utc: datetime
    daily_baseline_id: str
    weekly_baseline_id: str
    symbol: str
    outcome: str
    realized_pnl_account_currency: float
    schema_version: str = EVENT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        object.__setattr__(self, "trade_id", _exact_id("trade_id", self.trade_id))
        object.__setattr__(self, "entry_id", _exact_id("entry_id", self.entry_id))
        if type(self.binding) is not RiskLedgerBinding:
            raise TypeError("binding must be a RiskLedgerBinding")
        require_utc("occurred_at_utc", self.occurred_at_utc)
        object.__setattr__(
            self,
            "daily_baseline_id",
            _exact_id("daily_baseline_id", self.daily_baseline_id),
        )
        object.__setattr__(
            self,
            "weekly_baseline_id",
            _exact_id("weekly_baseline_id", self.weekly_baseline_id),
        )
        object.__setattr__(self, "symbol", _symbol(self.symbol))
        outcome = require_text("outcome", self.outcome, upper=True)
        if outcome not in {"WIN", "LOSS", "BREAKEVEN"}:
            raise ValueError("outcome must be WIN, LOSS, or BREAKEVEN")
        pnl = require_finite(
            "realized_pnl_account_currency",
            self.realized_pnl_account_currency,
        )
        if (
            (outcome == "WIN" and pnl <= 0)
            or (outcome == "LOSS" and pnl >= 0)
            or (outcome == "BREAKEVEN" and pnl != 0)
        ):
            raise ValueError("outcome and realized PnL are inconsistent")
        object.__setattr__(self, "outcome", outcome)
        object.__setattr__(self, "realized_pnl_account_currency", pnl)
        if self.schema_version != EVENT_SCHEMA_VERSION:
            raise ValueError("closed-trade schema version is invalid")


@dataclass(frozen=True)
class RiskStateReceipt(CanonicalContract):
    ledger_id: str
    binding: RiskLedgerBinding
    key_id: str
    issued_at_utc: datetime
    latest_event_at_utc: datetime
    event_sequence: int
    head_hmac_sha256: str
    daily_baseline_id: str
    weekly_baseline_id: str
    daily_baseline_equity: float
    weekly_baseline_equity: float
    current_equity: float
    high_water_equity: float
    entries_today: int
    consecutive_losses: int
    loss_latch_active: bool
    source_verified: bool
    source_evidence_count: int
    latest_source_receipt_sha256: str
    source_receipt_chain_sha256: str
    latest_source_issuer_id: str
    latest_source_key_id: str
    receipt_hmac_sha256: str
    schema_version: str = RECEIPT_SCHEMA_VERSION
    _seal: InitVar[object | None] = None

    def __post_init__(self, _seal: object | None) -> None:
        if _seal is not _RECEIPT_SEAL:
            raise TypeError("RiskStateReceipt can only be created by DurableRiskLedger")
        object.__setattr__(self, "ledger_id", _exact_id("ledger_id", self.ledger_id))
        if type(self.binding) is not RiskLedgerBinding:
            raise TypeError("binding must be a RiskLedgerBinding")
        object.__setattr__(self, "key_id", _exact_id("key_id", self.key_id))
        require_utc("issued_at_utc", self.issued_at_utc)
        require_utc("latest_event_at_utc", self.latest_event_at_utc)
        if self.issued_at_utc < self.latest_event_at_utc:
            raise ValueError("receipt cannot predate the latest event")
        require_int("event_sequence", self.event_sequence, minimum=1)
        object.__setattr__(
            self,
            "head_hmac_sha256",
            require_hash("head_hmac_sha256", self.head_hmac_sha256),
        )
        object.__setattr__(
            self,
            "daily_baseline_id",
            _exact_id("daily_baseline_id", self.daily_baseline_id),
        )
        object.__setattr__(
            self,
            "weekly_baseline_id",
            _exact_id("weekly_baseline_id", self.weekly_baseline_id),
        )
        for field in (
            "daily_baseline_equity",
            "weekly_baseline_equity",
            "current_equity",
            "high_water_equity",
        ):
            object.__setattr__(
                self,
                field,
                require_finite(field, getattr(self, field), positive=True),
            )
        if self.high_water_equity < self.current_equity:
            raise ValueError("high-water equity cannot be below current equity")
        require_int("entries_today", self.entries_today, minimum=0)
        require_int("consecutive_losses", self.consecutive_losses, minimum=0)
        if type(self.loss_latch_active) is not bool:
            raise TypeError("loss_latch_active must be boolean")
        if self.consecutive_losses >= LOSS_LATCH_COUNT and not self.loss_latch_active:
            raise ValueError("two consecutive losses must latch the risk stop")
        if self.source_verified is not True:
            raise ValueError("execution-trusted risk receipt requires verified sources")
        require_int(
            "source_evidence_count", self.source_evidence_count, minimum=1
        )
        if self.source_evidence_count != self.event_sequence:
            raise ValueError("each risk event requires exactly one verified source")
        object.__setattr__(
            self,
            "latest_source_receipt_sha256",
            require_hash(
                "latest_source_receipt_sha256",
                self.latest_source_receipt_sha256,
            ),
        )
        object.__setattr__(
            self,
            "source_receipt_chain_sha256",
            require_hash(
                "source_receipt_chain_sha256", self.source_receipt_chain_sha256
            ),
        )
        object.__setattr__(
            self,
            "latest_source_issuer_id",
            _exact_id("latest_source_issuer_id", self.latest_source_issuer_id),
        )
        object.__setattr__(
            self,
            "latest_source_key_id",
            _exact_id("latest_source_key_id", self.latest_source_key_id),
        )
        signature = require_hash(
            "receipt_hmac_sha256",
            self.receipt_hmac_sha256,
        )
        object.__setattr__(self, "receipt_hmac_sha256", signature)
        if self.schema_version != RECEIPT_SCHEMA_VERSION:
            raise ValueError("risk-state receipt schema is invalid")

    @property
    def signing_payload(self) -> dict[str, Any]:
        payload = self.to_canonical_dict()
        payload.pop("receipt_hmac_sha256")
        return payload


@dataclass(frozen=True)
class RiskStateCheckpointCASAcknowledgement(CanonicalContract):
    """Exact compare-and-swap acknowledgement from external risk custody."""

    expected_current_checkpoint_sha256: str
    written_checkpoint_sha256: str
    schema_version: str = CHECKPOINT_CAS_ACK_SCHEMA_VERSION

    def __post_init__(self) -> None:
        for name in (
            "expected_current_checkpoint_sha256",
            "written_checkpoint_sha256",
        ):
            object.__setattr__(self, name, require_hash(name, getattr(self, name)))
        if self.schema_version != CHECKPOINT_CAS_ACK_SCHEMA_VERSION:
            raise ValueError("unsupported risk checkpoint CAS acknowledgement")


@dataclass(frozen=True)
class _DerivedState:
    event_sequence: int
    head_hmac_sha256: str
    latest_event_at_utc: datetime
    daily_baseline_id: str
    weekly_baseline_id: str
    daily_baseline_equity: float
    weekly_baseline_equity: float
    current_equity: float
    high_water_equity: float
    entries_today: int
    consecutive_losses: int
    loss_latch_active: bool
    source_verified: bool
    source_evidence_count: int
    latest_source_receipt_sha256: str
    source_receipt_chain_sha256: str
    latest_source_issuer_id: str
    latest_source_key_id: str


@dataclass
class _ReplayContext:
    state: _DerivedState | None
    seen_daily_baselines: set[str]
    seen_weekly_baselines: set[str]
    entries: dict[str, str]
    closed_entries: set[str]


def _new_replay() -> _ReplayContext:
    return _ReplayContext(None, set(), set(), {}, set())


def _binding_from_payload(value: object) -> RiskLedgerBinding:
    payload = _strict_object(value, "binding")
    _exact_fields(
        payload,
        {
            "account_id_sha256",
            "server",
            "environment",
            "journal_sha256",
            "broker_spec_sha256",
            "account_currency",
        },
        "binding",
    )
    try:
        return RiskLedgerBinding(**payload)
    except (TypeError, ValueError) as exc:
        raise RiskLedgerIntegrityError("stored binding is invalid") from exc


def _event_from_payload(event_type: str, value: object) -> object:
    payload = _strict_object(value, "event payload")
    try:
        if event_type == "ACCOUNT_SNAPSHOT":
            _exact_fields(
                payload,
                {
                    "snapshot_id",
                    "binding",
                    "observed_at_utc",
                    "daily_baseline_id",
                    "weekly_baseline_id",
                    "equity",
                    "schema_version",
                },
                "account snapshot",
            )
            return AccountRiskSnapshot(
                snapshot_id=payload["snapshot_id"],
                binding=_binding_from_payload(payload["binding"]),
                observed_at_utc=_parse_utc(payload["observed_at_utc"]),
                daily_baseline_id=payload["daily_baseline_id"],
                weekly_baseline_id=payload["weekly_baseline_id"],
                equity=payload["equity"],
                schema_version=payload["schema_version"],
            )
        if event_type == "ENTRY":
            _exact_fields(
                payload,
                {
                    "entry_id",
                    "binding",
                    "occurred_at_utc",
                    "daily_baseline_id",
                    "weekly_baseline_id",
                    "symbol",
                    "schema_version",
                },
                "entry event",
            )
            return EntryRiskEvent(
                entry_id=payload["entry_id"],
                binding=_binding_from_payload(payload["binding"]),
                occurred_at_utc=_parse_utc(payload["occurred_at_utc"]),
                daily_baseline_id=payload["daily_baseline_id"],
                weekly_baseline_id=payload["weekly_baseline_id"],
                symbol=payload["symbol"],
                schema_version=payload["schema_version"],
            )
        if event_type == "CLOSED_TRADE":
            _exact_fields(
                payload,
                {
                    "trade_id",
                    "entry_id",
                    "binding",
                    "occurred_at_utc",
                    "daily_baseline_id",
                    "weekly_baseline_id",
                    "symbol",
                    "outcome",
                    "realized_pnl_account_currency",
                    "schema_version",
                },
                "closed-trade event",
            )
            return ClosedTradeRiskEvent(
                trade_id=payload["trade_id"],
                entry_id=payload["entry_id"],
                binding=_binding_from_payload(payload["binding"]),
                occurred_at_utc=_parse_utc(payload["occurred_at_utc"]),
                daily_baseline_id=payload["daily_baseline_id"],
                weekly_baseline_id=payload["weekly_baseline_id"],
                symbol=payload["symbol"],
                outcome=payload["outcome"],
                realized_pnl_account_currency=payload[
                    "realized_pnl_account_currency"
                ],
                schema_version=payload["schema_version"],
            )
    except RiskLedgerIntegrityError:
        raise
    except (KeyError, TypeError, ValueError) as exc:
        raise RiskLedgerIntegrityError("stored risk event is invalid") from exc
    raise RiskLedgerIntegrityError("stored risk event type is invalid")


def _event_metadata(event: object) -> tuple[str, str, str | None, datetime, str, str]:
    if type(event) is AccountRiskSnapshot:
        return (
            "ACCOUNT_SNAPSHOT",
            event.snapshot_id,
            None,
            event.observed_at_utc,
            event.daily_baseline_id,
            event.weekly_baseline_id,
        )
    if type(event) is EntryRiskEvent:
        return (
            "ENTRY",
            event.entry_id,
            None,
            event.occurred_at_utc,
            event.daily_baseline_id,
            event.weekly_baseline_id,
        )
    if type(event) is ClosedTradeRiskEvent:
        return (
            "CLOSED_TRADE",
            event.trade_id,
            event.entry_id,
            event.occurred_at_utc,
            event.daily_baseline_id,
            event.weekly_baseline_id,
        )
    raise TypeError("unsupported risk event")


def _event_binding(event: object) -> RiskLedgerBinding:
    binding = getattr(event, "binding", None)
    if type(binding) is not RiskLedgerBinding:
        raise TypeError("risk event binding is invalid")
    return binding


def verify_risk_source_receipt(
    payload: Mapping[str, Any],
    *,
    expected_event: object,
    expected_binding: RiskLedgerBinding,
    key_provider: Callable[[str], str | bytes],
    trusted_issuer_keys: Mapping[str, tuple[str, ...] | list[str] | set[str] | frozenset[str]],
    clock_provider: Callable[[], datetime] = _utc_now,
    enforce_freshness: bool = True,
) -> RiskSourceReceipt:
    """Verify and seal a provenance receipt for one exact risk event.

    ``payload`` must already have been signed by an upstream issuer which only
    signs after validating the exact broker/runtime receipt.  This function
    never accepts a boolean attestation and returns a sealed value only after
    exact binding, event hash, issuer/key, signature, and time checks succeed.
    """

    if type(expected_binding) is not RiskLedgerBinding:
        raise TypeError("expected_binding must be a RiskLedgerBinding")
    if not callable(key_provider) or not callable(clock_provider):
        raise TypeError("risk source key and clock providers must be callable")
    event_type, _, _, event_time, _, _ = _event_metadata(expected_event)
    raw = _strict_object(payload, "risk source receipt")
    _exact_fields(
        raw,
        {
            "source_receipt_id",
            "source_kind",
            "issuer_id",
            "key_id",
            "binding",
            "event_sha256",
            "upstream_receipt_type",
            "upstream_receipt_sha256",
            "observed_at_utc",
            "valid_until_utc",
            "signature_hmac_sha256",
            "schema_version",
        },
        "risk source receipt",
    )
    try:
        receipt = RiskSourceReceipt(
            source_receipt_id=raw["source_receipt_id"],
            source_kind=raw["source_kind"],
            issuer_id=raw["issuer_id"],
            key_id=raw["key_id"],
            binding=_binding_from_payload(raw["binding"]),
            event_sha256=raw["event_sha256"],
            upstream_receipt_type=raw["upstream_receipt_type"],
            upstream_receipt_sha256=raw["upstream_receipt_sha256"],
            observed_at_utc=_source_utc(raw["observed_at_utc"]),
            valid_until_utc=_source_utc(raw["valid_until_utc"]),
            signature_hmac_sha256=raw["signature_hmac_sha256"],
            schema_version=raw["schema_version"],
            _seal=_SOURCE_RECEIPT_SEAL,
        )
    except RiskLedgerError:
        raise
    except (KeyError, TypeError, ValueError) as exc:
        raise RiskLedgerSourceError("risk source receipt is structurally invalid") from exc
    if canonical_json(raw) != canonical_json(receipt.to_canonical_dict()):
        raise RiskLedgerSourceError("risk source receipt is not canonical")
    if receipt.binding != expected_binding:
        raise RiskLedgerBindingError("risk source receipt exact binding does not match")
    if receipt.source_kind != event_type:
        raise RiskLedgerSourceError("risk source receipt kind does not match event")
    if receipt.event_sha256 != expected_event.content_sha256:
        raise RiskLedgerSourceError("risk source receipt event hash does not match")
    allowed_keys = trusted_issuer_keys.get(receipt.issuer_id)
    if (
        not isinstance(allowed_keys, (tuple, list, set, frozenset))
        or isinstance(allowed_keys, (str, bytes))
        or receipt.key_id not in set(allowed_keys)
    ):
        raise RiskLedgerSourceError("risk source issuer or key is not trusted")
    try:
        secret = _key(key_provider(receipt.key_id))
    except Exception as exc:
        raise RiskLedgerSourceError("risk source HMAC key is unavailable") from exc
    expected_signature = _hmac_sha256(
        secret,
        _SOURCE_HMAC_DOMAIN,
        receipt.signing_payload,
    )
    if not hmac.compare_digest(receipt.signature_hmac_sha256, expected_signature):
        raise RiskLedgerSourceError("risk source receipt HMAC is invalid")
    if receipt.observed_at_utc < event_time:
        raise RiskLedgerSourceError("risk source receipt predates its event")
    if (
        receipt.observed_at_utc - event_time
    ).total_seconds() > MAX_SOURCE_RECEIPT_LIFETIME_SECONDS:
        raise RiskLedgerSourceError("risk source receipt is detached from event time")
    if enforce_freshness:
        now = require_utc("trusted risk source clock", clock_provider())
        if receipt.observed_at_utc > now + timedelta(
            seconds=MAX_FUTURE_CLOCK_DRIFT_SECONDS
        ):
            raise RiskLedgerSourceError("risk source receipt is from the future")
        if now > receipt.valid_until_utc:
            raise RiskLedgerSourceError("risk source receipt is stale")
    return receipt


def _source_chain_sha256(previous: str, receipt_sha256: str) -> str:
    return hashlib.sha256(
        canonical_json(
            {
                "previous_source_chain_sha256": previous,
                "source_receipt_sha256": receipt_sha256,
            }
        ).encode("utf-8")
    ).hexdigest()


def _apply_event(
    context: _ReplayContext,
    event: object,
    source_receipt: RiskSourceReceipt,
    *,
    sequence: int,
    head_hmac_sha256: str,
) -> None:
    _, _, _, occurred_at, daily_id, weekly_id = _event_metadata(event)
    previous = context.state
    source_sha256 = source_receipt.content_sha256
    previous_source_chain = (
        ZERO_HMAC_SHA256
        if previous is None
        else previous.source_receipt_chain_sha256
    )
    source_chain = _source_chain_sha256(previous_source_chain, source_sha256)
    if previous is not None and occurred_at < previous.latest_event_at_utc:
        raise RiskLedgerRollbackError("risk event timestamp regressed")

    if type(event) is AccountRiskSnapshot:
        if previous is None:
            daily_baseline = event.equity
            weekly_baseline = event.equity
            high_water = event.equity
            entries_today = 0
            consecutive_losses = 0
            loss_latch_active = False
            context.seen_daily_baselines.add(daily_id)
            context.seen_weekly_baselines.add(weekly_id)
        else:
            daily_baseline = previous.daily_baseline_equity
            weekly_baseline = previous.weekly_baseline_equity
            entries_today = previous.entries_today
            consecutive_losses = previous.consecutive_losses
            loss_latch_active = previous.loss_latch_active
            if daily_id != previous.daily_baseline_id:
                if daily_id in context.seen_daily_baselines:
                    raise RiskLedgerRollbackError("daily baseline identifier regressed")
                context.seen_daily_baselines.add(daily_id)
                daily_baseline = event.equity
                entries_today = 0
            if weekly_id != previous.weekly_baseline_id:
                if weekly_id in context.seen_weekly_baselines:
                    raise RiskLedgerRollbackError("weekly baseline identifier regressed")
                context.seen_weekly_baselines.add(weekly_id)
                weekly_baseline = event.equity
            high_water = max(previous.high_water_equity, event.equity)
        context.state = _DerivedState(
            event_sequence=sequence,
            head_hmac_sha256=head_hmac_sha256,
            latest_event_at_utc=occurred_at,
            daily_baseline_id=daily_id,
            weekly_baseline_id=weekly_id,
            daily_baseline_equity=daily_baseline,
            weekly_baseline_equity=weekly_baseline,
            current_equity=event.equity,
            high_water_equity=high_water,
            entries_today=entries_today,
            consecutive_losses=consecutive_losses,
            loss_latch_active=loss_latch_active,
            source_verified=True,
            source_evidence_count=sequence,
            latest_source_receipt_sha256=source_sha256,
            source_receipt_chain_sha256=source_chain,
            latest_source_issuer_id=source_receipt.issuer_id,
            latest_source_key_id=source_receipt.key_id,
        )
        return

    if previous is None:
        raise RiskLedgerIntegrityError("the first risk event must be an account snapshot")
    if (
        daily_id != previous.daily_baseline_id
        or weekly_id != previous.weekly_baseline_id
    ):
        raise RiskLedgerRollbackError(
            "entry and closed-trade events require the current baseline identifiers"
        )

    entries_today = previous.entries_today
    consecutive_losses = previous.consecutive_losses
    loss_latch_active = previous.loss_latch_active
    if type(event) is EntryRiskEvent:
        if event.entry_id in context.entries:
            raise RiskLedgerDuplicateError("entry event already exists")
        context.entries[event.entry_id] = event.symbol
        entries_today += 1
    elif type(event) is ClosedTradeRiskEvent:
        entry_symbol = context.entries.get(event.entry_id)
        if entry_symbol is None:
            raise RiskLedgerIntegrityError("closed trade references an unknown entry")
        if event.entry_id in context.closed_entries:
            raise RiskLedgerDuplicateError("entry already has a closed-trade event")
        if entry_symbol != event.symbol:
            raise RiskLedgerIntegrityError("closed trade symbol does not match its entry")
        context.closed_entries.add(event.entry_id)
        if event.outcome == "LOSS":
            consecutive_losses += 1
            if consecutive_losses >= LOSS_LATCH_COUNT:
                loss_latch_active = True
        else:
            consecutive_losses = 0
    else:
        raise TypeError("unsupported risk event")

    context.state = _DerivedState(
        event_sequence=sequence,
        head_hmac_sha256=head_hmac_sha256,
        latest_event_at_utc=occurred_at,
        daily_baseline_id=previous.daily_baseline_id,
        weekly_baseline_id=previous.weekly_baseline_id,
        daily_baseline_equity=previous.daily_baseline_equity,
        weekly_baseline_equity=previous.weekly_baseline_equity,
        current_equity=previous.current_equity,
        high_water_equity=previous.high_water_equity,
        entries_today=entries_today,
        consecutive_losses=consecutive_losses,
        loss_latch_active=loss_latch_active,
        source_verified=True,
        source_evidence_count=sequence,
        latest_source_receipt_sha256=source_sha256,
        source_receipt_chain_sha256=source_chain,
        latest_source_issuer_id=source_receipt.issuer_id,
        latest_source_key_id=source_receipt.key_id,
    )


class DurableRiskLedger:
    """SQLite WAL/FULL risk state bound to one account, server, and journal."""

    def __init__(
        self,
        path: str | Path,
        *,
        binding: RiskLedgerBinding,
        key_id: str,
        key_provider: Callable[[str], str | bytes],
        source_key_provider: Callable[[str], str | bytes],
        trusted_source_issuer_keys: Mapping[
            str, tuple[str, ...] | list[str] | set[str] | frozenset[str]
        ],
        upstream_receipt_verifier: Callable[[str, object], object],
        clock_provider: Callable[[], datetime] = _utc_now,
        expected_receipt: RiskStateReceipt | None = None,
    ) -> None:
        if type(binding) is not RiskLedgerBinding:
            raise TypeError("binding must be a RiskLedgerBinding")
        if not callable(key_provider):
            raise TypeError("key_provider must be callable")
        if not callable(source_key_provider):
            raise TypeError("source_key_provider must be callable")
        if not isinstance(trusted_source_issuer_keys, Mapping):
            raise TypeError("trusted_source_issuer_keys must be a mapping")
        if not callable(upstream_receipt_verifier):
            raise TypeError("upstream_receipt_verifier must be callable")
        if not callable(clock_provider):
            raise TypeError("clock_provider must be callable")
        if expected_receipt is not None and type(expected_receipt) is not RiskStateReceipt:
            raise TypeError("expected_receipt must be a sealed RiskStateReceipt")
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.binding = binding
        self.key_id = _exact_id("key_id", key_id)
        self._key_provider = key_provider
        self._source_key_provider = source_key_provider
        normalized_issuers: dict[str, tuple[str, ...]] = {}
        for raw_issuer, raw_keys in trusted_source_issuer_keys.items():
            issuer = _exact_id("trusted source issuer", raw_issuer)
            if not isinstance(raw_keys, (tuple, list, set, frozenset)) or isinstance(
                raw_keys, (str, bytes)
            ):
                raise TypeError("trusted source keys must be a finite collection")
            keys = tuple(
                sorted({_exact_id("trusted source key", item) for item in raw_keys})
            )
            if not keys:
                raise ValueError("trusted source issuer requires at least one key")
            if self.key_id in keys:
                raise ValueError("risk source and ledger HMAC keys must be separated")
            normalized_issuers[issuer] = keys
        if not normalized_issuers:
            raise ValueError("at least one trusted risk source issuer is required")
        self._trusted_source_issuer_keys = MappingProxyType(normalized_issuers)
        self._upstream_receipt_verifier = upstream_receipt_verifier
        self._clock_provider = clock_provider
        self.ledger_id = ""
        self._initialize(expected_receipt=expected_receipt)

    def _now(self) -> datetime:
        return require_utc("trusted risk-ledger clock", self._clock_provider())

    def _secret(self) -> bytes:
        try:
            value = self._key_provider(self.key_id)
        except Exception as exc:
            raise RiskLedgerIntegrityError("risk-ledger HMAC key is unavailable") from exc
        return _key(value)

    def _source_secret(self, key_id: str) -> bytes:
        try:
            value = self._source_key_provider(key_id)
        except Exception as exc:
            raise RiskLedgerSourceError("risk source HMAC key is unavailable") from exc
        return _key(value)

    def _source_trust_sha256(self) -> str:
        trust = {
            issuer: {
                key_id: hashlib.sha256(self._source_secret(key_id)).hexdigest()
                for key_id in key_ids
            }
            for issuer, key_ids in self._trusted_source_issuer_keys.items()
        }
        return hashlib.sha256(canonical_json(trust).encode("utf-8")).hexdigest()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=10.0, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        mode = str(connection.execute("PRAGMA journal_mode=WAL").fetchone()[0]).lower()
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute("PRAGMA busy_timeout=10000")
        if mode != "wal":
            connection.close()
            raise RiskLedgerIntegrityError("risk ledger requires SQLite WAL mode")
        synchronous = int(connection.execute("PRAGMA synchronous").fetchone()[0])
        if synchronous != 2:
            connection.close()
            raise RiskLedgerIntegrityError("risk ledger requires SQLite FULL sync")
        return connection

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

    def _identity_body(self, *, ledger_id: str, created_at_utc: str) -> dict[str, Any]:
        return {
            "schema_version": LEDGER_SCHEMA_VERSION,
            "ledger_id": ledger_id,
            "binding": self.binding.to_canonical_dict(),
            "key_id": self.key_id,
            "source_trust_sha256": self._source_trust_sha256(),
            "created_at_utc": created_at_utc,
        }

    def _initialize(self, *, expected_receipt: RiskStateReceipt | None) -> None:
        secret = self._secret()
        now = self._now()
        with self._transaction() as connection:
            connection.execute(
                """CREATE TABLE IF NOT EXISTS risk_ledger_identity (
                    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                    schema_version TEXT NOT NULL,
                    ledger_id TEXT NOT NULL UNIQUE,
                    account_id_sha256 TEXT NOT NULL,
                    server TEXT NOT NULL,
                    environment TEXT NOT NULL,
                    journal_sha256 TEXT NOT NULL,
                    broker_spec_sha256 TEXT NOT NULL,
                    account_currency TEXT NOT NULL,
                    key_id TEXT NOT NULL,
                    key_fingerprint_sha256 TEXT NOT NULL,
                    source_trust_sha256 TEXT NOT NULL,
                    created_at_utc TEXT NOT NULL,
                    identity_hmac_sha256 TEXT NOT NULL
                )"""
            )
            connection.execute(
                """CREATE TABLE IF NOT EXISTS risk_events (
                    sequence INTEGER PRIMARY KEY CHECK(sequence > 0),
                    event_id TEXT NOT NULL UNIQUE,
                    event_type TEXT NOT NULL CHECK(
                        event_type IN ('ACCOUNT_SNAPSHOT','ENTRY','CLOSED_TRADE')
                    ),
                    related_entry_id TEXT,
                    occurred_at_utc TEXT NOT NULL,
                    daily_baseline_id TEXT NOT NULL,
                    weekly_baseline_id TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    source_receipt_id TEXT NOT NULL UNIQUE,
                    source_payload_json TEXT NOT NULL,
                    source_receipt_sha256 TEXT NOT NULL UNIQUE,
                    source_issuer_id TEXT NOT NULL,
                    source_key_id TEXT NOT NULL,
                    upstream_receipt_type TEXT NOT NULL,
                    upstream_receipt_sha256 TEXT NOT NULL UNIQUE,
                    previous_hmac_sha256 TEXT NOT NULL,
                    event_hmac_sha256 TEXT NOT NULL UNIQUE
                )"""
            )
            connection.execute(
                """CREATE UNIQUE INDEX IF NOT EXISTS idx_risk_closed_entry
                ON risk_events(related_entry_id)
                WHERE event_type='CLOSED_TRADE'"""
            )
            connection.execute(
                """CREATE TABLE IF NOT EXISTS risk_state (
                    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                    event_sequence INTEGER NOT NULL CHECK(event_sequence > 0),
                    head_hmac_sha256 TEXT NOT NULL,
                    latest_event_at_utc TEXT NOT NULL,
                    daily_baseline_id TEXT NOT NULL,
                    weekly_baseline_id TEXT NOT NULL,
                    daily_baseline_equity REAL NOT NULL CHECK(daily_baseline_equity > 0),
                    weekly_baseline_equity REAL NOT NULL CHECK(weekly_baseline_equity > 0),
                    current_equity REAL NOT NULL CHECK(current_equity > 0),
                    high_water_equity REAL NOT NULL CHECK(high_water_equity > 0),
                    entries_today INTEGER NOT NULL CHECK(entries_today >= 0),
                    consecutive_losses INTEGER NOT NULL CHECK(consecutive_losses >= 0),
                    loss_latch_active INTEGER NOT NULL CHECK(loss_latch_active IN (0,1)),
                    source_verified INTEGER NOT NULL CHECK(source_verified=1),
                    source_evidence_count INTEGER NOT NULL CHECK(source_evidence_count > 0),
                    latest_source_receipt_sha256 TEXT NOT NULL,
                    source_receipt_chain_sha256 TEXT NOT NULL,
                    latest_source_issuer_id TEXT NOT NULL,
                    latest_source_key_id TEXT NOT NULL,
                    state_hmac_sha256 TEXT NOT NULL
                )"""
            )
            connection.execute(
                """CREATE TRIGGER IF NOT EXISTS risk_events_no_update
                BEFORE UPDATE ON risk_events BEGIN
                    SELECT RAISE(ABORT, 'risk_events_append_only');
                END"""
            )
            connection.execute(
                """CREATE TRIGGER IF NOT EXISTS risk_events_no_delete
                BEFORE DELETE ON risk_events BEGIN
                    SELECT RAISE(ABORT, 'risk_events_append_only');
                END"""
            )
            connection.execute(
                """CREATE TRIGGER IF NOT EXISTS risk_identity_no_update
                BEFORE UPDATE ON risk_ledger_identity BEGIN
                    SELECT RAISE(ABORT, 'risk_identity_immutable');
                END"""
            )
            connection.execute(
                """CREATE TRIGGER IF NOT EXISTS risk_identity_no_delete
                BEFORE DELETE ON risk_ledger_identity BEGIN
                    SELECT RAISE(ABORT, 'risk_identity_immutable');
                END"""
            )

            identity = connection.execute(
                "SELECT * FROM risk_ledger_identity WHERE singleton=1"
            ).fetchone()
            if identity is None:
                event_count = int(
                    connection.execute("SELECT COUNT(*) FROM risk_events").fetchone()[0]
                )
                state_count = int(
                    connection.execute("SELECT COUNT(*) FROM risk_state").fetchone()[0]
                )
                if event_count or state_count:
                    raise RiskLedgerIntegrityError("risk ledger identity is missing")
                ledger_id = "risk-" + uuid.uuid4().hex
                created_at = _iso(now)
                identity_body = self._identity_body(
                    ledger_id=ledger_id,
                    created_at_utc=created_at,
                )
                connection.execute(
                    """INSERT INTO risk_ledger_identity(
                        singleton, schema_version, ledger_id, account_id_sha256,
                        server, environment, journal_sha256, broker_spec_sha256,
                        account_currency, key_id, key_fingerprint_sha256,
                        source_trust_sha256, created_at_utc,
                        identity_hmac_sha256
                    ) VALUES(1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        LEDGER_SCHEMA_VERSION,
                        ledger_id,
                        self.binding.account_id_sha256,
                        self.binding.server,
                        self.binding.environment,
                        self.binding.journal_sha256,
                        self.binding.broker_spec_sha256,
                        self.binding.account_currency,
                        self.key_id,
                        hashlib.sha256(secret).hexdigest(),
                        self._source_trust_sha256(),
                        created_at,
                        _hmac_sha256(secret, _IDENTITY_HMAC_DOMAIN, identity_body),
                    ),
                )
                self.ledger_id = ledger_id
            else:
                self.ledger_id = str(identity["ledger_id"])

            context = self._verify_connection(connection, secret)
            if expected_receipt is not None:
                self._verify_checkpoint(connection, context, expected_receipt)

    def _verify_identity(self, connection: sqlite3.Connection, secret: bytes) -> None:
        rows = connection.execute("SELECT * FROM risk_ledger_identity").fetchall()
        if len(rows) != 1 or int(rows[0]["singleton"]) != 1:
            raise RiskLedgerIntegrityError("risk ledger identity cardinality is invalid")
        row = rows[0]
        if row["schema_version"] != LEDGER_SCHEMA_VERSION:
            raise RiskLedgerIntegrityError("risk ledger schema version is invalid")
        try:
            ledger_id = _exact_id("ledger_id", row["ledger_id"])
            created_at = _iso(_parse_utc(row["created_at_utc"]))
        except ValueError as exc:
            raise RiskLedgerIntegrityError("risk ledger identity is invalid") from exc
        try:
            observed_binding = RiskLedgerBinding(
                account_id_sha256=row["account_id_sha256"],
                server=row["server"],
                environment=row["environment"],
                journal_sha256=row["journal_sha256"],
                broker_spec_sha256=row["broker_spec_sha256"],
                account_currency=row["account_currency"],
            )
        except (TypeError, ValueError) as exc:
            raise RiskLedgerIntegrityError("stored risk-ledger binding is invalid") from exc
        if observed_binding != self.binding or row["key_id"] != self.key_id:
            raise RiskLedgerBindingError("risk ledger exact binding does not match")
        if row["key_fingerprint_sha256"] != hashlib.sha256(secret).hexdigest():
            raise RiskLedgerIntegrityError("risk ledger HMAC key does not match")
        if row["source_trust_sha256"] != self._source_trust_sha256():
            raise RiskLedgerBindingError("risk source trust binding does not match")
        body = self._identity_body(ledger_id=ledger_id, created_at_utc=created_at)
        expected_hmac = _hmac_sha256(secret, _IDENTITY_HMAC_DOMAIN, body)
        if not hmac.compare_digest(str(row["identity_hmac_sha256"]), expected_hmac):
            raise RiskLedgerIntegrityError("risk ledger identity HMAC is invalid")
        if self.ledger_id and self.ledger_id != ledger_id:
            raise RiskLedgerIntegrityError("risk ledger identity changed")
        self.ledger_id = ledger_id

    def _event_hmac_body(
        self,
        *,
        sequence: int,
        event_type: str,
        event_id: str,
        related_entry_id: str | None,
        occurred_at_utc: str,
        daily_baseline_id: str,
        weekly_baseline_id: str,
        payload: Mapping[str, Any],
        source_payload: Mapping[str, Any],
        previous_hmac_sha256: str,
    ) -> dict[str, Any]:
        return {
            "schema_version": EVENT_SCHEMA_VERSION,
            "ledger_id": self.ledger_id,
            "binding_sha256": self.binding.content_sha256,
            "sequence": sequence,
            "event_type": event_type,
            "event_id": event_id,
            "related_entry_id": related_entry_id,
            "occurred_at_utc": occurred_at_utc,
            "daily_baseline_id": daily_baseline_id,
            "weekly_baseline_id": weekly_baseline_id,
            "payload": dict(payload),
            "source_payload": dict(source_payload),
            "previous_hmac_sha256": previous_hmac_sha256,
        }

    def _state_body(self, state: _DerivedState) -> dict[str, Any]:
        return {
            "schema_version": LEDGER_SCHEMA_VERSION,
            "ledger_id": self.ledger_id,
            "binding_sha256": self.binding.content_sha256,
            "event_sequence": state.event_sequence,
            "head_hmac_sha256": state.head_hmac_sha256,
            "latest_event_at_utc": _iso(state.latest_event_at_utc),
            "daily_baseline_id": state.daily_baseline_id,
            "weekly_baseline_id": state.weekly_baseline_id,
            "daily_baseline_equity": state.daily_baseline_equity,
            "weekly_baseline_equity": state.weekly_baseline_equity,
            "current_equity": state.current_equity,
            "high_water_equity": state.high_water_equity,
            "entries_today": state.entries_today,
            "consecutive_losses": state.consecutive_losses,
            "loss_latch_active": state.loss_latch_active,
            "source_verified": state.source_verified,
            "source_evidence_count": state.source_evidence_count,
            "latest_source_receipt_sha256": state.latest_source_receipt_sha256,
            "source_receipt_chain_sha256": state.source_receipt_chain_sha256,
            "latest_source_issuer_id": state.latest_source_issuer_id,
            "latest_source_key_id": state.latest_source_key_id,
        }

    def _state_from_row(self, row: sqlite3.Row) -> _DerivedState:
        try:
            loss_latch_value = row["loss_latch_active"]
            if type(loss_latch_value) is not int or loss_latch_value not in {0, 1}:
                raise ValueError("stored loss_latch_active is invalid")
            source_verified_value = row["source_verified"]
            if type(source_verified_value) is not int or source_verified_value != 1:
                raise ValueError("stored source_verified is invalid")
            return _DerivedState(
                event_sequence=require_int(
                    "stored event_sequence", row["event_sequence"], minimum=1
                ),
                head_hmac_sha256=require_hash(
                    "stored head_hmac_sha256", row["head_hmac_sha256"]
                ),
                latest_event_at_utc=_parse_utc(row["latest_event_at_utc"]),
                daily_baseline_id=_exact_id(
                    "stored daily_baseline_id", row["daily_baseline_id"]
                ),
                weekly_baseline_id=_exact_id(
                    "stored weekly_baseline_id", row["weekly_baseline_id"]
                ),
                daily_baseline_equity=require_finite(
                    "stored daily_baseline_equity",
                    row["daily_baseline_equity"],
                    positive=True,
                ),
                weekly_baseline_equity=require_finite(
                    "stored weekly_baseline_equity",
                    row["weekly_baseline_equity"],
                    positive=True,
                ),
                current_equity=require_finite(
                    "stored current_equity", row["current_equity"], positive=True
                ),
                high_water_equity=require_finite(
                    "stored high_water_equity",
                    row["high_water_equity"],
                    positive=True,
                ),
                entries_today=require_int(
                    "stored entries_today", row["entries_today"], minimum=0
                ),
                consecutive_losses=require_int(
                    "stored consecutive_losses",
                    row["consecutive_losses"],
                    minimum=0,
                ),
                loss_latch_active=bool(loss_latch_value),
                source_verified=True,
                source_evidence_count=require_int(
                    "stored source_evidence_count",
                    row["source_evidence_count"],
                    minimum=1,
                ),
                latest_source_receipt_sha256=require_hash(
                    "stored latest_source_receipt_sha256",
                    row["latest_source_receipt_sha256"],
                ),
                source_receipt_chain_sha256=require_hash(
                    "stored source_receipt_chain_sha256",
                    row["source_receipt_chain_sha256"],
                ),
                latest_source_issuer_id=_exact_id(
                    "stored latest_source_issuer_id",
                    row["latest_source_issuer_id"],
                ),
                latest_source_key_id=_exact_id(
                    "stored latest_source_key_id", row["latest_source_key_id"]
                ),
            )
        except (TypeError, ValueError) as exc:
            raise RiskLedgerIntegrityError("materialized risk state is invalid") from exc

    def _verify_connection(
        self,
        connection: sqlite3.Connection,
        secret: bytes,
    ) -> _ReplayContext:
        integrity_rows = connection.execute("PRAGMA integrity_check").fetchall()
        if not integrity_rows or any(str(row[0]).lower() != "ok" for row in integrity_rows):
            raise RiskLedgerIntegrityError("SQLite integrity check failed")
        self._verify_identity(connection, secret)
        rows = connection.execute("SELECT * FROM risk_events ORDER BY sequence").fetchall()
        state_rows = connection.execute("SELECT * FROM risk_state").fetchall()
        if not rows:
            if state_rows:
                raise RiskLedgerIntegrityError("risk state exists without events")
            return _new_replay()
        if len(state_rows) != 1 or int(state_rows[0]["singleton"]) != 1:
            raise RiskLedgerIntegrityError("materialized risk state is missing")

        context = _new_replay()
        previous_hmac = ZERO_HMAC_SHA256
        for expected_sequence, row in enumerate(rows, start=1):
            if int(row["sequence"]) != expected_sequence:
                raise RiskLedgerRollbackError("risk event sequence is not contiguous")
            if row["previous_hmac_sha256"] != previous_hmac:
                raise RiskLedgerIntegrityError("risk event chain predecessor is invalid")
            try:
                payload = json.loads(row["payload_json"])
                source_payload = json.loads(row["source_payload_json"])
            except json.JSONDecodeError as exc:
                raise RiskLedgerIntegrityError("risk event payload JSON is invalid") from exc
            payload = _strict_object(payload, "event payload")
            source_payload = _strict_object(source_payload, "risk source payload")
            event = _event_from_payload(str(row["event_type"]), payload)
            source_receipt = verify_risk_source_receipt(
                source_payload,
                expected_event=event,
                expected_binding=self.binding,
                key_provider=self._source_key_provider,
                trusted_issuer_keys=self._trusted_source_issuer_keys,
                clock_provider=self._clock_provider,
                enforce_freshness=False,
            )
            event_type, event_id, related_id, occurred_at, daily_id, weekly_id = (
                _event_metadata(event)
            )
            if (
                row["event_type"] != event_type
                or row["event_id"] != event_id
                or row["related_entry_id"] != related_id
                or row["occurred_at_utc"] != _iso(occurred_at)
                or row["daily_baseline_id"] != daily_id
                or row["weekly_baseline_id"] != weekly_id
                or canonical_json(payload) != row["payload_json"]
                or canonical_json(source_payload) != row["source_payload_json"]
                or row["source_receipt_id"] != source_receipt.source_receipt_id
                or row["source_receipt_sha256"] != source_receipt.content_sha256
                or row["source_issuer_id"] != source_receipt.issuer_id
                or row["source_key_id"] != source_receipt.key_id
                or row["upstream_receipt_type"]
                != source_receipt.upstream_receipt_type
                or row["upstream_receipt_sha256"]
                != source_receipt.upstream_receipt_sha256
            ):
                raise RiskLedgerIntegrityError("risk event columns and payload disagree")
            if _event_binding(event) != self.binding:
                raise RiskLedgerBindingError("stored risk event binding does not match")
            body = self._event_hmac_body(
                sequence=expected_sequence,
                event_type=event_type,
                event_id=event_id,
                related_entry_id=related_id,
                occurred_at_utc=_iso(occurred_at),
                daily_baseline_id=daily_id,
                weekly_baseline_id=weekly_id,
                payload=payload,
                source_payload=source_payload,
                previous_hmac_sha256=previous_hmac,
            )
            expected_hmac = _hmac_sha256(secret, _EVENT_HMAC_DOMAIN, body)
            if not hmac.compare_digest(str(row["event_hmac_sha256"]), expected_hmac):
                raise RiskLedgerIntegrityError("risk event HMAC is invalid")
            _apply_event(
                context,
                event,
                source_receipt,
                sequence=expected_sequence,
                head_hmac_sha256=expected_hmac,
            )
            previous_hmac = expected_hmac

        stored_state = self._state_from_row(state_rows[0])
        if context.state != stored_state:
            raise RiskLedgerIntegrityError("materialized risk state disagrees with event replay")
        expected_state_hmac = _hmac_sha256(
            secret,
            _STATE_HMAC_DOMAIN,
            self._state_body(stored_state),
        )
        if not hmac.compare_digest(
            str(state_rows[0]["state_hmac_sha256"]), expected_state_hmac
        ):
            raise RiskLedgerIntegrityError("materialized risk state HMAC is invalid")
        return context

    def _verify_checkpoint(
        self,
        connection: sqlite3.Connection,
        context: _ReplayContext,
        receipt: RiskStateReceipt,
    ) -> None:
        if not verify_risk_state_receipt(receipt, self._key_provider):
            raise RiskLedgerRollbackError("expected risk-state receipt signature is invalid")
        if (
            receipt.ledger_id != self.ledger_id
            or receipt.binding != self.binding
            or receipt.key_id != self.key_id
        ):
            raise RiskLedgerRollbackError("expected risk-state receipt binding is invalid")
        if context.state is None or context.state.event_sequence < receipt.event_sequence:
            raise RiskLedgerRollbackError("risk ledger is older than the expected receipt")
        row = connection.execute(
            "SELECT event_hmac_sha256 FROM risk_events WHERE sequence=?",
            (receipt.event_sequence,),
        ).fetchone()
        if row is None or not hmac.compare_digest(
            str(row["event_hmac_sha256"]), receipt.head_hmac_sha256
        ):
            raise RiskLedgerRollbackError("risk ledger forked from the expected receipt")

    def _write_state(
        self,
        connection: sqlite3.Connection,
        state: _DerivedState,
        secret: bytes,
    ) -> None:
        state_hmac = _hmac_sha256(secret, _STATE_HMAC_DOMAIN, self._state_body(state))
        connection.execute(
            """INSERT INTO risk_state(
                singleton, event_sequence, head_hmac_sha256,
                latest_event_at_utc, daily_baseline_id, weekly_baseline_id,
                daily_baseline_equity, weekly_baseline_equity, current_equity,
                high_water_equity, entries_today, consecutive_losses,
                loss_latch_active, source_verified, source_evidence_count,
                latest_source_receipt_sha256, source_receipt_chain_sha256,
                latest_source_issuer_id, latest_source_key_id,
                state_hmac_sha256
            ) VALUES(1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(singleton) DO UPDATE SET
                event_sequence=excluded.event_sequence,
                head_hmac_sha256=excluded.head_hmac_sha256,
                latest_event_at_utc=excluded.latest_event_at_utc,
                daily_baseline_id=excluded.daily_baseline_id,
                weekly_baseline_id=excluded.weekly_baseline_id,
                daily_baseline_equity=excluded.daily_baseline_equity,
                weekly_baseline_equity=excluded.weekly_baseline_equity,
                current_equity=excluded.current_equity,
                high_water_equity=excluded.high_water_equity,
                entries_today=excluded.entries_today,
                consecutive_losses=excluded.consecutive_losses,
                loss_latch_active=excluded.loss_latch_active,
                source_verified=excluded.source_verified,
                source_evidence_count=excluded.source_evidence_count,
                latest_source_receipt_sha256=excluded.latest_source_receipt_sha256,
                source_receipt_chain_sha256=excluded.source_receipt_chain_sha256,
                latest_source_issuer_id=excluded.latest_source_issuer_id,
                latest_source_key_id=excluded.latest_source_key_id,
                state_hmac_sha256=excluded.state_hmac_sha256""",
            (
                state.event_sequence,
                state.head_hmac_sha256,
                _iso(state.latest_event_at_utc),
                state.daily_baseline_id,
                state.weekly_baseline_id,
                state.daily_baseline_equity,
                state.weekly_baseline_equity,
                state.current_equity,
                state.high_water_equity,
                state.entries_today,
                state.consecutive_losses,
                int(state.loss_latch_active),
                1,
                state.source_evidence_count,
                state.latest_source_receipt_sha256,
                state.source_receipt_chain_sha256,
                state.latest_source_issuer_id,
                state.latest_source_key_id,
                state_hmac,
            ),
        )

    def _verified_source_for_append(
        self,
        event: object,
        source_receipt: RiskSourceReceipt,
        upstream_receipt: object,
    ) -> RiskSourceReceipt:
        if type(source_receipt) is not RiskSourceReceipt:
            raise RiskLedgerSourceError(
                "a sealed RiskSourceReceipt is required for production ingestion"
            )
        verified_source = verify_risk_source_receipt(
            source_receipt.to_canonical_dict(),
            expected_event=event,
            expected_binding=self.binding,
            key_provider=self._source_key_provider,
            trusted_issuer_keys=self._trusted_source_issuer_keys,
            clock_provider=self._clock_provider,
            enforce_freshness=True,
        )
        try:
            verified_upstream = self._upstream_receipt_verifier(
                verified_source.upstream_receipt_type,
                upstream_receipt,
            )
        except Exception as exc:
            raise RiskLedgerSourceError(
                "exact upstream receipt verification failed"
            ) from exc
        if verified_upstream is not upstream_receipt:
            raise RiskLedgerSourceError(
                "upstream verifier must return the exact sealed receipt"
            )
        try:
            upstream_sha256 = require_hash(
                "verified upstream receipt hash",
                verified_upstream.content_sha256,
            )
        except (AttributeError, TypeError, ValueError) as exc:
            raise RiskLedgerSourceError(
                "verified upstream receipt has no canonical hash"
            ) from exc
        if upstream_sha256 != verified_source.upstream_receipt_sha256:
            raise RiskLedgerSourceError("upstream receipt hash does not match source")
        return verified_source

    def _append(
        self,
        event: object,
        *,
        source_receipt: RiskSourceReceipt,
        upstream_receipt: object,
    ) -> RiskStateReceipt:
        if _event_binding(event) != self.binding:
            raise RiskLedgerBindingError("risk event exact binding does not match")
        verified_source = self._verified_source_for_append(
            event,
            source_receipt,
            upstream_receipt,
        )
        event_type, event_id, related_id, occurred_at, daily_id, weekly_id = (
            _event_metadata(event)
        )
        now = self._now()
        if occurred_at > now + timedelta(seconds=MAX_FUTURE_CLOCK_DRIFT_SECONDS):
            raise RiskLedgerRollbackError("risk event timestamp is ahead of trusted UTC")
        secret = self._secret()
        with self._transaction() as connection:
            context = self._verify_connection(connection, secret)
            duplicate = connection.execute(
                "SELECT 1 FROM risk_events WHERE event_id=?",
                (event_id,),
            ).fetchone()
            if duplicate is not None:
                raise RiskLedgerDuplicateError("risk event identifier already exists")
            source_duplicate = connection.execute(
                """SELECT 1 FROM risk_events
                WHERE source_receipt_id=? OR source_receipt_sha256=?
                   OR upstream_receipt_sha256=?""",
                (
                    verified_source.source_receipt_id,
                    verified_source.content_sha256,
                    verified_source.upstream_receipt_sha256,
                ),
            ).fetchone()
            if source_duplicate is not None:
                raise RiskLedgerDuplicateError(
                    "risk source or upstream receipt was already consumed"
                )
            sequence = 1 if context.state is None else context.state.event_sequence + 1
            previous_hmac = (
                ZERO_HMAC_SHA256
                if context.state is None
                else context.state.head_hmac_sha256
            )
            payload = event.to_canonical_dict()
            payload_json = canonical_json(payload)
            source_payload = verified_source.to_canonical_dict()
            source_payload_json = canonical_json(source_payload)
            body = self._event_hmac_body(
                sequence=sequence,
                event_type=event_type,
                event_id=event_id,
                related_entry_id=related_id,
                occurred_at_utc=_iso(occurred_at),
                daily_baseline_id=daily_id,
                weekly_baseline_id=weekly_id,
                payload=payload,
                source_payload=source_payload,
                previous_hmac_sha256=previous_hmac,
            )
            event_hmac = _hmac_sha256(secret, _EVENT_HMAC_DOMAIN, body)
            _apply_event(
                context,
                event,
                verified_source,
                sequence=sequence,
                head_hmac_sha256=event_hmac,
            )
            connection.execute(
                """INSERT INTO risk_events(
                    sequence, event_id, event_type, related_entry_id,
                    occurred_at_utc, daily_baseline_id, weekly_baseline_id,
                    payload_json, source_receipt_id, source_payload_json,
                    source_receipt_sha256, source_issuer_id, source_key_id,
                    upstream_receipt_type, upstream_receipt_sha256,
                    previous_hmac_sha256, event_hmac_sha256
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    sequence,
                    event_id,
                    event_type,
                    related_id,
                    _iso(occurred_at),
                    daily_id,
                    weekly_id,
                    payload_json,
                    verified_source.source_receipt_id,
                    source_payload_json,
                    verified_source.content_sha256,
                    verified_source.issuer_id,
                    verified_source.key_id,
                    verified_source.upstream_receipt_type,
                    verified_source.upstream_receipt_sha256,
                    previous_hmac,
                    event_hmac,
                ),
            )
            if context.state is None:
                raise AssertionError("event replay did not produce state")
            self._write_state(connection, context.state, secret)
            verified = self._verify_connection(connection, secret)
            if verified.state != context.state:
                raise RiskLedgerIntegrityError("risk state changed during append")
            return self._receipt(context.state, now, secret)

    def append_account_snapshot(
        self,
        snapshot: AccountRiskSnapshot,
        *,
        source_receipt: RiskSourceReceipt,
        upstream_receipt: object,
    ) -> RiskStateReceipt:
        if type(snapshot) is not AccountRiskSnapshot:
            raise TypeError("snapshot must be an AccountRiskSnapshot")
        return self._append(
            snapshot,
            source_receipt=source_receipt,
            upstream_receipt=upstream_receipt,
        )

    def append_entry(
        self,
        event: EntryRiskEvent,
        *,
        source_receipt: RiskSourceReceipt,
        upstream_receipt: object,
    ) -> RiskStateReceipt:
        if type(event) is not EntryRiskEvent:
            raise TypeError("event must be an EntryRiskEvent")
        return self._append(
            event,
            source_receipt=source_receipt,
            upstream_receipt=upstream_receipt,
        )

    def append_closed_trade(
        self,
        event: ClosedTradeRiskEvent,
        *,
        source_receipt: RiskSourceReceipt,
        upstream_receipt: object,
    ) -> RiskStateReceipt:
        if type(event) is not ClosedTradeRiskEvent:
            raise TypeError("event must be a ClosedTradeRiskEvent")
        return self._append(
            event,
            source_receipt=source_receipt,
            upstream_receipt=upstream_receipt,
        )

    def _receipt(
        self,
        state: _DerivedState,
        issued_at: datetime,
        secret: bytes,
    ) -> RiskStateReceipt:
        values = {
            "ledger_id": self.ledger_id,
            "binding": self.binding,
            "key_id": self.key_id,
            "issued_at_utc": issued_at,
            "latest_event_at_utc": state.latest_event_at_utc,
            "event_sequence": state.event_sequence,
            "head_hmac_sha256": state.head_hmac_sha256,
            "daily_baseline_id": state.daily_baseline_id,
            "weekly_baseline_id": state.weekly_baseline_id,
            "daily_baseline_equity": state.daily_baseline_equity,
            "weekly_baseline_equity": state.weekly_baseline_equity,
            "current_equity": state.current_equity,
            "high_water_equity": state.high_water_equity,
            "entries_today": state.entries_today,
            "consecutive_losses": state.consecutive_losses,
            "loss_latch_active": state.loss_latch_active,
            "source_verified": state.source_verified,
            "source_evidence_count": state.source_evidence_count,
            "latest_source_receipt_sha256": state.latest_source_receipt_sha256,
            "source_receipt_chain_sha256": state.source_receipt_chain_sha256,
            "latest_source_issuer_id": state.latest_source_issuer_id,
            "latest_source_key_id": state.latest_source_key_id,
            "schema_version": RECEIPT_SCHEMA_VERSION,
        }
        signature = _hmac_sha256(secret, _RECEIPT_HMAC_DOMAIN, values)
        return RiskStateReceipt(
            **values,
            receipt_hmac_sha256=signature,
            _seal=_RECEIPT_SEAL,
        )

    def current_receipt(self) -> RiskStateReceipt:
        secret = self._secret()
        now = self._now()
        with self._reader() as connection:
            context = self._verify_connection(connection, secret)
        if context.state is None:
            raise RiskLedgerError("an account snapshot is required before a receipt")
        return self._receipt(context.state, now, secret)

    def verify_integrity(
        self,
        *,
        expected_receipt: RiskStateReceipt | None = None,
    ) -> bool:
        if expected_receipt is not None and type(expected_receipt) is not RiskStateReceipt:
            raise TypeError("expected_receipt must be a sealed RiskStateReceipt")
        secret = self._secret()
        with self._reader() as connection:
            context = self._verify_connection(connection, secret)
            if expected_receipt is not None:
                self._verify_checkpoint(connection, context, expected_receipt)
        return True

    def storage_settings(self) -> Mapping[str, object]:
        with self._reader() as connection:
            mode = str(connection.execute("PRAGMA journal_mode").fetchone()[0]).upper()
            synchronous = int(connection.execute("PRAGMA synchronous").fetchone()[0])
        return MappingProxyType(
            {
                "journal_mode": mode,
                "synchronous": "FULL" if synchronous == 2 else str(synchronous),
            }
        )


def verify_risk_state_receipt(
    receipt: RiskStateReceipt,
    key_provider: Callable[[str], str | bytes],
) -> bool:
    if type(receipt) is not RiskStateReceipt or not callable(key_provider):
        return False
    try:
        secret = _key(key_provider(receipt.key_id))
        expected = _hmac_sha256(
            secret,
            _RECEIPT_HMAC_DOMAIN,
            receipt.signing_payload,
        )
    except Exception:
        return False
    return hmac.compare_digest(receipt.receipt_hmac_sha256, expected)


__all__ = [
    "AccountRiskSnapshot",
    "ClosedTradeRiskEvent",
    "DurableRiskLedger",
    "EntryRiskEvent",
    "RiskLedgerBinding",
    "RiskLedgerBindingError",
    "RiskLedgerDuplicateError",
    "RiskLedgerError",
    "RiskLedgerIntegrityError",
    "RiskLedgerRollbackError",
    "RiskLedgerSourceError",
    "RiskSourceReceipt",
    "RiskStateReceipt",
    "RiskStateCheckpointCASAcknowledgement",
    "CHECKPOINT_CAS_ACK_SCHEMA_VERSION",
    "verify_risk_source_receipt",
    "verify_risk_state_receipt",
]
