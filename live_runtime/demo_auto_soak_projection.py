"""Fail-closed projection of authenticated DEMO_AUTO broker facts into soak.

The projection is deliberately a one-way evidence adapter.  It has no MT5
object, no order callback, no activation callback, and no authority-bearing
return value.  It accepts only exact sealed/session-authenticated inputs,
records a tamper-evident local projection, anchors every local head with an
independent compare-and-swap checkpoint, and emits the narrow signed source
receipts accepted by :mod:`live_runtime.soak_tracker`.

The unavoidable two-ledger boundary is made restart safe by deterministic
tracker event identifiers.  The soak tracker is written first.  If the process
dies before the projection event is committed, the next identical call finds
the exact tracker event and completes the local projection without appending a
second ``CLOSED_FILL``.  A different payload for the same broker deal cannot
recover through this path and fails closed.
"""

from __future__ import annotations

from contextlib import closing, contextmanager
from dataclasses import InitVar, dataclass, field, replace
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
from pathlib import Path
import re
import sqlite3
from types import MappingProxyType
from typing import Any, Callable, Iterator, Mapping, Sequence

from .contracts import (
    CanonicalContract,
    ExecutionReceipt,
    TradeIntent,
    canonical_json,
    canonical_sha256,
    require_finite,
    require_hash,
    require_int,
    require_text,
    require_utc,
)
from .demo_auto_session_capability import (
    DemoAutoSessionBinding,
    DemoAutoSessionCapabilityStore,
    DemoAutoSessionCheckpoint,
    DemoAutoSessionLease,
    verify_demo_auto_session_capability,
)
from .reconciliation import (
    BrokerClosedTradeReceipt,
    BrokerDealReceipt,
    BrokerReconciliationReceipt,
    ReconciliationResult,
    reconciliation_result_sha256,
    verify_broker_closed_trade_receipt,
    verify_broker_reconciliation_receipt,
)
from .soak_tracker import (
    DemoAutoSoakTracker,
    SoakBinding,
    SoakEventReceipt,
    SoakSourceReceipt,
    SoakTrackerDuplicateError,
    verify_soak_source_receipt,
)


UTC = timezone.utc
ZERO_SHA256 = "0" * 64

PROJECTION_BINDING_SCHEMA_VERSION = "demo-auto-soak-projection-binding-v1"
EXECUTION_EVIDENCE_SCHEMA_VERSION = "demo-auto-execution-evidence-v1"
PROJECTION_EVENT_SCHEMA_VERSION = "demo-auto-soak-projection-event-v1"
PROJECTION_CHECKPOINT_SCHEMA_VERSION = "demo-auto-soak-projection-checkpoint-v1"
PROJECTION_CAS_ACK_SCHEMA_VERSION = "demo-auto-soak-projection-cas-ack-v1"

MAX_EXECUTION_EVIDENCE_OBSERVATION_DELAY = timedelta(seconds=30)
MAX_EXECUTION_EVIDENCE_TTL = timedelta(seconds=5)
MAX_FUTURE_DRIFT = timedelta(seconds=1)

ORDER_CAPABILITY = "DISABLED"
SAFE_TO_DEMO_AUTO_ORDER = False
LIVE_ALLOWED = False

_EXECUTION_EVIDENCE_SEAL = object()
_CHECKPOINT_SEAL = object()
_CAS_ACK_SEAL = object()

_IDENTITY_DOMAIN = b"AI_SCALPER_DEMO_AUTO_SOAK_PROJECTION_IDENTITY_V1\x00"
_EVENT_DOMAIN = b"AI_SCALPER_DEMO_AUTO_SOAK_PROJECTION_EVENT_V1\x00"
_CHECKPOINT_DOMAIN = b"AI_SCALPER_DEMO_AUTO_SOAK_PROJECTION_CHECKPOINT_V1\x00"
_CAS_ACK_DOMAIN = b"AI_SCALPER_DEMO_AUTO_SOAK_PROJECTION_CAS_ACK_V1\x00"
_EXECUTION_EVIDENCE_DOMAIN = b"AI_SCALPER_DEMO_AUTO_EXECUTION_EVIDENCE_V1\x00"
_SOAK_SOURCE_DOMAINS = MappingProxyType(
    {
        "DEMO_AUTO_ACTIVATION": b"AI_SCALPER_SOAK_DEMO_AUTO_ACTIVATION_V1\x00",
        "BROKER_CLOSED_DEAL": b"AI_SCALPER_SOAK_BROKER_CLOSED_DEAL_V1\x00",
        "CRITICAL_INCIDENT": b"AI_SCALPER_SOAK_CRITICAL_INCIDENT_V1\x00",
    }
)

_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@+\-]{0,255}$")
_SYMBOL_RE = re.compile(r"^[A-Z][A-Z0-9._-]{1,31}$")

_SAFETY = MappingProxyType(
    {
        "execution_authorized": False,
        "activation_authorized": False,
        "safe_to_demo_auto_order": False,
        "live_allowed": False,
        "order_capability": ORDER_CAPABILITY,
    }
)

_EVENT_TYPES = frozenset(
    {
        "ACTIVATION",
        "EXECUTION_OBSERVED",
        "RECONCILIATION_OBSERVED",
        "CLOSED_FILL",
        "CRITICAL_INCIDENT",
    }
)


class DemoAutoSoakProjectionError(RuntimeError):
    """Base fail-closed projection error."""


class DemoAutoSoakProjectionBindingError(DemoAutoSoakProjectionError):
    """An input belongs to another account, lane, build, or session."""


class DemoAutoSoakProjectionIntegrityError(DemoAutoSoakProjectionError):
    """Local or independently anchored evidence is invalid."""


class DemoAutoSoakProjectionReplayError(DemoAutoSoakProjectionIntegrityError):
    """A deal, reconciliation sequence, event, or checkpoint forked/replayed."""


class DemoAutoSoakProjectionSourceError(DemoAutoSoakProjectionIntegrityError):
    """An execution or broker source is untrusted, stale, or unsealed."""


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _identifier(name: str, value: object) -> str:
    normalized = require_text(name, value)
    if _IDENTIFIER_RE.fullmatch(normalized) is None:
        raise ValueError(f"{name} is not a canonical identifier")
    return normalized


def _symbol(name: str, value: object) -> str:
    normalized = require_text(name, value, upper=True)
    if _SYMBOL_RE.fullmatch(normalized) is None:
        raise ValueError(f"{name} is invalid")
    return normalized


def _secret(value: str | bytes) -> bytes:
    if isinstance(value, str):
        result = value.encode("utf-8")
    elif isinstance(value, bytes):
        result = value
    else:
        raise TypeError("HMAC key must be str or bytes")
    if len(result) < 32:
        raise ValueError("HMAC key must contain at least 32 bytes")
    return result


def _sign(secret: bytes, domain: bytes, payload: Mapping[str, Any]) -> str:
    return hmac.new(
        secret,
        domain + canonical_json(payload).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def _utc_text(value: datetime) -> str:
    return require_utc("UTC timestamp", value).isoformat(
        timespec="microseconds"
    ).replace("+00:00", "Z")


def _parse_utc(name: str, value: object) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise DemoAutoSoakProjectionIntegrityError(
            f"{name} must be canonical UTC text"
        )
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        require_utc(name, parsed)
    except (TypeError, ValueError) as exc:
        raise DemoAutoSoakProjectionIntegrityError(
            f"{name} is not valid UTC"
        ) from exc
    if _utc_text(parsed) != value:
        raise DemoAutoSoakProjectionIntegrityError(
            f"{name} is not canonical UTC text"
        )
    return parsed


def _account_sha256(account_id: str) -> str:
    return hashlib.sha256(require_text("account_id", account_id).encode("utf-8")).hexdigest()


def _ticket_text(value: str | None) -> str:
    return "" if value is None else require_text("broker ticket", value)


def _safe_payload() -> dict[str, object]:
    return dict(_SAFETY)


@dataclass(frozen=True)
class DemoAutoSoakProjectionBinding(CanonicalContract):
    """Exact immutable trust/broker/session identity for one projection."""

    soak_binding: SoakBinding
    session_binding: DemoAutoSessionBinding
    execution_issuer_id: str
    execution_key_id: str
    broker_provider_id: str
    broker_key_id: str
    projection_key_id: str
    custody_issuer_id: str
    custody_key_id: str
    activation_source_issuer_id: str
    activation_source_key_id: str
    closed_deal_source_issuer_id: str
    closed_deal_source_key_id: str
    incident_source_issuer_id: str
    incident_source_key_id: str
    schema_version: str = PROJECTION_BINDING_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if type(self.soak_binding) is not SoakBinding:
            raise TypeError("soak_binding must be exact SoakBinding")
        if type(self.session_binding) is not DemoAutoSessionBinding:
            raise TypeError("session_binding must be exact DemoAutoSessionBinding")
        for name in (
            "execution_issuer_id",
            "execution_key_id",
            "broker_provider_id",
            "broker_key_id",
            "projection_key_id",
            "custody_issuer_id",
            "custody_key_id",
            "activation_source_issuer_id",
            "activation_source_key_id",
            "closed_deal_source_issuer_id",
            "closed_deal_source_key_id",
            "incident_source_issuer_id",
            "incident_source_key_id",
        ):
            object.__setattr__(self, name, _identifier(name, getattr(self, name)))
        stage = self.session_binding.stage_binding
        soak = self.soak_binding
        if (
            stage.broker_id != soak.broker_id
            or stage.environment != "DEMO"
            or soak.environment != "DEMO"
            or stage.account_alias_sha256 != soak.account_alias_sha256
            or stage.server != soak.broker_server
            or stage.journal_sha256 != soak.journal_sha256
            or stage.commit_sha != soak.commit_sha
            or stage.config_sha256 != soak.config_sha256
            or stage.broker_spec_sha256 != soak.broker_spec_sha256
            or stage.model_artifact_sha256 != soak.model_artifact_sha256
            or stage.lane_id != soak.lane_id
        ):
            raise DemoAutoSoakProjectionBindingError(
                "soak and session bindings are not the same exact DEMO lane"
            )
        key_ids = (
            self.execution_key_id,
            self.broker_key_id,
            self.projection_key_id,
            self.custody_key_id,
            self.activation_source_key_id,
            self.closed_deal_source_key_id,
            self.incident_source_key_id,
        )
        if len(set(key_ids)) != len(key_ids):
            raise ValueError("projection trust domains require distinct key ids")
        if self.schema_version != PROJECTION_BINDING_SCHEMA_VERSION:
            raise ValueError("unsupported projection binding schema")

    @property
    def ledger_id(self) -> str:
        return f"demo-auto-soak-projection-{self.content_sha256[:32]}"

    @property
    def candidate_id(self) -> str:
        return self.soak_binding.broker_id

    @property
    def account_alias_sha256(self) -> str:
        return self.soak_binding.account_alias_sha256

    @property
    def server(self) -> str:
        return self.soak_binding.broker_server

    @property
    def symbol(self) -> str:
        return self.session_binding.stage_binding.symbol


@dataclass(frozen=True)
class DemoAutoExecutionEvidence(CanonicalContract):
    """Authenticated exact entry execution; it grants no future capability."""

    receipt_id: str
    candidate_id: str
    mode: str
    account_alias_sha256: str
    server: str
    symbol: str
    lane_id: str
    journal_sha256: str
    commit_sha: str
    config_sha256: str
    model_artifact_sha256: str
    session_id: str
    session_lease_sha256: str
    intent_id: str
    intent_sha256: str
    decision_sha256: str
    execution_receipt_sha256: str
    execution_state: str
    order_ticket: str | None
    deal_ticket: str | None
    filled_volume: float
    occurred_at_utc: datetime
    observed_at_utc: datetime
    valid_until_utc: datetime
    issuer_id: str
    key_id: str
    signature_hmac_sha256: str
    execution_authorized: bool = field(default=False, init=False)
    activation_authorized: bool = field(default=False, init=False)
    safe_to_demo_auto_order: bool = field(
        default=SAFE_TO_DEMO_AUTO_ORDER, init=False
    )
    live_allowed: bool = field(default=LIVE_ALLOWED, init=False)
    order_capability: str = field(default=ORDER_CAPABILITY, init=False)
    schema_version: str = EXECUTION_EVIDENCE_SCHEMA_VERSION
    _seal: InitVar[object | None] = None

    def __post_init__(self, _seal: object | None) -> None:
        if _seal is not _EXECUTION_EVIDENCE_SEAL:
            raise TypeError(
                "execution evidence can only be created by the authenticated verifier"
            )
        for name in (
            "receipt_id",
            "candidate_id",
            "server",
            "lane_id",
            "session_id",
            "intent_id",
            "issuer_id",
            "key_id",
        ):
            object.__setattr__(self, name, _identifier(name, getattr(self, name)))
        mode = require_text("mode", self.mode, upper=True)
        if mode != "DEMO_AUTO":
            raise ValueError("execution evidence mode must be DEMO_AUTO")
        object.__setattr__(self, "mode", mode)
        object.__setattr__(self, "symbol", _symbol("symbol", self.symbol))
        for name in (
            "account_alias_sha256",
            "journal_sha256",
            "config_sha256",
            "model_artifact_sha256",
            "session_lease_sha256",
            "intent_sha256",
            "decision_sha256",
            "execution_receipt_sha256",
            "signature_hmac_sha256",
        ):
            object.__setattr__(self, name, require_hash(name, getattr(self, name)))
        object.__setattr__(
            self,
            "commit_sha",
            require_hash("commit_sha", self.commit_sha, minimum_length=7),
        )
        state = require_text("execution_state", self.execution_state, upper=True)
        if state not in {"FILLED", "RECONCILED"}:
            raise ValueError("execution evidence requires a filled broker entry")
        object.__setattr__(self, "execution_state", state)
        if self.order_ticket is not None:
            object.__setattr__(
                self, "order_ticket", require_text("order_ticket", self.order_ticket)
            )
        if self.deal_ticket is not None:
            object.__setattr__(
                self, "deal_ticket", require_text("deal_ticket", self.deal_ticket)
            )
        if self.order_ticket is None and self.deal_ticket is None:
            raise ValueError("execution evidence requires a broker ticket")
        object.__setattr__(
            self,
            "filled_volume",
            require_finite("filled_volume", self.filled_volume, positive=True),
        )
        occurred = require_utc("occurred_at_utc", self.occurred_at_utc)
        observed = require_utc("observed_at_utc", self.observed_at_utc)
        valid_until = require_utc("valid_until_utc", self.valid_until_utc)
        if not occurred <= observed <= valid_until:
            raise ValueError("execution evidence time ordering is invalid")
        if observed - occurred > MAX_EXECUTION_EVIDENCE_OBSERVATION_DELAY:
            raise ValueError("execution evidence observation delay is too large")
        if valid_until - observed > MAX_EXECUTION_EVIDENCE_TTL:
            raise ValueError("execution evidence lifetime is too large")
        if (
            self.execution_authorized
            or self.activation_authorized
            or self.safe_to_demo_auto_order
            or self.live_allowed
            or self.order_capability != ORDER_CAPABILITY
        ):
            raise ValueError("execution evidence cannot grant order capability")
        if self.schema_version != EXECUTION_EVIDENCE_SCHEMA_VERSION:
            raise ValueError("unsupported execution evidence schema")

    @property
    def signing_dict(self) -> dict[str, Any]:
        payload = self.to_canonical_dict()
        payload.pop("signature_hmac_sha256")
        return payload


def verify_demo_auto_execution_evidence(
    payload: Mapping[str, Any],
    *,
    binding: DemoAutoSoakProjectionBinding,
    lease: DemoAutoSessionLease,
    intent: TradeIntent,
    execution_receipt: ExecutionReceipt,
    key_provider: Callable[[str], str | bytes],
    clock_provider: Callable[[], datetime] = _utc_now,
) -> DemoAutoExecutionEvidence:
    """Authenticate a short-lived executor envelope and every referenced fact."""

    if type(binding) is not DemoAutoSoakProjectionBinding:
        raise TypeError("binding must be exact DemoAutoSoakProjectionBinding")
    if type(lease) is not DemoAutoSessionLease:
        raise TypeError("lease must be exact DemoAutoSessionLease")
    if type(intent) is not TradeIntent:
        raise TypeError("intent must be exact TradeIntent")
    if type(execution_receipt) is not ExecutionReceipt:
        raise TypeError("execution_receipt must be exact ExecutionReceipt")
    if not isinstance(payload, Mapping):
        raise DemoAutoSoakProjectionSourceError(
            "execution evidence payload must be an object"
        )
    if not callable(key_provider) or not callable(clock_provider):
        raise TypeError("execution key and clock providers must be callable")
    raw = dict(payload)
    expected_fields = {
        "receipt_id",
        "candidate_id",
        "mode",
        "account_alias_sha256",
        "server",
        "symbol",
        "lane_id",
        "journal_sha256",
        "commit_sha",
        "config_sha256",
        "model_artifact_sha256",
        "session_id",
        "session_lease_sha256",
        "intent_id",
        "intent_sha256",
        "decision_sha256",
        "execution_receipt_sha256",
        "execution_state",
        "order_ticket",
        "deal_ticket",
        "filled_volume",
        "occurred_at_utc",
        "observed_at_utc",
        "valid_until_utc",
        "issuer_id",
        "key_id",
        "signature_hmac_sha256",
        "execution_authorized",
        "activation_authorized",
        "safe_to_demo_auto_order",
        "live_allowed",
        "order_capability",
        "schema_version",
    }
    if set(raw) != expected_fields:
        raise DemoAutoSoakProjectionSourceError(
            "execution evidence fields are invalid"
        )
    try:
        evidence = DemoAutoExecutionEvidence(
            receipt_id=raw["receipt_id"],
            candidate_id=raw["candidate_id"],
            mode=raw["mode"],
            account_alias_sha256=raw["account_alias_sha256"],
            server=raw["server"],
            symbol=raw["symbol"],
            lane_id=raw["lane_id"],
            journal_sha256=raw["journal_sha256"],
            commit_sha=raw["commit_sha"],
            config_sha256=raw["config_sha256"],
            model_artifact_sha256=raw["model_artifact_sha256"],
            session_id=raw["session_id"],
            session_lease_sha256=raw["session_lease_sha256"],
            intent_id=raw["intent_id"],
            intent_sha256=raw["intent_sha256"],
            decision_sha256=raw["decision_sha256"],
            execution_receipt_sha256=raw["execution_receipt_sha256"],
            execution_state=raw["execution_state"],
            order_ticket=raw["order_ticket"],
            deal_ticket=raw["deal_ticket"],
            filled_volume=raw["filled_volume"],
            occurred_at_utc=_evidence_utc(raw["occurred_at_utc"]),
            observed_at_utc=_evidence_utc(raw["observed_at_utc"]),
            valid_until_utc=_evidence_utc(raw["valid_until_utc"]),
            issuer_id=raw["issuer_id"],
            key_id=raw["key_id"],
            signature_hmac_sha256=raw["signature_hmac_sha256"],
            schema_version=raw["schema_version"],
            _seal=_EXECUTION_EVIDENCE_SEAL,
        )
    except Exception as exc:
        raise DemoAutoSoakProjectionSourceError(
            "execution evidence is structurally invalid"
        ) from exc
    if evidence.to_canonical_dict() != raw:
        raise DemoAutoSoakProjectionSourceError(
            "execution evidence is not canonical"
        )
    stage = binding.session_binding.stage_binding
    decision = intent.decision
    if (
        evidence.candidate_id != binding.candidate_id
        or evidence.account_alias_sha256 != binding.account_alias_sha256
        or evidence.server != binding.server
        or evidence.symbol != binding.symbol
        or evidence.lane_id != binding.soak_binding.lane_id
        or evidence.journal_sha256 != binding.soak_binding.journal_sha256
        or evidence.commit_sha != binding.soak_binding.commit_sha
        or evidence.config_sha256 != binding.soak_binding.config_sha256
        or evidence.model_artifact_sha256
        != binding.soak_binding.model_artifact_sha256
        or evidence.session_id != binding.session_binding.session_id
        or evidence.session_lease_sha256 != lease.content_sha256
        or evidence.intent_id != intent.intent_id
        or evidence.intent_sha256 != intent.content_sha256
        or evidence.decision_sha256 != decision.content_sha256
        or evidence.execution_receipt_sha256
        != execution_receipt.content_sha256
        or evidence.execution_state != execution_receipt.state
        or evidence.order_ticket != execution_receipt.order_ticket
        or evidence.deal_ticket != execution_receipt.deal_ticket
        or evidence.filled_volume != execution_receipt.filled_volume
        or evidence.occurred_at_utc != execution_receipt.received_at
        or evidence.issuer_id != binding.execution_issuer_id
        or evidence.key_id != binding.execution_key_id
        or lease.session_id != binding.session_binding.session_id
        or lease.stage_binding_sha256 != stage.binding_sha256
        or lease.account_alias_sha256 != binding.account_alias_sha256
        or lease.server != binding.server
        or lease.lane_id != binding.soak_binding.lane_id
        or lease.journal_sha256 != binding.soak_binding.journal_sha256
        or lease.commit_sha != binding.soak_binding.commit_sha
        or lease.config_sha256 != binding.soak_binding.config_sha256
        or lease.model_artifact_sha256
        != binding.soak_binding.model_artifact_sha256
        or intent.mode != "DEMO_AUTO"
        or _account_sha256(intent.account_id) != binding.account_alias_sha256
        or intent.server != binding.server
        or intent.symbol != binding.symbol
        or decision.symbol != binding.symbol
        or decision.commit_sha != binding.soak_binding.commit_sha
        or decision.config_sha256 != binding.soak_binding.config_sha256
        or decision.model_artifact_sha256
        != binding.soak_binding.model_artifact_sha256
        or execution_receipt.intent_id != intent.intent_id
        or execution_receipt.account_id != intent.account_id
        or execution_receipt.server != intent.server
        or execution_receipt.symbol != intent.symbol
        or execution_receipt.state not in {"FILLED", "RECONCILED"}
        or execution_receipt.filled_volume <= 0
        or execution_receipt.filled_volume > intent.requested_lot
        or not lease.issued_at_utc <= intent.created_at
        or execution_receipt.received_at >= lease.expires_at_utc
    ):
        raise DemoAutoSoakProjectionBindingError(
            "execution evidence does not bind the exact DEMO_AUTO entry"
        )
    try:
        signature = _sign(
            _secret(key_provider(evidence.key_id)),
            _EXECUTION_EVIDENCE_DOMAIN,
            evidence.signing_dict,
        )
    except Exception as exc:
        raise DemoAutoSoakProjectionSourceError(
            "execution evidence key is unavailable"
        ) from exc
    if not hmac.compare_digest(signature, evidence.signature_hmac_sha256):
        raise DemoAutoSoakProjectionSourceError(
            "execution evidence HMAC is invalid"
        )
    try:
        now = require_utc("trusted execution clock", clock_provider())
    except (TypeError, ValueError) as exc:
        raise DemoAutoSoakProjectionSourceError(
            "trusted execution clock is invalid"
        ) from exc
    if evidence.observed_at_utc > now + MAX_FUTURE_DRIFT or now > evidence.valid_until_utc:
        raise DemoAutoSoakProjectionSourceError(
            "execution evidence is stale or future-dated"
        )
    return evidence


def _evidence_utc(value: object) -> datetime:
    if isinstance(value, datetime):
        return require_utc("execution evidence UTC", value)
    if not isinstance(value, str):
        raise TypeError("execution evidence timestamp must be UTC")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return require_utc("execution evidence UTC", parsed)


@dataclass(frozen=True)
class DemoAutoSoakProjectionCheckpoint(CanonicalContract):
    ledger_id: str
    binding_sha256: str
    event_count: int
    event_head_sha256: str
    previous_checkpoint_sha256: str
    issued_at_utc: datetime
    custody_issuer_id: str
    custody_key_id: str
    signature_hmac_sha256: str
    schema_version: str = PROJECTION_CHECKPOINT_SCHEMA_VERSION
    _seal: InitVar[object | None] = None

    def __post_init__(self, _seal: object | None) -> None:
        if _seal is not _CHECKPOINT_SEAL:
            raise TypeError("projection checkpoints require the custody issuer")
        for name in ("ledger_id", "custody_issuer_id", "custody_key_id"):
            object.__setattr__(self, name, _identifier(name, getattr(self, name)))
        object.__setattr__(
            self, "binding_sha256", require_hash("binding_sha256", self.binding_sha256)
        )
        require_int("event_count", self.event_count, minimum=0)
        for name in ("event_head_sha256", "previous_checkpoint_sha256"):
            object.__setattr__(self, name, require_hash(name, getattr(self, name)))
        if self.event_count == 0:
            if (
                self.event_head_sha256 != ZERO_SHA256
                or self.previous_checkpoint_sha256 != ZERO_SHA256
            ):
                raise ValueError("genesis projection checkpoint is invalid")
        elif (
            self.event_head_sha256 == ZERO_SHA256
            or self.previous_checkpoint_sha256 == ZERO_SHA256
        ):
            raise ValueError("non-genesis projection checkpoint is invalid")
        require_utc("issued_at_utc", self.issued_at_utc)
        object.__setattr__(
            self,
            "signature_hmac_sha256",
            require_hash("signature_hmac_sha256", self.signature_hmac_sha256),
        )
        if self.schema_version != PROJECTION_CHECKPOINT_SCHEMA_VERSION:
            raise ValueError("unsupported projection checkpoint schema")

    @property
    def signing_dict(self) -> dict[str, Any]:
        payload = self.to_canonical_dict()
        payload.pop("signature_hmac_sha256")
        return payload


@dataclass(frozen=True)
class DemoAutoSoakProjectionCASAcknowledgement(CanonicalContract):
    ledger_id: str
    expected_previous_checkpoint_sha256: str
    observed_previous_checkpoint_sha256: str
    accepted_checkpoint_sha256: str
    accepted: bool
    issued_at_utc: datetime
    custody_issuer_id: str
    custody_key_id: str
    signature_hmac_sha256: str
    schema_version: str = PROJECTION_CAS_ACK_SCHEMA_VERSION
    _seal: InitVar[object | None] = None

    def __post_init__(self, _seal: object | None) -> None:
        if _seal is not _CAS_ACK_SEAL:
            raise TypeError("projection CAS acknowledgements require custody")
        for name in ("ledger_id", "custody_issuer_id", "custody_key_id"):
            object.__setattr__(self, name, _identifier(name, getattr(self, name)))
        for name in (
            "expected_previous_checkpoint_sha256",
            "observed_previous_checkpoint_sha256",
            "accepted_checkpoint_sha256",
            "signature_hmac_sha256",
        ):
            object.__setattr__(self, name, require_hash(name, getattr(self, name)))
        if type(self.accepted) is not bool:
            raise TypeError("accepted must be bool")
        require_utc("issued_at_utc", self.issued_at_utc)
        if self.schema_version != PROJECTION_CAS_ACK_SCHEMA_VERSION:
            raise ValueError("unsupported projection CAS acknowledgement schema")

    @property
    def signing_dict(self) -> dict[str, Any]:
        payload = self.to_canonical_dict()
        payload.pop("signature_hmac_sha256")
        return payload


def issue_demo_auto_soak_projection_cas_acknowledgement(
    *,
    ledger_id: str,
    expected_previous_checkpoint_sha256: str,
    observed_previous_checkpoint_sha256: str,
    accepted_checkpoint_sha256: str,
    accepted: bool,
    issued_at_utc: datetime,
    custody_issuer_id: str,
    custody_key_id: str,
    custody_key: str | bytes,
) -> DemoAutoSoakProjectionCASAcknowledgement:
    unsigned = DemoAutoSoakProjectionCASAcknowledgement(
        ledger_id=ledger_id,
        expected_previous_checkpoint_sha256=expected_previous_checkpoint_sha256,
        observed_previous_checkpoint_sha256=observed_previous_checkpoint_sha256,
        accepted_checkpoint_sha256=accepted_checkpoint_sha256,
        accepted=accepted,
        issued_at_utc=issued_at_utc,
        custody_issuer_id=custody_issuer_id,
        custody_key_id=custody_key_id,
        signature_hmac_sha256=ZERO_SHA256,
        _seal=_CAS_ACK_SEAL,
    )
    return replace(
        unsigned,
        signature_hmac_sha256=_sign(
            _secret(custody_key), _CAS_ACK_DOMAIN, unsigned.signing_dict
        ),
        _seal=_CAS_ACK_SEAL,
    )


@dataclass(frozen=True)
class DemoAutoSoakProjectionEventReceipt(CanonicalContract):
    ledger_id: str
    sequence: int
    event_id: str
    event_type: str
    dedup_key: str
    occurred_at_utc: datetime
    upstream_sha256: str
    previous_event_sha256: str
    event_sha256: str
    checkpoint_sha256: str
    execution_authorized: bool = field(default=False, init=False)
    activation_authorized: bool = field(default=False, init=False)
    safe_to_demo_auto_order: bool = field(
        default=SAFE_TO_DEMO_AUTO_ORDER, init=False
    )
    live_allowed: bool = field(default=LIVE_ALLOWED, init=False)
    order_capability: str = field(default=ORDER_CAPABILITY, init=False)
    schema_version: str = PROJECTION_EVENT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        object.__setattr__(self, "ledger_id", _identifier("ledger_id", self.ledger_id))
        require_int("sequence", self.sequence, minimum=1)
        object.__setattr__(self, "event_id", _identifier("event_id", self.event_id))
        event_type = require_text("event_type", self.event_type, upper=True)
        if event_type not in _EVENT_TYPES:
            raise ValueError("unsupported projection event type")
        object.__setattr__(self, "event_type", event_type)
        object.__setattr__(self, "dedup_key", _identifier("dedup_key", self.dedup_key))
        require_utc("occurred_at_utc", self.occurred_at_utc)
        for name in (
            "upstream_sha256",
            "previous_event_sha256",
            "event_sha256",
            "checkpoint_sha256",
        ):
            object.__setattr__(self, name, require_hash(name, getattr(self, name)))
        if (
            self.execution_authorized
            or self.activation_authorized
            or self.safe_to_demo_auto_order
            or self.live_allowed
            or self.order_capability != ORDER_CAPABILITY
        ):
            raise ValueError("projection event cannot enable order capability")
        if self.schema_version != PROJECTION_EVENT_SCHEMA_VERSION:
            raise ValueError("unsupported projection event receipt schema")


@dataclass(frozen=True)
class DemoAutoReconciliationProjectionResult(CanonicalContract):
    reconciliation_event: DemoAutoSoakProjectionEventReceipt
    incident_event: DemoAutoSoakProjectionEventReceipt | None
    critical_reason_code: str | None
    execution_authorized: bool = field(default=False, init=False)
    activation_authorized: bool = field(default=False, init=False)
    safe_to_demo_auto_order: bool = field(default=False, init=False)
    live_allowed: bool = field(default=False, init=False)
    order_capability: str = field(default=ORDER_CAPABILITY, init=False)

    def __post_init__(self) -> None:
        if type(self.reconciliation_event) is not DemoAutoSoakProjectionEventReceipt:
            raise TypeError("reconciliation_event must be exact projection receipt")
        if self.incident_event is not None and type(
            self.incident_event
        ) is not DemoAutoSoakProjectionEventReceipt:
            raise TypeError("incident_event must be exact projection receipt")
        if (self.incident_event is None) != (self.critical_reason_code is None):
            raise ValueError("incident event and critical reason must agree")


_TABLE_SQL = {
    "projection_identity": """CREATE TABLE projection_identity (
        singleton INTEGER PRIMARY KEY CHECK(singleton=1),
        ledger_id TEXT NOT NULL UNIQUE,
        binding_json TEXT NOT NULL,
        binding_sha256 TEXT NOT NULL,
        projection_key_fingerprint_sha256 TEXT NOT NULL,
        custody_key_fingerprint_sha256 TEXT NOT NULL,
        created_at_utc TEXT NOT NULL,
        identity_hmac_sha256 TEXT NOT NULL
    )""",
    "projection_events": """CREATE TABLE projection_events (
        sequence INTEGER PRIMARY KEY CHECK(sequence > 0),
        event_id TEXT NOT NULL UNIQUE,
        event_type TEXT NOT NULL CHECK(event_type IN (
            'ACTIVATION','EXECUTION_OBSERVED','RECONCILIATION_OBSERVED',
            'CLOSED_FILL','CRITICAL_INCIDENT'
        )),
        dedup_key TEXT NOT NULL UNIQUE,
        occurred_at_utc TEXT NOT NULL,
        upstream_sha256 TEXT NOT NULL,
        payload_json TEXT NOT NULL,
        previous_event_sha256 TEXT NOT NULL,
        event_sha256 TEXT NOT NULL UNIQUE,
        event_hmac_sha256 TEXT NOT NULL UNIQUE
    )""",
    "projection_checkpoints": """CREATE TABLE projection_checkpoints (
        event_count INTEGER PRIMARY KEY CHECK(event_count >= 0),
        checkpoint_json TEXT NOT NULL,
        checkpoint_sha256 TEXT NOT NULL UNIQUE
    )""",
}

_TRIGGER_SQL = {
    "projection_identity_no_update": """CREATE TRIGGER projection_identity_no_update
        BEFORE UPDATE ON projection_identity BEGIN
            SELECT RAISE(ABORT, 'projection identity is immutable');
        END""",
    "projection_identity_no_delete": """CREATE TRIGGER projection_identity_no_delete
        BEFORE DELETE ON projection_identity BEGIN
            SELECT RAISE(ABORT, 'projection identity is immutable');
        END""",
    "projection_events_no_update": """CREATE TRIGGER projection_events_no_update
        BEFORE UPDATE ON projection_events BEGIN
            SELECT RAISE(ABORT, 'projection events are append-only');
        END""",
    "projection_events_no_delete": """CREATE TRIGGER projection_events_no_delete
        BEFORE DELETE ON projection_events BEGIN
            SELECT RAISE(ABORT, 'projection events are append-only');
        END""",
    "projection_checkpoints_no_update": """CREATE TRIGGER projection_checkpoints_no_update
        BEFORE UPDATE ON projection_checkpoints BEGIN
            SELECT RAISE(ABORT, 'projection checkpoints are append-only');
        END""",
    "projection_checkpoints_no_delete": """CREATE TRIGGER projection_checkpoints_no_delete
        BEFORE DELETE ON projection_checkpoints BEGIN
            SELECT RAISE(ABORT, 'projection checkpoints are append-only');
        END""",
}


def _normalized_sql(value: object) -> str:
    return " ".join(str(value).strip().rstrip(";").split()).lower()


class DemoAutoSoakProjection:
    """Durable, authenticated, deny-only adapter into DemoAutoSoakTracker."""

    def __init__(
        self,
        path: str | Path,
        *,
        binding: DemoAutoSoakProjectionBinding,
        projection_key_provider: Callable[[str], str | bytes],
        custody_key_provider: Callable[[str], str | bytes],
        execution_key_provider: Callable[[str], str | bytes],
        broker_key_provider: Callable[[str], str | bytes],
        soak_source_key_provider: Callable[[str], str | bytes],
        tracker: DemoAutoSoakTracker,
        external_checkpoint_provider: Callable[
            [str], DemoAutoSoakProjectionCheckpoint | None
        ],
        external_checkpoint_compare_and_swap: Callable[
            [str, str, DemoAutoSoakProjectionCheckpoint],
            DemoAutoSoakProjectionCASAcknowledgement,
        ],
        clock_provider: Callable[[], datetime] = _utc_now,
    ) -> None:
        if type(binding) is not DemoAutoSoakProjectionBinding:
            raise TypeError("binding must be exact DemoAutoSoakProjectionBinding")
        if type(tracker) is not DemoAutoSoakTracker:
            raise TypeError("tracker must be exact DemoAutoSoakTracker")
        providers = (
            projection_key_provider,
            custody_key_provider,
            execution_key_provider,
            broker_key_provider,
            soak_source_key_provider,
            external_checkpoint_provider,
            external_checkpoint_compare_and_swap,
            clock_provider,
        )
        if any(not callable(item) for item in providers):
            raise TypeError("all projection providers must be callable")
        if tracker.binding != binding.soak_binding:
            raise DemoAutoSoakProjectionBindingError(
                "soak tracker binding does not match projection"
            )
        self.path = Path(path)
        self.binding = binding
        self.tracker = tracker
        self._projection_key_provider = projection_key_provider
        self._custody_key_provider = custody_key_provider
        self._execution_key_provider = execution_key_provider
        self._broker_key_provider = broker_key_provider
        self._source_key_provider = soak_source_key_provider
        self._external_provider = external_checkpoint_provider
        self._external_cas = external_checkpoint_compare_and_swap
        self._clock_provider = clock_provider
        self._require_key_separation()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            self._provision()
        self._verify_all()

    def _now(self) -> datetime:
        try:
            return require_utc("trusted projection clock", self._clock_provider())
        except (TypeError, ValueError) as exc:
            raise DemoAutoSoakProjectionIntegrityError(
                "trusted projection clock is invalid"
            ) from exc

    def _projection_secret(self) -> bytes:
        try:
            return _secret(
                self._projection_key_provider(self.binding.projection_key_id)
            )
        except Exception as exc:
            raise DemoAutoSoakProjectionIntegrityError(
                "projection HMAC key is unavailable"
            ) from exc

    def _custody_secret(self) -> bytes:
        try:
            return _secret(self._custody_key_provider(self.binding.custody_key_id))
        except Exception as exc:
            raise DemoAutoSoakProjectionIntegrityError(
                "projection custody key is unavailable"
            ) from exc

    def _source_secret(self, key_id: str) -> bytes:
        try:
            return _secret(self._source_key_provider(key_id))
        except Exception as exc:
            raise DemoAutoSoakProjectionSourceError(
                "projection soak-source key is unavailable"
            ) from exc

    def _require_key_separation(self) -> None:
        materials = {
            "projection": _secret(
                self._projection_key_provider(self.binding.projection_key_id)
            ),
            "custody": _secret(
                self._custody_key_provider(self.binding.custody_key_id)
            ),
            "execution": _secret(
                self._execution_key_provider(self.binding.execution_key_id)
            ),
            "broker": _secret(self._broker_key_provider(self.binding.broker_key_id)),
            "activation-source": self._source_secret(
                self.binding.activation_source_key_id
            ),
            "closed-deal-source": self._source_secret(
                self.binding.closed_deal_source_key_id
            ),
            "incident-source": self._source_secret(
                self.binding.incident_source_key_id
            ),
        }
        fingerprints = [hashlib.sha256(item).hexdigest() for item in materials.values()]
        if len(set(fingerprints)) != len(fingerprints):
            raise DemoAutoSoakProjectionBindingError(
                "projection trust domains require distinct secret material"
            )

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(str(self.path), timeout=10.0, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout=10000")
        connection.execute("PRAGMA foreign_keys=ON")
        mode = str(connection.execute("PRAGMA journal_mode=WAL").fetchone()[0]).lower()
        connection.execute("PRAGMA synchronous=FULL")
        if mode != "wal":
            connection.close()
            raise DemoAutoSoakProjectionIntegrityError(
                "projection database requires SQLite WAL"
            )
        synchronous = int(connection.execute("PRAGMA synchronous").fetchone()[0])
        if synchronous < 2:
            connection.close()
            raise DemoAutoSoakProjectionIntegrityError(
                "projection database requires synchronous FULL"
            )
        return connection

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        with closing(self._connect()) as connection:
            try:
                connection.execute("BEGIN IMMEDIATE")
                yield connection
                connection.execute("COMMIT")
            except Exception:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise

    def _issue_checkpoint(
        self,
        *,
        event_count: int,
        event_head_sha256: str,
        previous_checkpoint_sha256: str,
        issued_at_utc: datetime,
    ) -> DemoAutoSoakProjectionCheckpoint:
        unsigned = DemoAutoSoakProjectionCheckpoint(
            ledger_id=self.binding.ledger_id,
            binding_sha256=self.binding.content_sha256,
            event_count=event_count,
            event_head_sha256=event_head_sha256,
            previous_checkpoint_sha256=previous_checkpoint_sha256,
            issued_at_utc=issued_at_utc,
            custody_issuer_id=self.binding.custody_issuer_id,
            custody_key_id=self.binding.custody_key_id,
            signature_hmac_sha256=ZERO_SHA256,
            _seal=_CHECKPOINT_SEAL,
        )
        return replace(
            unsigned,
            signature_hmac_sha256=_sign(
                self._custody_secret(), _CHECKPOINT_DOMAIN, unsigned.signing_dict
            ),
            _seal=_CHECKPOINT_SEAL,
        )

    def _verify_checkpoint(
        self, checkpoint: object
    ) -> DemoAutoSoakProjectionCheckpoint:
        if type(checkpoint) is not DemoAutoSoakProjectionCheckpoint:
            raise DemoAutoSoakProjectionIntegrityError(
                "projection checkpoint type is invalid"
            )
        assert isinstance(checkpoint, DemoAutoSoakProjectionCheckpoint)
        expected = _sign(
            self._custody_secret(), _CHECKPOINT_DOMAIN, checkpoint.signing_dict
        )
        if not hmac.compare_digest(expected, checkpoint.signature_hmac_sha256):
            raise DemoAutoSoakProjectionIntegrityError(
                "projection checkpoint HMAC is invalid"
            )
        if (
            checkpoint.ledger_id != self.binding.ledger_id
            or checkpoint.binding_sha256 != self.binding.content_sha256
            or checkpoint.custody_issuer_id != self.binding.custody_issuer_id
            or checkpoint.custody_key_id != self.binding.custody_key_id
        ):
            raise DemoAutoSoakProjectionBindingError(
                "projection checkpoint binding mismatch"
            )
        return checkpoint

    def _verify_ack(
        self,
        acknowledgement: object,
        *,
        expected_previous: str,
        checkpoint: DemoAutoSoakProjectionCheckpoint,
        not_before: datetime,
        not_after: datetime,
    ) -> None:
        if type(acknowledgement) is not DemoAutoSoakProjectionCASAcknowledgement:
            raise DemoAutoSoakProjectionIntegrityError(
                "projection CAS acknowledgement type is invalid"
            )
        assert isinstance(
            acknowledgement, DemoAutoSoakProjectionCASAcknowledgement
        )
        expected = _sign(
            self._custody_secret(), _CAS_ACK_DOMAIN, acknowledgement.signing_dict
        )
        if not hmac.compare_digest(expected, acknowledgement.signature_hmac_sha256):
            raise DemoAutoSoakProjectionIntegrityError(
                "projection CAS acknowledgement HMAC is invalid"
            )
        if (
            not acknowledgement.accepted
            or acknowledgement.ledger_id != self.binding.ledger_id
            or acknowledgement.expected_previous_checkpoint_sha256
            != expected_previous
            or acknowledgement.observed_previous_checkpoint_sha256
            != expected_previous
            or acknowledgement.accepted_checkpoint_sha256
            != checkpoint.content_sha256
            or acknowledgement.custody_issuer_id != self.binding.custody_issuer_id
            or acknowledgement.custody_key_id != self.binding.custody_key_id
            or not not_before <= acknowledgement.issued_at_utc <= not_after
        ):
            raise DemoAutoSoakProjectionReplayError(
                "projection external checkpoint CAS was not accepted exactly"
            )

    def _export_checkpoint(
        self,
        *,
        expected_previous: str,
        checkpoint: DemoAutoSoakProjectionCheckpoint,
    ) -> None:
        before = self._now()
        acknowledgement = self._external_cas(
            self.binding.ledger_id, expected_previous, checkpoint
        )
        after = self._now()
        if after < before:
            raise DemoAutoSoakProjectionIntegrityError(
                "trusted clock regressed during projection CAS"
            )
        self._verify_ack(
            acknowledgement,
            expected_previous=expected_previous,
            checkpoint=checkpoint,
            not_before=before,
            not_after=after,
        )
        readback = self._external_provider(self.binding.ledger_id)
        verified = self._verify_checkpoint(readback)
        if verified != checkpoint:
            raise DemoAutoSoakProjectionReplayError(
                "projection checkpoint readback differs after CAS"
            )

    def _provision(self) -> None:
        now = self._now()
        existing_external = self._external_provider(self.binding.ledger_id)
        if existing_external is not None:
            raise DemoAutoSoakProjectionReplayError(
                "projection ledger namespace already exists externally"
            )
        binding_json = canonical_json(self.binding)
        identity_body = {
            "ledger_id": self.binding.ledger_id,
            "binding_sha256": self.binding.content_sha256,
            "binding_json_sha256": hashlib.sha256(
                binding_json.encode("utf-8")
            ).hexdigest(),
            "projection_key_fingerprint_sha256": hashlib.sha256(
                self._projection_secret()
            ).hexdigest(),
            "custody_key_fingerprint_sha256": hashlib.sha256(
                self._custody_secret()
            ).hexdigest(),
            "created_at_utc": _utc_text(now),
        }
        genesis = self._issue_checkpoint(
            event_count=0,
            event_head_sha256=ZERO_SHA256,
            previous_checkpoint_sha256=ZERO_SHA256,
            issued_at_utc=now,
        )
        with closing(self._connect()) as connection:
            try:
                connection.execute("BEGIN IMMEDIATE")
                for sql in _TABLE_SQL.values():
                    connection.execute(sql)
                for sql in _TRIGGER_SQL.values():
                    connection.execute(sql)
                connection.execute(
                    "INSERT INTO projection_identity VALUES(1,?,?,?,?,?,?,?)",
                    (
                        self.binding.ledger_id,
                        binding_json,
                        self.binding.content_sha256,
                        identity_body["projection_key_fingerprint_sha256"],
                        identity_body["custody_key_fingerprint_sha256"],
                        identity_body["created_at_utc"],
                        _sign(
                            self._projection_secret(),
                            _IDENTITY_DOMAIN,
                            identity_body,
                        ),
                    ),
                )
                connection.execute(
                    "INSERT INTO projection_checkpoints VALUES(?,?,?)",
                    (0, canonical_json(genesis), genesis.content_sha256),
                )
                connection.execute("COMMIT")
            except Exception:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise
        self._export_checkpoint(expected_previous=ZERO_SHA256, checkpoint=genesis)

    def _verify_schema(self, connection: sqlite3.Connection) -> None:
        objects = {
            (str(row["type"]), str(row["name"])): _normalized_sql(row["sql"])
            for row in connection.execute(
                "SELECT type,name,sql FROM sqlite_master "
                "WHERE name LIKE 'projection_%' AND sql IS NOT NULL"
            )
        }
        expected = {
            **{("table", name): _normalized_sql(sql) for name, sql in _TABLE_SQL.items()},
            **{("trigger", name): _normalized_sql(sql) for name, sql in _TRIGGER_SQL.items()},
        }
        if objects != expected:
            raise DemoAutoSoakProjectionIntegrityError(
                "projection database schema changed"
            )

    def _checkpoint_from_json(self, value: str) -> DemoAutoSoakProjectionCheckpoint:
        try:
            raw = json.loads(value)
            checkpoint = DemoAutoSoakProjectionCheckpoint(
                ledger_id=raw["ledger_id"],
                binding_sha256=raw["binding_sha256"],
                event_count=raw["event_count"],
                event_head_sha256=raw["event_head_sha256"],
                previous_checkpoint_sha256=raw["previous_checkpoint_sha256"],
                issued_at_utc=_parse_utc("checkpoint issued_at", raw["issued_at_utc"]),
                custody_issuer_id=raw["custody_issuer_id"],
                custody_key_id=raw["custody_key_id"],
                signature_hmac_sha256=raw["signature_hmac_sha256"],
                schema_version=raw["schema_version"],
                _seal=_CHECKPOINT_SEAL,
            )
        except Exception as exc:
            raise DemoAutoSoakProjectionIntegrityError(
                "stored projection checkpoint is invalid"
            ) from exc
        if checkpoint.canonical_json() != value:
            raise DemoAutoSoakProjectionIntegrityError(
                "stored projection checkpoint is not canonical"
            )
        return self._verify_checkpoint(checkpoint)

    def _verify_connection(
        self, connection: sqlite3.Connection
    ) -> tuple[DemoAutoSoakProjectionCheckpoint, tuple[sqlite3.Row, ...]]:
        self._verify_schema(connection)
        identity = connection.execute(
            "SELECT * FROM projection_identity WHERE singleton=1"
        ).fetchone()
        if identity is None:
            raise DemoAutoSoakProjectionIntegrityError(
                "projection identity is missing"
            )
        binding_json = canonical_json(self.binding)
        body = {
            "ledger_id": self.binding.ledger_id,
            "binding_sha256": self.binding.content_sha256,
            "binding_json_sha256": hashlib.sha256(
                binding_json.encode("utf-8")
            ).hexdigest(),
            "projection_key_fingerprint_sha256": hashlib.sha256(
                self._projection_secret()
            ).hexdigest(),
            "custody_key_fingerprint_sha256": hashlib.sha256(
                self._custody_secret()
            ).hexdigest(),
            "created_at_utc": str(identity["created_at_utc"]),
        }
        if (
            str(identity["ledger_id"]) != self.binding.ledger_id
            or str(identity["binding_json"]) != binding_json
            or str(identity["binding_sha256"]) != self.binding.content_sha256
            or str(identity["projection_key_fingerprint_sha256"])
            != body["projection_key_fingerprint_sha256"]
            or str(identity["custody_key_fingerprint_sha256"])
            != body["custody_key_fingerprint_sha256"]
            or not hmac.compare_digest(
                str(identity["identity_hmac_sha256"]),
                _sign(self._projection_secret(), _IDENTITY_DOMAIN, body),
            )
        ):
            raise DemoAutoSoakProjectionIntegrityError(
                "projection identity changed"
            )
        _parse_utc("projection created_at", str(identity["created_at_utc"]))
        rows = tuple(
            connection.execute("SELECT * FROM projection_events ORDER BY sequence")
        )
        previous = ZERO_SHA256
        seen_dedup: set[str] = set()
        last_time: datetime | None = None
        for expected_sequence, row in enumerate(rows, start=1):
            if int(row["sequence"]) != expected_sequence:
                raise DemoAutoSoakProjectionIntegrityError(
                    "projection event sequence has a gap"
                )
            event_type = str(row["event_type"])
            if event_type not in _EVENT_TYPES:
                raise DemoAutoSoakProjectionIntegrityError(
                    "projection event type is invalid"
                )
            dedup = str(row["dedup_key"])
            if dedup in seen_dedup:
                raise DemoAutoSoakProjectionIntegrityError(
                    "projection event dedup key repeats"
                )
            seen_dedup.add(dedup)
            occurred = _parse_utc("projection occurred_at", str(row["occurred_at_utc"]))
            if last_time is not None and occurred < last_time:
                raise DemoAutoSoakProjectionIntegrityError(
                    "projection event clock regressed"
                )
            last_time = occurred
            try:
                payload = json.loads(str(row["payload_json"]))
            except json.JSONDecodeError as exc:
                raise DemoAutoSoakProjectionIntegrityError(
                    "projection payload is invalid JSON"
                ) from exc
            if not isinstance(payload, dict) or canonical_json(payload) != str(
                row["payload_json"]
            ):
                raise DemoAutoSoakProjectionIntegrityError(
                    "projection payload is not canonical"
                )
            if payload.get("safety") != _safe_payload():
                raise DemoAutoSoakProjectionIntegrityError(
                    "projection event safety locks changed"
                )
            body = {
                "ledger_id": self.binding.ledger_id,
                "binding_sha256": self.binding.content_sha256,
                "sequence": expected_sequence,
                "event_id": str(row["event_id"]),
                "event_type": event_type,
                "dedup_key": dedup,
                "occurred_at_utc": str(row["occurred_at_utc"]),
                "upstream_sha256": str(row["upstream_sha256"]),
                "payload_sha256": hashlib.sha256(
                    str(row["payload_json"]).encode("utf-8")
                ).hexdigest(),
                "previous_event_sha256": previous,
            }
            event_sha = hashlib.sha256(canonical_json(body).encode("utf-8")).hexdigest()
            expected_hmac = _sign(
                self._projection_secret(), _EVENT_DOMAIN, {"event_sha256": event_sha}
            )
            if (
                str(row["previous_event_sha256"]) != previous
                or str(row["event_sha256"]) != event_sha
                or not hmac.compare_digest(
                    str(row["event_hmac_sha256"]), expected_hmac
                )
            ):
                raise DemoAutoSoakProjectionIntegrityError(
                    "projection event HMAC chain is invalid"
                )
            previous = event_sha
        checkpoint_rows = tuple(
            connection.execute(
                "SELECT * FROM projection_checkpoints ORDER BY event_count"
            )
        )
        if len(checkpoint_rows) != len(rows) + 1:
            raise DemoAutoSoakProjectionIntegrityError(
                "projection checkpoint chain is incomplete"
            )
        previous_checkpoint = ZERO_SHA256
        for index, row in enumerate(checkpoint_rows):
            if int(row["event_count"]) != index:
                raise DemoAutoSoakProjectionIntegrityError(
                    "projection checkpoint sequence has a gap"
                )
            checkpoint = self._checkpoint_from_json(str(row["checkpoint_json"]))
            expected_head = ZERO_SHA256 if index == 0 else str(
                rows[index - 1]["event_sha256"]
            )
            if (
                checkpoint.event_count != index
                or checkpoint.event_head_sha256 != expected_head
                or checkpoint.previous_checkpoint_sha256 != previous_checkpoint
                or checkpoint.content_sha256 != str(row["checkpoint_sha256"])
            ):
                raise DemoAutoSoakProjectionIntegrityError(
                    "projection checkpoint chain is invalid"
                )
            previous_checkpoint = checkpoint.content_sha256
        return checkpoint, rows

    def _verify_all(
        self,
    ) -> tuple[DemoAutoSoakProjectionCheckpoint, tuple[sqlite3.Row, ...]]:
        with closing(self._connect()) as connection:
            checkpoint, rows = self._verify_connection(connection)
        external = self._external_provider(self.binding.ledger_id)
        verified_external = self._verify_checkpoint(external)
        if verified_external != checkpoint:
            raise DemoAutoSoakProjectionReplayError(
                "local projection is rolled back, forked, or not externally anchored"
            )
        return checkpoint, rows

    def _event_receipt(
        self, row: sqlite3.Row, checkpoint: DemoAutoSoakProjectionCheckpoint
    ) -> DemoAutoSoakProjectionEventReceipt:
        return DemoAutoSoakProjectionEventReceipt(
            ledger_id=self.binding.ledger_id,
            sequence=int(row["sequence"]),
            event_id=str(row["event_id"]),
            event_type=str(row["event_type"]),
            dedup_key=str(row["dedup_key"]),
            occurred_at_utc=_parse_utc("event receipt time", str(row["occurred_at_utc"])),
            upstream_sha256=str(row["upstream_sha256"]),
            previous_event_sha256=str(row["previous_event_sha256"]),
            event_sha256=str(row["event_sha256"]),
            checkpoint_sha256=checkpoint.content_sha256,
        )

    def _find_event(
        self, *, event_id: str | None = None, dedup_key: str | None = None
    ) -> tuple[DemoAutoSoakProjectionEventReceipt, dict[str, Any]] | None:
        checkpoint, _rows = self._verify_all()
        where: list[str] = []
        parameters: list[str] = []
        if event_id is not None:
            where.append("event_id=?")
            parameters.append(event_id)
        if dedup_key is not None:
            where.append("dedup_key=?")
            parameters.append(dedup_key)
        if not where:
            raise ValueError("event lookup requires an identifier")
        with closing(self._connect()) as connection:
            row = connection.execute(
                "SELECT * FROM projection_events WHERE " + " OR ".join(where),
                tuple(parameters),
            ).fetchone()
            checkpoint_row = (
                None
                if row is None
                else connection.execute(
                    "SELECT checkpoint_json FROM projection_checkpoints "
                    "WHERE event_count=?",
                    (int(row["sequence"]),),
                ).fetchone()
            )
        if row is None:
            return None
        if checkpoint_row is None:
            raise DemoAutoSoakProjectionIntegrityError(
                "projection event checkpoint is missing"
            )
        event_checkpoint = self._checkpoint_from_json(
            str(checkpoint_row["checkpoint_json"])
        )
        return self._event_receipt(row, event_checkpoint), json.loads(
            str(row["payload_json"])
        )

    def _append_event(
        self,
        *,
        event_id: str,
        event_type: str,
        dedup_key: str,
        occurred_at_utc: datetime,
        upstream_sha256: str,
        payload: Mapping[str, Any],
    ) -> DemoAutoSoakProjectionEventReceipt:
        normalized_event_id = _identifier("event_id", event_id)
        normalized_dedup = _identifier("dedup_key", dedup_key)
        normalized_type = require_text("event_type", event_type, upper=True)
        if normalized_type not in _EVENT_TYPES:
            raise ValueError("unsupported projection event type")
        upstream = require_hash("upstream_sha256", upstream_sha256)
        occurred = require_utc("occurred_at_utc", occurred_at_utc)
        canonical_payload = dict(payload)
        canonical_payload["safety"] = _safe_payload()
        payload_json = canonical_json(canonical_payload)
        prior_checkpoint, _rows = self._verify_all()
        with self._transaction() as connection:
            current_checkpoint, rows = self._verify_connection(connection)
            existing = connection.execute(
                "SELECT * FROM projection_events WHERE event_id=? OR dedup_key=?",
                (normalized_event_id, normalized_dedup),
            ).fetchone()
            if existing is not None:
                if (
                    str(existing["event_id"]) != normalized_event_id
                    or str(existing["dedup_key"]) != normalized_dedup
                    or str(existing["event_type"]) != normalized_type
                    or str(existing["upstream_sha256"]) != upstream
                    or str(existing["payload_json"]) != payload_json
                ):
                    raise DemoAutoSoakProjectionReplayError(
                        "projection idempotency key was reused with different facts"
                    )
                checkpoint_row = connection.execute(
                    "SELECT checkpoint_json FROM projection_checkpoints "
                    "WHERE event_count=?",
                    (int(existing["sequence"]),),
                ).fetchone()
                if checkpoint_row is None:
                    raise DemoAutoSoakProjectionIntegrityError(
                        "projection idempotent event checkpoint is missing"
                    )
                return self._event_receipt(
                    existing,
                    self._checkpoint_from_json(str(checkpoint_row["checkpoint_json"])),
                )
            if current_checkpoint != prior_checkpoint:
                raise DemoAutoSoakProjectionReplayError(
                    "projection head changed during append"
                )
            if rows:
                latest_time = _parse_utc(
                    "latest projection time", str(rows[-1]["occurred_at_utc"])
                )
                if occurred < latest_time:
                    raise DemoAutoSoakProjectionReplayError(
                        "projection event clock regressed"
                    )
            sequence = len(rows) + 1
            previous_event = current_checkpoint.event_head_sha256
            body = {
                "ledger_id": self.binding.ledger_id,
                "binding_sha256": self.binding.content_sha256,
                "sequence": sequence,
                "event_id": normalized_event_id,
                "event_type": normalized_type,
                "dedup_key": normalized_dedup,
                "occurred_at_utc": _utc_text(occurred),
                "upstream_sha256": upstream,
                "payload_sha256": hashlib.sha256(
                    payload_json.encode("utf-8")
                ).hexdigest(),
                "previous_event_sha256": previous_event,
            }
            event_sha = hashlib.sha256(canonical_json(body).encode("utf-8")).hexdigest()
            connection.execute(
                """INSERT INTO projection_events VALUES(?,?,?,?,?,?,?,?,?,?)""",
                (
                    sequence,
                    normalized_event_id,
                    normalized_type,
                    normalized_dedup,
                    body["occurred_at_utc"],
                    upstream,
                    payload_json,
                    previous_event,
                    event_sha,
                    _sign(
                        self._projection_secret(),
                        _EVENT_DOMAIN,
                        {"event_sha256": event_sha},
                    ),
                ),
            )
            checkpoint = self._issue_checkpoint(
                event_count=sequence,
                event_head_sha256=event_sha,
                previous_checkpoint_sha256=current_checkpoint.content_sha256,
                issued_at_utc=self._now(),
            )
            connection.execute(
                "INSERT INTO projection_checkpoints VALUES(?,?,?)",
                (sequence, canonical_json(checkpoint), checkpoint.content_sha256),
            )
            # Hold SQLite's single-writer fence until independent custody has
            # accepted and read back the exact head.  Competing processes then
            # see either the old fully anchored head or the new fully anchored
            # head, never the local-ahead CAS window.
            self._export_checkpoint(
                expected_previous=prior_checkpoint.content_sha256,
                checkpoint=checkpoint,
            )
        return DemoAutoSoakProjectionEventReceipt(
            ledger_id=self.binding.ledger_id,
            sequence=sequence,
            event_id=normalized_event_id,
            event_type=normalized_type,
            dedup_key=normalized_dedup,
            occurred_at_utc=occurred,
            upstream_sha256=upstream,
            previous_event_sha256=previous_event,
            event_sha256=event_sha,
            checkpoint_sha256=checkpoint.content_sha256,
        )

    def _session_exact(
        self,
        *,
        store: DemoAutoSessionCapabilityStore,
        lease: DemoAutoSessionLease,
        checkpoint: DemoAutoSessionCheckpoint,
    ) -> DemoAutoSessionLease:
        if type(store) is not DemoAutoSessionCapabilityStore:
            raise TypeError("store must be exact DemoAutoSessionCapabilityStore")
        if type(lease) is not DemoAutoSessionLease:
            raise TypeError("lease must be exact DemoAutoSessionLease")
        if type(checkpoint) is not DemoAutoSessionCheckpoint:
            raise TypeError("checkpoint must be exact DemoAutoSessionCheckpoint")
        if store.binding != self.binding.session_binding:
            raise DemoAutoSoakProjectionBindingError(
                "session capability store belongs to another binding"
            )
        verified = verify_demo_auto_session_capability(store, lease)
        current = store.current_checkpoint()
        if (
            verified != lease
            or current != checkpoint
            or checkpoint.current_lease_sha256 != lease.content_sha256
            or checkpoint.session_id != self.binding.session_binding.session_id
            or checkpoint.binding_sha256
            != self.binding.session_binding.content_sha256
            or lease.activation_authorized
            or lease.execution_authorized
            or lease.safe_to_demo_auto_order
            or lease.live_allowed
            or lease.order_capability != ORDER_CAPABILITY
        ):
            raise DemoAutoSoakProjectionBindingError(
                "session lease/checkpoint is not the exact verified dormant capability"
            )
        return verified

    def _tracker_has_exact_event(self, event_id: str, event_type: str) -> bool:
        matches = [item for item in self.tracker.events() if item.event_id == event_id]
        if not matches:
            return False
        if len(matches) != 1 or matches[0].event_type != event_type:
            raise DemoAutoSoakProjectionReplayError(
                "tracker event id exists with conflicting facts"
            )
        return True

    def _soak_source_receipt(
        self,
        *,
        source_kind: str,
        subject_id: str,
        upstream_receipt_sha256: str,
        occurred_at_utc: datetime,
        details: Sequence[tuple[str, object]],
    ) -> SoakSourceReceipt:
        issuer_id, key_id = {
            "DEMO_AUTO_ACTIVATION": (
                self.binding.activation_source_issuer_id,
                self.binding.activation_source_key_id,
            ),
            "BROKER_CLOSED_DEAL": (
                self.binding.closed_deal_source_issuer_id,
                self.binding.closed_deal_source_key_id,
            ),
            "CRITICAL_INCIDENT": (
                self.binding.incident_source_issuer_id,
                self.binding.incident_source_key_id,
            ),
        }[source_kind]
        now = self._now()
        occurred = require_utc("source occurrence", occurred_at_utc)
        if occurred > now or now - occurred > timedelta(seconds=30):
            raise DemoAutoSoakProjectionSourceError(
                "soak source occurrence is outside the authenticated freshness window"
            )
        receipt_id = f"projection-{source_kind.lower()}-{upstream_receipt_sha256[:32]}"
        payload: dict[str, Any] = {
            "source_receipt_id": receipt_id,
            "source_kind": source_kind,
            "issuer_id": issuer_id,
            "key_id": key_id,
            "binding_sha256": self.binding.soak_binding.binding_sha256,
            "account_alias_sha256": self.binding.account_alias_sha256,
            "broker_server": self.binding.server,
            "environment": "DEMO",
            "journal_sha256": self.binding.soak_binding.journal_sha256,
            "subject_id": subject_id,
            "upstream_receipt_sha256": upstream_receipt_sha256,
            "occurred_at_utc": occurred,
            "observed_at_utc": now,
            "valid_until_utc": now + timedelta(seconds=5),
            "details": tuple(sorted(details)),
            "schema_version": "demo-auto-soak-source-receipt-v1",
        }
        payload["receipt_hmac_sha256"] = _sign(
            self._source_secret(key_id),
            _SOAK_SOURCE_DOMAINS[source_kind],
            payload,
        )
        trust = {
            source_kind: {issuer_id: (key_id,)},
        }
        return verify_soak_source_receipt(
            payload,
            expected_binding=self.binding.soak_binding,
            key_provider=self._source_key_provider,
            trusted_source_issuer_keys=trust,
            clock_provider=self._clock_provider,
        )

    def project_activation(
        self,
        *,
        session_store: DemoAutoSessionCapabilityStore,
        lease: DemoAutoSessionLease,
        checkpoint: DemoAutoSessionCheckpoint,
    ) -> DemoAutoSoakProjectionEventReceipt:
        """Project the exact verified dormant session as DEMO_AUTO soak start."""

        verified = self._session_exact(
            store=session_store, lease=lease, checkpoint=checkpoint
        )
        upstream = canonical_sha256(
            {
                "session_lease_sha256": verified.content_sha256,
                "session_checkpoint_sha256": checkpoint.content_sha256,
                "session_binding_sha256": self.binding.session_binding.content_sha256,
            }
        )
        event_id = f"projection-activation-{upstream[:40]}"
        dedup_key = f"activation:{self.binding.session_binding.session_id}"
        payload = {
            "candidate_id": self.binding.candidate_id,
            "mode": "DEMO_AUTO",
            "account_alias_sha256": self.binding.account_alias_sha256,
            "server": self.binding.server,
            "symbol": self.binding.symbol,
            "lane_id": self.binding.soak_binding.lane_id,
            "session_id": verified.session_id,
            "session_lease_sha256": verified.content_sha256,
            "session_checkpoint_sha256": checkpoint.content_sha256,
            "session_binding_sha256": self.binding.session_binding.content_sha256,
            "stage_binding_sha256": verified.stage_binding_sha256,
            "commit_sha": verified.commit_sha,
            "config_sha256": verified.config_sha256,
            "model_artifact_sha256": verified.model_artifact_sha256,
        }
        existing = self._find_event(event_id=event_id, dedup_key=dedup_key)
        if existing is not None:
            receipt, stored = existing
            if stored != {**payload, "safety": _safe_payload()}:
                raise DemoAutoSoakProjectionReplayError(
                    "activation projection conflicts with stored facts"
                )
            return receipt
        if not self._tracker_has_exact_event(event_id, "SOAK_STARTED"):
            source = self._soak_source_receipt(
                source_kind="DEMO_AUTO_ACTIVATION",
                subject_id=f"session-{upstream[:40]}",
                upstream_receipt_sha256=upstream,
                occurred_at_utc=verified.issued_at_utc,
                details=(("mode", "DEMO_AUTO"),),
            )
            try:
                self.tracker.start_soak(
                    event_id=event_id,
                    activation_receipt=source,
                )
            except SoakTrackerDuplicateError as exc:
                if not self._tracker_has_exact_event(event_id, "SOAK_STARTED"):
                    raise DemoAutoSoakProjectionReplayError(
                        "soak activation dedup conflict"
                    ) from exc
        return self._append_event(
            event_id=event_id,
            event_type="ACTIVATION",
            dedup_key=dedup_key,
            occurred_at_utc=verified.issued_at_utc,
            upstream_sha256=upstream,
            payload=payload,
        )

    def observe_execution(
        self,
        *,
        session_store: DemoAutoSessionCapabilityStore,
        lease: DemoAutoSessionLease,
        checkpoint: DemoAutoSessionCheckpoint,
        intent: TradeIntent,
        execution_receipt: ExecutionReceipt,
        evidence_payload: Mapping[str, Any],
    ) -> DemoAutoSoakProjectionEventReceipt:
        """Record a fresh authenticated DEMO_AUTO broker entry, without dispatch."""

        self._require_activation()
        verified_lease = self._session_exact(
            store=session_store, lease=lease, checkpoint=checkpoint
        )
        evidence = verify_demo_auto_execution_evidence(
            evidence_payload,
            binding=self.binding,
            lease=verified_lease,
            intent=intent,
            execution_receipt=execution_receipt,
            key_provider=self._execution_key_provider,
            clock_provider=self._clock_provider,
        )
        upstream = evidence.content_sha256
        event_id = f"projection-execution-{upstream[:40]}"
        dedup_key = f"execution:{intent.intent_id}"
        payload = {
            "candidate_id": self.binding.candidate_id,
            "mode": "DEMO_AUTO",
            "account_alias_sha256": self.binding.account_alias_sha256,
            "server": self.binding.server,
            "symbol": intent.symbol,
            "lane_id": self.binding.soak_binding.lane_id,
            "session_id": verified_lease.session_id,
            "session_lease_sha256": verified_lease.content_sha256,
            "intent_id": intent.intent_id,
            "intent_sha256": intent.content_sha256,
            "decision_sha256": intent.decision.content_sha256,
            "commit_sha": intent.decision.commit_sha,
            "config_sha256": intent.decision.config_sha256,
            "model_artifact_sha256": intent.decision.model_artifact_sha256,
            "execution_evidence_sha256": evidence.content_sha256,
            "execution_receipt_sha256": execution_receipt.content_sha256,
            "execution_state": execution_receipt.state,
            "order_ticket": _ticket_text(execution_receipt.order_ticket),
            "entry_deal_ticket": _ticket_text(execution_receipt.deal_ticket),
            "filled_volume": execution_receipt.filled_volume,
        }
        return self._append_event(
            event_id=event_id,
            event_type="EXECUTION_OBSERVED",
            dedup_key=dedup_key,
            occurred_at_utc=evidence.occurred_at_utc,
            upstream_sha256=upstream,
            payload=payload,
        )

    def _require_activation(self) -> dict[str, Any]:
        _checkpoint, rows = self._verify_all()
        activations = [row for row in rows if row["event_type"] == "ACTIVATION"]
        if len(activations) != 1:
            raise DemoAutoSoakProjectionError(
                "exactly one authenticated DEMO_AUTO activation is required"
            )
        return json.loads(str(activations[0]["payload_json"]))

    def _prior_reconciliation_state(
        self,
    ) -> tuple[int, str, sqlite3.Row | None]:
        _checkpoint, rows = self._verify_all()
        reconciliations = [
            row for row in rows if row["event_type"] == "RECONCILIATION_OBSERVED"
        ]
        if not reconciliations:
            return 0, ZERO_SHA256, None
        latest = reconciliations[-1]
        payload = json.loads(str(latest["payload_json"]))
        return (
            int(payload["source_sequence"]),
            str(payload["reconciliation_receipt_sha256"]),
            latest,
        )

    def observe_reconciliation(
        self,
        *,
        result: ReconciliationResult,
        receipt: BrokerReconciliationReceipt,
        prior_receipt: BrokerReconciliationReceipt | None = None,
    ) -> DemoAutoReconciliationProjectionResult:
        """Authenticate a monotonic broker snapshot and latch any critical fact."""

        self._require_activation()
        if type(result) is not ReconciliationResult:
            raise TypeError("result must be exact ReconciliationResult")
        if type(receipt) is not BrokerReconciliationReceipt:
            raise TypeError("receipt must be exact BrokerReconciliationReceipt")
        prior_sequence, prior_sha, _row = self._prior_reconciliation_state()
        replaying_exact_head = (
            prior_sequence == receipt.source_sequence
            and prior_sha == receipt.content_sha256
        )
        if receipt.source_sequence == 1:
            if prior_receipt is not None:
                raise DemoAutoSoakProjectionReplayError(
                    "first reconciliation cannot have a predecessor"
                )
        elif (
            type(prior_receipt) is not BrokerReconciliationReceipt
            or prior_receipt.source_sequence != receipt.source_sequence - 1
            or prior_receipt.content_sha256 != receipt.previous_receipt_sha256
        ):
            raise DemoAutoSoakProjectionReplayError(
                "reconciliation predecessor is absent or not exact"
            )
        if not replaying_exact_head and (
            prior_sequence != receipt.source_sequence - 1
            or prior_sha != receipt.previous_receipt_sha256
        ):
            raise DemoAutoSoakProjectionReplayError(
                "reconciliation is a gap, rollback, or fork of the anchored head"
            )
        now = self._now()
        try:
            verified = verify_broker_reconciliation_receipt(
                receipt,
                expected_result=result,
                expected_account_id_sha256=self.binding.account_alias_sha256,
                expected_server=self.binding.server,
                expected_environment="DEMO",
                expected_journal_sha256=self.binding.soak_binding.journal_sha256,
                expected_provider_id=self.binding.broker_provider_id,
                expected_key_id=self.binding.broker_key_id,
                key_provider=self._broker_key_provider,
                now=now,
                prior_receipt=prior_receipt,
            )
        except Exception as exc:
            raise DemoAutoSoakProjectionSourceError(
                "broker reconciliation receipt is not exact/authenticated"
            ) from exc
        upstream = verified.content_sha256
        event_id = f"projection-reconciliation-{upstream[:40]}"
        dedup_key = f"reconciliation:{verified.source_sequence}"
        reason = _critical_reason(result)
        payload = {
            "candidate_id": self.binding.candidate_id,
            "account_alias_sha256": self.binding.account_alias_sha256,
            "server": self.binding.server,
            "journal_sha256": self.binding.soak_binding.journal_sha256,
            "reconciliation_receipt_id": verified.receipt_id,
            "reconciliation_receipt_sha256": verified.content_sha256,
            "reconciliation_result_sha256": reconciliation_result_sha256(result),
            "source_sequence": verified.source_sequence,
            "previous_reconciliation_receipt_sha256": verified.previous_receipt_sha256,
            "status": result.status,
            "critical_reason_code": "" if reason is None else reason,
            "closed_intents": list(result.closed_intents),
            "orphan_position_count": len(result.orphan_position_tickets),
            "orphan_order_count": len(result.orphan_order_tickets),
            "protection_failure_count": len(result.protection_failures),
            "volume_failure_count": len(result.volume_failures),
            "binding_failure_count": len(result.binding_failures),
            "kill_switch_latched": result.kill_switch_latched,
        }
        reconciliation_event = self._append_event(
            event_id=event_id,
            event_type="RECONCILIATION_OBSERVED",
            dedup_key=dedup_key,
            occurred_at_utc=verified.observed_at_utc,
            upstream_sha256=upstream,
            payload=payload,
        )
        incident_event = None
        if reason is not None:
            incident_event = self._project_incident(
                result=result, receipt=verified, reason_code=reason
            )
        return DemoAutoReconciliationProjectionResult(
            reconciliation_event=reconciliation_event,
            incident_event=incident_event,
            critical_reason_code=reason,
        )

    def _project_incident(
        self,
        *,
        result: ReconciliationResult,
        receipt: BrokerReconciliationReceipt,
        reason_code: str,
    ) -> DemoAutoSoakProjectionEventReceipt:
        upstream = canonical_sha256(
            {
                "reconciliation_receipt_sha256": receipt.content_sha256,
                "reconciliation_result_sha256": reconciliation_result_sha256(result),
                "reason_code": reason_code,
            }
        )
        event_id = f"projection-incident-{upstream[:40]}"
        dedup_key = f"incident:{receipt.content_sha256}"
        payload = {
            "candidate_id": self.binding.candidate_id,
            "account_alias_sha256": self.binding.account_alias_sha256,
            "server": self.binding.server,
            "reconciliation_receipt_sha256": receipt.content_sha256,
            "reconciliation_result_sha256": reconciliation_result_sha256(result),
            "reason_code": reason_code,
            "source_sequence": receipt.source_sequence,
            "orphan_position_count": len(result.orphan_position_tickets),
            "orphan_order_count": len(result.orphan_order_tickets),
            "protection_failure_count": len(result.protection_failures),
            "volume_failure_count": len(result.volume_failures),
            "binding_failure_count": len(result.binding_failures),
        }
        existing = self._find_event(event_id=event_id, dedup_key=dedup_key)
        if existing is not None:
            projected, stored = existing
            if stored != {**payload, "safety": _safe_payload()}:
                raise DemoAutoSoakProjectionReplayError(
                    "critical incident projection conflicts with stored facts"
                )
            return projected
        if not self._tracker_has_exact_event(event_id, "CRITICAL_INCIDENT"):
            source = self._soak_source_receipt(
                source_kind="CRITICAL_INCIDENT",
                subject_id=f"incident-{upstream[:40]}",
                upstream_receipt_sha256=upstream,
                occurred_at_utc=receipt.observed_at_utc,
                details=(("reason_code", reason_code),),
            )
            try:
                self.tracker.record_critical_incident(
                    event_id=event_id, incident_receipt=source
                )
            except SoakTrackerDuplicateError as exc:
                if not self._tracker_has_exact_event(event_id, "CRITICAL_INCIDENT"):
                    raise DemoAutoSoakProjectionReplayError(
                        "critical incident tracker dedup conflict"
                    ) from exc
        return self._append_event(
            event_id=event_id,
            event_type="CRITICAL_INCIDENT",
            dedup_key=dedup_key,
            occurred_at_utc=receipt.observed_at_utc,
            upstream_sha256=upstream,
            payload=payload,
        )

    def project_closed_trade(
        self,
        *,
        intent: TradeIntent,
        execution_receipt: ExecutionReceipt,
        reconciliation_receipt: BrokerReconciliationReceipt,
        closed_trade_receipt: BrokerClosedTradeReceipt,
    ) -> tuple[DemoAutoSoakProjectionEventReceipt, ...]:
        """Project each exact exit deal once after a fully reconciled close."""

        self._require_activation()
        if type(intent) is not TradeIntent:
            raise TypeError("intent must be exact TradeIntent")
        if type(execution_receipt) is not ExecutionReceipt:
            raise TypeError("execution_receipt must be exact ExecutionReceipt")
        if type(reconciliation_receipt) is not BrokerReconciliationReceipt:
            raise TypeError(
                "reconciliation_receipt must be exact BrokerReconciliationReceipt"
            )
        if type(closed_trade_receipt) is not BrokerClosedTradeReceipt:
            raise TypeError(
                "closed_trade_receipt must be exact BrokerClosedTradeReceipt"
            )
        if intent.mode != "DEMO_AUTO":
            raise DemoAutoSoakProjectionSourceError(
                "manual, PAPER, shadow, and non-DEMO_AUTO intents are rejected"
            )
        execution = self._execution_payload(intent.intent_id)
        if (
            execution["intent_sha256"] != intent.content_sha256
            or execution["decision_sha256"] != intent.decision.content_sha256
            or execution["execution_receipt_sha256"]
            != execution_receipt.content_sha256
            or execution["commit_sha"] != intent.decision.commit_sha
            or execution["config_sha256"] != intent.decision.config_sha256
            or execution["symbol"] != intent.symbol
            or execution["mode"] != "DEMO_AUTO"
        ):
            raise DemoAutoSoakProjectionBindingError(
                "closed trade does not bind the authenticated entry execution"
            )
        reconciliation = self._reconciliation_payload(
            reconciliation_receipt.content_sha256
        )
        if reconciliation["critical_reason_code"]:
            raise DemoAutoSoakProjectionError(
                "critical reconciliation cannot project a closed fill"
            )
        try:
            verified = verify_broker_closed_trade_receipt(
                closed_trade_receipt,
                reconciliation_receipt=reconciliation_receipt,
                expected_intent_id=intent.intent_id,
                key_provider=self._broker_key_provider,
            )
        except Exception as exc:
            raise DemoAutoSoakProjectionSourceError(
                "broker closed-trade/deal receipts are not exact/authenticated"
            ) from exc
        if (
            verified.environment != "DEMO"
            or verified.account_id_sha256 != self.binding.account_alias_sha256
            or verified.server != self.binding.server
            or verified.journal_sha256 != self.binding.soak_binding.journal_sha256
            or verified.canonical_symbol != self.binding.symbol
            or verified.intent_id != intent.intent_id
            or verified.provider_id != self.binding.broker_provider_id
            or verified.key_id != self.binding.broker_key_id
            or verified.reconciliation_receipt_sha256
            != reconciliation_receipt.content_sha256
            or reconciliation["reconciliation_result_sha256"]
            != reconciliation_receipt.reconciliation_result_sha256
        ):
            raise DemoAutoSoakProjectionBindingError(
                "closed trade receipt belongs to another broker/lane/intent"
            )
        projected: list[DemoAutoSoakProjectionEventReceipt] = []
        for deal in verified.deal_receipts:
            projected.append(
                self._project_closed_deal(
                    intent=intent,
                    execution_receipt=execution_receipt,
                    execution_payload=execution,
                    reconciliation_receipt=reconciliation_receipt,
                    closed_trade_receipt=verified,
                    deal=deal,
                )
            )
        return tuple(projected)

    def _execution_payload(self, intent_id: str) -> dict[str, Any]:
        found = self._find_event(dedup_key=f"execution:{intent_id}")
        if found is None:
            raise DemoAutoSoakProjectionError(
                "closed trade has no authenticated entry execution"
            )
        receipt, payload = found
        if receipt.event_type != "EXECUTION_OBSERVED":
            raise DemoAutoSoakProjectionIntegrityError(
                "execution dedup key maps to the wrong event type"
            )
        return payload

    def _reconciliation_payload(self, receipt_sha256: str) -> dict[str, Any]:
        _checkpoint, rows = self._verify_all()
        matches = []
        for row in rows:
            if row["event_type"] != "RECONCILIATION_OBSERVED":
                continue
            payload = json.loads(str(row["payload_json"]))
            if payload["reconciliation_receipt_sha256"] == receipt_sha256:
                matches.append(payload)
        if len(matches) != 1:
            raise DemoAutoSoakProjectionError(
                "closed trade reconciliation was not authenticated exactly once"
            )
        return matches[0]

    def _project_closed_deal(
        self,
        *,
        intent: TradeIntent,
        execution_receipt: ExecutionReceipt,
        execution_payload: Mapping[str, Any],
        reconciliation_receipt: BrokerReconciliationReceipt,
        closed_trade_receipt: BrokerClosedTradeReceipt,
        deal: BrokerDealReceipt,
    ) -> DemoAutoSoakProjectionEventReceipt:
        deal_identity = canonical_sha256(
            {
                "candidate_id": self.binding.candidate_id,
                "account_alias_sha256": self.binding.account_alias_sha256,
                "server": self.binding.server,
                "provider_id": deal.provider_id,
                "source_sequence": deal.source_sequence,
                "deal_ticket": deal.deal_ticket,
            }
        )
        upstream = canonical_sha256(
            {
                "deal_identity_sha256": deal_identity,
                "deal_receipt_sha256": deal.content_sha256,
                "closed_trade_receipt_sha256": closed_trade_receipt.content_sha256,
                "reconciliation_receipt_sha256": reconciliation_receipt.content_sha256,
                "execution_receipt_sha256": execution_receipt.content_sha256,
                "intent_sha256": intent.content_sha256,
                "decision_sha256": intent.decision.content_sha256,
                "session_lease_sha256": execution_payload["session_lease_sha256"],
            }
        )
        event_id = f"projection-closed-fill-{upstream[:40]}"
        dedup_key = f"deal:{deal_identity}"
        payload = {
            "candidate_id": self.binding.candidate_id,
            "mode": "DEMO_AUTO",
            "account_alias_sha256": self.binding.account_alias_sha256,
            "server": self.binding.server,
            "symbol": deal.canonical_symbol,
            "lane_id": self.binding.soak_binding.lane_id,
            "intent_id": intent.intent_id,
            "intent_sha256": intent.content_sha256,
            "decision_sha256": intent.decision.content_sha256,
            "commit_sha": intent.decision.commit_sha,
            "config_sha256": intent.decision.config_sha256,
            "model_artifact_sha256": intent.decision.model_artifact_sha256,
            "session_id": self.binding.session_binding.session_id,
            "session_lease_sha256": execution_payload["session_lease_sha256"],
            "execution_receipt_sha256": execution_receipt.content_sha256,
            "reconciliation_receipt_sha256": reconciliation_receipt.content_sha256,
            "closed_trade_receipt_sha256": closed_trade_receipt.content_sha256,
            "deal_receipt_sha256": deal.content_sha256,
            "deal_identity_sha256": deal_identity,
            "trade_id": closed_trade_receipt.trade_id,
            "position_ticket": deal.position_ticket,
            "order_ticket": _ticket_text(deal.order_ticket),
            "deal_ticket": deal.deal_ticket,
            "deal_time_utc": _utc_text(deal.deal_time_utc),
            "closed_volume": deal.volume,
        }
        existing = self._find_event(event_id=event_id, dedup_key=dedup_key)
        if existing is not None:
            projected, stored = existing
            if stored != {**payload, "safety": _safe_payload()}:
                raise DemoAutoSoakProjectionReplayError(
                    "broker deal was replayed with different facts"
                )
            return projected
        if not self._tracker_has_exact_event(event_id, "CLOSED_FILL"):
            source = self._soak_source_receipt(
                source_kind="BROKER_CLOSED_DEAL",
                subject_id=f"broker-deal-{deal_identity[:40]}",
                upstream_receipt_sha256=upstream,
                occurred_at_utc=deal.deal_time_utc,
                details=(
                    ("closed_volume", deal.volume),
                    ("intent_id", intent.intent_id),
                    ("symbol", deal.canonical_symbol),
                    ("ticket", deal.deal_ticket),
                ),
            )
            try:
                self.tracker.record_closed_fill(
                    event_id=event_id, closed_deal_receipt=source
                )
            except SoakTrackerDuplicateError as exc:
                if not self._tracker_has_exact_event(event_id, "CLOSED_FILL"):
                    raise DemoAutoSoakProjectionReplayError(
                        "broker deal tracker dedup conflict"
                    ) from exc
        return self._append_event(
            event_id=event_id,
            event_type="CLOSED_FILL",
            dedup_key=dedup_key,
            occurred_at_utc=reconciliation_receipt.observed_at_utc,
            upstream_sha256=upstream,
            payload=payload,
        )

    def current_checkpoint(self) -> DemoAutoSoakProjectionCheckpoint:
        checkpoint, _rows = self._verify_all()
        return checkpoint

    def events(self) -> tuple[DemoAutoSoakProjectionEventReceipt, ...]:
        _checkpoint, rows = self._verify_all()
        with closing(self._connect()) as connection:
            checkpoints = {
                int(row["event_count"]): self._checkpoint_from_json(
                    str(row["checkpoint_json"])
                )
                for row in connection.execute(
                    "SELECT * FROM projection_checkpoints WHERE event_count > 0"
                )
            }
        return tuple(
            self._event_receipt(row, checkpoints[int(row["sequence"])])
            for row in rows
        )

    def status(self) -> dict[str, object]:
        checkpoint, rows = self._verify_all()
        counts = {event_type: 0 for event_type in sorted(_EVENT_TYPES)}
        for row in rows:
            counts[str(row["event_type"])] += 1
        return {
            "schema_version": PROJECTION_BINDING_SCHEMA_VERSION,
            "ledger_id": self.binding.ledger_id,
            "candidate_id": self.binding.candidate_id,
            "environment": "DEMO",
            "server": self.binding.server,
            "symbol": self.binding.symbol,
            "lane_id": self.binding.soak_binding.lane_id,
            "event_count": checkpoint.event_count,
            "event_counts": counts,
            "checkpoint_sha256": checkpoint.content_sha256,
            "no_pnl_projection": True,
            **_safe_payload(),
        }


def _critical_reason(result: ReconciliationResult) -> str | None:
    if result.orphan_position_tickets:
        return "ORPHAN_BROKER_POSITION"
    if result.orphan_order_tickets:
        return "ORPHAN_BROKER_ORDER"
    if result.protection_failures:
        return "MISSING_SERVER_SLTP"
    if result.volume_failures:
        return "BROKER_VOLUME_MISMATCH"
    if result.binding_failures:
        return "BROKER_BINDING_MISMATCH"
    if result.kill_switch_latched or result.status == "RECONCILIATION_CRITICAL_HOLD":
        return "CRITICAL_RECONCILIATION"
    return None


__all__ = [
    "DemoAutoExecutionEvidence",
    "DemoAutoReconciliationProjectionResult",
    "DemoAutoSoakProjection",
    "DemoAutoSoakProjectionBinding",
    "DemoAutoSoakProjectionBindingError",
    "DemoAutoSoakProjectionCASAcknowledgement",
    "DemoAutoSoakProjectionCheckpoint",
    "DemoAutoSoakProjectionError",
    "DemoAutoSoakProjectionEventReceipt",
    "DemoAutoSoakProjectionIntegrityError",
    "DemoAutoSoakProjectionReplayError",
    "DemoAutoSoakProjectionSourceError",
    "issue_demo_auto_soak_projection_cas_acknowledgement",
    "verify_demo_auto_execution_evidence",
]
