"""Fail-closed production runtime supervisor with no execution authority.

The supervisor coordinates already trusted ports.  It does not import MT5,
read credentials, mint approvals or permits, reset a kill switch, or grant an
automatic/live execution mode.  Its local SQLite store provides a singleton
lease and an HMAC-chained receipt for every startup, cycle, and shutdown.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import InitVar, dataclass, replace
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
from pathlib import Path
import sqlite3
from typing import Any, Callable, Iterator, Mapping, Sequence
import uuid

import execution_policy
from execution_policy import LIVE_ALLOWED, SAFE_TO_DEMO_AUTO_ORDER

from .contracts import (
    CanonicalContract,
    ExecutionReceipt,
    canonical_json,
    canonical_sha256,
    require_currency,
    require_hash,
    require_int,
    require_text,
    require_utc,
)
from .controls import ManualDemoApprovalValidation, manual_demo_account_sha256
from .journal_integrity import (
    ExecutionJournalCheckpoint,
    ExecutionJournalCheckpointCASAcknowledgement,
)
from .reconciliation import (
    BrokerClosedTradeReceipt,
    BrokerDealReceipt,
    BrokerReconciliationReceipt,
    ReconciliationResult,
    reconciliation_result_sha256,
)
from .risk_ledger import (
    AccountRiskSnapshot,
    ClosedTradeRiskEvent,
    EntryRiskEvent,
    RiskSourceReceipt,
    RiskStateCheckpointCASAcknowledgement,
    RiskStateReceipt,
)
from .runtime_fact_collector import RuntimeFactReceipt
from .stage_authorization import (
    StageAuthorizationReplayRegistry,
    StageAuthorizationValidation,
    StageBinding,
    StageReadinessAuthorization,
    StageReplayCheckpoint,
)


UTC = timezone.utc
SUPERVISOR_SCHEMA_VERSION = 3
SUPERVISOR_BINDING_SCHEMA_VERSION = "runtime-supervisor-binding-v2"
SUPERVISOR_RECEIPT_SCHEMA_VERSION = "runtime-supervisor-cycle-receipt-v2"
SUPERVISOR_DECISION_SCHEMA_VERSION = "runtime-supervisor-decision-v1"
NEWS_GUARD_SCHEMA_VERSION = "runtime-supervisor-news-guard-v1"
NEWS_GUARD_RECEIPT_SCHEMA_VERSION = "runtime-supervisor-news-guard-receipt-v1"
ZERO_HMAC_SHA256 = "0" * 64
MAX_DECISION_AGE_SECONDS = 1.0
MAX_RISK_RECEIPT_AGE_SECONDS = 1.0
# Stricter than the one-second runtime-fact TTL so a fact can remain valid
# while an account snapshot that is too old for a new order is still denied.
MAX_ACCOUNT_SNAPSHOT_AGE_SECONDS = 0.5

LIVE_ALLOWED = False
SAFE_TO_DEMO_AUTO_ORDER = False
ORDER_CAPABILITY = "DISABLED"

_IDENTITY_DOMAIN = b"AI_SCALPER_RUNTIME_SUPERVISOR_IDENTITY_V1\x00"
_RECEIPT_DOMAIN = b"AI_SCALPER_RUNTIME_SUPERVISOR_RECEIPT_V1\x00"
_NEWS_GUARD_DOMAIN = b"AI_SCALPER_RUNTIME_NEWS_GUARD_RECEIPT_V1\x00"
_CRITICAL_STATE_DOMAIN = b"AI_SCALPER_RUNTIME_SUPERVISOR_CRITICAL_STATE_V1\x00"
_CHECKPOINT_DOMAIN = b"AI_SCALPER_RUNTIME_SUPERVISOR_CHECKPOINT_V2\x00"
_RECEIPT_SEAL = object()
_NEWS_GUARD_SEAL = object()
_EXECUTION_RESULT_SEAL = object()
_RECONCILIATION_RESULT_SEAL = object()
_ALLOWED_MODES = frozenset({"SHADOW", "DEMO", "DEMO_AUTO", "LIVE"})
_ALLOWED_DECISION_ACTIONS = frozenset(
    {"NO_ACTION", "MANUAL_DEMO_EXECUTE", "DEMO_AUTO_EXECUTE"}
)
SUPERVISOR_CHECKPOINT_SCHEMA_VERSION = "runtime-supervisor-checkpoint-v2"
SUPERVISOR_CHECKPOINT_CAS_ACK_SCHEMA_VERSION = (
    "runtime-supervisor-checkpoint-cas-ack-v1"
)


class RuntimeSupervisorError(RuntimeError):
    """Base supervisor failure."""


class RuntimeSupervisorBindingError(RuntimeSupervisorError):
    """The durable store or an injected receipt has the wrong binding."""


class RuntimeSupervisorIntegrityError(RuntimeSupervisorError):
    """Durable supervisor state or an upstream journal failed integrity."""


class RuntimeSupervisorLeaseError(RuntimeSupervisorError):
    """The singleton supervisor lease is absent, held, expired, or stale."""


class RuntimeSupervisorCriticalError(RuntimeSupervisorError):
    """A critical failure latched the journal kill switch and stopped runtime."""


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _iso(value: datetime) -> str:
    return require_utc("timestamp", value).isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )


def _parse_utc(value: object) -> datetime:
    if not isinstance(value, str):
        raise RuntimeSupervisorIntegrityError("stored timestamp must be text")
    try:
        parsed = require_utc(
            "stored timestamp",
            datetime.fromisoformat(value.replace("Z", "+00:00")),
        )
    except (TypeError, ValueError) as exc:
        raise RuntimeSupervisorIntegrityError("stored timestamp is invalid") from exc
    if _iso(parsed) != value:
        raise RuntimeSupervisorIntegrityError("stored timestamp is not canonical UTC")
    return parsed


def _bool(name: str, value: object) -> bool:
    if type(value) is not bool:
        raise TypeError(f"{name} must be bool")
    return value


def _secret(value: object) -> bytes:
    if isinstance(value, str):
        result = value.encode("utf-8")
    elif isinstance(value, bytes):
        result = value
    else:
        raise RuntimeSupervisorIntegrityError("supervisor HMAC key is unavailable")
    if len(result) < 32:
        raise RuntimeSupervisorIntegrityError(
            "supervisor HMAC key must contain at least 32 bytes"
        )
    return result


def _hmac(secret: bytes, domain: bytes, payload: Mapping[str, Any]) -> str:
    return hmac.new(
        secret,
        domain + canonical_json(payload).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


@dataclass(frozen=True)
class RuntimeSupervisorBinding(CanonicalContract):
    account_id_sha256: str
    server: str
    environment: str
    account_currency: str
    journal_sha256: str
    commit_sha: str
    config_sha256: str
    mode: str
    stage_binding_sha256: str | None = None
    news_guard_trust_sha256: str | None = None
    schema_version: str = SUPERVISOR_BINDING_SCHEMA_VERSION

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "account_id_sha256",
            require_hash("account_id_sha256", self.account_id_sha256),
        )
        if self.account_id_sha256 == ZERO_HMAC_SHA256:
            raise ValueError("account_id_sha256 cannot be the zero hash")
        object.__setattr__(self, "server", require_text("server", self.server))
        environment = require_text("environment", self.environment, upper=True)
        if environment not in {"DEMO", "LIVE", "LIVE_READ_ONLY"}:
            raise ValueError("environment must be DEMO, LIVE, or LIVE_READ_ONLY")
        object.__setattr__(self, "environment", environment)
        object.__setattr__(
            self,
            "account_currency",
            require_currency("account_currency", self.account_currency),
        )
        for name in ("journal_sha256", "config_sha256"):
            object.__setattr__(self, name, require_hash(name, getattr(self, name)))
        object.__setattr__(
            self,
            "commit_sha",
            require_hash("commit_sha", self.commit_sha, minimum_length=7),
        )
        mode = require_text("mode", self.mode, upper=True)
        if mode not in _ALLOWED_MODES:
            raise ValueError("unsupported runtime supervisor mode")
        object.__setattr__(self, "mode", mode)
        if mode in {"DEMO", "DEMO_AUTO"}:
            object.__setattr__(
                self,
                "stage_binding_sha256",
                require_hash("stage_binding_sha256", self.stage_binding_sha256),
            )
            if self.stage_binding_sha256 == ZERO_HMAC_SHA256:
                raise ValueError("stage_binding_sha256 cannot be the zero hash")
            if environment != "DEMO":
                raise ValueError("DEMO stage modes require the DEMO environment")
        elif self.stage_binding_sha256 is not None:
            raise ValueError("stage_binding_sha256 is restricted to DEMO stage modes")
        if mode != "SHADOW":
            object.__setattr__(
                self,
                "news_guard_trust_sha256",
                require_hash("news_guard_trust_sha256", self.news_guard_trust_sha256),
            )
            if self.news_guard_trust_sha256 == ZERO_HMAC_SHA256:
                raise ValueError("news_guard_trust_sha256 cannot be the zero hash")
        elif self.news_guard_trust_sha256 is not None:
            object.__setattr__(
                self,
                "news_guard_trust_sha256",
                require_hash("news_guard_trust_sha256", self.news_guard_trust_sha256),
            )
        if self.schema_version != SUPERVISOR_BINDING_SCHEMA_VERSION:
            raise ValueError("unsupported supervisor binding schema")


@dataclass(frozen=True)
class RuntimeNewsGuard(CanonicalContract):
    observed_at_utc: datetime
    news_feed_fresh: bool
    news_blackout_active: bool
    rollover_blackout_active: bool
    schema_version: str = NEWS_GUARD_SCHEMA_VERSION

    def __post_init__(self) -> None:
        require_utc("observed_at_utc", self.observed_at_utc)
        for name in (
            "news_feed_fresh",
            "news_blackout_active",
            "rollover_blackout_active",
        ):
            _bool(name, getattr(self, name))
        if self.schema_version != NEWS_GUARD_SCHEMA_VERSION:
            raise ValueError("unsupported runtime news guard schema")


@dataclass(frozen=True)
class RuntimeNewsGuardReceipt(CanonicalContract):
    """Signed, exactly bound news/rollover fact used by execution modes."""

    provider_id: str
    key_id: str
    account_id_sha256: str
    server: str
    environment: str
    observed_at_utc: datetime
    valid_until_utc: datetime
    feed_sequence: int
    feed_payload_sha256: str
    previous_receipt_sha256: str
    news_feed_fresh: bool
    news_blackout_active: bool
    rollover_blackout_active: bool
    blackout_window_sha256: str
    ruleset_sha256: str
    config_sha256: str
    signature_hmac_sha256: str = ""
    schema_version: str = NEWS_GUARD_RECEIPT_SCHEMA_VERSION
    _seal: InitVar[object | None] = None

    def __post_init__(self, _seal: object | None) -> None:
        if _seal is not _NEWS_GUARD_SEAL:
            raise TypeError("news guard receipts can only be created by the signed issuer")
        for name in ("provider_id", "key_id", "server"):
            object.__setattr__(self, name, require_text(name, getattr(self, name)))
        object.__setattr__(
            self,
            "account_id_sha256",
            require_hash("account_id_sha256", self.account_id_sha256),
        )
        if self.account_id_sha256 == ZERO_HMAC_SHA256:
            raise ValueError("news guard account hash cannot be zero")
        environment = require_text("environment", self.environment, upper=True)
        if environment not in {"DEMO", "LIVE", "LIVE_READ_ONLY"}:
            raise ValueError("news guard environment is unsupported")
        object.__setattr__(self, "environment", environment)
        observed = require_utc("observed_at_utc", self.observed_at_utc)
        valid_until = require_utc("valid_until_utc", self.valid_until_utc)
        if not observed < valid_until <= observed + timedelta(seconds=60):
            raise ValueError("news guard validity window must be positive and <=60 seconds")
        require_int("feed_sequence", self.feed_sequence, minimum=1)
        for name in (
            "feed_payload_sha256",
            "blackout_window_sha256",
            "ruleset_sha256",
            "config_sha256",
        ):
            object.__setattr__(self, name, require_hash(name, getattr(self, name)))
            if getattr(self, name) == ZERO_HMAC_SHA256:
                raise ValueError(f"{name} cannot be the zero hash")
        object.__setattr__(
            self,
            "previous_receipt_sha256",
            require_hash("previous_receipt_sha256", self.previous_receipt_sha256),
        )
        for name in (
            "news_feed_fresh",
            "news_blackout_active",
            "rollover_blackout_active",
        ):
            _bool(name, getattr(self, name))
        if self.signature_hmac_sha256:
            object.__setattr__(
                self,
                "signature_hmac_sha256",
                require_hash("signature_hmac_sha256", self.signature_hmac_sha256),
            )
        if self.schema_version != NEWS_GUARD_RECEIPT_SCHEMA_VERSION:
            raise ValueError("unsupported signed news guard schema")

    @property
    def signing_payload(self) -> bytes:
        payload = self.to_canonical_dict()
        payload.pop("signature_hmac_sha256")
        return canonical_json(payload).encode("utf-8")


def runtime_news_guard_trust_sha256(
    *,
    provider_id: str,
    key_id: str,
    ruleset_sha256: str,
    blackout_window_sha256: str,
) -> str:
    return canonical_sha256(
        {
            "provider_id": require_text("provider_id", provider_id),
            "key_id": require_text("key_id", key_id),
            "ruleset_sha256": require_hash("ruleset_sha256", ruleset_sha256),
            "blackout_window_sha256": require_hash(
                "blackout_window_sha256", blackout_window_sha256
            ),
            "schema_version": NEWS_GUARD_RECEIPT_SCHEMA_VERSION,
        }
    )


def issue_runtime_news_guard_receipt(
    *,
    provider_id: str,
    key_id: str,
    key: str | bytes,
    account_id_sha256: str,
    server: str,
    environment: str,
    observed_at_utc: datetime,
    valid_until_utc: datetime,
    feed_sequence: int,
    feed_payload_sha256: str,
    previous_receipt_sha256: str,
    news_feed_fresh: bool,
    news_blackout_active: bool,
    rollover_blackout_active: bool,
    blackout_window_sha256: str,
    ruleset_sha256: str,
    config_sha256: str,
) -> RuntimeNewsGuardReceipt:
    unsigned = RuntimeNewsGuardReceipt(
        provider_id=provider_id,
        key_id=key_id,
        account_id_sha256=account_id_sha256,
        server=server,
        environment=environment,
        observed_at_utc=observed_at_utc,
        valid_until_utc=valid_until_utc,
        feed_sequence=feed_sequence,
        feed_payload_sha256=feed_payload_sha256,
        previous_receipt_sha256=previous_receipt_sha256,
        news_feed_fresh=news_feed_fresh,
        news_blackout_active=news_blackout_active,
        rollover_blackout_active=rollover_blackout_active,
        blackout_window_sha256=blackout_window_sha256,
        ruleset_sha256=ruleset_sha256,
        config_sha256=config_sha256,
        _seal=_NEWS_GUARD_SEAL,
    )
    signature = hmac.new(
        _secret(key), _NEWS_GUARD_DOMAIN + unsigned.signing_payload, hashlib.sha256
    ).hexdigest()
    return replace(unsigned, signature_hmac_sha256=signature, _seal=_NEWS_GUARD_SEAL)


def verify_runtime_news_guard_receipt(
    receipt: RuntimeNewsGuardReceipt,
    *,
    expected_provider_id: str,
    expected_key_id: str,
    expected_account_id_sha256: str,
    expected_server: str,
    expected_environment: str,
    expected_config_sha256: str,
    key_provider: Callable[[str], str | bytes],
    now: datetime,
) -> RuntimeNewsGuardReceipt:
    if type(receipt) is not RuntimeNewsGuardReceipt:
        raise RuntimeSupervisorIntegrityError("news guard receipt is not sealed")
    expected = hmac.new(
        _secret(key_provider(receipt.key_id)),
        _NEWS_GUARD_DOMAIN + receipt.signing_payload,
        hashlib.sha256,
    ).hexdigest()
    if not receipt.signature_hmac_sha256 or not hmac.compare_digest(
        receipt.signature_hmac_sha256, expected
    ):
        raise RuntimeSupervisorIntegrityError("news guard signature is invalid")
    if (
        receipt.provider_id != expected_provider_id
        or receipt.key_id != expected_key_id
        or receipt.account_id_sha256 != expected_account_id_sha256
        or receipt.server != expected_server
        or receipt.environment != expected_environment
        or receipt.config_sha256 != expected_config_sha256
    ):
        raise RuntimeSupervisorBindingError("news guard binding mismatch")
    checked = require_utc("now", now)
    if not receipt.observed_at_utc <= checked < receipt.valid_until_utc:
        raise RuntimeSupervisorCriticalError("NEWS_GUARD_STALE_OR_FUTURE")
    return receipt


@dataclass(frozen=True)
class RuntimeStageAuthorizationPorts:
    """Explicit ports for one startup-only stage-authorization consumption."""

    authorization: StageReadinessAuthorization
    expected_binding: StageBinding
    external_replay_checkpoint: StageReplayCheckpoint
    authorization_validator: Callable[[datetime, str], StageAuthorizationValidation]
    replay_registry: StageAuthorizationReplayRegistry
    checkpoint_key_id: str
    checkpoint_key_provider: Callable[[str], str | bytes]

    def __post_init__(self) -> None:
        if type(self.authorization) is not StageReadinessAuthorization:
            raise TypeError("authorization must be exact StageReadinessAuthorization")
        if type(self.expected_binding) is not StageBinding:
            raise TypeError("expected_binding must be exact StageBinding")
        if type(self.external_replay_checkpoint) is not StageReplayCheckpoint:
            raise TypeError("external checkpoint must be exact StageReplayCheckpoint")
        if type(self.replay_registry) is not StageAuthorizationReplayRegistry:
            raise TypeError("replay_registry must be exact StageAuthorizationReplayRegistry")
        object.__setattr__(
            self,
            "checkpoint_key_id",
            require_text("checkpoint_key_id", self.checkpoint_key_id),
        )
        for name in ("authorization_validator", "checkpoint_key_provider"):
            if not callable(getattr(self, name)):
                raise TypeError(f"{name} must be callable")


@dataclass(frozen=True)
class RuntimeSupervisorDecision(CanonicalContract):
    decision_id: str
    action: str
    decided_at_utc: datetime
    decision_payload_sha256: str
    intent_id: str | None = None
    schema_version: str = SUPERVISOR_DECISION_SCHEMA_VERSION

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "decision_id", require_text("decision_id", self.decision_id)
        )
        action = require_text("action", self.action, upper=True)
        if action not in _ALLOWED_DECISION_ACTIONS:
            raise ValueError("unsupported supervisor decision action")
        object.__setattr__(self, "action", action)
        require_utc("decided_at_utc", self.decided_at_utc)
        object.__setattr__(
            self,
            "decision_payload_sha256",
            require_hash("decision_payload_sha256", self.decision_payload_sha256),
        )
        if action in {"MANUAL_DEMO_EXECUTE", "DEMO_AUTO_EXECUTE"}:
            object.__setattr__(
                self, "intent_id", require_text("intent_id", self.intent_id)
            )
        elif self.intent_id is not None:
            raise ValueError("NO_ACTION decision cannot reference an intent")
        if self.schema_version != SUPERVISOR_DECISION_SCHEMA_VERSION:
            raise ValueError("unsupported supervisor decision schema")


@dataclass(frozen=True)
class RuntimeManualDemoExecutionResult(CanonicalContract):
    """Sealed proof that one manual-demo call produced one broker fill.

    The exact adapter ``ExecutionReceipt`` is also the signed upstream evidence
    for the one and only risk-ledger ``ENTRY`` event.  The supervisor, not the
    execution provider, owns the durable append and verifies the resulting
    sequence/head advance before it records a completed cycle.
    """

    execution_receipt: ExecutionReceipt
    entry_event: EntryRiskEvent
    entry_source_receipt: RiskSourceReceipt
    schema_version: str = "runtime-manual-demo-execution-result-v1"
    _seal: InitVar[object | None] = None

    def __post_init__(self, _seal: object | None) -> None:
        if _seal is not _EXECUTION_RESULT_SEAL:
            raise TypeError(
                "manual-demo execution results require the sealing factory"
            )
        if type(self.execution_receipt) is not ExecutionReceipt:
            raise TypeError("exact sealed ExecutionReceipt is required")
        if type(self.entry_event) is not EntryRiskEvent:
            raise TypeError("exact EntryRiskEvent is required")
        if type(self.entry_source_receipt) is not RiskSourceReceipt:
            raise TypeError("exact sealed RiskSourceReceipt is required")
        receipt = self.execution_receipt
        event = self.entry_event
        source = self.entry_source_receipt
        if receipt.state not in {"PARTIAL", "FILLED", "RECONCILED"}:
            raise ValueError("manual-demo result does not prove a broker fill")
        if (
            event.entry_id != receipt.intent_id
            or event.symbol != receipt.symbol
            or event.occurred_at_utc != receipt.received_at
            or event.binding.account_id_sha256
            != manual_demo_account_sha256(receipt.account_id)
            or event.binding.server != receipt.server
            or event.binding.journal_sha256 != receipt.journal_sha256
            or source.binding != event.binding
            or source.source_kind != "ENTRY"
            or source.event_sha256 != event.content_sha256
            or source.upstream_receipt_type != "EXECUTION_RECEIPT"
            or source.upstream_receipt_sha256 != receipt.content_sha256
        ):
            raise ValueError("manual-demo execution/risk evidence is not exact")
        if self.schema_version != "runtime-manual-demo-execution-result-v1":
            raise ValueError("unsupported manual-demo execution result schema")


def seal_runtime_manual_demo_execution_result(
    *,
    execution_receipt: ExecutionReceipt,
    entry_event: EntryRiskEvent,
    entry_source_receipt: RiskSourceReceipt,
) -> RuntimeManualDemoExecutionResult:
    """Seal exact execution-to-risk evidence without granting execution."""

    return RuntimeManualDemoExecutionResult(
        execution_receipt=execution_receipt,
        entry_event=entry_event,
        entry_source_receipt=entry_source_receipt,
        _seal=_EXECUTION_RESULT_SEAL,
    )


@dataclass(frozen=True)
class RuntimeDemoAutoExecutionResult(CanonicalContract):
    """Sealed one-shot DEMO_AUTO dispatch and risk-ingestion evidence.

    The result deliberately stores immutable hashes for every authority and
    pre-dispatch high-water mark.  It can only be created by the sealing
    factory below, which accepts the exact sealed objects.  The checked-in
    release cannot reach that factory because the centralized DEMO_AUTO policy
    remains disabled.
    """

    execution_receipt: ExecutionReceipt
    entry_event: EntryRiskEvent
    entry_source_receipt: RiskSourceReceipt
    decision_id: str
    decision_payload_sha256: str
    ipc_input_sha256: str
    session_store_binding_sha256: str
    session_lease_sha256: str
    session_checkpoint_sha256: str
    session_dispatch_verification_sha256: str
    permit_validation_sha256: str
    promotion_validation_sha256: str
    environment_arm_sha256: str
    supervisor_checkpoint_sha256: str
    journal_checkpoint_sha256: str
    risk_receipt_sha256: str
    reconciliation_receipt_sha256: str
    schema_version: str = "runtime-demo-auto-execution-result-v1"
    _seal: InitVar[object | None] = None

    def __post_init__(self, _seal: object | None) -> None:
        if _seal is not _EXECUTION_RESULT_SEAL:
            raise TypeError("DEMO_AUTO execution results require the sealing factory")
        if type(self.execution_receipt) is not ExecutionReceipt:
            raise TypeError("exact sealed ExecutionReceipt is required")
        if type(self.entry_event) is not EntryRiskEvent:
            raise TypeError("exact EntryRiskEvent is required")
        if type(self.entry_source_receipt) is not RiskSourceReceipt:
            raise TypeError("exact sealed RiskSourceReceipt is required")
        object.__setattr__(self, "decision_id", require_text("decision_id", self.decision_id))
        for name in (
            "decision_payload_sha256",
            "ipc_input_sha256",
            "session_store_binding_sha256",
            "session_lease_sha256",
            "session_checkpoint_sha256",
            "session_dispatch_verification_sha256",
            "permit_validation_sha256",
            "promotion_validation_sha256",
            "environment_arm_sha256",
            "supervisor_checkpoint_sha256",
            "journal_checkpoint_sha256",
            "risk_receipt_sha256",
            "reconciliation_receipt_sha256",
        ):
            object.__setattr__(self, name, require_hash(name, getattr(self, name)))
        receipt = self.execution_receipt
        event = self.entry_event
        source = self.entry_source_receipt
        if (
            receipt.state not in {"PARTIAL", "FILLED", "RECONCILED"}
            or event.entry_id != receipt.intent_id
            or event.symbol != receipt.symbol
            or event.occurred_at_utc != receipt.received_at
            or event.binding.account_id_sha256
            != manual_demo_account_sha256(receipt.account_id)
            or event.binding.server != receipt.server
            or event.binding.journal_sha256 != receipt.journal_sha256
            or source.binding != event.binding
            or source.source_kind != "ENTRY"
            or source.event_sha256 != event.content_sha256
            or source.upstream_receipt_type != "EXECUTION_RECEIPT"
            or source.upstream_receipt_sha256 != receipt.content_sha256
        ):
            raise ValueError("DEMO_AUTO execution/risk evidence is not exact")
        if self.schema_version != "runtime-demo-auto-execution-result-v1":
            raise ValueError("unsupported DEMO_AUTO execution result schema")


def seal_runtime_demo_auto_execution_result(
    *,
    execution_receipt: ExecutionReceipt,
    entry_event: EntryRiskEvent,
    entry_source_receipt: RiskSourceReceipt,
    decision: RuntimeSupervisorDecision,
    ipc_input: object,
    session_store: object,
    session_lease: object,
    session_checkpoint: object,
    session_dispatch_verification: object,
    permit_validation: object,
    promotion_validation: object,
    environment_arm: object,
    supervisor_checkpoint: RuntimeSupervisorCheckpoint,
    journal_checkpoint: ExecutionJournalCheckpoint,
    risk_receipt: RiskStateReceipt,
    reconciliation: RuntimeReconciliationRiskResult,
) -> RuntimeDemoAutoExecutionResult:
    """Seal exact DEMO_AUTO authority and custody inputs without granting them."""

    from .controls import EnvironmentArmDecision
    from .demo_auto_ipc_consumer import DemoAutoIPCRiskIntentInput
    from .demo_auto_session_capability import (
        DemoAutoSessionCapabilityStore,
        DemoAutoSessionCheckpoint,
        DemoAutoSessionDispatchVerification,
        DemoAutoSessionLease,
    )
    from .permit import PermitValidation
    from .promotion_evidence import PromotionEvidenceValidation

    exact = (
        (decision, RuntimeSupervisorDecision, "decision"),
        (ipc_input, DemoAutoIPCRiskIntentInput, "ipc_input"),
        (session_store, DemoAutoSessionCapabilityStore, "session_store"),
        (session_lease, DemoAutoSessionLease, "session_lease"),
        (session_checkpoint, DemoAutoSessionCheckpoint, "session_checkpoint"),
        (
            session_dispatch_verification,
            DemoAutoSessionDispatchVerification,
            "session_dispatch_verification",
        ),
        (permit_validation, PermitValidation, "permit_validation"),
        (promotion_validation, PromotionEvidenceValidation, "promotion_validation"),
        (environment_arm, EnvironmentArmDecision, "environment_arm"),
        (supervisor_checkpoint, RuntimeSupervisorCheckpoint, "supervisor_checkpoint"),
        (journal_checkpoint, ExecutionJournalCheckpoint, "journal_checkpoint"),
        (risk_receipt, RiskStateReceipt, "risk_receipt"),
        (reconciliation, RuntimeReconciliationRiskResult, "reconciliation"),
    )
    for value, expected, label in exact:
        if type(value) is not expected:
            raise TypeError(f"{label} must be exact {expected.__name__}")
    return RuntimeDemoAutoExecutionResult(
        execution_receipt=execution_receipt,
        entry_event=entry_event,
        entry_source_receipt=entry_source_receipt,
        decision_id=decision.decision_id,
        decision_payload_sha256=decision.decision_payload_sha256,
        ipc_input_sha256=ipc_input.content_sha256,
        session_store_binding_sha256=session_store.binding.content_sha256,
        session_lease_sha256=session_lease.content_sha256,
        session_checkpoint_sha256=session_checkpoint.content_sha256,
        session_dispatch_verification_sha256=(
            session_dispatch_verification.content_sha256
        ),
        permit_validation_sha256=permit_validation.content_sha256,
        promotion_validation_sha256=promotion_validation.content_sha256,
        environment_arm_sha256=environment_arm.content_sha256,
        supervisor_checkpoint_sha256=supervisor_checkpoint.content_sha256,
        journal_checkpoint_sha256=journal_checkpoint.content_sha256,
        risk_receipt_sha256=risk_receipt.content_sha256,
        reconciliation_receipt_sha256=reconciliation.content_sha256,
        _seal=_EXECUTION_RESULT_SEAL,
    )


def _verify_demo_auto_dispatch_controls(
    *,
    binding: RuntimeSupervisorBinding,
    decision: RuntimeSupervisorDecision,
    ipc_input: object,
    session_store: object,
    session_lease: object,
    session_checkpoint: object,
    session_dispatch_verification: object,
    permit_validation: object,
    promotion_validation: object,
    environment_arm: object,
    supervisor_checkpoint: RuntimeSupervisorCheckpoint,
    checked_at: datetime,
) -> None:
    """Verify the exact one-use DEMO_AUTO authority chain at dispatch time."""

    from .controls import EnvironmentArmDecision
    from .demo_auto_ipc_consumer import DemoAutoIPCRiskIntentInput
    from .demo_auto_session_capability import (
        DemoAutoSessionCapabilityStore,
        DemoAutoSessionCheckpoint,
        DemoAutoSessionDispatchVerification,
        DemoAutoSessionLease,
    )
    from .permit import PermitValidation
    from .promotion_evidence import PromotionEvidenceValidation

    exact = (
        (ipc_input, DemoAutoIPCRiskIntentInput, "ipc_input"),
        (session_store, DemoAutoSessionCapabilityStore, "session_store"),
        (session_lease, DemoAutoSessionLease, "session_lease"),
        (session_checkpoint, DemoAutoSessionCheckpoint, "session_checkpoint"),
        (
            session_dispatch_verification,
            DemoAutoSessionDispatchVerification,
            "session_dispatch_verification",
        ),
        (permit_validation, PermitValidation, "permit_validation"),
        (promotion_validation, PromotionEvidenceValidation, "promotion_validation"),
        (environment_arm, EnvironmentArmDecision, "environment_arm"),
        (supervisor_checkpoint, RuntimeSupervisorCheckpoint, "supervisor_checkpoint"),
    )
    for value, expected, label in exact:
        if type(value) is not expected:
            raise RuntimeSupervisorCriticalError(
                f"DEMO_AUTO_{label.upper()}_INVALID"
            )
    try:
        verified_dispatch = session_store.verify_dispatch_verification(
            session_dispatch_verification,
            session_lease,
            expected_intent_id=decision.intent_id,
        )
    except Exception as exc:
        raise RuntimeSupervisorCriticalError(
            "DEMO_AUTO_SESSION_VERIFICATION_FAILED"
        ) from exc
    if verified_dispatch is not session_dispatch_verification:
        raise RuntimeSupervisorIntegrityError(
            "DEMO_AUTO_SESSION_STORE_DID_NOT_RETURN_EXACT_VERIFICATION"
        )
    now = require_utc("checked_at", checked_at)
    envelope = ipc_input.verified_envelope.envelope
    snapshot = envelope.decision
    stage = ipc_input.stage_binding
    permit = ipc_input.permit
    queue_binding = envelope.binding
    symbol_allowed, _symbol_reason = execution_policy.validate_execution_symbol(
        snapshot.symbol,
        mode=binding.mode,
    )
    if (
        binding.mode != "DEMO_AUTO"
        or binding.environment != "DEMO"
        or decision.action != "DEMO_AUTO_EXECUTE"
        or snapshot.snapshot_id != decision.decision_id
        or snapshot.content_sha256 != decision.decision_payload_sha256
        or decision.intent_id is None
        or not symbol_allowed
        or stage.symbol != snapshot.symbol
        or queue_binding.environment != "DEMO"
        or ipc_input.supervisor_binding != binding
        or stage.binding_sha256 != binding.stage_binding_sha256
        or stage.account_alias_sha256 != binding.account_id_sha256
        or stage.server != binding.server
        or stage.journal_sha256 != binding.journal_sha256
        or stage.commit_sha != binding.commit_sha
        or stage.config_sha256 != binding.config_sha256
        or not ipc_input.consumed_at_utc <= now < ipc_input.valid_until_utc
    ):
        raise RuntimeSupervisorCriticalError("DEMO_AUTO_IPC_BINDING_INVALID")
    if (
        not permit_validation.valid
        or permit_validation.permit_id != permit.permit_id
        or permit_validation.mode != "DEMO_AUTO"
        or permit_validation.account_alias_sha256 != binding.account_id_sha256
        or permit_validation.server != binding.server
        or permit_validation.symbols != (snapshot.symbol,)
        or permit_validation.commit_sha != binding.commit_sha
        or permit_validation.config_sha256 != binding.config_sha256
        or permit_validation.model_artifact_sha256 != stage.model_artifact_sha256
        or permit_validation.journal_sha256 != binding.journal_sha256
        or permit_validation.checked_at > now
        or (now - permit_validation.checked_at).total_seconds()
        > MAX_DECISION_AGE_SECONDS
        or not permit_validation.issued_at <= now < permit_validation.expires_at
    ):
        raise RuntimeSupervisorCriticalError("DEMO_AUTO_PERMIT_VALIDATION_FAILED")
    if (
        not promotion_validation.valid
        or promotion_validation.mode != "DEMO_AUTO"
        or promotion_validation.lane_id != stage.lane_id
        or promotion_validation.symbol != snapshot.symbol
        or promotion_validation.commit_sha != binding.commit_sha
        or promotion_validation.config_sha256 != binding.config_sha256
        or promotion_validation.model_artifact_sha256 != stage.model_artifact_sha256
        or promotion_validation.receipt_sha256
        != permit_validation.promotion_evidence_sha256
        or promotion_validation.checked_at > now
        or (now - promotion_validation.checked_at).total_seconds()
        > MAX_DECISION_AGE_SECONDS
        or not now < promotion_validation.expires_at
    ):
        raise RuntimeSupervisorCriticalError(
            "DEMO_AUTO_PROMOTION_EVIDENCE_VALIDATION_FAILED"
        )
    if (
        not environment_arm.armed
        or not environment_arm.is_fresh(now)
        or environment_arm.journal_sha256 != binding.journal_sha256
        or environment_arm.observed_value_sha256 is None
        or environment_arm.binding_sha256
        != ipc_input.environment_arm.binding_sha256
        or environment_arm.observed_value_sha256
        != ipc_input.environment_arm.observed_value_sha256
    ):
        raise RuntimeSupervisorCriticalError("DEMO_AUTO_ENVIRONMENT_ARM_INVALID")
    if (
        session_lease.stage_binding_sha256 != stage.binding_sha256
        or session_lease.stage_authorization_id
        != ipc_input.stage_authorization.authorization_id
        or session_lease.stage_authorization_sha256
        != ipc_input.stage_authorization.content_sha256
        or session_lease.stage_validation_sha256
        != ipc_input.stage_validation.content_sha256
        or session_lease.account_alias_sha256 != binding.account_id_sha256
        or session_lease.server != binding.server
        or session_lease.lane_id != stage.lane_id
        or session_lease.journal_sha256 != binding.journal_sha256
        or session_lease.commit_sha != binding.commit_sha
        or session_lease.config_sha256 != binding.config_sha256
        or session_lease.dependency_lock_sha256 != stage.dependency_lock_sha256
        or session_lease.runtime_profile_sha256 != stage.runtime_profile_sha256
        or session_lease.model_artifact_sha256 != stage.model_artifact_sha256
        or session_lease.supervisor_binding_sha256 != binding.content_sha256
        or session_lease.supervisor_checkpoint_sha256
        != supervisor_checkpoint.content_sha256
        or session_lease.supervisor_checkpoint_event_count
        != supervisor_checkpoint.event_count
        or not session_lease.issued_at_utc <= now < session_lease.expires_at_utc
        or session_checkpoint.ledger_id != session_lease.ledger_id
        or session_checkpoint.session_id != session_lease.session_id
        or session_checkpoint.current_lease_sha256 != session_lease.content_sha256
        or session_checkpoint.event_count != session_lease.sequence
        or session_checkpoint.issued_at_utc > now
        or session_store.binding.content_sha256
        != session_dispatch_verification.binding_sha256
        or session_dispatch_verification.lease_sha256
        != session_lease.content_sha256
        or session_dispatch_verification.checkpoint_sha256
        != session_checkpoint.content_sha256
        or session_dispatch_verification.intent_id != decision.intent_id
        or not session_dispatch_verification.verified_at_utc
        <= now
        < session_dispatch_verification.valid_until_utc
    ):
        raise RuntimeSupervisorCriticalError("DEMO_AUTO_SESSION_BINDING_INVALID")


@dataclass(frozen=True)
class RuntimeClosedTradeRiskEvidence(CanonicalContract):
    """Exact signed risk ingestion evidence for one reconciled close."""

    event: ClosedTradeRiskEvent
    source_receipt: RiskSourceReceipt
    upstream_receipt: BrokerClosedTradeReceipt

    def __post_init__(self) -> None:
        if type(self.event) is not ClosedTradeRiskEvent:
            raise TypeError("exact ClosedTradeRiskEvent is required")
        if type(self.source_receipt) is not RiskSourceReceipt:
            raise TypeError("exact sealed RiskSourceReceipt is required")
        if type(self.upstream_receipt) is not BrokerClosedTradeReceipt:
            raise TypeError(
                "closed trade requires an exact BrokerClosedTradeReceipt"
            )
        source = self.source_receipt
        if (
            source.binding != self.event.binding
            or source.source_kind != "CLOSED_TRADE"
            or source.event_sha256 != self.event.content_sha256
            or source.upstream_receipt_type
            != "BROKER_CLOSED_TRADE_RECEIPT"
            or source.upstream_receipt_sha256
            != self.upstream_receipt.content_sha256
            or self.upstream_receipt.intent_id != self.event.entry_id
            or self.upstream_receipt.trade_id != self.event.trade_id
            or self.upstream_receipt.canonical_symbol != self.event.symbol
            or self.upstream_receipt.closed_at_utc != self.event.occurred_at_utc
            or self.upstream_receipt.account_currency
            != self.event.binding.account_currency
            or self.upstream_receipt.realized_net_pnl_account_currency
            != self.event.realized_pnl_account_currency
            or (
                "WIN"
                if self.upstream_receipt.realized_net_pnl_account_currency > 0
                else (
                    "LOSS"
                    if self.upstream_receipt.realized_net_pnl_account_currency < 0
                    else "BREAKEVEN"
                )
            )
            != self.event.outcome
        ):
            raise ValueError("closed-trade risk evidence is not exact")


@dataclass(frozen=True)
class RuntimeAccountSnapshotRiskEvidence(CanonicalContract):
    """Exact broker-account snapshot bound to one verified runtime fact."""

    event: AccountRiskSnapshot
    source_receipt: RiskSourceReceipt
    upstream_receipt: RuntimeFactReceipt

    def __post_init__(self) -> None:
        if type(self.event) is not AccountRiskSnapshot:
            raise TypeError("exact AccountRiskSnapshot is required")
        if type(self.source_receipt) is not RiskSourceReceipt:
            raise TypeError("exact sealed RiskSourceReceipt is required")
        if type(self.upstream_receipt) is not RuntimeFactReceipt:
            raise TypeError("exact sealed RuntimeFactReceipt is required")
        event = self.event
        source = self.source_receipt
        upstream = self.upstream_receipt
        if (
            source.binding != event.binding
            or source.source_kind != "ACCOUNT_SNAPSHOT"
            or source.event_sha256 != event.content_sha256
            or source.upstream_receipt_type != "RUNTIME_FACT_RECEIPT"
            or source.upstream_receipt_sha256 != upstream.content_sha256
            or event.observed_at_utc != upstream.observed_at_utc
            or event.equity != upstream.account_fact.equity
            or event.binding.account_id_sha256
            != manual_demo_account_sha256(upstream.account_id)
            or event.binding.server != upstream.server
            or event.binding.environment != upstream.environment
            or event.binding.journal_sha256 != upstream.journal_sha256
            or event.binding.account_currency != upstream.account_fact.currency
        ):
            raise ValueError("account-snapshot risk evidence is not exact")


@dataclass(frozen=True)
class RuntimeReconciliationRiskResult(CanonicalContract):
    """Sealed reconciliation plus complete closed-trade risk evidence."""

    reconciliation: ReconciliationResult
    closed_trade_evidence: tuple[RuntimeClosedTradeRiskEvidence, ...]
    broker_reconciliation_receipt: BrokerReconciliationReceipt | None = None
    account_snapshot_evidence: RuntimeAccountSnapshotRiskEvidence | None = None
    schema_version: str = "runtime-reconciliation-risk-result-v1"
    _seal: InitVar[object | None] = None

    def __post_init__(self, _seal: object | None) -> None:
        if _seal is not _RECONCILIATION_RESULT_SEAL:
            raise TypeError("reconciliation risk results require the sealing factory")
        if type(self.reconciliation) is not ReconciliationResult:
            raise TypeError("exact ReconciliationResult is required")
        evidence = tuple(self.closed_trade_evidence)
        if any(type(item) is not RuntimeClosedTradeRiskEvidence for item in evidence):
            raise TypeError("closed_trade_evidence contains an invalid item")
        expected = tuple(sorted(self.reconciliation.closed_intents))
        observed = tuple(sorted(item.event.entry_id for item in evidence))
        if observed != expected or len(set(observed)) != len(observed):
            raise ValueError(
                "every reconciled closed intent requires exactly one risk receipt"
            )
        object.__setattr__(self, "closed_trade_evidence", evidence)
        broker_receipt = self.broker_reconciliation_receipt
        if broker_receipt is not None:
            if type(broker_receipt) is not BrokerReconciliationReceipt:
                raise TypeError("broker_reconciliation_receipt is invalid")
            if (
                broker_receipt.reconciliation_result_sha256
                != reconciliation_result_sha256(self.reconciliation)
                or any(
                    item.upstream_receipt.reconciliation_receipt_sha256
                    != broker_receipt.content_sha256
                    for item in evidence
                )
                or any(
                    item.upstream_receipt.source_sequence
                    != broker_receipt.source_sequence
                    for item in evidence
                )
                or len(
                    {
                        ticket
                        for item in evidence
                        for ticket in item.upstream_receipt.deal_tickets
                    }
                )
                != sum(
                    len(item.upstream_receipt.deal_tickets)
                    for item in evidence
                )
            ):
                raise ValueError(
                    "broker reconciliation/deal receipt set is not exact"
                )
        elif evidence:
            raise ValueError(
                "closed-trade evidence requires a broker reconciliation receipt"
            )
        if (
            self.account_snapshot_evidence is not None
            and type(self.account_snapshot_evidence)
            is not RuntimeAccountSnapshotRiskEvidence
        ):
            raise TypeError("account_snapshot_evidence is invalid")
        if self.schema_version != "runtime-reconciliation-risk-result-v1":
            raise ValueError("unsupported reconciliation risk result schema")


def seal_runtime_reconciliation_risk_result(
    reconciliation: ReconciliationResult,
    *,
    closed_trade_evidence: Sequence[RuntimeClosedTradeRiskEvidence] = (),
    broker_reconciliation_receipt: BrokerReconciliationReceipt | None = None,
    account_snapshot_evidence: RuntimeAccountSnapshotRiskEvidence | None = None,
) -> RuntimeReconciliationRiskResult:
    """Seal one clean reconciliation and its exact close-ingestion evidence."""

    return RuntimeReconciliationRiskResult(
        reconciliation=reconciliation,
        closed_trade_evidence=tuple(closed_trade_evidence),
        broker_reconciliation_receipt=broker_reconciliation_receipt,
        account_snapshot_evidence=account_snapshot_evidence,
        _seal=_RECONCILIATION_RESULT_SEAL,
    )


@dataclass(frozen=True)
class RuntimeSupervisorCycleReceipt(CanonicalContract):
    sequence: int
    cycle_id: str
    binding: RuntimeSupervisorBinding
    owner_id: str
    fence_token: int
    phase: str
    status: str
    occurred_at_utc: datetime
    reconciliation_status: str | None
    journal_checkpoint_sha256: str | None
    risk_receipt_hmac_sha256: str | None
    runtime_fact_receipt_sha256s: tuple[str, ...]
    news_guard_sha256: str | None
    news_guard_provider_id: str | None
    news_guard_feed_sequence: int | None
    news_guard_previous_sha256: str | None
    stage_mode: str | None
    stage_authorization_id: str | None
    stage_authorization_sha256: str | None
    stage_validation_sha256: str | None
    stage_external_checkpoint_sha256: str | None
    stage_replay_checkpoint_sha256: str | None
    decision_id: str | None
    decision_payload_sha256: str | None
    execution_service_called: bool
    execution_result_sha256: str | None
    reason_codes: tuple[str, ...]
    previous_receipt_hmac_sha256: str
    receipt_hmac_sha256: str
    schema_version: str = SUPERVISOR_RECEIPT_SCHEMA_VERSION
    _seal: InitVar[object | None] = None

    def __post_init__(self, _seal: object | None) -> None:
        if _seal is not _RECEIPT_SEAL:
            raise TypeError("cycle receipts can only be created by RuntimeSupervisor")
        require_int("sequence", self.sequence, minimum=1)
        object.__setattr__(self, "cycle_id", require_text("cycle_id", self.cycle_id))
        if type(self.binding) is not RuntimeSupervisorBinding:
            raise TypeError("binding must be RuntimeSupervisorBinding")
        object.__setattr__(self, "owner_id", require_text("owner_id", self.owner_id))
        require_int("fence_token", self.fence_token, minimum=1)
        object.__setattr__(self, "phase", require_text("phase", self.phase, upper=True))
        object.__setattr__(self, "status", require_text("status", self.status, upper=True))
        require_utc("occurred_at_utc", self.occurred_at_utc)
        if self.risk_receipt_hmac_sha256 is not None:
            object.__setattr__(
                self,
                "risk_receipt_hmac_sha256",
                require_hash(
                    "risk_receipt_hmac_sha256", self.risk_receipt_hmac_sha256
                ),
            )
        if self.journal_checkpoint_sha256 is not None:
            object.__setattr__(
                self,
                "journal_checkpoint_sha256",
                require_hash(
                    "journal_checkpoint_sha256", self.journal_checkpoint_sha256
                ),
            )
        facts = tuple(
            require_hash("runtime fact receipt hash", item)
            for item in self.runtime_fact_receipt_sha256s
        )
        if len(set(facts)) != len(facts):
            raise ValueError("runtime fact receipt hashes must be unique")
        object.__setattr__(self, "runtime_fact_receipt_sha256s", facts)
        if self.news_guard_sha256 is not None:
            object.__setattr__(
                self,
                "news_guard_sha256",
                require_hash("news_guard_sha256", self.news_guard_sha256),
            )
        if self.news_guard_provider_id is not None:
            object.__setattr__(
                self,
                "news_guard_provider_id",
                require_text("news_guard_provider_id", self.news_guard_provider_id),
            )
        if self.news_guard_feed_sequence is not None:
            require_int("news_guard_feed_sequence", self.news_guard_feed_sequence, minimum=1)
        if bool(self.news_guard_provider_id) != bool(self.news_guard_feed_sequence):
            raise ValueError("news guard provider and sequence must appear together")
        if self.news_guard_previous_sha256 is not None:
            object.__setattr__(
                self,
                "news_guard_previous_sha256",
                require_hash("news_guard_previous_sha256", self.news_guard_previous_sha256),
            )
        if bool(self.news_guard_provider_id) != bool(self.news_guard_previous_sha256):
            raise ValueError("news guard chain predecessor must appear with provider")
        stage_values = (
            self.stage_mode,
            self.stage_authorization_id,
            self.stage_authorization_sha256,
            self.stage_validation_sha256,
            self.stage_external_checkpoint_sha256,
            self.stage_replay_checkpoint_sha256,
        )
        if any(value is not None for value in stage_values):
            if not all(value is not None for value in stage_values):
                raise ValueError("stage startup receipt fields must be complete")
            mode = require_text("stage_mode", self.stage_mode, upper=True)
            if mode not in {"MANUAL_DEMO", "DEMO_AUTO"}:
                raise ValueError("unsupported stage receipt mode")
            object.__setattr__(self, "stage_mode", mode)
            object.__setattr__(
                self,
                "stage_authorization_id",
                require_text("stage_authorization_id", self.stage_authorization_id),
            )
            for name in (
                "stage_authorization_sha256",
                "stage_validation_sha256",
                "stage_external_checkpoint_sha256",
                "stage_replay_checkpoint_sha256",
            ):
                object.__setattr__(self, name, require_hash(name, getattr(self, name)))
            if self.phase != "STARTUP":
                raise ValueError("stage authorization evidence is restricted to STARTUP")
        if self.phase == "STARTUP" and self.binding.mode in {"DEMO", "DEMO_AUTO"}:
            if not all(value is not None for value in stage_values):
                raise ValueError("DEMO startup receipt requires complete stage evidence")
        if (
            self.phase in {"STARTUP", "CYCLE"}
            and self.binding.mode != "SHADOW"
            and self.news_guard_provider_id is None
        ):
            raise ValueError("execution-mode receipts require signed news guard facts")
        if self.decision_payload_sha256 is not None:
            object.__setattr__(
                self,
                "decision_payload_sha256",
                require_hash(
                    "decision_payload_sha256", self.decision_payload_sha256
                ),
            )
        if bool(self.decision_id) != bool(self.decision_payload_sha256):
            raise ValueError("decision ID and payload hash must appear together")
        _bool("execution_service_called", self.execution_service_called)
        if self.execution_result_sha256 is not None:
            object.__setattr__(
                self,
                "execution_result_sha256",
                require_hash("execution_result_sha256", self.execution_result_sha256),
            )
        if bool(self.execution_result_sha256) != self.execution_service_called:
            raise ValueError("execution result hash must match service invocation")
        reasons = tuple(sorted({require_text("reason code", item, upper=True) for item in self.reason_codes}))
        object.__setattr__(self, "reason_codes", reasons)
        for name in ("previous_receipt_hmac_sha256", "receipt_hmac_sha256"):
            object.__setattr__(self, name, require_hash(name, getattr(self, name)))
        if self.schema_version != SUPERVISOR_RECEIPT_SCHEMA_VERSION:
            raise ValueError("unsupported supervisor receipt schema")


@dataclass(frozen=True)
class RuntimeSupervisorNewsHead(CanonicalContract):
    provider_id: str
    feed_sequence: int
    receipt_sha256: str

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "provider_id", require_text("provider_id", self.provider_id)
        )
        require_int("feed_sequence", self.feed_sequence, minimum=1)
        object.__setattr__(
            self,
            "receipt_sha256",
            require_hash("receipt_sha256", self.receipt_sha256),
        )


@dataclass(frozen=True)
class RuntimeSupervisorCheckpoint(CanonicalContract):
    """Signed checkpoint that must be custodied outside the supervisor DB."""

    binding_sha256: str
    store_incarnation_sha256: str
    event_count: int
    event_head_hmac_sha256: str
    critical_latched: bool
    critical_reason: str | None
    critical_latched_at_utc: datetime | None
    critical_state_hmac_sha256: str
    news_heads: tuple[RuntimeSupervisorNewsHead, ...]
    predecessor_checkpoint_sha256: str
    issued_at_utc: datetime
    key_id: str
    signature_hmac_sha256: str = ""
    schema_version: str = SUPERVISOR_CHECKPOINT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        for name in (
            "binding_sha256",
            "store_incarnation_sha256",
            "event_head_hmac_sha256",
            "critical_state_hmac_sha256",
            "predecessor_checkpoint_sha256",
        ):
            object.__setattr__(self, name, require_hash(name, getattr(self, name)))
        require_int("event_count", self.event_count, minimum=0)
        _bool("critical_latched", self.critical_latched)
        if self.critical_latched:
            object.__setattr__(
                self,
                "critical_reason",
                require_text("critical_reason", self.critical_reason, upper=True),
            )
            require_utc("critical_latched_at_utc", self.critical_latched_at_utc)
        elif self.critical_reason is not None or self.critical_latched_at_utc is not None:
            raise ValueError("unlatched checkpoint cannot contain critical details")
        heads = tuple(self.news_heads)
        if any(type(item) is not RuntimeSupervisorNewsHead for item in heads):
            raise TypeError("news_heads must contain exact RuntimeSupervisorNewsHead")
        if tuple(item.provider_id for item in heads) != tuple(
            sorted(item.provider_id for item in heads)
        ) or len({item.provider_id for item in heads}) != len(heads):
            raise ValueError("news heads must be unique and sorted")
        object.__setattr__(self, "news_heads", heads)
        require_utc("issued_at_utc", self.issued_at_utc)
        object.__setattr__(self, "key_id", require_text("key_id", self.key_id))
        if self.signature_hmac_sha256:
            object.__setattr__(
                self,
                "signature_hmac_sha256",
                require_hash(
                    "signature_hmac_sha256", self.signature_hmac_sha256
                ),
            )
        if self.schema_version != SUPERVISOR_CHECKPOINT_SCHEMA_VERSION:
            raise ValueError("unsupported runtime supervisor checkpoint schema")

    @property
    def signing_payload(self) -> dict[str, Any]:
        payload = self.to_canonical_dict()
        payload.pop("signature_hmac_sha256")
        return payload

    def sign(self, secret: str | bytes) -> "RuntimeSupervisorCheckpoint":
        signature = hmac.new(
            _secret(secret),
            _CHECKPOINT_DOMAIN + canonical_json(self.signing_payload).encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        return replace(self, signature_hmac_sha256=signature)


@dataclass(frozen=True)
class RuntimeSupervisorCheckpointCASAcknowledgement(CanonicalContract):
    """Exact compare-and-swap acknowledgement from off-host custody."""

    expected_current_checkpoint_sha256: str
    written_checkpoint_sha256: str
    schema_version: str = SUPERVISOR_CHECKPOINT_CAS_ACK_SCHEMA_VERSION

    def __post_init__(self) -> None:
        for name in (
            "expected_current_checkpoint_sha256",
            "written_checkpoint_sha256",
        ):
            object.__setattr__(self, name, require_hash(name, getattr(self, name)))
        if self.schema_version != SUPERVISOR_CHECKPOINT_CAS_ACK_SCHEMA_VERSION:
            raise ValueError("unsupported supervisor checkpoint CAS acknowledgement")


def verify_runtime_supervisor_checkpoint_signature(
    checkpoint: RuntimeSupervisorCheckpoint,
    *,
    expected_key_id: str,
    key_provider: Callable[[str], str | bytes],
) -> RuntimeSupervisorCheckpoint:
    if type(checkpoint) is not RuntimeSupervisorCheckpoint:
        raise RuntimeSupervisorIntegrityError("external supervisor checkpoint type invalid")
    if checkpoint.key_id != require_text("expected_key_id", expected_key_id):
        raise RuntimeSupervisorIntegrityError("external supervisor checkpoint key mismatch")
    try:
        key = _secret(key_provider(checkpoint.key_id))
    except Exception as exc:
        raise RuntimeSupervisorIntegrityError(
            "external supervisor checkpoint key unavailable"
        ) from exc
    expected = hmac.new(
        key,
        _CHECKPOINT_DOMAIN + canonical_json(checkpoint.signing_payload).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    if not checkpoint.signature_hmac_sha256 or not hmac.compare_digest(
        checkpoint.signature_hmac_sha256, expected
    ):
        raise RuntimeSupervisorIntegrityError(
            "external supervisor checkpoint signature invalid"
        )
    return checkpoint


@dataclass(frozen=True)
class RuntimeSupervisorStatus(CanonicalContract):
    state: str
    owner_id: str | None
    fence_token: int | None
    receipts: int
    stopped: bool
    stop_reason: str | None
    order_capability: str = ORDER_CAPABILITY
    execution_enabled: bool = False
    manual_demo_enabled: bool = False
    live_allowed: bool = LIVE_ALLOWED
    safe_to_demo_auto_order: bool = SAFE_TO_DEMO_AUTO_ORDER

    def __post_init__(self) -> None:
        object.__setattr__(self, "state", require_text("state", self.state, upper=True))
        require_int("receipts", self.receipts, minimum=0)
        for name in (
            "stopped",
            "execution_enabled",
            "manual_demo_enabled",
            "live_allowed",
            "safe_to_demo_auto_order",
        ):
            _bool(name, getattr(self, name))
        if (
            self.order_capability != ORDER_CAPABILITY
            or self.execution_enabled
            or self.manual_demo_enabled
            or self.live_allowed
            or self.safe_to_demo_auto_order
        ):
            raise ValueError("supervisor status cannot grant execution")


class _SupervisorStore:
    def __init__(
        self,
        path: str | Path,
        *,
        binding: RuntimeSupervisorBinding,
        key_id: str,
        key_provider: Callable[[str], str | bytes],
    ) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.binding = binding
        self.key_id = require_text("key_id", key_id)
        if not callable(key_provider):
            raise TypeError("key_provider must be callable")
        self.key_provider = key_provider
        self.store_incarnation_sha256 = hashlib.sha256(uuid.uuid4().bytes).hexdigest()
        self._initialize()
        self.verify_integrity()

    def _key(self) -> bytes:
        try:
            return _secret(self.key_provider(self.key_id))
        except RuntimeSupervisorIntegrityError:
            raise
        except Exception as exc:
            raise RuntimeSupervisorIntegrityError(
                "supervisor HMAC key provider failed"
            ) from exc

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute("PRAGMA busy_timeout=10000")
        return connection

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            yield connection
            connection.execute("COMMIT")
        except Exception:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass
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

    def _identity_payload(self) -> dict[str, Any]:
        return {
            "binding": self.binding.to_canonical_dict(),
            "key_id": self.key_id,
            "schema_version": SUPERVISOR_SCHEMA_VERSION,
            "store_incarnation_sha256": self.store_incarnation_sha256,
        }

    def _critical_payload(
        self,
        *,
        latched: bool,
        reason: str | None,
        latched_at_utc: str | None,
    ) -> dict[str, Any]:
        return {
            "critical_latched": latched,
            "critical_reason": reason,
            "critical_latched_at_utc": latched_at_utc,
            "store_incarnation_sha256": self.store_incarnation_sha256,
        }

    def _initialize(self) -> None:
        binding_json = canonical_json(self.binding)
        # ``executescript`` owns its transaction boundary under sqlite3, so schema
        # creation is kept separate from the identity compare-and-insert below.
        connection = self._connect()
        try:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS supervisor_identity(
                    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                    binding_json TEXT NOT NULL,
                    key_id TEXT NOT NULL,
                    store_incarnation_sha256 TEXT NOT NULL,
                    identity_hmac_sha256 TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS supervisor_lease(
                    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                    owner_id TEXT NOT NULL,
                    fence_token INTEGER NOT NULL CHECK(fence_token > 0),
                    expires_at_utc TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS supervisor_cycle_receipts(
                    sequence INTEGER PRIMARY KEY,
                    cycle_id TEXT NOT NULL UNIQUE,
                    payload_json TEXT NOT NULL,
                    previous_receipt_hmac_sha256 TEXT NOT NULL,
                    receipt_hmac_sha256 TEXT NOT NULL UNIQUE
                );
                CREATE TABLE IF NOT EXISTS supervisor_critical_state(
                    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                    critical_latched INTEGER NOT NULL CHECK(critical_latched IN (0,1)),
                    critical_reason TEXT,
                    critical_latched_at_utc TEXT,
                    state_hmac_sha256 TEXT NOT NULL,
                    CHECK(
                        (critical_latched=0 AND critical_reason IS NULL AND critical_latched_at_utc IS NULL)
                        OR
                        (critical_latched=1 AND critical_reason IS NOT NULL AND critical_latched_at_utc IS NOT NULL)
                    )
                );
                CREATE TRIGGER IF NOT EXISTS supervisor_identity_no_update
                BEFORE UPDATE ON supervisor_identity BEGIN
                    SELECT RAISE(ABORT, 'supervisor_identity_immutable');
                END;
                CREATE TRIGGER IF NOT EXISTS supervisor_identity_no_delete
                BEFORE DELETE ON supervisor_identity BEGIN
                    SELECT RAISE(ABORT, 'supervisor_identity_immutable');
                END;
                CREATE TRIGGER IF NOT EXISTS supervisor_receipts_no_update
                BEFORE UPDATE ON supervisor_cycle_receipts BEGIN
                    SELECT RAISE(ABORT, 'supervisor_receipts_append_only');
                END;
                CREATE TRIGGER IF NOT EXISTS supervisor_receipts_no_delete
                BEFORE DELETE ON supervisor_cycle_receipts BEGIN
                    SELECT RAISE(ABORT, 'supervisor_receipts_append_only');
                END;
                CREATE TRIGGER IF NOT EXISTS supervisor_critical_no_delete
                BEFORE DELETE ON supervisor_critical_state BEGIN
                    SELECT RAISE(ABORT, 'supervisor_critical_state_immutable');
                END;
                CREATE TRIGGER IF NOT EXISTS supervisor_critical_no_reset
                BEFORE UPDATE ON supervisor_critical_state
                WHEN OLD.critical_latched=1 OR NEW.critical_latched!=1 BEGIN
                    SELECT RAISE(ABORT, 'supervisor_critical_latch_irreversible');
                END;
                """
            )
        finally:
            connection.close()
        with self._transaction() as connection:
            row = connection.execute(
                "SELECT * FROM supervisor_identity WHERE singleton=1"
            ).fetchone()
            if row is None:
                identity_hmac = _hmac(
                    self._key(), _IDENTITY_DOMAIN, self._identity_payload()
                )
                connection.execute(
                    "INSERT INTO supervisor_identity VALUES(1, ?, ?, ?, ?)",
                    (
                        binding_json,
                        self.key_id,
                        self.store_incarnation_sha256,
                        identity_hmac,
                    ),
                )
            else:
                self.store_incarnation_sha256 = require_hash(
                    "store_incarnation_sha256",
                    row["store_incarnation_sha256"],
                )
                identity_hmac = _hmac(
                    self._key(), _IDENTITY_DOMAIN, self._identity_payload()
                )
                if (
                    row["binding_json"] != binding_json
                    or row["key_id"] != self.key_id
                    or not hmac.compare_digest(
                        row["identity_hmac_sha256"], identity_hmac
                    )
                ):
                    raise RuntimeSupervisorBindingError(
                        "supervisor database binding or identity mismatch"
                    )
            critical = connection.execute(
                "SELECT * FROM supervisor_critical_state WHERE singleton=1"
            ).fetchone()
            if critical is None:
                critical_hmac = _hmac(
                    self._key(),
                    _CRITICAL_STATE_DOMAIN,
                    self._critical_payload(
                        latched=False, reason=None, latched_at_utc=None
                    ),
                )
                connection.execute(
                    "INSERT INTO supervisor_critical_state VALUES(1, 0, NULL, NULL, ?)",
                    (critical_hmac,),
                )
            connection.execute(f"PRAGMA user_version={SUPERVISOR_SCHEMA_VERSION}")

    def storage_settings(self) -> dict[str, object]:
        with self._reader() as connection:
            return {
                "journal_mode": str(
                    connection.execute("PRAGMA journal_mode").fetchone()[0]
                ).upper(),
                "synchronous": (
                    "FULL"
                    if int(connection.execute("PRAGMA synchronous").fetchone()[0]) == 2
                    else "INVALID"
                ),
            }

    def verify_integrity(self) -> bool:
        secret = self._key()
        with self._reader() as connection:
            if int(connection.execute("PRAGMA user_version").fetchone()[0]) != SUPERVISOR_SCHEMA_VERSION:
                raise RuntimeSupervisorIntegrityError(
                    "supervisor schema version mismatch"
                )
            required_triggers = {
                "supervisor_identity_no_update",
                "supervisor_identity_no_delete",
                "supervisor_receipts_no_update",
                "supervisor_receipts_no_delete",
                "supervisor_critical_no_delete",
                "supervisor_critical_no_reset",
            }
            observed_triggers = {
                str(row[0])
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='trigger'"
                ).fetchall()
            }
            if not required_triggers.issubset(observed_triggers):
                raise RuntimeSupervisorIntegrityError(
                    "supervisor append-only trigger is missing"
                )
            checks = connection.execute("PRAGMA integrity_check").fetchall()
            if not checks or any(str(row[0]).lower() != "ok" for row in checks):
                raise RuntimeSupervisorIntegrityError(
                    "supervisor SQLite integrity check failed"
                )
            identity = connection.execute(
                "SELECT * FROM supervisor_identity WHERE singleton=1"
            ).fetchone()
            if identity is None:
                raise RuntimeSupervisorIntegrityError("supervisor identity is missing")
            expected_identity = _hmac(
                secret, _IDENTITY_DOMAIN, self._identity_payload()
            )
            if (
                identity["binding_json"] != canonical_json(self.binding)
                or identity["key_id"] != self.key_id
                or identity["store_incarnation_sha256"]
                != self.store_incarnation_sha256
                or not hmac.compare_digest(
                    identity["identity_hmac_sha256"], expected_identity
                )
            ):
                raise RuntimeSupervisorIntegrityError(
                    "supervisor identity authentication failed"
                )
            critical = connection.execute(
                "SELECT * FROM supervisor_critical_state WHERE singleton=1"
            ).fetchone()
            if critical is None:
                raise RuntimeSupervisorIntegrityError(
                    "supervisor critical state is missing"
                )
            critical_latched = int(critical["critical_latched"]) == 1
            critical_payload = self._critical_payload(
                latched=critical_latched,
                reason=critical["critical_reason"],
                latched_at_utc=critical["critical_latched_at_utc"],
            )
            expected_critical_hmac = _hmac(
                secret, _CRITICAL_STATE_DOMAIN, critical_payload
            )
            if not hmac.compare_digest(
                critical["state_hmac_sha256"], expected_critical_hmac
            ):
                raise RuntimeSupervisorIntegrityError(
                    "supervisor critical state authentication failed"
                )
            if critical_latched:
                require_text(
                    "critical_reason", critical["critical_reason"], upper=True
                )
                _parse_utc(critical["critical_latched_at_utc"])
            previous = ZERO_HMAC_SHA256
            seen_stage_ids: set[str] = set()
            seen_stage_hashes: set[str] = set()
            news_heads: dict[str, tuple[int, str]] = {}
            rows = connection.execute(
                "SELECT * FROM supervisor_cycle_receipts ORDER BY sequence"
            ).fetchall()
            for expected_sequence, row in enumerate(rows, start=1):
                if int(row["sequence"]) != expected_sequence:
                    raise RuntimeSupervisorIntegrityError(
                        "supervisor receipt sequence is not contiguous"
                    )
                try:
                    payload = json.loads(row["payload_json"])
                except (TypeError, json.JSONDecodeError) as exc:
                    raise RuntimeSupervisorIntegrityError(
                        "supervisor receipt payload is invalid"
                    ) from exc
                if canonical_json(payload) != row["payload_json"]:
                    raise RuntimeSupervisorIntegrityError(
                        "supervisor receipt payload is not canonical"
                    )
                if row["previous_receipt_hmac_sha256"] != previous:
                    raise RuntimeSupervisorIntegrityError(
                        "supervisor receipt chain predecessor mismatch"
                    )
                signed = {
                    "sequence": expected_sequence,
                    "payload": payload,
                    "previous_receipt_hmac_sha256": previous,
                }
                expected_hmac = _hmac(secret, _RECEIPT_DOMAIN, signed)
                if not hmac.compare_digest(
                    row["receipt_hmac_sha256"], expected_hmac
                ):
                    raise RuntimeSupervisorIntegrityError(
                        "supervisor receipt authentication failed"
                    )
                provider_id = payload.get("news_guard_provider_id")
                feed_sequence = payload.get("news_guard_feed_sequence")
                guard_hash = payload.get("news_guard_sha256")
                guard_previous = payload.get("news_guard_previous_sha256")
                if provider_id is not None:
                    if (
                        not isinstance(provider_id, str)
                        or not isinstance(feed_sequence, int)
                        or not isinstance(guard_hash, str)
                        or not isinstance(guard_previous, str)
                    ):
                        raise RuntimeSupervisorIntegrityError(
                            "stored news guard chain facts are invalid"
                        )
                    prior = news_heads.get(provider_id)
                    expected_previous = ZERO_HMAC_SHA256 if prior is None else prior[1]
                    if (
                        guard_previous != expected_previous
                        or (prior is not None and feed_sequence <= prior[0])
                    ):
                        raise RuntimeSupervisorIntegrityError(
                            "stored news guard replay, rollback, fork, or predecessor mismatch"
                        )
                    news_heads[provider_id] = (feed_sequence, guard_hash)
                stage_id = payload.get("stage_authorization_id")
                stage_hash = payload.get("stage_authorization_sha256")
                if stage_id is not None:
                    if (
                        not isinstance(stage_id, str)
                        or not isinstance(stage_hash, str)
                        or stage_id in seen_stage_ids
                        or stage_hash in seen_stage_hashes
                    ):
                        raise RuntimeSupervisorIntegrityError(
                            "stored stage authorization was replayed"
                        )
                    seen_stage_ids.add(stage_id)
                    seen_stage_hashes.add(stage_hash)
                previous = expected_hmac
        return True

    def critical_state(self) -> dict[str, object]:
        self.verify_integrity()
        with self._reader() as connection:
            row = connection.execute(
                "SELECT * FROM supervisor_critical_state WHERE singleton=1"
            ).fetchone()
        if row is None:
            raise RuntimeSupervisorIntegrityError("supervisor critical state is missing")
        return {
            "critical_latched": int(row["critical_latched"]) == 1,
            "critical_reason": row["critical_reason"],
            "critical_latched_at_utc": row["critical_latched_at_utc"],
            "critical_state_hmac_sha256": row["state_hmac_sha256"],
        }

    def latch_critical(self, reason: str, *, occurred_at: datetime) -> dict[str, object]:
        """Persist the irreversible local latch before any journal operation."""

        normalized_reason = require_text("critical reason", reason, upper=True)
        occurred = _iso(require_utc("critical occurred_at", occurred_at))
        secret = self._key()
        with self._transaction() as connection:
            row = connection.execute(
                "SELECT * FROM supervisor_critical_state WHERE singleton=1"
            ).fetchone()
            if row is None:
                raise RuntimeSupervisorIntegrityError(
                    "supervisor critical state is missing"
                )
            current_latched = int(row["critical_latched"]) == 1
            current_payload = self._critical_payload(
                latched=current_latched,
                reason=row["critical_reason"],
                latched_at_utc=row["critical_latched_at_utc"],
            )
            current_hmac = _hmac(secret, _CRITICAL_STATE_DOMAIN, current_payload)
            if not hmac.compare_digest(row["state_hmac_sha256"], current_hmac):
                raise RuntimeSupervisorIntegrityError(
                    "supervisor critical state authentication failed"
                )
            if not current_latched:
                payload = self._critical_payload(
                    latched=True,
                    reason=normalized_reason,
                    latched_at_utc=occurred,
                )
                state_hmac = _hmac(secret, _CRITICAL_STATE_DOMAIN, payload)
                connection.execute(
                    """
                    UPDATE supervisor_critical_state
                    SET critical_latched=1,
                        critical_reason=?,
                        critical_latched_at_utc=?,
                        state_hmac_sha256=?
                    WHERE singleton=1
                    """,
                    (normalized_reason, occurred, state_hmac),
                )
                return {
                    "critical_latched": True,
                    "critical_reason": normalized_reason,
                    "critical_latched_at_utc": occurred,
                    "critical_state_hmac_sha256": state_hmac,
                }
            return {
                "critical_latched": True,
                "critical_reason": row["critical_reason"],
                "critical_latched_at_utc": row["critical_latched_at_utc"],
                "critical_state_hmac_sha256": row["state_hmac_sha256"],
            }

    def create_checkpoint(
        self,
        *,
        key_id: str,
        key_provider: Callable[[str], str | bytes],
        issued_at_utc: datetime,
        predecessor_checkpoint_sha256: str = ZERO_HMAC_SHA256,
    ) -> RuntimeSupervisorCheckpoint:
        self.verify_integrity()
        with self._reader() as connection:
            head = connection.execute(
                """
                SELECT sequence, receipt_hmac_sha256
                FROM supervisor_cycle_receipts ORDER BY sequence DESC LIMIT 1
                """
            ).fetchone()
            critical = connection.execute(
                "SELECT * FROM supervisor_critical_state WHERE singleton=1"
            ).fetchone()
            rows = connection.execute(
                "SELECT payload_json FROM supervisor_cycle_receipts ORDER BY sequence"
            ).fetchall()
        if critical is None:
            raise RuntimeSupervisorIntegrityError("supervisor critical state is missing")
        news: dict[str, RuntimeSupervisorNewsHead] = {}
        for row in rows:
            payload = json.loads(row["payload_json"])
            provider_id = payload.get("news_guard_provider_id")
            if provider_id is not None:
                news[str(provider_id)] = RuntimeSupervisorNewsHead(
                    provider_id=str(provider_id),
                    feed_sequence=int(payload["news_guard_feed_sequence"]),
                    receipt_sha256=require_hash(
                        "news_guard_sha256", payload["news_guard_sha256"]
                    ),
                )
        latched_at = (
            None
            if critical["critical_latched_at_utc"] is None
            else _parse_utc(critical["critical_latched_at_utc"])
        )
        checkpoint = RuntimeSupervisorCheckpoint(
            binding_sha256=self.binding.content_sha256,
            store_incarnation_sha256=self.store_incarnation_sha256,
            event_count=0 if head is None else int(head["sequence"]),
            event_head_hmac_sha256=(
                ZERO_HMAC_SHA256 if head is None else head["receipt_hmac_sha256"]
            ),
            critical_latched=int(critical["critical_latched"]) == 1,
            critical_reason=critical["critical_reason"],
            critical_latched_at_utc=latched_at,
            critical_state_hmac_sha256=critical["state_hmac_sha256"],
            news_heads=tuple(news[key] for key in sorted(news)),
            predecessor_checkpoint_sha256=require_hash(
                "predecessor_checkpoint_sha256",
                predecessor_checkpoint_sha256,
            ),
            issued_at_utc=require_utc("checkpoint issued_at_utc", issued_at_utc),
            key_id=require_text("checkpoint key_id", key_id),
        )
        try:
            key = key_provider(checkpoint.key_id)
        except Exception as exc:
            raise RuntimeSupervisorIntegrityError(
                "supervisor checkpoint signing key unavailable"
            ) from exc
        return checkpoint.sign(key)

    def verify_external_checkpoint(
        self,
        checkpoint: RuntimeSupervisorCheckpoint,
        *,
        expected_key_id: str,
        key_provider: Callable[[str], str | bytes],
    ) -> RuntimeSupervisorCheckpoint:
        checked = verify_runtime_supervisor_checkpoint_signature(
            checkpoint,
            expected_key_id=expected_key_id,
            key_provider=key_provider,
        )
        local = self.create_checkpoint(
            key_id=expected_key_id,
            key_provider=key_provider,
            issued_at_utc=checked.issued_at_utc,
            predecessor_checkpoint_sha256=(
                checked.predecessor_checkpoint_sha256
            ),
        )
        comparable_fields = (
            "binding_sha256",
            "store_incarnation_sha256",
            "event_count",
            "event_head_hmac_sha256",
            "critical_latched",
            "critical_reason",
            "critical_latched_at_utc",
            "critical_state_hmac_sha256",
            "news_heads",
            "predecessor_checkpoint_sha256",
        )
        if any(getattr(checked, name) != getattr(local, name) for name in comparable_fields):
            raise RuntimeSupervisorIntegrityError(
                "external supervisor checkpoint does not match local store head"
            )
        return checked

    def latest_news_guard(self, provider_id: str) -> tuple[int, str] | None:
        provider = require_text("provider_id", provider_id)
        self.verify_integrity()
        with self._reader() as connection:
            rows = connection.execute(
                "SELECT payload_json FROM supervisor_cycle_receipts ORDER BY sequence DESC"
            ).fetchall()
        for row in rows:
            payload = json.loads(row["payload_json"])
            if payload.get("news_guard_provider_id") == provider:
                return (
                    int(payload["news_guard_feed_sequence"]),
                    require_hash("news_guard_sha256", payload["news_guard_sha256"]),
                )
        return None

    def stage_authorization_seen(self, authorization_id: str, authorization_sha256: str) -> bool:
        auth_id = require_text("authorization_id", authorization_id)
        auth_hash = require_hash("authorization_sha256", authorization_sha256)
        self.verify_integrity()
        with self._reader() as connection:
            rows = connection.execute(
                "SELECT payload_json FROM supervisor_cycle_receipts"
            ).fetchall()
        for row in rows:
            payload = json.loads(row["payload_json"])
            if (
                payload.get("stage_authorization_id") == auth_id
                or payload.get("stage_authorization_sha256") == auth_hash
            ):
                return True
        return False

    def claim(self, owner_id: str, *, lease_seconds: int, now: datetime) -> int:
        owner = require_text("owner_id", owner_id)
        require_int("lease_seconds", lease_seconds, minimum=1, maximum=300)
        checked_at = require_utc("now", now)
        self.verify_integrity()
        with self._transaction() as connection:
            row = connection.execute(
                "SELECT * FROM supervisor_lease WHERE singleton=1"
            ).fetchone()
            prior_token = 0
            if row is not None:
                prior_token = int(row["fence_token"])
                if _parse_utc(row["expires_at_utc"]) > checked_at:
                    raise RuntimeSupervisorLeaseError(
                        "supervisor singleton lease is already held"
                    )
            token = prior_token + 1
            connection.execute(
                """
                INSERT INTO supervisor_lease(singleton, owner_id, fence_token, expires_at_utc)
                VALUES(1, ?, ?, ?)
                ON CONFLICT(singleton) DO UPDATE SET
                    owner_id=excluded.owner_id,
                    fence_token=excluded.fence_token,
                    expires_at_utc=excluded.expires_at_utc
                """,
                (owner, token, _iso(checked_at + timedelta(seconds=lease_seconds))),
            )
        return token

    def refresh(
        self,
        owner_id: str,
        fence_token: int,
        *,
        lease_seconds: int,
        now: datetime,
    ) -> None:
        checked_at = require_utc("now", now)
        with self._transaction() as connection:
            row = connection.execute(
                "SELECT * FROM supervisor_lease WHERE singleton=1"
            ).fetchone()
            if (
                row is None
                or row["owner_id"] != owner_id
                or int(row["fence_token"]) != fence_token
                or _parse_utc(row["expires_at_utc"]) <= checked_at
            ):
                raise RuntimeSupervisorLeaseError("supervisor lease was lost")
            connection.execute(
                "UPDATE supervisor_lease SET expires_at_utc=? WHERE singleton=1",
                (_iso(checked_at + timedelta(seconds=lease_seconds)),),
            )

    def release(self, owner_id: str, fence_token: int) -> None:
        with self._transaction() as connection:
            row = connection.execute(
                "SELECT owner_id, fence_token FROM supervisor_lease WHERE singleton=1"
            ).fetchone()
            if row is None:
                return
            if row["owner_id"] != owner_id or int(row["fence_token"]) != fence_token:
                raise RuntimeSupervisorLeaseError("cannot release another owner lease")
            # Retain the last fence token so a graceful restart cannot reuse it.
            connection.execute(
                """
                UPDATE supervisor_lease
                SET expires_at_utc='1970-01-01T00:00:00.000000Z'
                WHERE singleton=1
                """
            )

    def append(
        self,
        *,
        owner_id: str,
        fence_token: int,
        cycle_id: str,
        phase: str,
        status: str,
        occurred_at: datetime,
        reconciliation_status: str | None = None,
        journal_checkpoint_sha256: str | None = None,
        risk_receipt_hmac_sha256: str | None = None,
        runtime_fact_receipt_sha256s: Sequence[str] = (),
        news_guard_sha256: str | None = None,
        news_guard_provider_id: str | None = None,
        news_guard_feed_sequence: int | None = None,
        news_guard_previous_sha256: str | None = None,
        stage_mode: str | None = None,
        stage_authorization_id: str | None = None,
        stage_authorization_sha256: str | None = None,
        stage_validation_sha256: str | None = None,
        stage_external_checkpoint_sha256: str | None = None,
        stage_replay_checkpoint_sha256: str | None = None,
        decision_id: str | None = None,
        decision_payload_sha256: str | None = None,
        execution_service_called: bool = False,
        execution_result_sha256: str | None = None,
        reason_codes: Sequence[str] = (),
    ) -> RuntimeSupervisorCycleReceipt:
        self.verify_integrity()
        secret = self._key()
        with self._transaction() as connection:
            lease = connection.execute(
                "SELECT * FROM supervisor_lease WHERE singleton=1"
            ).fetchone()
            if (
                lease is None
                or lease["owner_id"] != owner_id
                or int(lease["fence_token"]) != fence_token
                or _parse_utc(lease["expires_at_utc"]) <= occurred_at
            ):
                raise RuntimeSupervisorLeaseError(
                    "cannot append receipt without the active lease"
                )
            head = connection.execute(
                """
                SELECT sequence, receipt_hmac_sha256
                FROM supervisor_cycle_receipts ORDER BY sequence DESC LIMIT 1
                """
            ).fetchone()
            sequence = 1 if head is None else int(head["sequence"]) + 1
            previous = ZERO_HMAC_SHA256 if head is None else head["receipt_hmac_sha256"]
            payload = {
                "binding": self.binding.to_canonical_dict(),
                "cycle_id": require_text("cycle_id", cycle_id),
                "decision_id": decision_id,
                "decision_payload_sha256": decision_payload_sha256,
                "execution_result_sha256": execution_result_sha256,
                "execution_service_called": _bool(
                    "execution_service_called", execution_service_called
                ),
                "fence_token": fence_token,
                "journal_checkpoint_sha256": journal_checkpoint_sha256,
                "news_guard_sha256": news_guard_sha256,
                "news_guard_provider_id": news_guard_provider_id,
                "news_guard_feed_sequence": news_guard_feed_sequence,
                "news_guard_previous_sha256": news_guard_previous_sha256,
                "occurred_at_utc": _iso(occurred_at),
                "owner_id": require_text("owner_id", owner_id),
                "phase": require_text("phase", phase, upper=True),
                "reason_codes": sorted(
                    {require_text("reason code", item, upper=True) for item in reason_codes}
                ),
                "reconciliation_status": reconciliation_status,
                "risk_receipt_hmac_sha256": risk_receipt_hmac_sha256,
                "runtime_fact_receipt_sha256s": list(runtime_fact_receipt_sha256s),
                "schema_version": SUPERVISOR_RECEIPT_SCHEMA_VERSION,
                "status": require_text("status", status, upper=True),
                "stage_mode": stage_mode,
                "stage_authorization_id": stage_authorization_id,
                "stage_authorization_sha256": stage_authorization_sha256,
                "stage_validation_sha256": stage_validation_sha256,
                "stage_external_checkpoint_sha256": stage_external_checkpoint_sha256,
                "stage_replay_checkpoint_sha256": stage_replay_checkpoint_sha256,
            }
            signed = {
                "sequence": sequence,
                "payload": payload,
                "previous_receipt_hmac_sha256": previous,
            }
            receipt_hmac = _hmac(secret, _RECEIPT_DOMAIN, signed)
            if news_guard_provider_id is not None:
                prior_rows = connection.execute(
                    "SELECT payload_json FROM supervisor_cycle_receipts ORDER BY sequence DESC"
                ).fetchall()
                prior_guard: tuple[int, str] | None = None
                for prior_row in prior_rows:
                    prior_payload = json.loads(prior_row["payload_json"])
                    if prior_payload.get("news_guard_provider_id") == news_guard_provider_id:
                        prior_guard = (
                            int(prior_payload["news_guard_feed_sequence"]),
                            str(prior_payload["news_guard_sha256"]),
                        )
                        break
                expected_previous = ZERO_HMAC_SHA256 if prior_guard is None else prior_guard[1]
                if (
                    news_guard_previous_sha256 != expected_previous
                    or news_guard_feed_sequence is None
                    or (prior_guard is not None and news_guard_feed_sequence <= prior_guard[0])
                ):
                    raise RuntimeSupervisorIntegrityError(
                        "news guard replay, rollback, fork, or predecessor mismatch"
                    )
            if stage_authorization_id is not None:
                for prior_row in connection.execute(
                    "SELECT payload_json FROM supervisor_cycle_receipts"
                ).fetchall():
                    prior_payload = json.loads(prior_row["payload_json"])
                    if (
                        prior_payload.get("stage_authorization_id")
                        == stage_authorization_id
                        or prior_payload.get("stage_authorization_sha256")
                        == stage_authorization_sha256
                    ):
                        raise RuntimeSupervisorIntegrityError(
                            "stage authorization replay detected atomically"
                        )
            connection.execute(
                """
                INSERT INTO supervisor_cycle_receipts(
                    sequence, cycle_id, payload_json,
                    previous_receipt_hmac_sha256, receipt_hmac_sha256
                ) VALUES(?, ?, ?, ?, ?)
                """,
                (
                    sequence,
                    payload["cycle_id"],
                    canonical_json(payload),
                    previous,
                    receipt_hmac,
                ),
            )
        return RuntimeSupervisorCycleReceipt(
            sequence=sequence,
            cycle_id=payload["cycle_id"],
            binding=self.binding,
            owner_id=owner_id,
            fence_token=fence_token,
            phase=payload["phase"],
            status=payload["status"],
            occurred_at_utc=occurred_at,
            reconciliation_status=reconciliation_status,
            journal_checkpoint_sha256=journal_checkpoint_sha256,
            risk_receipt_hmac_sha256=risk_receipt_hmac_sha256,
            runtime_fact_receipt_sha256s=tuple(runtime_fact_receipt_sha256s),
            news_guard_sha256=news_guard_sha256,
            news_guard_provider_id=news_guard_provider_id,
            news_guard_feed_sequence=news_guard_feed_sequence,
            news_guard_previous_sha256=news_guard_previous_sha256,
            stage_mode=stage_mode,
            stage_authorization_id=stage_authorization_id,
            stage_authorization_sha256=stage_authorization_sha256,
            stage_validation_sha256=stage_validation_sha256,
            stage_external_checkpoint_sha256=stage_external_checkpoint_sha256,
            stage_replay_checkpoint_sha256=stage_replay_checkpoint_sha256,
            decision_id=decision_id,
            decision_payload_sha256=decision_payload_sha256,
            execution_service_called=execution_service_called,
            execution_result_sha256=execution_result_sha256,
            reason_codes=tuple(reason_codes),
            previous_receipt_hmac_sha256=previous,
            receipt_hmac_sha256=receipt_hmac,
            _seal=_RECEIPT_SEAL,
        )

    def receipt_count(self) -> int:
        with self._reader() as connection:
            return int(
                connection.execute(
                    "SELECT COUNT(*) FROM supervisor_cycle_receipts"
                ).fetchone()[0]
            )


class RuntimeSupervisor:
    """Coordinate trusted runtime ports under a durable singleton fence."""

    def __init__(
        self,
        database: str | Path,
        *,
        binding: RuntimeSupervisorBinding,
        journal: object,
        risk_ledger: object,
        journal_checkpoint_provider: Callable[[], ExecutionJournalCheckpoint],
        journal_checkpoint_verifier: Callable[
            [ExecutionJournalCheckpoint, ExecutionJournalCheckpoint | None], None
        ],
        risk_checkpoint_provider: Callable[[], RiskStateReceipt],
        risk_source_provider: Callable[[], RiskSourceReceipt] | None,
        reconciliation_provider: Callable[
            [], ReconciliationResult | RuntimeReconciliationRiskResult
        ],
        runtime_fact_provider: Callable[[], Sequence[RuntimeFactReceipt]],
        runtime_fact_verifier: Callable[[RuntimeFactReceipt], RuntimeFactReceipt],
        news_guard_provider: Callable[[], RuntimeNewsGuard | RuntimeNewsGuardReceipt],
        decision_provider: Callable[
            [tuple[RuntimeFactReceipt, ...], RiskStateReceipt],
            RuntimeSupervisorDecision,
        ],
        key_id: str,
        key_provider: Callable[[str], str | bytes],
        supervisor_checkpoint_provider: Callable[
            [], RuntimeSupervisorCheckpoint | None
        ],
        supervisor_checkpoint_exporter: Callable[
            [str, RuntimeSupervisorCheckpoint],
            RuntimeSupervisorCheckpointCASAcknowledgement,
        ],
        supervisor_checkpoint_key_id: str,
        supervisor_checkpoint_key_provider: Callable[[str], str | bytes],
        clock_provider: Callable[[], datetime] = _utc_now,
        allow_checkpoint_bootstrap: bool = False,
        external_journal_checkpoint_provider: Callable[
            [], ExecutionJournalCheckpoint | None
        ]
        | None = None,
        journal_checkpoint_exporter: Callable[
            [str, ExecutionJournalCheckpoint],
            ExecutionJournalCheckpointCASAcknowledgement,
        ]
        | None = None,
        risk_checkpoint_exporter: Callable[
            [str, RiskStateReceipt],
            RiskStateCheckpointCASAcknowledgement,
        ]
        | None = None,
        manual_approval_provider: Callable[
            [RuntimeSupervisorDecision], ManualDemoApprovalValidation
        ]
        | None = None,
        manual_demo_policy_callback: Callable[
            [RuntimeSupervisorDecision, ManualDemoApprovalValidation], bool
        ]
        | None = None,
        execution_service: Callable[
            [RuntimeSupervisorDecision, ManualDemoApprovalValidation], object
        ]
        | None = None,
        news_guard_verifier: Callable[
            [RuntimeNewsGuardReceipt], RuntimeNewsGuardReceipt
        ]
        | None = None,
        news_guard_provider_id: str | None = None,
        news_guard_key_id: str | None = None,
        news_guard_ruleset_sha256: str | None = None,
        news_guard_blackout_window_sha256: str | None = None,
        allow_legacy_shadow_news_guard: bool = False,
        stage_authorization_ports: RuntimeStageAuthorizationPorts | None = None,
        broker_reconciliation_receipt_verifier: Callable[
            [BrokerReconciliationReceipt, ReconciliationResult],
            BrokerReconciliationReceipt,
        ]
        | None = None,
        broker_deal_receipt_verifier: Callable[
            [BrokerDealReceipt, BrokerReconciliationReceipt], BrokerDealReceipt
        ]
        | None = None,
        broker_closed_trade_receipt_verifier: Callable[
            [BrokerClosedTradeReceipt, BrokerReconciliationReceipt],
            BrokerClosedTradeReceipt,
        ]
        | None = None,
        demo_auto_ipc_input_provider: Callable[
            [RuntimeSupervisorDecision], object
        ]
        | None = None,
        demo_auto_session_lease_provider: Callable[
            [RuntimeSupervisorDecision, object], object
        ]
        | None = None,
        demo_auto_session_store: object | None = None,
        demo_auto_permit_validation_provider: Callable[
            [RuntimeSupervisorDecision, object], object
        ]
        | None = None,
        demo_auto_promotion_validation_provider: Callable[
            [RuntimeSupervisorDecision, object], object
        ]
        | None = None,
        demo_auto_environment_arm_provider: Callable[
            [RuntimeSupervisorDecision, object], object
        ]
        | None = None,
        demo_auto_execution_service: Callable[..., object] | None = None,
    ) -> None:
        if type(binding) is not RuntimeSupervisorBinding:
            raise TypeError("binding must be RuntimeSupervisorBinding")
        self.binding = binding
        self.journal = journal
        self.risk_ledger = risk_ledger
        self.journal_checkpoint_provider = journal_checkpoint_provider
        self.journal_checkpoint_verifier = journal_checkpoint_verifier
        self.risk_checkpoint_provider = risk_checkpoint_provider
        self.risk_source_provider = risk_source_provider
        self.reconciliation_provider = reconciliation_provider
        self.runtime_fact_provider = runtime_fact_provider
        self.runtime_fact_verifier = runtime_fact_verifier
        self.news_guard_provider = news_guard_provider
        self.news_guard_verifier = news_guard_verifier
        self.news_guard_provider_id = news_guard_provider_id
        self.news_guard_key_id = news_guard_key_id
        self.news_guard_ruleset_sha256 = news_guard_ruleset_sha256
        self.news_guard_blackout_window_sha256 = news_guard_blackout_window_sha256
        self.allow_legacy_shadow_news_guard = _bool(
            "allow_legacy_shadow_news_guard", allow_legacy_shadow_news_guard
        )
        self.stage_authorization_ports = stage_authorization_ports
        self.broker_reconciliation_receipt_verifier = (
            broker_reconciliation_receipt_verifier
        )
        self.broker_deal_receipt_verifier = broker_deal_receipt_verifier
        self.broker_closed_trade_receipt_verifier = (
            broker_closed_trade_receipt_verifier
        )
        self.decision_provider = decision_provider
        self.manual_approval_provider = manual_approval_provider
        self.manual_demo_policy_callback = manual_demo_policy_callback
        self.execution_service = execution_service
        self.demo_auto_ipc_input_provider = demo_auto_ipc_input_provider
        self.demo_auto_session_lease_provider = demo_auto_session_lease_provider
        self.demo_auto_session_store = demo_auto_session_store
        self.demo_auto_permit_validation_provider = (
            demo_auto_permit_validation_provider
        )
        self.demo_auto_promotion_validation_provider = (
            demo_auto_promotion_validation_provider
        )
        self.demo_auto_environment_arm_provider = demo_auto_environment_arm_provider
        self.demo_auto_execution_service = demo_auto_execution_service
        self.clock_provider = clock_provider
        self.supervisor_checkpoint_provider = supervisor_checkpoint_provider
        self.supervisor_checkpoint_exporter = supervisor_checkpoint_exporter
        self.supervisor_checkpoint_key_id = require_text(
            "supervisor_checkpoint_key_id", supervisor_checkpoint_key_id
        )
        self.supervisor_checkpoint_key_provider = (
            supervisor_checkpoint_key_provider
        )
        self.allow_checkpoint_bootstrap = _bool(
            "allow_checkpoint_bootstrap", allow_checkpoint_bootstrap
        )
        self.external_journal_checkpoint_provider = (
            external_journal_checkpoint_provider
        )
        self.journal_checkpoint_exporter = journal_checkpoint_exporter
        self.risk_checkpoint_exporter = risk_checkpoint_exporter
        for name in (
            "risk_checkpoint_provider",
            "journal_checkpoint_provider",
            "journal_checkpoint_verifier",
            "reconciliation_provider",
            "runtime_fact_provider",
            "runtime_fact_verifier",
            "news_guard_provider",
            "decision_provider",
            "clock_provider",
            "supervisor_checkpoint_provider",
            "supervisor_checkpoint_exporter",
            "supervisor_checkpoint_key_provider",
        ):
            if not callable(getattr(self, name)):
                raise TypeError(f"{name} must be callable")
        if binding.mode != "SHADOW" and (
            not callable(external_journal_checkpoint_provider)
            or not callable(journal_checkpoint_exporter)
            or not callable(risk_checkpoint_exporter)
            or not callable(risk_source_provider)
            or not callable(broker_reconciliation_receipt_verifier)
            or not callable(broker_deal_receipt_verifier)
            or not callable(broker_closed_trade_receipt_verifier)
        ):
            raise TypeError(
                "execution modes require journal and risk custody CAS ports"
            )
        if binding.mode == "SHADOW":
            for name, value in (
                (
                    "external journal checkpoint provider",
                    external_journal_checkpoint_provider,
                ),
                ("journal checkpoint exporter", journal_checkpoint_exporter),
                ("risk checkpoint exporter", risk_checkpoint_exporter),
                ("risk source provider", risk_source_provider),
                (
                    "broker reconciliation receipt verifier",
                    broker_reconciliation_receipt_verifier,
                ),
                ("broker deal receipt verifier", broker_deal_receipt_verifier),
                (
                    "broker closed-trade receipt verifier",
                    broker_closed_trade_receipt_verifier,
                ),
            ):
                if value is not None and not callable(value):
                    raise TypeError(f"{name} must be callable")
        if binding.mode != "SHADOW":
            if (
                not callable(news_guard_verifier)
                or news_guard_provider_id is None
                or news_guard_key_id is None
                or news_guard_ruleset_sha256 is None
                or news_guard_blackout_window_sha256 is None
            ):
                raise TypeError(
                    "execution modes require explicit signed news guard verification ports"
                )
            if self.allow_legacy_shadow_news_guard:
                raise ValueError("legacy news guard is restricted to SHADOW")
        elif self.allow_legacy_shadow_news_guard and any(
            value is not None
            for value in (
                news_guard_verifier,
                news_guard_provider_id,
                news_guard_key_id,
                news_guard_ruleset_sha256,
                news_guard_blackout_window_sha256,
            )
        ):
            raise ValueError("legacy SHADOW guard cannot mix with signed guard ports")
        elif not self.allow_legacy_shadow_news_guard and (
            not callable(news_guard_verifier)
            or news_guard_provider_id is None
            or news_guard_key_id is None
            or news_guard_ruleset_sha256 is None
            or news_guard_blackout_window_sha256 is None
        ):
            raise TypeError(
                "SHADOW requires signed news guard ports or explicit legacy compatibility"
            )
        if not self.allow_legacy_shadow_news_guard:
            self.news_guard_provider_id = require_text(
                "news_guard_provider_id", self.news_guard_provider_id
            )
            self.news_guard_key_id = require_text(
                "news_guard_key_id", self.news_guard_key_id
            )
            self.news_guard_ruleset_sha256 = require_hash(
                "news_guard_ruleset_sha256", self.news_guard_ruleset_sha256
            )
            self.news_guard_blackout_window_sha256 = require_hash(
                "news_guard_blackout_window_sha256",
                self.news_guard_blackout_window_sha256,
            )
            expected_news_trust = runtime_news_guard_trust_sha256(
                provider_id=self.news_guard_provider_id,
                key_id=self.news_guard_key_id,
                ruleset_sha256=self.news_guard_ruleset_sha256,
                blackout_window_sha256=self.news_guard_blackout_window_sha256,
            )
            if self.binding.news_guard_trust_sha256 != expected_news_trust:
                raise RuntimeSupervisorBindingError(
                    "signed news guard trust profile does not match durable binding"
                )
        if binding.mode in {"DEMO", "DEMO_AUTO"}:
            if type(stage_authorization_ports) is not RuntimeStageAuthorizationPorts:
                raise TypeError("DEMO stage modes require explicit stage authorization ports")
        elif stage_authorization_ports is not None:
            raise ValueError("stage authorization ports are restricted to DEMO stage modes")
        demo_auto_ports = (
            ("demo_auto_ipc_input_provider", demo_auto_ipc_input_provider),
            ("demo_auto_session_lease_provider", demo_auto_session_lease_provider),
            (
                "demo_auto_permit_validation_provider",
                demo_auto_permit_validation_provider,
            ),
            (
                "demo_auto_promotion_validation_provider",
                demo_auto_promotion_validation_provider,
            ),
            ("demo_auto_environment_arm_provider", demo_auto_environment_arm_provider),
            ("demo_auto_execution_service", demo_auto_execution_service),
        )
        if binding.mode == "DEMO_AUTO" and execution_policy.demo_auto_execution_policy_enabled():
            missing = tuple(name for name, value in demo_auto_ports if not callable(value))
            from .demo_auto_session_capability import DemoAutoSessionCapabilityStore

            if type(demo_auto_session_store) is not DemoAutoSessionCapabilityStore:
                missing += ("demo_auto_session_store",)
            if missing:
                raise TypeError(
                    "enabled DEMO_AUTO mode requires all dispatch ports: "
                    + ", ".join(missing)
                )
        else:
            for name, value in demo_auto_ports:
                if value is not None and not callable(value):
                    raise TypeError(f"{name} must be callable or None")
            if demo_auto_session_store is not None:
                from .demo_auto_session_capability import (
                    DemoAutoSessionCapabilityStore,
                )

                if type(demo_auto_session_store) is not DemoAutoSessionCapabilityStore:
                    raise TypeError(
                        "demo_auto_session_store must be exact "
                        "DemoAutoSessionCapabilityStore or None"
                    )
        try:
            self.store = _SupervisorStore(
                database,
                binding=binding,
                key_id=key_id,
                key_provider=key_provider,
            )
            self._initialize_checkpoint_custody()
        except Exception as exc:
            if hasattr(self, "store"):
                verified_external: RuntimeSupervisorCheckpoint | None = None
                try:
                    verified_external = (
                        self._verify_external_supervisor_checkpoint()
                    )
                except Exception:
                    # The initialization failure may itself be a rollback or
                    # incarnation mismatch.  Never regress the custodian head.
                    pass
                try:
                    self.store.latch_critical(
                        "SUPERVISOR_STORE_INITIALIZATION_FAILED",
                        occurred_at=self._now(),
                    )
                    if verified_external is not None:
                        self._publish_supervisor_checkpoint(
                            expected_external=verified_external
                        )
                except Exception:
                    pass
            try:
                journal.latch_kill_switch(
                    "SUPERVISOR_STORE_INITIALIZATION_FAILED",
                    source="RUNTIME_SUPERVISOR",
                )
            except Exception:
                pass
            raise RuntimeSupervisorCriticalError(
                f"SUPERVISOR_STORE_INITIALIZATION_FAILED: {type(exc).__name__}"
            ) from exc
        self.owner_id: str | None = None
        self.fence_token: int | None = None
        self.lease_seconds = 30
        self._state = "CREATED"
        self._stopped = False
        self._stop_reason: str | None = None

    def _provided_supervisor_checkpoint(
        self, *, required: bool = True
    ) -> RuntimeSupervisorCheckpoint | None:
        try:
            checkpoint = self.supervisor_checkpoint_provider()
        except Exception as exc:
            raise RuntimeSupervisorIntegrityError(
                "external supervisor checkpoint provider failed"
            ) from exc
        if checkpoint is None:
            if required:
                raise RuntimeSupervisorIntegrityError(
                    "external supervisor checkpoint is required"
                )
            return None
        if type(checkpoint) is not RuntimeSupervisorCheckpoint:
            raise RuntimeSupervisorIntegrityError(
                "external supervisor checkpoint type invalid"
            )
        return checkpoint

    def _verify_external_supervisor_checkpoint(self) -> RuntimeSupervisorCheckpoint:
        checkpoint = self._provided_supervisor_checkpoint(required=True)
        assert checkpoint is not None
        return self.store.verify_external_checkpoint(
            checkpoint,
            expected_key_id=self.supervisor_checkpoint_key_id,
            key_provider=self.supervisor_checkpoint_key_provider,
        )

    def export_supervisor_checkpoint(self) -> RuntimeSupervisorCheckpoint:
        """Return a signed successor for the current off-host checkpoint.

        This method does not mutate custody.  Persistence must still cross the
        configured exporter boundary before another local mutation is safe.
        """

        external = self._provided_supervisor_checkpoint(required=False)
        predecessor = ZERO_HMAC_SHA256
        if external is not None:
            checked = self.store.verify_external_checkpoint(
                external,
                expected_key_id=self.supervisor_checkpoint_key_id,
                key_provider=self.supervisor_checkpoint_key_provider,
            )
            predecessor = checked.content_sha256
        return self.store.create_checkpoint(
            key_id=self.supervisor_checkpoint_key_id,
            key_provider=self.supervisor_checkpoint_key_provider,
            issued_at_utc=self._now(),
            predecessor_checkpoint_sha256=predecessor,
        )

    def _publish_supervisor_checkpoint(
        self,
        *,
        expected_external: RuntimeSupervisorCheckpoint | None,
    ) -> RuntimeSupervisorCheckpoint:
        """CAS-publish without overwriting an unexpected custodian head."""

        observed = self._provided_supervisor_checkpoint(required=False)
        if expected_external is None:
            if observed is not None:
                raise RuntimeSupervisorIntegrityError(
                    "off-host supervisor checkpoint appeared during bootstrap"
                )
            predecessor = ZERO_HMAC_SHA256
        else:
            verify_runtime_supervisor_checkpoint_signature(
                expected_external,
                expected_key_id=self.supervisor_checkpoint_key_id,
                key_provider=self.supervisor_checkpoint_key_provider,
            )
            if (
                observed is None
                or observed.content_sha256 != expected_external.content_sha256
            ):
                raise RuntimeSupervisorIntegrityError(
                    "off-host supervisor checkpoint changed before export"
                )
            predecessor = expected_external.content_sha256
        checkpoint = self.store.create_checkpoint(
            key_id=self.supervisor_checkpoint_key_id,
            key_provider=self.supervisor_checkpoint_key_provider,
            issued_at_utc=self._now(),
            predecessor_checkpoint_sha256=predecessor,
        )
        try:
            acknowledgement = self.supervisor_checkpoint_exporter(
                predecessor,
                checkpoint,
            )
        except Exception as exc:
            raise RuntimeSupervisorIntegrityError(
                "off-host supervisor checkpoint CAS failed"
            ) from exc
        if (
            type(acknowledgement)
            is not RuntimeSupervisorCheckpointCASAcknowledgement
            or acknowledgement.expected_current_checkpoint_sha256
            != predecessor
            or acknowledgement.written_checkpoint_sha256
            != checkpoint.content_sha256
        ):
            raise RuntimeSupervisorIntegrityError(
                "off-host supervisor checkpoint CAS acknowledgement is invalid"
            )
        external = self._provided_supervisor_checkpoint(required=True)
        assert external is not None
        if external.content_sha256 != checkpoint.content_sha256:
            raise RuntimeSupervisorIntegrityError(
                "off-host supervisor checkpoint custody acknowledgement mismatch"
            )
        self.store.verify_external_checkpoint(
            external,
            expected_key_id=self.supervisor_checkpoint_key_id,
            key_provider=self.supervisor_checkpoint_key_provider,
        )
        return checkpoint

    def _initialize_checkpoint_custody(self) -> None:
        external = self._provided_supervisor_checkpoint(required=False)
        if external is not None:
            self.store.verify_external_checkpoint(
                external,
                expected_key_id=self.supervisor_checkpoint_key_id,
                key_provider=self.supervisor_checkpoint_key_provider,
            )
            return
        if not self.allow_checkpoint_bootstrap:
            raise RuntimeSupervisorIntegrityError(
                "external supervisor checkpoint is required before startup"
            )
        local = self.export_supervisor_checkpoint()
        if local.event_count != 0 or local.critical_latched or local.news_heads:
            raise RuntimeSupervisorIntegrityError(
                "only a pristine supervisor store can bootstrap external custody"
            )
        self._publish_supervisor_checkpoint(expected_external=None)

    def _append_and_checkpoint(self, **kwargs: Any) -> RuntimeSupervisorCycleReceipt:
        external = self._verify_external_supervisor_checkpoint()
        receipt = self.store.append(**kwargs)
        self._publish_supervisor_checkpoint(expected_external=external)
        return receipt

    def _now(self) -> datetime:
        try:
            return require_utc("trusted supervisor clock", self.clock_provider())
        except Exception as exc:
            raise RuntimeSupervisorCriticalError(
                "TRUSTED_CLOCK_PROVIDER_UNAVAILABLE"
            ) from exc

    def _lease(self, *, refresh: bool = True) -> tuple[str, int]:
        if self.owner_id is None or self.fence_token is None:
            raise RuntimeSupervisorLeaseError("supervisor has no active lease")
        if refresh:
            self.store.refresh(
                self.owner_id,
                self.fence_token,
                lease_seconds=self.lease_seconds,
                now=self._now(),
            )
        return self.owner_id, self.fence_token

    def _latch_and_stop(self, reason_code: str, *, exc: Exception | None = None) -> None:
        reason = require_text("reason_code", reason_code, upper=True)
        verified_external: RuntimeSupervisorCheckpoint | None = None
        try:
            verified_external = self._verify_external_supervisor_checkpoint()
        except Exception:
            # Preserve a newer/unexpected custodian head; never overwrite it
            # merely because this local database may have been rolled back.
            pass
        try:
            self.store.latch_critical(reason, occurred_at=self._now())
            if verified_external is not None:
                self._publish_supervisor_checkpoint(
                    expected_external=verified_external
                )
        except Exception:
            # The local latch update is committed before export.  If export fails,
            # the external/local mismatch itself remains a permanent startup deny.
            pass
        journal_latch_observed = False
        try:
            status = self.journal.kill_switch_status()
            if not isinstance(status, Mapping) or status.get("latched") is not True:
                self.journal.latch_kill_switch(
                    reason,
                    source="RUNTIME_SUPERVISOR",
                )
            journal_latch_observed = True
        except Exception:
            pass
        if journal_latch_observed and self.binding.mode != "SHADOW":
            try:
                self._verify_journal_checkpoint()
            except Exception:
                # Critical state is already persistent. A custody outage or
                # rollback remains an additional startup deny.
                pass
        self._state = "STOPPED_CRITICAL"
        self._stopped = True
        self._stop_reason = reason
        owner = self.owner_id
        fence = self.fence_token
        if owner is not None and fence is not None:
            try:
                self._append_and_checkpoint(
                    owner_id=owner,
                    fence_token=fence,
                    cycle_id=f"critical-{uuid.uuid4().hex}",
                    phase="CRITICAL",
                    status="STOPPED",
                    occurred_at=self._now(),
                    reason_codes=(reason,),
                )
            except Exception:
                pass
            try:
                self.store.release(owner, fence)
            except Exception:
                pass
        self.owner_id = None
        self.fence_token = None
        message = reason if exc is None else f"{reason}: {type(exc).__name__}"
        raise RuntimeSupervisorCriticalError(message) from exc

    def _verify_journal(self) -> None:
        if require_hash("journal identity", self.journal.journal_sha256) != self.binding.journal_sha256:
            raise RuntimeSupervisorBindingError("journal binding mismatch")
        if self.journal.integrity_check() is not True:
            raise RuntimeSupervisorIntegrityError("journal integrity failed")
        status = self.journal.kill_switch_status()
        if not isinstance(status, Mapping) or type(status.get("latched")) is not bool:
            raise RuntimeSupervisorCriticalError("KILL_SWITCH_STATUS_INVALID")
        if status["latched"]:
            raise RuntimeSupervisorCriticalError("KILL_SWITCH_LATCHED")

    def _publish_risk_checkpoint(
        self,
        external: RiskStateReceipt,
        current: RiskStateReceipt,
    ) -> None:
        if self.binding.mode == "SHADOW":
            return
        if not callable(self.risk_checkpoint_exporter):
            raise RuntimeSupervisorIntegrityError(
                "risk checkpoint custody CAS port is unavailable"
            )
        if (
            current.ledger_id != external.ledger_id
            or current.binding != external.binding
            or current.event_sequence < external.event_sequence
            or (
                current.event_sequence == external.event_sequence
                and (
                    current.head_hmac_sha256 != external.head_hmac_sha256
                    or current.source_receipt_chain_sha256
                    != external.source_receipt_chain_sha256
                )
            )
        ):
            raise RuntimeSupervisorIntegrityError(
                "risk checkpoint high-water decreased or forked"
            )
        expected_current = external.content_sha256
        observed = self.risk_checkpoint_provider()
        if (
            type(observed) is not RiskStateReceipt
            or observed.content_sha256 != expected_current
        ):
            raise RuntimeSupervisorIntegrityError(
                "external risk checkpoint changed before CAS"
            )
        try:
            acknowledgement = self.risk_checkpoint_exporter(
                expected_current,
                current,
            )
        except Exception as exc:
            raise RuntimeSupervisorIntegrityError(
                "external risk checkpoint CAS failed"
            ) from exc
        if (
            type(acknowledgement)
            is not RiskStateCheckpointCASAcknowledgement
            or acknowledgement.expected_current_checkpoint_sha256
            != expected_current
            or acknowledgement.written_checkpoint_sha256
            != current.content_sha256
        ):
            raise RuntimeSupervisorIntegrityError(
                "external risk checkpoint CAS acknowledgement is invalid"
            )
        published = self.risk_checkpoint_provider()
        if (
            type(published) is not RiskStateReceipt
            or published.content_sha256 != current.content_sha256
        ):
            raise RuntimeSupervisorIntegrityError(
                "external risk checkpoint read-after-write mismatch"
            )

    def _verify_risk(self) -> RiskStateReceipt:
        checkpoint = self.risk_checkpoint_provider()
        if type(checkpoint) is not RiskStateReceipt:
            raise RuntimeSupervisorIntegrityError("risk checkpoint is not sealed")
        if self.risk_ledger.verify_integrity(expected_receipt=checkpoint) is not True:
            raise RuntimeSupervisorIntegrityError("risk ledger integrity failed")
        current = self.risk_ledger.current_receipt()
        if type(current) is not RiskStateReceipt:
            raise RuntimeSupervisorIntegrityError("risk receipt is not sealed")
        expected = (
            current.binding.account_id_sha256 == self.binding.account_id_sha256,
            current.binding.server == self.binding.server,
            current.binding.environment == self.binding.environment,
            current.binding.journal_sha256 == self.binding.journal_sha256,
            current.binding.account_currency == self.binding.account_currency,
        )
        if not all(expected):
            raise RuntimeSupervisorBindingError("risk receipt binding mismatch")
        risk_age = (self._now() - current.issued_at_utc).total_seconds()
        if risk_age < 0 or risk_age > MAX_RISK_RECEIPT_AGE_SECONDS:
            raise RuntimeSupervisorCriticalError("RISK_RECEIPT_STALE_OR_FUTURE")
        self._publish_risk_checkpoint(checkpoint, current)
        if current.loss_latch_active:
            raise RuntimeSupervisorCriticalError("RISK_LOSS_LATCH_ACTIVE")
        return current

    def _verify_current_risk_source(
        self,
        risk: RiskStateReceipt,
        *,
        supplied: RiskSourceReceipt | None = None,
        require_fresh: bool = False,
    ) -> RiskSourceReceipt:
        source = supplied
        if source is None:
            if not callable(self.risk_source_provider):
                raise RuntimeSupervisorIntegrityError(
                    "risk source provider is unavailable"
                )
            source = self.risk_source_provider()
        if type(source) is not RiskSourceReceipt:
            raise RuntimeSupervisorIntegrityError("risk source receipt is not sealed")
        if (
            source.binding != risk.binding
            or source.content_sha256 != risk.latest_source_receipt_sha256
            or source.issuer_id != risk.latest_source_issuer_id
            or source.key_id != risk.latest_source_key_id
        ):
            raise RuntimeSupervisorIntegrityError(
                "risk source does not match the risk-state high-water receipt"
            )
        if require_fresh:
            now = self._now()
            if not source.observed_at_utc <= now <= source.valid_until_utc:
                raise RuntimeSupervisorCriticalError(
                    "RISK_SOURCE_RECEIPT_STALE_OR_FUTURE"
                )
        return source

    def _require_execution_account_snapshot(
        self,
        risk: RiskStateReceipt,
        facts: Sequence[RuntimeFactReceipt],
        *,
        evidence: RuntimeAccountSnapshotRiskEvidence | None = None,
    ) -> RiskSourceReceipt:
        source = self._verify_current_risk_source(
            risk,
            supplied=None if evidence is None else evidence.source_receipt,
            require_fresh=True,
        )
        age = (self._now() - risk.latest_event_at_utc).total_seconds()
        if (
            source.source_kind != "ACCOUNT_SNAPSHOT"
            or age < 0
            or age > MAX_ACCOUNT_SNAPSHOT_AGE_SECONDS
        ):
            raise RuntimeSupervisorCriticalError(
                "FRESH_ACCOUNT_RISK_SNAPSHOT_REQUIRED"
            )
        equities = tuple(item.account_fact.equity for item in facts)
        if (
            not equities
            or any(value != equities[0] for value in equities)
            or risk.current_equity != equities[0]
        ):
            raise RuntimeSupervisorCriticalError(
                "RISK_EQUITY_RUNTIME_FACT_MISMATCH"
            )
        return source

    def _append_entry_risk_event(
        self,
        result: RuntimeManualDemoExecutionResult | RuntimeDemoAutoExecutionResult,
        before: RiskStateReceipt,
    ) -> RiskStateReceipt:
        receipt = result.execution_receipt
        event = result.entry_event
        source = result.entry_source_receipt
        if (
            receipt.intent_id != event.entry_id
            or receipt.server != self.binding.server
            or receipt.journal_sha256 != self.binding.journal_sha256
            or event.binding != before.binding
            or event.daily_baseline_id != before.daily_baseline_id
            or event.weekly_baseline_id != before.weekly_baseline_id
            or source.upstream_receipt_sha256 != receipt.content_sha256
        ):
            raise RuntimeSupervisorIntegrityError(
                "execution entry evidence binding mismatch"
            )
        try:
            appended = self.risk_ledger.append_entry(
                event,
                source_receipt=source,
                upstream_receipt=receipt,
            )
        except Exception as exc:
            raise RuntimeSupervisorIntegrityError(
                "execution ENTRY risk append failed"
            ) from exc
        if (
            type(appended) is not RiskStateReceipt
            or appended.event_sequence != before.event_sequence + 1
            or appended.entries_today != before.entries_today + 1
            or appended.latest_source_receipt_sha256 != source.content_sha256
            or appended.latest_source_issuer_id != source.issuer_id
            or appended.latest_source_key_id != source.key_id
            or appended.current_equity != before.current_equity
        ):
            raise RuntimeSupervisorIntegrityError(
                "execution ENTRY risk high-water did not advance exactly once"
            )
        current = self._verify_risk_with_source(source)
        if (
            current.event_sequence != appended.event_sequence
            or current.head_hmac_sha256 != appended.head_hmac_sha256
            or current.latest_source_receipt_sha256 != source.content_sha256
            or source.source_kind != "ENTRY"
            or source.upstream_receipt_type != "EXECUTION_RECEIPT"
            or source.upstream_receipt_sha256 != receipt.content_sha256
        ):
            raise RuntimeSupervisorIntegrityError(
                "execution ENTRY risk receipt verification failed"
            )
        return current

    def _verify_risk_with_source(
        self,
        source: RiskSourceReceipt,
    ) -> RiskStateReceipt:
        """Refresh risk custody while binding the exact newly ingested source."""

        checkpoint = self.risk_checkpoint_provider()
        if type(checkpoint) is not RiskStateReceipt:
            raise RuntimeSupervisorIntegrityError("risk checkpoint is not sealed")
        if self.risk_ledger.verify_integrity(expected_receipt=checkpoint) is not True:
            raise RuntimeSupervisorIntegrityError("risk ledger integrity failed")
        current = self.risk_ledger.current_receipt()
        if type(current) is not RiskStateReceipt:
            raise RuntimeSupervisorIntegrityError("risk receipt is not sealed")
        if not all(
            (
                current.binding.account_id_sha256
                == self.binding.account_id_sha256,
                current.binding.server == self.binding.server,
                current.binding.environment == self.binding.environment,
                current.binding.journal_sha256 == self.binding.journal_sha256,
                current.binding.account_currency == self.binding.account_currency,
            )
        ):
            raise RuntimeSupervisorBindingError("risk receipt binding mismatch")
        risk_age = (self._now() - current.issued_at_utc).total_seconds()
        if risk_age < 0 or risk_age > MAX_RISK_RECEIPT_AGE_SECONDS:
            raise RuntimeSupervisorCriticalError("RISK_RECEIPT_STALE_OR_FUTURE")
        self._verify_current_risk_source(current, supplied=source, require_fresh=True)
        self._publish_risk_checkpoint(checkpoint, current)
        if current.loss_latch_active:
            raise RuntimeSupervisorCriticalError("RISK_LOSS_LATCH_ACTIVE")
        return current

    def _append_reconciled_closed_trades(
        self,
        result: RuntimeReconciliationRiskResult,
        before: RiskStateReceipt,
    ) -> RiskStateReceipt:
        current = before
        for evidence in result.closed_trade_evidence:
            event = evidence.event
            source = evidence.source_receipt
            if (
                event.binding != before.binding
                or event.daily_baseline_id != current.daily_baseline_id
                or event.weekly_baseline_id != current.weekly_baseline_id
            ):
                raise RuntimeSupervisorIntegrityError(
                    "closed-trade risk evidence binding mismatch"
                )
            try:
                appended = self.risk_ledger.append_closed_trade(
                    event,
                    source_receipt=source,
                    upstream_receipt=evidence.upstream_receipt,
                )
            except Exception as exc:
                raise RuntimeSupervisorIntegrityError(
                    "reconciled CLOSED_TRADE risk append failed"
                ) from exc
            if (
                type(appended) is not RiskStateReceipt
                or appended.event_sequence != current.event_sequence + 1
                or appended.latest_source_receipt_sha256 != source.content_sha256
                or source.source_kind != "CLOSED_TRADE"
                or source.upstream_receipt_sha256
                != evidence.upstream_receipt.content_sha256
            ):
                raise RuntimeSupervisorIntegrityError(
                    "reconciled CLOSED_TRADE risk head did not advance exactly once"
                )
            current = appended
        snapshot = result.account_snapshot_evidence
        if snapshot is not None:
            try:
                appended = self.risk_ledger.append_account_snapshot(
                    snapshot.event,
                    source_receipt=snapshot.source_receipt,
                    upstream_receipt=snapshot.upstream_receipt,
                )
            except Exception as exc:
                raise RuntimeSupervisorIntegrityError(
                    "reconciliation ACCOUNT_SNAPSHOT risk append failed"
                ) from exc
            if (
                type(appended) is not RiskStateReceipt
                or appended.event_sequence != current.event_sequence + 1
                or appended.current_equity != snapshot.event.equity
                or appended.latest_event_at_utc != snapshot.event.observed_at_utc
                or appended.latest_source_receipt_sha256
                != snapshot.source_receipt.content_sha256
            ):
                raise RuntimeSupervisorIntegrityError(
                    "reconciliation ACCOUNT_SNAPSHOT risk head did not advance exactly once"
                )
            current = appended
        if current.event_sequence == before.event_sequence:
            return before
        latest_source = (
            snapshot.source_receipt
            if snapshot is not None
            else result.closed_trade_evidence[-1].source_receipt
        )
        return self._verify_risk_with_source(latest_source)

    def _verify_reconciliation_snapshot_facts(
        self,
        result: RuntimeReconciliationRiskResult,
        risk: RiskStateReceipt,
        facts: Sequence[RuntimeFactReceipt],
    ) -> None:
        snapshot = result.account_snapshot_evidence
        if snapshot is None:
            if self.binding.mode != "SHADOW":
                raise RuntimeSupervisorCriticalError(
                    "RECONCILIATION_ACCOUNT_SNAPSHOT_MISSING"
                )
            return
        upstream = snapshot.upstream_receipt
        if (
            not any(item is upstream for item in facts)
            or risk.latest_source_receipt_sha256
            != snapshot.source_receipt.content_sha256
            or risk.latest_event_at_utc != snapshot.event.observed_at_utc
            or risk.current_equity != snapshot.event.equity
            or risk.current_equity != upstream.account_fact.equity
        ):
            raise RuntimeSupervisorCriticalError(
                "RECONCILIATION_ACCOUNT_SNAPSHOT_FACT_MISMATCH"
            )

    def _publish_execution_journal_checkpoint(
        self,
        checkpoint: ExecutionJournalCheckpoint,
        prior_checkpoint: ExecutionJournalCheckpoint | None,
    ) -> None:
        if self.binding.mode == "SHADOW":
            return
        if (
            type(prior_checkpoint) is not ExecutionJournalCheckpoint
            or not callable(self.external_journal_checkpoint_provider)
            or not callable(self.journal_checkpoint_exporter)
        ):
            raise RuntimeSupervisorIntegrityError(
                "journal checkpoint custody CAS ports are unavailable"
            )
        expected_current = prior_checkpoint.content_sha256
        if checkpoint.predecessor_checkpoint_sha256 != expected_current:
            raise RuntimeSupervisorIntegrityError(
                "journal checkpoint CAS predecessor mismatch"
            )
        observed = self.external_journal_checkpoint_provider()
        if (
            type(observed) is not ExecutionJournalCheckpoint
            or observed.content_sha256 != expected_current
        ):
            raise RuntimeSupervisorIntegrityError(
                "external journal checkpoint changed before CAS"
            )
        try:
            acknowledgement = self.journal_checkpoint_exporter(
                expected_current,
                checkpoint,
            )
        except Exception as exc:
            raise RuntimeSupervisorIntegrityError(
                "external journal checkpoint CAS failed"
            ) from exc
        if (
            type(acknowledgement)
            is not ExecutionJournalCheckpointCASAcknowledgement
            or acknowledgement.expected_current_checkpoint_sha256
            != expected_current
            or acknowledgement.written_checkpoint_sha256
            != checkpoint.content_sha256
        ):
            raise RuntimeSupervisorIntegrityError(
                "external journal checkpoint CAS acknowledgement is invalid"
            )
        published = self.external_journal_checkpoint_provider()
        if (
            type(published) is not ExecutionJournalCheckpoint
            or published.content_sha256 != checkpoint.content_sha256
        ):
            raise RuntimeSupervisorIntegrityError(
                "external journal checkpoint read-after-write mismatch"
            )

    def _verify_journal_checkpoint(self) -> ExecutionJournalCheckpoint:
        checkpoint = self.journal_checkpoint_provider()
        if type(checkpoint) is not ExecutionJournalCheckpoint:
            raise RuntimeSupervisorIntegrityError(
                "execution journal checkpoint is not signed contract"
            )
        prior_checkpoint = (
            None
            if self.external_journal_checkpoint_provider is None
            else self.external_journal_checkpoint_provider()
        )
        if self.binding.mode != "SHADOW" and type(prior_checkpoint) is not ExecutionJournalCheckpoint:
            raise RuntimeSupervisorIntegrityError(
                "externally custodied journal predecessor is required"
            )
        if (
            self.binding.mode != "SHADOW"
            and checkpoint.predecessor_checkpoint_sha256
            != prior_checkpoint.content_sha256
        ):
            raise RuntimeSupervisorIntegrityError(
                "journal checkpoint predecessor does not match external custody"
            )
        verification_result = self.journal_checkpoint_verifier(
            checkpoint, prior_checkpoint
        )
        if verification_result is not None:
            raise RuntimeSupervisorIntegrityError(
                "journal checkpoint verifier returned an invalid result"
            )
        expected = (
            checkpoint.journal_sha256 == self.binding.journal_sha256,
            checkpoint.account_id_sha256
            == self.binding.account_id_sha256,
            checkpoint.server == self.binding.server,
            checkpoint.environment == self.binding.environment,
            checkpoint.commit_sha == self.binding.commit_sha,
            checkpoint.config_sha256 == self.binding.config_sha256,
        )
        if not all(expected):
            raise RuntimeSupervisorBindingError(
                "execution journal checkpoint binding mismatch"
            )
        checked_at = self._now()
        if not (
            checkpoint.checked_at_utc <= checked_at < checkpoint.valid_until_utc
        ):
            raise RuntimeSupervisorCriticalError(
                "JOURNAL_CHECKPOINT_STALE_OR_FUTURE"
            )
        self._publish_execution_journal_checkpoint(checkpoint, prior_checkpoint)
        return checkpoint

    def _verify_reconciliation(
        self, result: object
    ) -> RuntimeReconciliationRiskResult:
        if type(result) is ReconciliationResult and self.binding.mode == "SHADOW":
            result = seal_runtime_reconciliation_risk_result(result)
        if type(result) is not RuntimeReconciliationRiskResult:
            raise RuntimeSupervisorCriticalError(
                "RECONCILIATION_RISK_RESULT_REQUIRED"
            )
        reconciliation = result.reconciliation
        broker_receipt = result.broker_reconciliation_receipt
        if self.binding.mode != "SHADOW":
            if type(broker_receipt) is not BrokerReconciliationReceipt:
                raise RuntimeSupervisorCriticalError(
                    "BROKER_RECONCILIATION_RECEIPT_REQUIRED"
                )
            if (
                broker_receipt.account_id_sha256
                != self.binding.account_id_sha256
                or broker_receipt.server != self.binding.server
                or broker_receipt.environment != self.binding.environment
                or broker_receipt.journal_sha256 != self.binding.journal_sha256
                or broker_receipt.reconciliation_result_sha256
                != reconciliation_result_sha256(reconciliation)
            ):
                raise RuntimeSupervisorBindingError(
                    "broker reconciliation receipt binding mismatch"
                )
            verified_broker = self.broker_reconciliation_receipt_verifier(
                broker_receipt,
                reconciliation,
            )
            if verified_broker is not broker_receipt:
                raise RuntimeSupervisorIntegrityError(
                    "broker reconciliation verifier changed receipt identity"
                )
            observed_closed_deals: dict[str, tuple[str, ...]] = {}
            for evidence in result.closed_trade_evidence:
                aggregate = evidence.upstream_receipt
                verified_aggregate = self.broker_closed_trade_receipt_verifier(
                    aggregate,
                    broker_receipt,
                )
                if verified_aggregate is not aggregate:
                    raise RuntimeSupervisorIntegrityError(
                        "broker close verifier changed receipt identity"
                    )
                for deal in aggregate.deal_receipts:
                    verified_deal = self.broker_deal_receipt_verifier(
                        deal, broker_receipt
                    )
                    if verified_deal is not deal:
                        raise RuntimeSupervisorIntegrityError(
                            "broker deal verifier changed receipt identity"
                        )
                observed_closed_deals[aggregate.intent_id] = aggregate.deal_tickets
            if observed_closed_deals != dict(
                broker_receipt.closed_intent_deal_tickets
            ):
                raise RuntimeSupervisorCriticalError(
                    "BROKER_DEAL_RECEIPT_SET_INCOMPLETE"
                )
        expected_closed = tuple(sorted(reconciliation.closed_intents))
        observed_closed = tuple(
            sorted(item.event.entry_id for item in result.closed_trade_evidence)
        )
        if expected_closed != observed_closed or (
            self.binding.mode != "SHADOW"
            and type(result.account_snapshot_evidence)
            is not RuntimeAccountSnapshotRiskEvidence
        ):
            raise RuntimeSupervisorCriticalError(
                "RECONCILIATION_RISK_EVIDENCE_INCOMPLETE"
            )
        critical_fields = (
            reconciliation.uncertain_intents,
            reconciliation.orphan_position_tickets,
            reconciliation.orphan_order_tickets,
            reconciliation.protection_failures,
            reconciliation.volume_failures,
            reconciliation.binding_failures,
        )
        if (
            reconciliation.status != "RECONCILIATION_COMPLETE"
            or any(critical_fields)
            or reconciliation.kill_switch_latched
        ):
            raise RuntimeSupervisorCriticalError("RECONCILIATION_NOT_CLEAN")
        return result

    def _verify_facts(self) -> tuple[RuntimeFactReceipt, ...]:
        raw = self.runtime_fact_provider()
        if not isinstance(raw, Sequence) or isinstance(raw, (str, bytes)) or not raw:
            raise RuntimeSupervisorCriticalError("RUNTIME_FACT_RECEIPTS_MISSING")
        verified: list[RuntimeFactReceipt] = []
        symbols: set[str] = set()
        for receipt in raw:
            checked = self.runtime_fact_verifier(receipt)
            if type(checked) is not RuntimeFactReceipt or checked is not receipt:
                raise RuntimeSupervisorIntegrityError(
                    "runtime fact verifier did not return the exact sealed receipt"
                )
            if (
                manual_demo_account_sha256(checked.account_id)
                != self.binding.account_id_sha256
                or checked.server != self.binding.server
                or checked.environment != self.binding.environment
                or checked.journal_sha256 != self.binding.journal_sha256
            ):
                raise RuntimeSupervisorBindingError("runtime fact binding mismatch")
            if checked.symbol in symbols:
                raise RuntimeSupervisorIntegrityError("duplicate runtime fact symbol")
            if not checked.health_decision.healthy:
                raise RuntimeSupervisorCriticalError("RUNTIME_HEALTH_UNHEALTHY")
            if checked.live_allowed or checked.safe_to_demo_auto_order:
                raise RuntimeSupervisorCriticalError("RUNTIME_FACT_UNLOCK_ATTEMPT")
            checked_at = self._now()
            if not (
                checked.observed_at_utc
                <= checked_at
                < checked.valid_until_utc
            ):
                raise RuntimeSupervisorCriticalError(
                    "RUNTIME_FACT_RECEIPT_STALE_OR_FUTURE"
                )
            symbols.add(checked.symbol)
            verified.append(checked)
        return tuple(verified)

    def _require_facts_still_fresh(
        self,
        facts: Sequence[RuntimeFactReceipt],
        *,
        checked_at: datetime | None = None,
    ) -> None:
        checked_at = (
            self._now()
            if checked_at is None
            else require_utc("fact freshness time", checked_at)
        )
        if not facts or any(
            not (item.observed_at_utc <= checked_at < item.valid_until_utc)
            for item in facts
        ):
            raise RuntimeSupervisorCriticalError(
                "RUNTIME_FACT_RECEIPT_EXPIRED_DURING_CYCLE"
            )

    def _require_cycle_evidence_fresh(
        self,
        journal_checkpoint: ExecutionJournalCheckpoint,
        risk: RiskStateReceipt,
        facts: Sequence[RuntimeFactReceipt],
        *,
        checked_at: datetime | None = None,
    ) -> None:
        checked_at = (
            self._now()
            if checked_at is None
            else require_utc("cycle evidence freshness time", checked_at)
        )
        if not (
            journal_checkpoint.checked_at_utc
            <= checked_at
            < journal_checkpoint.valid_until_utc
        ):
            raise RuntimeSupervisorCriticalError(
                "JOURNAL_CHECKPOINT_EXPIRED_DURING_CYCLE"
            )
        risk_age = (checked_at - risk.issued_at_utc).total_seconds()
        if risk_age < 0 or risk_age > MAX_RISK_RECEIPT_AGE_SECONDS:
            raise RuntimeSupervisorCriticalError(
                "RISK_RECEIPT_EXPIRED_DURING_CYCLE"
            )
        self._require_facts_still_fresh(facts, checked_at=checked_at)

    def _require_decision_fresh(
        self,
        decision: RuntimeSupervisorDecision,
        *,
        reason_code: str,
        checked_at: datetime | None = None,
    ) -> None:
        """Re-check one immutable decision against the trusted clock.

        Approval, policy, checkpoint-custody, and news-provider calls are all
        external ports and may block.  A decision that was current before one
        of those calls is not authorization to dispatch afterwards.
        """

        current = (
            self._now()
            if checked_at is None
            else require_utc("decision freshness time", checked_at)
        )
        decision_age = (current - decision.decided_at_utc).total_seconds()
        if decision_age < 0 or decision_age > MAX_DECISION_AGE_SECONDS:
            raise RuntimeSupervisorCriticalError(reason_code)

    def _reverify_runtime_facts(
        self,
        facts: Sequence[RuntimeFactReceipt],
    ) -> None:
        """Re-authenticate the exact decision-time facts before dispatch."""

        if not facts:
            raise RuntimeSupervisorCriticalError("RUNTIME_FACT_RECEIPTS_MISSING")
        for receipt in facts:
            checked = self.runtime_fact_verifier(receipt)
            if type(checked) is not RuntimeFactReceipt or checked is not receipt:
                raise RuntimeSupervisorIntegrityError(
                    "runtime fact verifier did not return the exact sealed receipt"
                )
            if (
                not checked.health_decision.healthy
                or checked.live_allowed
                or checked.safe_to_demo_auto_order
            ):
                raise RuntimeSupervisorCriticalError(
                    "RUNTIME_FACT_CHANGED_BEFORE_DISPATCH"
                )
        self._require_facts_still_fresh(facts)

    def _require_news_guard_current(
        self,
        guard: RuntimeNewsGuard | RuntimeNewsGuardReceipt,
        *,
        checked_at: datetime | None = None,
    ) -> None:
        """Require the already verified final guard to remain current."""

        now = (
            self._now()
            if checked_at is None
            else require_utc("news guard freshness time", checked_at)
        )
        if type(guard) is RuntimeNewsGuardReceipt:
            if not guard.observed_at_utc <= now < guard.valid_until_utc:
                raise RuntimeSupervisorCriticalError(
                    "NEWS_GUARD_EXPIRED_DURING_DISPATCH"
                )
        else:
            age = (now - guard.observed_at_utc).total_seconds()
            if age < 0 or age > 30:
                raise RuntimeSupervisorCriticalError(
                    "NEWS_GUARD_EXPIRED_DURING_DISPATCH"
                )
        if not guard.news_feed_fresh:
            raise RuntimeSupervisorCriticalError("NEWS_FEED_STALE")
        if guard.news_blackout_active:
            raise RuntimeSupervisorCriticalError("NEWS_BLACKOUT_ACTIVE")
        if guard.rollover_blackout_active:
            raise RuntimeSupervisorCriticalError("ROLLOVER_BLACKOUT_ACTIVE")

    def _verify_news_guard(self) -> RuntimeNewsGuard | RuntimeNewsGuardReceipt:
        guard = self.news_guard_provider()
        if self.allow_legacy_shadow_news_guard:
            if self.binding.mode != "SHADOW" or type(guard) is not RuntimeNewsGuard:
                raise RuntimeSupervisorCriticalError("LEGACY_NEWS_GUARD_INVALID")
            age = (self._now() - guard.observed_at_utc).total_seconds()
            if age < 0 or age > 30:
                raise RuntimeSupervisorCriticalError("NEWS_GUARD_STALE")
        else:
            if type(guard) is not RuntimeNewsGuardReceipt:
                raise RuntimeSupervisorCriticalError("SIGNED_NEWS_GUARD_REQUIRED")
            assert self.news_guard_verifier is not None
            checked = self.news_guard_verifier(guard)
            if type(checked) is not RuntimeNewsGuardReceipt or checked is not guard:
                raise RuntimeSupervisorIntegrityError(
                    "news guard verifier did not return the exact sealed receipt"
                )
            if (
                guard.provider_id != self.news_guard_provider_id
                or guard.key_id != self.news_guard_key_id
                or guard.account_id_sha256 != self.binding.account_id_sha256
                or guard.server != self.binding.server
                or guard.environment != self.binding.environment
                or guard.config_sha256 != self.binding.config_sha256
                or guard.ruleset_sha256 != self.news_guard_ruleset_sha256
                or guard.blackout_window_sha256
                != self.news_guard_blackout_window_sha256
            ):
                raise RuntimeSupervisorBindingError("news guard binding mismatch")
            now = self._now()
            if not guard.observed_at_utc <= now < guard.valid_until_utc:
                raise RuntimeSupervisorCriticalError("NEWS_GUARD_STALE_OR_FUTURE")
            prior = self.store.latest_news_guard(guard.provider_id)
            expected_previous = ZERO_HMAC_SHA256 if prior is None else prior[1]
            if (
                guard.previous_receipt_sha256 != expected_previous
                or (prior is not None and guard.feed_sequence <= prior[0])
            ):
                raise RuntimeSupervisorCriticalError(
                    "NEWS_GUARD_REPLAY_ROLLBACK_OR_FORK"
                )
        if not guard.news_feed_fresh:
            raise RuntimeSupervisorCriticalError("NEWS_FEED_STALE")
        if guard.news_blackout_active:
            raise RuntimeSupervisorCriticalError("NEWS_BLACKOUT_ACTIVE")
        if guard.rollover_blackout_active:
            raise RuntimeSupervisorCriticalError("ROLLOVER_BLACKOUT_ACTIVE")
        return guard

    def _verify_stage_authorization(
        self,
    ) -> tuple[
        StageReadinessAuthorization,
        StageAuthorizationValidation,
        StageReplayCheckpoint,
        StageReplayCheckpoint,
    ] | None:
        if self.binding.mode == "SHADOW":
            return None
        if self.binding.mode in {"LIVE", "DEMO_AUTO"}:
            mode_allowed, _reason_codes = (
                execution_policy.execution_mode_policy_decision(self.binding.mode)
            )
            if not mode_allowed:
                raise RuntimeSupervisorCriticalError(
                    f"{self.binding.mode}_MODE_POLICY_LOCKED"
                )
        ports = self.stage_authorization_ports
        if type(ports) is not RuntimeStageAuthorizationPorts:
            raise RuntimeSupervisorCriticalError("STAGE_AUTHORIZATION_PORTS_MISSING")
        expected_mode = "MANUAL_DEMO" if self.binding.mode == "DEMO" else "DEMO_AUTO"
        authorization = ports.authorization
        stage_binding = ports.expected_binding
        if (
            authorization.request.mode != expected_mode
            or authorization.request.binding != stage_binding
            or stage_binding.binding_sha256 != self.binding.stage_binding_sha256
            or stage_binding.account_alias_sha256 != self.binding.account_id_sha256
            or stage_binding.server != self.binding.server
            or stage_binding.environment != self.binding.environment
            or stage_binding.journal_sha256 != self.binding.journal_sha256
            or stage_binding.commit_sha != self.binding.commit_sha
            or stage_binding.config_sha256 != self.binding.config_sha256
        ):
            raise RuntimeSupervisorBindingError("stage authorization binding mismatch")
        if self.store.stage_authorization_seen(
            authorization.authorization_id, authorization.content_sha256
        ):
            raise RuntimeSupervisorCriticalError("STAGE_AUTHORIZATION_REPLAYED")
        checked_at = self._now()
        external = ports.replay_registry.verify_checkpoint(
            ports.external_replay_checkpoint,
            key_provider=ports.checkpoint_key_provider,
            require_current=True,
        )
        if (
            type(external) is not StageReplayCheckpoint
            or external is not ports.external_replay_checkpoint
            or external.issued_at > checked_at
        ):
            raise RuntimeSupervisorIntegrityError(
                "external stage replay checkpoint verification failed"
            )
        validation = ports.authorization_validator(checked_at, expected_mode)
        if (
            type(validation) is not StageAuthorizationValidation
            or not validation.valid
            or not validation.consumed_once
            or not validation.evidence_eligible_for_review
            or validation.mode != expected_mode
            or validation.authorization_id != authorization.authorization_id
            or validation.authorization_sha256 != authorization.content_sha256
            or validation.request_sha256 != authorization.request.request_sha256
            or validation.binding_sha256 != stage_binding.binding_sha256
            or validation.checked_at != checked_at
            or validation.execution_authorized
            or validation.activation_authorized
            or validation.safe_to_demo_auto_order
            or validation.live_allowed
            or validation.order_capability != "DISABLED"
        ):
            raise RuntimeSupervisorCriticalError(
                "STAGE_AUTHORIZATION_VALIDATION_FAILED"
            )
        checkpoint_issued_at = self._now()
        checkpoint = ports.replay_registry.create_checkpoint(
            issued_at=checkpoint_issued_at,
            checkpoint_key_id=ports.checkpoint_key_id,
            checkpoint_secret=ports.checkpoint_key_provider(ports.checkpoint_key_id),
        )
        checked_checkpoint = ports.replay_registry.verify_checkpoint(
            checkpoint,
            key_provider=ports.checkpoint_key_provider,
            require_current=True,
        )
        checkpoint_age = (self._now() - checkpoint.issued_at).total_seconds()
        if (
            type(checkpoint) is not StageReplayCheckpoint
            or checked_checkpoint is not checkpoint
            or checkpoint.event_count != external.event_count + 1
            or checkpoint.last_authorization_id != authorization.authorization_id
            or checkpoint.registry_id != external.registry_id
            or checkpoint.registry_key_id != external.registry_key_id
            or checkpoint.registry_key_fingerprint_sha256
            != external.registry_key_fingerprint_sha256
            or checkpoint_age < 0
            or checkpoint_age > 5
        ):
            raise RuntimeSupervisorIntegrityError(
                "post-consumption stage replay checkpoint is invalid"
            )
        return authorization, validation, external, checkpoint

    def _startup_checks(
        self,
    ) -> tuple[
        ExecutionJournalCheckpoint,
        RiskStateReceipt,
        RuntimeReconciliationRiskResult,
        tuple[RuntimeFactReceipt, ...],
        RuntimeNewsGuard | RuntimeNewsGuardReceipt,
    ]:
        self.store.verify_integrity()
        self._verify_external_supervisor_checkpoint()
        critical = self.store.critical_state()
        if critical["critical_latched"] is True:
            raise RuntimeSupervisorCriticalError(
                "SUPERVISOR_CRITICAL_LATCHED"
            )
        self._verify_journal()
        journal_checkpoint = self._verify_journal_checkpoint()
        risk = self._verify_risk()
        reconciliation = self._verify_reconciliation(self.reconciliation_provider())
        risk = self._append_reconciled_closed_trades(reconciliation, risk)
        facts = self._verify_facts()
        self._verify_reconciliation_snapshot_facts(reconciliation, risk, facts)
        guard = self._verify_news_guard()
        return journal_checkpoint, risk, reconciliation, facts, guard

    @staticmethod
    def _news_store_fields(
        guard: RuntimeNewsGuard | RuntimeNewsGuardReceipt,
    ) -> dict[str, object | None]:
        if type(guard) is RuntimeNewsGuardReceipt:
            return {
                "news_guard_sha256": guard.content_sha256,
                "news_guard_provider_id": guard.provider_id,
                "news_guard_feed_sequence": guard.feed_sequence,
                "news_guard_previous_sha256": guard.previous_receipt_sha256,
            }
        return {
            "news_guard_sha256": guard.content_sha256,
            "news_guard_provider_id": None,
            "news_guard_feed_sequence": None,
            "news_guard_previous_sha256": None,
        }

    def start(
        self,
        *,
        owner_id: str,
        lease_seconds: int = 30,
    ) -> RuntimeSupervisorCycleReceipt:
        if self.owner_id is not None:
            raise RuntimeSupervisorError("supervisor is already started")
        self.lease_seconds = require_int(
            "lease_seconds", lease_seconds, minimum=1, maximum=300
        )
        try:
            self._verify_external_supervisor_checkpoint()
            self.owner_id = require_text("owner_id", owner_id)
            self.fence_token = self.store.claim(
                self.owner_id,
                lease_seconds=self.lease_seconds,
                now=self._now(),
            )
            if self.binding.mode in {"LIVE", "DEMO_AUTO"}:
                mode_allowed, _reason_codes = (
                    execution_policy.execution_mode_policy_decision(
                        self.binding.mode
                    )
                )
                if not mode_allowed:
                    raise RuntimeSupervisorCriticalError(
                        f"{self.binding.mode}_MODE_POLICY_LOCKED"
                    )
            journal_checkpoint, risk, reconciliation, facts, guard = self._startup_checks()
            stage_evidence = self._verify_stage_authorization()
            owner, fence = self._lease()
            self._require_cycle_evidence_fresh(journal_checkpoint, risk, facts)
            receipt = self._append_and_checkpoint(
                owner_id=owner,
                fence_token=fence,
                cycle_id=f"startup-{uuid.uuid4().hex}",
                phase="STARTUP",
                status="READY",
                occurred_at=self._now(),
                reconciliation_status=reconciliation.reconciliation.status,
                journal_checkpoint_sha256=journal_checkpoint.content_sha256,
                risk_receipt_hmac_sha256=risk.receipt_hmac_sha256,
                runtime_fact_receipt_sha256s=tuple(item.content_sha256 for item in facts),
                **self._news_store_fields(guard),
                stage_mode=None if stage_evidence is None else stage_evidence[1].mode,
                stage_authorization_id=(
                    None if stage_evidence is None else stage_evidence[0].authorization_id
                ),
                stage_authorization_sha256=(
                    None if stage_evidence is None else stage_evidence[0].content_sha256
                ),
                stage_validation_sha256=(
                    None if stage_evidence is None else stage_evidence[1].content_sha256
                ),
                stage_external_checkpoint_sha256=(
                    None if stage_evidence is None else stage_evidence[2].content_sha256
                ),
                stage_replay_checkpoint_sha256=(
                    None if stage_evidence is None else stage_evidence[3].content_sha256
                ),
            )
            self._state = "READY"
            self._stopped = False
            self._stop_reason = None
            return receipt
        except Exception as exc:
            if isinstance(exc, RuntimeSupervisorLeaseError) and self.fence_token is None:
                self.owner_id = None
                raise
            reason = (
                str(exc)
                if isinstance(exc, RuntimeSupervisorCriticalError)
                else "STARTUP_VERIFICATION_FAILED"
            )
            self._latch_and_stop(reason, exc=exc)
            raise AssertionError("unreachable")

    def _execute_demo_auto_decision(
        self,
        *,
        cycle_id: str,
        decision: RuntimeSupervisorDecision,
        reconciliation: RuntimeReconciliationRiskResult,
        journal_checkpoint: ExecutionJournalCheckpoint,
        risk: RiskStateReceipt,
        facts: tuple[RuntimeFactReceipt, ...],
        guard: RuntimeNewsGuard | RuntimeNewsGuardReceipt,
    ) -> tuple[
        str,
        RiskStateReceipt,
        ExecutionJournalCheckpoint,
        RuntimeNewsGuardReceipt,
    ]:
        """Dispatch one dormant DEMO_AUTO decision under exact fresh custody."""

        if self.binding.mode != "DEMO_AUTO" or self.binding.environment != "DEMO":
            raise RuntimeSupervisorCriticalError("DEMO_AUTO_EXECUTION_MODE_DENIED")
        mode_allowed, reason_codes = execution_policy.execution_mode_policy_decision(
            "DEMO_AUTO"
        )
        if not mode_allowed:
            raise RuntimeSupervisorCriticalError(reason_codes[0])
        required_ports = (
            self.demo_auto_ipc_input_provider,
            self.demo_auto_session_lease_provider,
            self.demo_auto_permit_validation_provider,
            self.demo_auto_promotion_validation_provider,
            self.demo_auto_environment_arm_provider,
            self.demo_auto_execution_service,
        )
        if any(not callable(port) for port in required_ports):
            raise RuntimeSupervisorCriticalError("DEMO_AUTO_EXECUTION_PORTS_MISSING")
        from .demo_auto_session_capability import DemoAutoSessionCapabilityStore

        if type(self.demo_auto_session_store) is not DemoAutoSessionCapabilityStore:
            raise RuntimeSupervisorCriticalError("DEMO_AUTO_SESSION_STORE_MISSING")
        assert self.demo_auto_ipc_input_provider is not None
        assert self.demo_auto_session_lease_provider is not None
        assert self.demo_auto_permit_validation_provider is not None
        assert self.demo_auto_promotion_validation_provider is not None
        assert self.demo_auto_environment_arm_provider is not None
        assert self.demo_auto_execution_service is not None
        session_store = self.demo_auto_session_store

        # Record the exact decision before the one-use IPC consume.  If the
        # process dies after the queue CAS but before PRE_DISPATCH, restart has
        # an auditable safe-loss marker and can never replay the consumed
        # envelope into a second broker attempt.
        owner, fence = self._lease()
        self._append_and_checkpoint(
            owner_id=owner,
            fence_token=fence,
            cycle_id=f"{cycle_id}-preconsume",
            phase="PRE_CONSUME",
            status="AWAITING_ONE_USE_IPC",
            occurred_at=self._now(),
            reconciliation_status=reconciliation.reconciliation.status,
            journal_checkpoint_sha256=journal_checkpoint.content_sha256,
            risk_receipt_hmac_sha256=risk.receipt_hmac_sha256,
            runtime_fact_receipt_sha256s=tuple(
                item.content_sha256 for item in facts
            ),
            **self._news_store_fields(guard),
            decision_id=decision.decision_id,
            decision_payload_sha256=decision.decision_payload_sha256,
        )

        # The IPC provider must durably consume the candidate exactly once.
        ipc_input = self.demo_auto_ipc_input_provider(decision)
        owner, fence = self._lease()
        self._append_and_checkpoint(
            owner_id=owner,
            fence_token=fence,
            cycle_id=f"{cycle_id}-predispatch",
            phase="PRE_DISPATCH",
            status="AWAITING_DEMO_AUTO_CONTROLS",
            occurred_at=self._now(),
            reconciliation_status=reconciliation.reconciliation.status,
            journal_checkpoint_sha256=journal_checkpoint.content_sha256,
            risk_receipt_hmac_sha256=risk.receipt_hmac_sha256,
            runtime_fact_receipt_sha256s=tuple(
                item.content_sha256 for item in facts
            ),
            **self._news_store_fields(guard),
            decision_id=decision.decision_id,
            decision_payload_sha256=decision.decision_payload_sha256,
        )

        # Refresh every mutable safety fact after the one-use IPC consumption.
        self._require_decision_fresh(
            decision,
            reason_code="DECISION_EXPIRED_DURING_DISPATCH",
        )
        supervisor_checkpoint = self._verify_external_supervisor_checkpoint()
        if self.store.critical_state()["critical_latched"] is True:
            raise RuntimeSupervisorCriticalError("SUPERVISOR_CRITICAL_LATCHED")
        self._verify_journal()
        refreshed_journal = self._verify_journal_checkpoint()
        if refreshed_journal.content_sha256 != journal_checkpoint.content_sha256:
            raise RuntimeSupervisorCriticalError(
                "JOURNAL_STATE_CHANGED_BEFORE_DISPATCH"
            )
        refreshed_risk = self._verify_risk()
        if refreshed_risk.content_sha256 != risk.content_sha256:
            raise RuntimeSupervisorCriticalError(
                "RISK_STATE_CHANGED_BEFORE_DISPATCH"
            )
        risk = refreshed_risk
        self._reverify_runtime_facts(facts)
        self._verify_reconciliation_snapshot_facts(reconciliation, risk, facts)
        self._require_cycle_evidence_fresh(journal_checkpoint, risk, facts)
        self._require_execution_account_snapshot(
            risk,
            facts,
            evidence=reconciliation.account_snapshot_evidence,
        )
        final_guard = self._verify_news_guard()
        if (
            type(final_guard) is not RuntimeNewsGuardReceipt
            or type(guard) is not RuntimeNewsGuardReceipt
            or final_guard.content_sha256 == guard.content_sha256
            or final_guard.feed_sequence <= guard.feed_sequence
            or final_guard.previous_receipt_sha256 != guard.content_sha256
        ):
            raise RuntimeSupervisorCriticalError(
                "PREDISPATCH_NEWS_GUARD_REFRESH_REQUIRED"
            )

        # A renewable session lease is requested only after PRE_DISPATCH is
        # durably checkpointed, so it must bind that exact supervisor head.
        session_lease = self.demo_auto_session_lease_provider(decision, ipc_input)
        session_checkpoint = session_store.current_checkpoint()
        permit_validation = self.demo_auto_permit_validation_provider(
            decision, ipc_input
        )
        promotion_validation = self.demo_auto_promotion_validation_provider(
            decision, ipc_input
        )
        environment_arm = self.demo_auto_environment_arm_provider(
            decision, ipc_input
        )
        session_dispatch_verification = session_store.issue_dispatch_verification(
            session_lease,
            intent_id=decision.intent_id,
            valid_until_utc=min(
                ipc_input.valid_until_utc,
                session_lease.expires_at_utc,
                permit_validation.expires_at,
                promotion_validation.expires_at,
                environment_arm.expires_at_utc,
            ),
        )

        # Final boundary: no authorization callbacks are permitted after this
        # verification and before the execution service receives control.
        dispatch_at = self._now()
        mode_allowed, reason_codes = execution_policy.execution_mode_policy_decision(
            "DEMO_AUTO"
        )
        if not mode_allowed:
            raise RuntimeSupervisorCriticalError(reason_codes[0])
        current_supervisor = self._verify_external_supervisor_checkpoint()
        if current_supervisor.content_sha256 != supervisor_checkpoint.content_sha256:
            raise RuntimeSupervisorCriticalError(
                "SUPERVISOR_CHECKPOINT_CHANGED_BEFORE_DISPATCH"
            )
        self._verify_journal()
        current_journal = self._verify_journal_checkpoint()
        if current_journal.content_sha256 != journal_checkpoint.content_sha256:
            raise RuntimeSupervisorCriticalError(
                "JOURNAL_STATE_CHANGED_BEFORE_DISPATCH"
            )
        current_risk = self._verify_risk()
        if current_risk.content_sha256 != risk.content_sha256:
            raise RuntimeSupervisorCriticalError(
                "RISK_STATE_CHANGED_BEFORE_DISPATCH"
            )
        self._reverify_runtime_facts(facts)
        self._require_execution_account_snapshot(
            current_risk,
            facts,
            evidence=reconciliation.account_snapshot_evidence,
        )
        self._require_news_guard_current(final_guard, checked_at=dispatch_at)
        self._require_cycle_evidence_fresh(
            current_journal,
            current_risk,
            facts,
            checked_at=dispatch_at,
        )
        self._require_decision_fresh(
            decision,
            reason_code="DECISION_EXPIRED_DURING_DISPATCH",
            checked_at=dispatch_at,
        )
        self._lease()
        _verify_demo_auto_dispatch_controls(
            binding=self.binding,
            decision=decision,
            ipc_input=ipc_input,
            session_store=session_store,
            session_lease=session_lease,
            session_checkpoint=session_checkpoint,
            session_dispatch_verification=session_dispatch_verification,
            permit_validation=permit_validation,
            promotion_validation=promotion_validation,
            environment_arm=environment_arm,
            supervisor_checkpoint=current_supervisor,
            checked_at=dispatch_at,
        )

        result = self.demo_auto_execution_service(
            decision,
            ipc_input,
            session_store,
            session_lease,
            session_checkpoint,
            session_dispatch_verification,
            permit_validation,
            promotion_validation,
            environment_arm,
            current_supervisor,
            current_journal,
            current_risk,
            reconciliation,
        )
        if type(result) is not RuntimeDemoAutoExecutionResult:
            raise RuntimeSupervisorCriticalError(
                "DEMO_AUTO_EXECUTION_RESULT_EVIDENCE_INVALID"
            )
        expected_hashes = (
            result.decision_id == decision.decision_id,
            result.decision_payload_sha256 == decision.decision_payload_sha256,
            result.ipc_input_sha256 == ipc_input.content_sha256,
            result.session_store_binding_sha256
            == session_store.binding.content_sha256,
            result.session_lease_sha256 == session_lease.content_sha256,
            result.session_checkpoint_sha256 == session_checkpoint.content_sha256,
            result.session_dispatch_verification_sha256
            == session_dispatch_verification.content_sha256,
            result.permit_validation_sha256 == permit_validation.content_sha256,
            result.promotion_validation_sha256
            == promotion_validation.content_sha256,
            result.environment_arm_sha256 == environment_arm.content_sha256,
            result.supervisor_checkpoint_sha256
            == current_supervisor.content_sha256,
            result.journal_checkpoint_sha256 == current_journal.content_sha256,
            result.risk_receipt_sha256 == current_risk.content_sha256,
            result.reconciliation_receipt_sha256
            == reconciliation.content_sha256,
            result.execution_receipt.intent_id == decision.intent_id,
        )
        if not all(expected_hashes):
            raise RuntimeSupervisorCriticalError(
                "DEMO_AUTO_EXECUTION_RESULT_BINDING_INVALID"
            )
        risk = self._append_entry_risk_event(result, current_risk)
        self._verify_journal()
        journal_checkpoint = self._verify_journal_checkpoint()
        self._require_cycle_evidence_fresh(journal_checkpoint, risk, facts)
        return result.content_sha256, risk, journal_checkpoint, final_guard

    def run_cycle(self) -> RuntimeSupervisorCycleReceipt:
        if self._state != "READY" or self._stopped:
            raise RuntimeSupervisorError("supervisor is not ready")
        cycle_id = f"cycle-{uuid.uuid4().hex}"
        try:
            owner, fence = self._lease()
            # Reconciliation is deliberately the first external cycle operation.
            reconciliation = self._verify_reconciliation(self.reconciliation_provider())
            self._verify_journal()
            journal_checkpoint = self._verify_journal_checkpoint()
            risk = self._verify_risk()
            risk = self._append_reconciled_closed_trades(reconciliation, risk)
            facts = self._verify_facts()
            self._verify_reconciliation_snapshot_facts(reconciliation, risk, facts)
            guard = self._verify_news_guard()
            owner, fence = self._lease()
            self._require_cycle_evidence_fresh(journal_checkpoint, risk, facts)
            decision = self.decision_provider(facts, risk)
            if type(decision) is not RuntimeSupervisorDecision:
                raise RuntimeSupervisorCriticalError("DECISION_RESULT_INVALID")
            self._require_decision_fresh(
                decision,
                reason_code="DECISION_STALE_OR_FUTURE",
            )
            self._require_cycle_evidence_fresh(journal_checkpoint, risk, facts)
            execution_called = False
            execution_result_sha: str | None = None
            if decision.action == "MANUAL_DEMO_EXECUTE":
                if self.binding.mode != "DEMO" or self.binding.environment != "DEMO":
                    raise RuntimeSupervisorCriticalError("MANUAL_EXECUTION_MODE_DENIED")
                if (
                    self.manual_approval_provider is None
                    or self.manual_demo_policy_callback is None
                    or self.execution_service is None
                ):
                    raise RuntimeSupervisorCriticalError(
                        "MANUAL_EXECUTION_PORTS_MISSING"
                    )
                # The first signed news receipt must become the durable accepted
                # predecessor before the external approval/policy callbacks can
                # block.  The final pre-dispatch refresh below can then require
                # a genuinely new signed successor without weakening the store's
                # monotonic news chain.
                owner, fence = self._lease()
                self._append_and_checkpoint(
                    owner_id=owner,
                    fence_token=fence,
                    cycle_id=f"{cycle_id}-predispatch",
                    phase="PRE_DISPATCH",
                    status="AWAITING_APPROVAL",
                    occurred_at=self._now(),
                    reconciliation_status=reconciliation.reconciliation.status,
                    journal_checkpoint_sha256=journal_checkpoint.content_sha256,
                    risk_receipt_hmac_sha256=risk.receipt_hmac_sha256,
                    runtime_fact_receipt_sha256s=tuple(
                        item.content_sha256 for item in facts
                    ),
                    **self._news_store_fields(guard),
                    decision_id=decision.decision_id,
                    decision_payload_sha256=decision.decision_payload_sha256,
                )
                validation = self.manual_approval_provider(decision)
                now = self._now()
                if (
                    type(validation) is not ManualDemoApprovalValidation
                    or not validation.valid
                    or not validation.is_fresh(now)
                    or validation.intent_id != decision.intent_id
                    or validation.account_id_sha256
                    != self.binding.account_id_sha256
                    or validation.server != self.binding.server
                    or validation.journal_sha256 != self.binding.journal_sha256
                    or validation.mode != "DEMO"
                ):
                    raise RuntimeSupervisorCriticalError(
                        "MANUAL_APPROVAL_VALIDATION_FAILED"
                    )
                policy_allowed = self.manual_demo_policy_callback(decision, validation)
                if policy_allowed is not True:
                    raise RuntimeSupervisorCriticalError("MANUAL_POLICY_DENIED")

                # Every potentially blocking authorization callback is now
                # behind us.  Re-check the decision and all execution-critical
                # evidence, then obtain a new signed news receipt whose exact
                # predecessor is the durable PRE_DISPATCH receipt above.
                self._require_decision_fresh(
                    decision,
                    reason_code="DECISION_EXPIRED_DURING_DISPATCH",
                )
                self._verify_external_supervisor_checkpoint()
                if self.store.critical_state()["critical_latched"] is True:
                    raise RuntimeSupervisorCriticalError(
                        "SUPERVISOR_CRITICAL_LATCHED"
                    )
                self._verify_journal()
                journal_checkpoint = self._verify_journal_checkpoint()
                refreshed_risk = self._verify_risk()
                if refreshed_risk.content_sha256 != risk.content_sha256:
                    raise RuntimeSupervisorCriticalError(
                        "RISK_STATE_CHANGED_BEFORE_DISPATCH"
                    )
                risk = refreshed_risk
                self._reverify_runtime_facts(facts)
                self._verify_reconciliation_snapshot_facts(
                    reconciliation,
                    risk,
                    facts,
                )
                self._require_cycle_evidence_fresh(journal_checkpoint, risk, facts)
                self._require_execution_account_snapshot(
                    risk,
                    facts,
                    evidence=reconciliation.account_snapshot_evidence,
                )
                self._lease()
                final_guard = self._verify_news_guard()
                if (
                    type(final_guard) is not RuntimeNewsGuardReceipt
                    or type(guard) is not RuntimeNewsGuardReceipt
                    or final_guard.content_sha256 == guard.content_sha256
                    or final_guard.feed_sequence <= guard.feed_sequence
                    or final_guard.previous_receipt_sha256
                    != guard.content_sha256
                ):
                    raise RuntimeSupervisorCriticalError(
                        "PREDISPATCH_NEWS_GUARD_REFRESH_REQUIRED"
                    )
                guard = final_guard

                # These checks intentionally contain no approval or policy
                # callbacks.  They are the final dispatch boundary immediately
                # before the execution service receives control.
                self._verify_external_supervisor_checkpoint()
                if self.store.critical_state()["critical_latched"] is True:
                    raise RuntimeSupervisorCriticalError(
                        "SUPERVISOR_CRITICAL_LATCHED"
                    )
                self._verify_journal()
                self._require_execution_account_snapshot(
                    risk,
                    facts,
                    evidence=reconciliation.account_snapshot_evidence,
                )
                self._lease()
                dispatch_at = self._now()
                self._require_cycle_evidence_fresh(
                    journal_checkpoint,
                    risk,
                    facts,
                    checked_at=dispatch_at,
                )
                self._require_decision_fresh(
                    decision,
                    reason_code="DECISION_EXPIRED_DURING_DISPATCH",
                    checked_at=dispatch_at,
                )
                if not validation.is_fresh(dispatch_at):
                    raise RuntimeSupervisorCriticalError(
                        "MANUAL_APPROVAL_EXPIRED_DURING_DISPATCH"
                    )
                self._require_news_guard_current(
                    guard,
                    checked_at=dispatch_at,
                )
                result = self.execution_service(decision, validation)
                execution_called = True
                if type(result) is not RuntimeManualDemoExecutionResult:
                    raise RuntimeSupervisorCriticalError(
                        "MANUAL_EXECUTION_RESULT_EVIDENCE_INVALID"
                    )
                execution_result_sha = result.content_sha256
                risk = self._append_entry_risk_event(result, risk)
                # The execution service may append intents, transitions, or
                # receipts.  Advance off-host journal custody before recording
                # the completed supervisor cycle.
                self._verify_journal()
                journal_checkpoint = self._verify_journal_checkpoint()
                self._require_cycle_evidence_fresh(
                    journal_checkpoint,
                    risk,
                    facts,
                )
            elif decision.action == "DEMO_AUTO_EXECUTE":
                (
                    execution_result_sha,
                    risk,
                    journal_checkpoint,
                    guard,
                ) = self._execute_demo_auto_decision(
                    cycle_id=cycle_id,
                    decision=decision,
                    reconciliation=reconciliation,
                    journal_checkpoint=journal_checkpoint,
                    risk=risk,
                    facts=facts,
                    guard=guard,
                )
                execution_called = True
            owner, fence = self._lease()
            return self._append_and_checkpoint(
                owner_id=owner,
                fence_token=fence,
                cycle_id=cycle_id,
                phase="CYCLE",
                status="COMPLETE",
                occurred_at=self._now(),
                reconciliation_status=reconciliation.reconciliation.status,
                journal_checkpoint_sha256=journal_checkpoint.content_sha256,
                risk_receipt_hmac_sha256=risk.receipt_hmac_sha256,
                runtime_fact_receipt_sha256s=tuple(item.content_sha256 for item in facts),
                **self._news_store_fields(guard),
                decision_id=decision.decision_id,
                decision_payload_sha256=decision.decision_payload_sha256,
                execution_service_called=execution_called,
                execution_result_sha256=execution_result_sha,
            )
        except Exception as exc:
            reason = (
                str(exc)
                if isinstance(exc, RuntimeSupervisorCriticalError)
                else (
                    "SUPERVISOR_LEASE_LOST"
                    if isinstance(exc, RuntimeSupervisorLeaseError)
                    else "RUNTIME_CYCLE_FAILED"
                )
            )
            self._latch_and_stop(reason, exc=exc)
            raise AssertionError("unreachable")

    def run_bounded(self, *, max_cycles: int) -> tuple[RuntimeSupervisorCycleReceipt, ...]:
        count = require_int("max_cycles", max_cycles, minimum=1, maximum=100_000)
        receipts: list[RuntimeSupervisorCycleReceipt] = []
        for _ in range(count):
            receipts.append(self.run_cycle())
        self.stop()
        return tuple(receipts)

    def fail_closed(
        self,
        reason_code: str,
        *,
        cause: Exception | None = None,
    ) -> None:
        """Public critical-abort boundary for composition-level failures.

        This persists the supervisor critical latch first, latches the execution
        journal, advances journal custody through its CAS exporter, releases the
        runtime lease, and always raises ``RuntimeSupervisorCriticalError``.
        """

        self._latch_and_stop(reason_code, exc=cause)
        raise AssertionError("unreachable")

    @property
    def is_stopped_critical(self) -> bool:
        """Return the local irreversible lifecycle state without mutating it."""

        return self._state == "STOPPED_CRITICAL" and self._stopped

    def stop(self) -> RuntimeSupervisorCycleReceipt | None:
        if self.owner_id is None or self.fence_token is None:
            if self.is_stopped_critical:
                return None
            self._state = "STOPPED"
            self._stopped = True
            return None
        try:
            owner, fence = self._lease()
            shutdown_receipt = self._append_and_checkpoint(
                owner_id=owner,
                fence_token=fence,
                cycle_id=f"shutdown-{uuid.uuid4().hex}",
                phase="SHUTDOWN",
                status="COMPLETE",
                occurred_at=self._now(),
            )
            self.store.release(owner, fence)
            self.owner_id = None
            self.fence_token = None
            self._state = "STOPPED"
            self._stopped = True
            self._stop_reason = None
            return shutdown_receipt
        except Exception as exc:
            reason = (
                "SUPERVISOR_LEASE_LOST"
                if isinstance(exc, RuntimeSupervisorLeaseError)
                else "SUPERVISOR_SHUTDOWN_FAILED"
            )
            self._latch_and_stop(reason, exc=exc)

    def status(self) -> RuntimeSupervisorStatus:
        return RuntimeSupervisorStatus(
            state=self._state,
            owner_id=self.owner_id,
            fence_token=self.fence_token,
            receipts=self.store.receipt_count(),
            stopped=self._stopped,
            stop_reason=self._stop_reason,
        )

    def verify_integrity(self) -> bool:
        try:
            return self.store.verify_integrity()
        except Exception as exc:
            self._latch_and_stop("SUPERVISOR_INTEGRITY_FAILED", exc=exc)
            raise AssertionError("unreachable")

    def storage_settings(self) -> Mapping[str, object]:
        return self.store.storage_settings()


__all__ = [
    "LIVE_ALLOWED",
    "NEWS_GUARD_SCHEMA_VERSION",
    "NEWS_GUARD_RECEIPT_SCHEMA_VERSION",
    "ORDER_CAPABILITY",
    "RuntimeNewsGuard",
    "RuntimeNewsGuardReceipt",
    "RuntimeStageAuthorizationPorts",
    "RuntimeSupervisor",
    "RuntimeSupervisorBinding",
    "RuntimeSupervisorBindingError",
    "RuntimeSupervisorCheckpoint",
    "RuntimeSupervisorCheckpointCASAcknowledgement",
    "RuntimeSupervisorCriticalError",
    "RuntimeSupervisorCycleReceipt",
    "RuntimeSupervisorDecision",
    "RuntimeDemoAutoExecutionResult",
    "RuntimeManualDemoExecutionResult",
    "RuntimeClosedTradeRiskEvidence",
    "RuntimeReconciliationRiskResult",
    "RuntimeSupervisorError",
    "RuntimeSupervisorIntegrityError",
    "RuntimeSupervisorLeaseError",
    "RuntimeSupervisorNewsHead",
    "RuntimeSupervisorStatus",
    "SUPERVISOR_CHECKPOINT_SCHEMA_VERSION",
    "SUPERVISOR_CHECKPOINT_CAS_ACK_SCHEMA_VERSION",
    "SAFE_TO_DEMO_AUTO_ORDER",
    "issue_runtime_news_guard_receipt",
    "runtime_news_guard_trust_sha256",
    "seal_runtime_demo_auto_execution_result",
    "seal_runtime_manual_demo_execution_result",
    "seal_runtime_reconciliation_risk_result",
    "verify_runtime_news_guard_receipt",
    "verify_runtime_supervisor_checkpoint_signature",
]
