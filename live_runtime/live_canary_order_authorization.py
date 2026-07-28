"""Verifier-sealed authority for exactly one bounded LIVE canary order.

The launch session admitted by :mod:`live_canary_runtime_launch_session` is
deliberately launch-only.  This module joins that session to one immutable
intent and to the fresh supervisor, journal, risk, reconciliation, news, and
runtime-fact evidence required at the order boundary.  Construction is pure;
the resulting capability performs no broker or persistence operation.
"""

from __future__ import annotations

from dataclasses import InitVar, dataclass, field, fields as dataclass_fields
from datetime import datetime, timedelta
from typing import Any, Sequence

import execution_policy

from .controls import EnvironmentArmDecision
from .contracts import (
    BrokerSpec,
    CanonicalContract,
    TradeIntent,
    canonicalize,
    require_hash,
    require_text,
    require_utc,
)
from .health import RuntimeHealthFacts
from .journal_integrity import ExecutionJournalCheckpoint
from .live_canary_runtime_authority import (
    LiveCanaryRuntimeLaunchSessionError,
    is_live_canary_runtime_candidate,
    is_live_canary_runtime_launch_session,
)
from .market_guard import MarketGuardDecision
from .model_governance import ModelArtifactManifest
from .permit import (
    PermitValidation,
    PromotionPermit,
    account_alias_sha256,
)
from .promotion_evidence import (
    PromotionEvidenceReceipt,
    PromotionEvidenceValidation,
)
from .risk_context_factory import VerifiedRiskContext
from .risk_ledger import RiskStateReceipt
from .runtime_fact_collector import RuntimeFactReceipt

LIVE_CANARY_ORDER_AUTHORIZATION_SCHEMA = "live-canary-order-authorization-v1"
LIVE_CANARY_PREPARED_ORDER_SCHEMA = "live-canary-prepared-order-v1"
LIVE_CANARY_ORDER_CAPABILITY = "LIVE_CANARY_ONE_ORDER"
LIVE_CANARY_ORDER_TTL = timedelta(seconds=1)
LIVE_CANARY_SYMBOL = "XAUUSD"
LIVE_CANARY_LOT = 0.01
_AUTHORIZATION_SEAL = object()


class LiveCanaryOrderAuthorizationError(RuntimeError):
    """Stable fail-closed error raised by the per-order verifier."""

    def __init__(self, reason_code: str) -> None:
        normalized = str(reason_code or "").strip().upper()
        if not normalized:
            normalized = "LIVE_CANARY_ORDER_AUTHORIZATION_REJECTED"
        self.reason_code = normalized
        super().__init__(normalized)


def _reject(reason_code: str) -> None:
    raise LiveCanaryOrderAuthorizationError(reason_code)


def _require_central_live_policy() -> None:
    allowed, reasons = execution_policy.execution_mode_policy_decision("LIVE")
    if (
        execution_policy.LIVE_ALLOWED is not True
        or execution_policy.SAFE_TO_DEMO_AUTO_ORDER is not False
        or allowed is not True
        or reasons != ()
    ):
        _reject("LIVE_MODE_POLICY_LOCKED")
    if execution_policy.LIVE_CANARY_EXECUTION_APPROVED_SYMBOLS != frozenset(
        {LIVE_CANARY_SYMBOL}
    ):
        _reject("LIVE_CANARY_SYMBOL_SCOPE_DRIFT")
    if (
        type(execution_policy.EXECUTION_MIN_LOT) is not float
        or type(execution_policy.EXECUTION_MAX_LOT) is not float
        or execution_policy.EXECUTION_MIN_LOT != LIVE_CANARY_LOT
        or execution_policy.EXECUTION_MAX_LOT != LIVE_CANARY_LOT
    ):
        _reject("LIVE_CANARY_LOT_SCOPE_DRIFT")


def _current_age(
    name: str,
    observed_at: datetime,
    now: datetime,
    *,
    maximum_seconds: float = 1.0,
) -> None:
    observed = require_utc(name, observed_at)
    age = (now - observed).total_seconds()
    if age < 0 or age > maximum_seconds:
        _reject(f"{name.upper()}_STALE_OR_FUTURE")


@dataclass(frozen=True, slots=True)
class LiveCanaryPreparedOrder(CanonicalContract):
    """Exact domain inputs for one LIVE intent; this is not authority."""

    intent: TradeIntent
    broker_symbol: str
    broker_spec: BrokerSpec
    risk_context: VerifiedRiskContext
    permit: PromotionPermit
    permit_validation: PermitValidation
    health_facts: RuntimeHealthFacts
    market_guard: MarketGuardDecision
    model_artifact: ModelArtifactManifest
    promotion_evidence: PromotionEvidenceReceipt
    promotion_validation: PromotionEvidenceValidation
    environment_arm: EnvironmentArmDecision
    schema_version: str = field(
        default=LIVE_CANARY_PREPARED_ORDER_SCHEMA,
        init=False,
    )

    def __post_init__(self) -> None:
        exact_types = (
            (self.intent, TradeIntent, "intent"),
            (self.broker_spec, BrokerSpec, "broker_spec"),
            (self.risk_context, VerifiedRiskContext, "risk_context"),
            (self.permit, PromotionPermit, "permit"),
            (self.permit_validation, PermitValidation, "permit_validation"),
            (self.health_facts, RuntimeHealthFacts, "health_facts"),
            (self.market_guard, MarketGuardDecision, "market_guard"),
            (self.model_artifact, ModelArtifactManifest, "model_artifact"),
            (
                self.promotion_evidence,
                PromotionEvidenceReceipt,
                "promotion_evidence",
            ),
            (
                self.promotion_validation,
                PromotionEvidenceValidation,
                "promotion_validation",
            ),
            (self.environment_arm, EnvironmentArmDecision, "environment_arm"),
        )
        for value, expected_type, name in exact_types:
            if type(value) is not expected_type:
                raise TypeError(f"{name} must be exact {expected_type.__name__}")
        broker_symbol = require_text("broker_symbol", self.broker_symbol)
        object.__setattr__(self, "broker_symbol", broker_symbol)
        intent = self.intent
        permit = self.permit
        permit_validation = self.permit_validation
        promotion = self.promotion_evidence
        promotion_validation = self.promotion_validation
        broker = self.broker_spec
        if (
            intent.mode != "LIVE"
            or intent.symbol != LIVE_CANARY_SYMBOL
            or type(intent.requested_lot) is not float
            or intent.requested_lot != LIVE_CANARY_LOT
            or broker.environment != "LIVE"
            or broker.account_id != intent.account_id
            or broker.server != intent.server
            or broker.symbol != intent.symbol
            or broker.broker_symbol != broker_symbol
            or permit.mode != "LIVE"
            or permit.permit_id != intent.permit_id
            or permit.account_alias_sha256 != account_alias_sha256(intent.account_id)
            or permit.server != intent.server
            or permit.symbols != (intent.symbol,)
            or permit.commit_sha != intent.decision.commit_sha
            or permit.config_sha256 != intent.decision.config_sha256
            or permit.model_artifact_sha256
            != intent.decision.model_artifact_sha256
            or permit_validation.valid is not True
            or permit_validation.mode != "LIVE"
            or permit_validation.permit_id != permit.permit_id
            or permit_validation.account_alias_sha256
            != permit.account_alias_sha256
            or permit_validation.server != permit.server
            or permit_validation.symbols != permit.symbols
            or permit_validation.commit_sha != permit.commit_sha
            or permit_validation.config_sha256 != permit.config_sha256
            or permit_validation.model_artifact_sha256
            != permit.model_artifact_sha256
            or permit_validation.journal_sha256 != permit.journal_sha256
            or permit_validation.promotion_evidence_sha256
            != permit.promotion_evidence_sha256
            or promotion.mode != "LIVE"
            or promotion.content_sha256
            != permit_validation.promotion_evidence_sha256
            or promotion.content_sha256 != permit.promotion_evidence_sha256
            or promotion.account_alias_sha256 != permit.account_alias_sha256
            or promotion.server != intent.server
            or promotion.journal_sha256 != permit.journal_sha256
            or promotion.symbol != intent.symbol
            or promotion.strategy != intent.decision.strategy
            or promotion.commit_sha != intent.decision.commit_sha
            or promotion.config_sha256 != intent.decision.config_sha256
            or promotion.model_artifact_sha256
            != intent.decision.model_artifact_sha256
            or promotion_validation.valid is not True
            or promotion_validation.receipt_sha256 != promotion.content_sha256
            or promotion_validation.mode != "LIVE"
            or promotion_validation.symbol != intent.symbol
            or promotion_validation.commit_sha != intent.decision.commit_sha
            or promotion_validation.config_sha256
            != intent.decision.config_sha256
            or promotion_validation.model_artifact_sha256
            != intent.decision.model_artifact_sha256
            or self.model_artifact.artifact_sha256
            != intent.decision.model_artifact_sha256
            or self.model_artifact.content_sha256
            != promotion_validation.champion_runtime_binding_sha256
            or self.risk_context.journal_sha256 != permit.journal_sha256
            or self.environment_arm.journal_sha256 != permit.journal_sha256
            or self.environment_arm.armed is not True
            or self.environment_arm.reason_codes != ()
            or self.market_guard.symbol != intent.symbol
        ):
            raise ValueError("prepared LIVE order binding mismatch")


@dataclass(frozen=True, slots=True)
class LiveCanaryOrderAuthorization(CanonicalContract):
    """One-second, one-intent capability accepted by the final LIVE boundary."""

    issued_at_utc: datetime
    valid_until_utc: datetime
    candidate_sha256: str
    launch_session_sha256: str
    supervisor_binding_sha256: str
    supervisor_decision_sha256: str
    prepared_order_sha256: str
    intent_sha256: str
    intent_id: str
    account_id_sha256: str
    server: str
    symbol: str
    broker_symbol: str
    side: str
    requested_lot: float
    journal_sha256: str
    broker_spec_sha256: str
    permit_validation_sha256: str
    promotion_validation_sha256: str
    environment_arm_sha256: str
    supervisor_checkpoint_sha256: str
    journal_checkpoint_sha256: str
    risk_receipt_sha256: str
    reconciliation_sha256: str
    news_guard_sha256: str
    runtime_fact_receipt_sha256s: tuple[str, ...]
    max_concurrent_positions: int = field(default=1, init=False)
    execution_authorized: bool = field(default=True, init=False)
    broker_mutation_authorized: bool = field(default=True, init=False)
    live_allowed: bool = field(default=True, init=False)
    safe_to_demo_auto_order: bool = field(default=False, init=False)
    order_capability: str = field(
        default=LIVE_CANARY_ORDER_CAPABILITY,
        init=False,
    )
    schema_version: str = field(
        default=LIVE_CANARY_ORDER_AUTHORIZATION_SCHEMA,
        init=False,
    )
    _authorization_seal: object = field(init=False, repr=False, compare=False)
    _seal: InitVar[object | None] = None

    def __post_init__(self, _seal: object | None) -> None:
        if _seal is not _AUTHORIZATION_SEAL:
            raise TypeError("LIVE canary order authority requires its verifier")
        issued = require_utc("issued_at_utc", self.issued_at_utc)
        expires = require_utc("valid_until_utc", self.valid_until_utc)
        if not issued < expires <= issued + LIVE_CANARY_ORDER_TTL:
            raise ValueError("LIVE canary order authority lifetime must be <=1 second")
        for name in (
            "candidate_sha256",
            "launch_session_sha256",
            "supervisor_binding_sha256",
            "supervisor_decision_sha256",
            "prepared_order_sha256",
            "intent_sha256",
            "account_id_sha256",
            "journal_sha256",
            "broker_spec_sha256",
            "permit_validation_sha256",
            "promotion_validation_sha256",
            "environment_arm_sha256",
            "supervisor_checkpoint_sha256",
            "journal_checkpoint_sha256",
            "risk_receipt_sha256",
            "reconciliation_sha256",
            "news_guard_sha256",
        ):
            object.__setattr__(self, name, require_hash(name, getattr(self, name)))
        object.__setattr__(self, "intent_id", require_text("intent_id", self.intent_id))
        object.__setattr__(self, "server", require_text("server", self.server))
        object.__setattr__(self, "broker_symbol", require_text("broker_symbol", self.broker_symbol))
        symbol = require_text("symbol", self.symbol, upper=True)
        side = require_text("side", self.side, upper=True)
        object.__setattr__(self, "symbol", symbol)
        object.__setattr__(self, "side", side)
        facts = tuple(
            require_hash("runtime_fact_receipt_sha256", item)
            for item in self.runtime_fact_receipt_sha256s
        )
        if facts != tuple(sorted(facts)) or len(facts) != 1:
            raise ValueError("LIVE canary requires one sorted unique runtime fact")
        object.__setattr__(self, "runtime_fact_receipt_sha256s", facts)
        if (
            symbol != LIVE_CANARY_SYMBOL
            or side not in {"BUY", "SELL"}
            or type(self.requested_lot) is not float
            or self.requested_lot != LIVE_CANARY_LOT
            or self.max_concurrent_positions != 1
            or self.execution_authorized is not True
            or self.broker_mutation_authorized is not True
            or self.live_allowed is not True
            or self.safe_to_demo_auto_order is not False
            or self.order_capability != LIVE_CANARY_ORDER_CAPABILITY
            or self.schema_version != LIVE_CANARY_ORDER_AUTHORIZATION_SCHEMA
        ):
            raise ValueError("LIVE canary order authority safety scope drift")
        object.__setattr__(self, "_authorization_seal", _AUTHORIZATION_SEAL)

    def to_canonical_dict(self) -> dict[str, object]:
        return {
            item.name: canonicalize(getattr(self, item.name))
            for item in dataclass_fields(self)
            if not item.name.startswith("_")
        }

    def assert_current(
        self,
        *,
        now: datetime,
        candidate: object,
        launch_session: object,
        prepared_order: LiveCanaryPreparedOrder,
    ) -> None:
        checked = require_utc("now", now)
        _require_central_live_policy()
        if not self.issued_at_utc <= checked < self.valid_until_utc:
            _reject("LIVE_CANARY_ORDER_AUTHORIZATION_NOT_CURRENT")
        if not is_live_canary_runtime_candidate(candidate):
            _reject("LIVE_CANARY_RUNTIME_CANDIDATE_NOT_EXACT")
        if not is_live_canary_runtime_launch_session(launch_session):
            _reject("LIVE_RUNTIME_LAUNCH_SESSION_NOT_SEALED")
        if type(prepared_order) is not LiveCanaryPreparedOrder:
            _reject("LIVE_CANARY_PREPARED_ORDER_NOT_EXACT")
        try:
            launch_session.assert_current(now=checked)
        except LiveCanaryRuntimeLaunchSessionError as exc:
            _reject(exc.reason_code)
        if (
            self.candidate_sha256 != candidate.content_sha256
            or self.launch_session_sha256 != launch_session.content_sha256
            or self.prepared_order_sha256 != prepared_order.content_sha256
            or self.intent_sha256 != prepared_order.intent.content_sha256
            or self.intent_id != prepared_order.intent.intent_id
            or self.account_id_sha256
            != account_alias_sha256(prepared_order.intent.account_id)
            or self.server != prepared_order.intent.server
            or self.symbol != prepared_order.intent.symbol
            or self.broker_symbol != prepared_order.broker_symbol
            or self.side != prepared_order.intent.side
            or self.requested_lot != prepared_order.intent.requested_lot
            or self.journal_sha256 != candidate.journal_sha256
            or self.broker_spec_sha256 != prepared_order.broker_spec.content_sha256
            or checked >= prepared_order.intent.expires_at
        ):
            _reject("LIVE_CANARY_ORDER_AUTHORIZATION_BINDING_MISMATCH")


def is_live_canary_order_authorization(value: object) -> bool:
    return (
        type(value) is LiveCanaryOrderAuthorization
        and getattr(value, "_authorization_seal", None) is _AUTHORIZATION_SEAL
    )


def verify_live_canary_order_execution_binding(
    authorization: object,
    *,
    candidate: object,
    launch_session: object,
    intent: object,
    broker_symbol: object,
    broker_spec: object,
    now: datetime,
) -> LiveCanaryOrderAuthorization:
    """Verify the stable subset available inside coordinator/adapter layers."""

    _require_central_live_policy()
    checked = require_utc("now", now)
    if not is_live_canary_order_authorization(authorization):
        _reject("LIVE_CANARY_ORDER_AUTHORIZATION_NOT_SEALED")
    if not is_live_canary_runtime_candidate(candidate):
        _reject("LIVE_CANARY_RUNTIME_CANDIDATE_NOT_EXACT")
    if not is_live_canary_runtime_launch_session(launch_session):
        _reject("LIVE_RUNTIME_LAUNCH_SESSION_NOT_SEALED")
    if type(intent) is not TradeIntent or type(broker_spec) is not BrokerSpec:
        _reject("LIVE_CANARY_EXECUTION_INPUT_NOT_EXACT")
    normalized_broker_symbol = require_text("broker_symbol", broker_symbol)
    try:
        launch_session.assert_current(now=checked)
    except LiveCanaryRuntimeLaunchSessionError as exc:
        _reject(exc.reason_code)
    if not authorization.issued_at_utc <= checked < authorization.valid_until_utc:
        _reject("LIVE_CANARY_ORDER_AUTHORIZATION_NOT_CURRENT")
    if (
        authorization.candidate_sha256 != candidate.content_sha256
        or authorization.launch_session_sha256 != launch_session.content_sha256
        or authorization.intent_sha256 != intent.content_sha256
        or authorization.intent_id != intent.intent_id
        or authorization.account_id_sha256 != account_alias_sha256(intent.account_id)
        or authorization.server != intent.server
        or authorization.symbol != intent.symbol
        or authorization.broker_symbol != normalized_broker_symbol
        or authorization.side != intent.side
        or authorization.requested_lot != intent.requested_lot
        or authorization.journal_sha256 != candidate.journal_sha256
        or authorization.broker_spec_sha256 != broker_spec.content_sha256
        or launch_session.candidate_sha256 != candidate.content_sha256
        or candidate.mode != "LIVE"
        or candidate.environment != "LIVE"
        or candidate.symbol_map != ((LIVE_CANARY_SYMBOL, normalized_broker_symbol),)
        or candidate.max_lot != LIVE_CANARY_LOT
        or candidate.max_concurrent_positions != 1
        or candidate.account_alias_sha256
        != account_alias_sha256(intent.account_id)
        or candidate.server != intent.server
        or candidate.broker_spec_sha256 != broker_spec.content_sha256
        or intent.mode != "LIVE"
        or intent.symbol != LIVE_CANARY_SYMBOL
        or intent.requested_lot != LIVE_CANARY_LOT
        or intent.decision.commit_sha != candidate.commit_sha
        or intent.decision.config_sha256 != candidate.champion_config_sha256
        or intent.decision.model_artifact_sha256 != candidate.model_artifact_sha256
        or checked >= intent.expires_at
    ):
        _reject("LIVE_CANARY_ORDER_AUTHORIZATION_BINDING_MISMATCH")
    return authorization


def _validate_exact_evidence(
    *,
    candidate: object,
    launch_session: object,
    supervisor_binding: object,
    supervisor_decision: object,
    prepared_order: object,
    supervisor_checkpoint: object,
    journal_checkpoint: object,
    risk_receipt: object,
    reconciliation: object,
    news_guard: object,
    runtime_facts: Sequence[object],
    now: datetime,
) -> tuple[Any, ...]:
    # Imported only while authorizing an already composed runtime.  Keeping
    # these supervisor classes out of module import time prevents the MT5
    # adapter's static safety path from opening the activation graph.
    from .runtime_supervisor import (
        RuntimeNewsGuardReceipt,
        RuntimeReconciliationRiskResult,
        RuntimeSupervisorBinding,
        RuntimeSupervisorCheckpoint,
        RuntimeSupervisorDecision,
    )

    exact = (
        (supervisor_binding, RuntimeSupervisorBinding, "LIVE_SUPERVISOR_BINDING_NOT_EXACT"),
        (supervisor_decision, RuntimeSupervisorDecision, "LIVE_SUPERVISOR_DECISION_NOT_EXACT"),
        (prepared_order, LiveCanaryPreparedOrder, "LIVE_CANARY_PREPARED_ORDER_NOT_EXACT"),
        (supervisor_checkpoint, RuntimeSupervisorCheckpoint, "LIVE_SUPERVISOR_CHECKPOINT_NOT_EXACT"),
        (journal_checkpoint, ExecutionJournalCheckpoint, "LIVE_JOURNAL_CHECKPOINT_NOT_EXACT"),
        (risk_receipt, RiskStateReceipt, "LIVE_RISK_RECEIPT_NOT_EXACT"),
        (reconciliation, RuntimeReconciliationRiskResult, "LIVE_RECONCILIATION_NOT_EXACT"),
        (news_guard, RuntimeNewsGuardReceipt, "LIVE_NEWS_GUARD_NOT_EXACT"),
    )
    for value, expected_type, reason in exact:
        if type(value) is not expected_type:
            _reject(reason)
    if not is_live_canary_runtime_candidate(candidate):
        _reject("LIVE_CANARY_RUNTIME_CANDIDATE_NOT_EXACT")
    if not is_live_canary_runtime_launch_session(launch_session):
        _reject("LIVE_RUNTIME_LAUNCH_SESSION_NOT_SEALED")
    facts = tuple(runtime_facts)
    if (
        len(facts) != 1
        or type(facts[0]) is not RuntimeFactReceipt
        or not facts[0].signature
    ):
        _reject("LIVE_RUNTIME_FACT_SET_INVALID")
    typed_candidate = candidate
    typed_session = launch_session
    typed_binding = supervisor_binding
    typed_decision = supervisor_decision
    typed_order = prepared_order
    typed_supervisor_checkpoint = supervisor_checkpoint
    typed_journal_checkpoint = journal_checkpoint
    typed_risk = risk_receipt
    typed_reconciliation = reconciliation
    typed_news = news_guard
    typed_fact = facts[0]
    intent = typed_order.intent
    broker = typed_order.broker_spec
    account_hash = account_alias_sha256(intent.account_id)
    try:
        typed_session.assert_current(now=now)
    except LiveCanaryRuntimeLaunchSessionError as exc:
        _reject(exc.reason_code)
    _current_age("SUPERVISOR_DECISION", typed_decision.decided_at_utc, now)
    _current_age("SUPERVISOR_CHECKPOINT", typed_supervisor_checkpoint.issued_at_utc, now)
    _current_age("RISK_RECEIPT", typed_risk.issued_at_utc, now)
    _current_age("BROKER_SPEC", broker.captured_at, now)
    _current_age("HEALTH_FACTS", typed_order.health_facts.observed_at, now)
    _current_age("MARKET_GUARD", typed_order.market_guard.evaluated_at, now)
    if not typed_journal_checkpoint.checked_at_utc <= now < typed_journal_checkpoint.valid_until_utc:
        _reject("LIVE_JOURNAL_CHECKPOINT_NOT_CURRENT")
    if not typed_news.observed_at_utc <= now < typed_news.valid_until_utc:
        _reject("LIVE_NEWS_GUARD_NOT_CURRENT")
    if not typed_fact.observed_at_utc <= now < typed_fact.valid_until_utc:
        _reject("LIVE_RUNTIME_FACT_NOT_CURRENT")
    if not typed_order.environment_arm.is_fresh(now):
        _reject("LIVE_ENVIRONMENT_ARM_NOT_CURRENT")
    if not typed_order.permit_validation.checked_at <= now < typed_order.permit_validation.expires_at:
        _reject("LIVE_PERMIT_VALIDATION_NOT_CURRENT")
    if not typed_order.promotion_validation.checked_at <= now < typed_order.promotion_validation.expires_at:
        _reject("LIVE_PROMOTION_VALIDATION_NOT_CURRENT")
    if not intent.created_at <= now < intent.expires_at:
        _reject("LIVE_INTENT_NOT_CURRENT")
    reconciliation_result = typed_reconciliation.reconciliation
    critical_reconciliation_fields = (
        reconciliation_result.uncertain_intents,
        reconciliation_result.orphan_position_tickets,
        reconciliation_result.orphan_order_tickets,
        reconciliation_result.protection_failures,
        reconciliation_result.volume_failures,
        reconciliation_result.binding_failures,
    )
    account_evidence = typed_reconciliation.account_snapshot_evidence
    if (
        reconciliation_result.status != "RECONCILIATION_COMPLETE"
        or any(critical_reconciliation_fields)
        or reconciliation_result.kill_switch_latched
        or account_evidence is None
    ):
        _reject("LIVE_RECONCILIATION_NOT_CLEAN")
    if (
        typed_binding.mode != "LIVE"
        or typed_binding.environment != "LIVE"
        or typed_binding.account_id_sha256 != typed_candidate.account_alias_sha256
        or typed_binding.server != typed_candidate.server
        or typed_binding.account_currency != typed_candidate.account_currency
        or typed_binding.journal_sha256 != typed_candidate.journal_sha256
        or typed_binding.commit_sha != typed_candidate.commit_sha
        or typed_binding.config_sha256 != typed_candidate.content_sha256
        or typed_binding.stage_binding_sha256 is not None
        or typed_decision.action != "LIVE_CANARY_EXECUTE"
        or typed_decision.intent_id != intent.intent_id
        or typed_session.candidate_sha256 != typed_candidate.content_sha256
        or typed_session.runtime_profile_sha256
        != typed_candidate.runtime_profile_sha256
        or typed_session.release_manifest_sha256
        != typed_candidate.release_manifest_sha256
        or typed_session.live_stage_binding_sha256
        != typed_candidate.live_stage_binding_sha256
        or typed_session.execution_authorized is not False
        or typed_session.broker_mutation_authorized is not False
        or typed_candidate.mode != "LIVE"
        or typed_candidate.environment != "LIVE"
        or typed_candidate.symbol_map != ((LIVE_CANARY_SYMBOL, typed_order.broker_symbol),)
        or typed_candidate.max_lot != LIVE_CANARY_LOT
        or typed_candidate.max_concurrent_positions != 1
        or typed_candidate.live_allowed is not False
        or typed_candidate.execution_authorized is not False
        or intent.mode != "LIVE"
        or intent.symbol != LIVE_CANARY_SYMBOL
        or intent.requested_lot != LIVE_CANARY_LOT
        or intent.server != typed_candidate.server
        or account_hash != typed_candidate.account_alias_sha256
        or intent.decision.commit_sha != typed_candidate.commit_sha
        or intent.decision.config_sha256 != typed_candidate.champion_config_sha256
        or intent.decision.model_artifact_sha256
        != typed_candidate.model_artifact_sha256
        or typed_order.model_artifact.artifact_sha256
        != typed_candidate.model_artifact_sha256
        or typed_order.model_artifact.content_sha256
        != typed_candidate.champion_runtime_binding_sha256
        or broker.content_sha256 != typed_candidate.broker_spec_sha256
        or broker.environment != "LIVE"
        or broker.server != typed_candidate.server
        or typed_order.permit.journal_sha256 != typed_candidate.journal_sha256
        or typed_order.permit_validation.journal_sha256
        != typed_candidate.journal_sha256
        or typed_order.promotion_evidence.journal_sha256
        != typed_candidate.journal_sha256
        or typed_order.promotion_validation.champion_archive_sha256
        != typed_candidate.champion_archive_sha256
        or typed_order.promotion_validation.champion_package_identity_sha256
        != typed_candidate.champion_package_identity_sha256
        or typed_order.promotion_validation.champion_training_snapshot_sha256
        != typed_candidate.champion_training_snapshot_sha256
        or typed_order.promotion_validation.champion_git_tree
        != typed_candidate.champion_git_tree
        or typed_order.promotion_validation.champion_runtime_binding_sha256
        != typed_candidate.champion_runtime_binding_sha256
        or typed_supervisor_checkpoint.binding_sha256 != typed_binding.content_sha256
        or typed_supervisor_checkpoint.critical_latched is not False
        or typed_journal_checkpoint.journal_sha256 != typed_candidate.journal_sha256
        or typed_journal_checkpoint.account_id_sha256
        != typed_candidate.account_alias_sha256
        or typed_journal_checkpoint.server != typed_candidate.server
        or typed_journal_checkpoint.environment != "LIVE"
        or typed_journal_checkpoint.commit_sha != typed_candidate.commit_sha
        or typed_journal_checkpoint.config_sha256 != typed_candidate.content_sha256
        or typed_risk.binding.account_id_sha256 != typed_candidate.account_alias_sha256
        or typed_risk.binding.server != typed_candidate.server
        or typed_risk.binding.environment != "LIVE"
        or typed_risk.binding.journal_sha256 != typed_candidate.journal_sha256
        or typed_risk.binding.broker_spec_sha256 != typed_candidate.broker_spec_sha256
        or typed_risk.loss_latch_active
        or typed_news.account_id_sha256 != typed_candidate.account_alias_sha256
        or typed_news.server != typed_candidate.server
        or typed_news.environment != "LIVE"
        or typed_news.config_sha256 != typed_candidate.content_sha256
        or not typed_news.signature_hmac_sha256
        or not typed_news.news_feed_fresh
        or typed_news.news_blackout_active
        or typed_news.rollover_blackout_active
        or account_alias_sha256(typed_fact.account_id)
        != typed_candidate.account_alias_sha256
        or typed_fact.server != typed_candidate.server
        or typed_fact.environment != "LIVE"
        or typed_fact.symbol != LIVE_CANARY_SYMBOL
        or typed_fact.broker_symbol != typed_order.broker_symbol
        or typed_fact.journal_sha256 != typed_candidate.journal_sha256
        or typed_fact.broker_spec_sha256 != typed_candidate.broker_spec_sha256
        or typed_fact.health_decision.healthy is not True
        or typed_fact.live_allowed is not False
        or typed_fact.safe_to_demo_auto_order is not False
        or account_evidence.upstream_receipt.content_sha256
        != typed_fact.content_sha256
        or account_evidence.source_receipt.event_sha256
        != account_evidence.event.content_sha256
        or account_evidence.event.binding != typed_risk.binding
    ):
        _reject("LIVE_CANARY_ORDER_EVIDENCE_BINDING_MISMATCH")
    return (
        typed_candidate,
        typed_session,
        typed_binding,
        typed_decision,
        typed_order,
        typed_supervisor_checkpoint,
        typed_journal_checkpoint,
        typed_risk,
        typed_reconciliation,
        typed_news,
        (typed_fact,),
    )


def authorize_live_canary_order(
    *,
    candidate: object,
    launch_session: object,
    supervisor_binding: object,
    supervisor_decision: object,
    prepared_order: object,
    supervisor_checkpoint: object,
    journal_checkpoint: object,
    risk_receipt: object,
    reconciliation: object,
    news_guard: object,
    runtime_facts: Sequence[object],
    now: datetime,
) -> LiveCanaryOrderAuthorization:
    """Mint one exact, in-memory LIVE canary order capability."""

    _require_central_live_policy()
    checked = require_utc("now", now)
    evidence = _validate_exact_evidence(
        candidate=candidate,
        launch_session=launch_session,
        supervisor_binding=supervisor_binding,
        supervisor_decision=supervisor_decision,
        prepared_order=prepared_order,
        supervisor_checkpoint=supervisor_checkpoint,
        journal_checkpoint=journal_checkpoint,
        risk_receipt=risk_receipt,
        reconciliation=reconciliation,
        news_guard=news_guard,
        runtime_facts=runtime_facts,
        now=checked,
    )
    (
        exact_candidate,
        exact_session,
        exact_binding,
        exact_decision,
        exact_order,
        exact_supervisor_checkpoint,
        exact_journal_checkpoint,
        exact_risk,
        exact_reconciliation,
        exact_news,
        exact_facts,
    ) = evidence
    valid_until = min(
        checked + LIVE_CANARY_ORDER_TTL,
        exact_session.valid_until_utc,
        exact_order.intent.expires_at,
        exact_order.permit_validation.expires_at,
        exact_order.promotion_validation.expires_at,
        exact_order.environment_arm.valid_until_utc,
        exact_news.valid_until_utc,
        *(item.valid_until_utc for item in exact_facts),
    )
    if valid_until <= checked:
        _reject("LIVE_CANARY_ORDER_AUTHORIZATION_WINDOW_EMPTY")
    return LiveCanaryOrderAuthorization(
        issued_at_utc=checked,
        valid_until_utc=valid_until,
        candidate_sha256=exact_candidate.content_sha256,
        launch_session_sha256=exact_session.content_sha256,
        supervisor_binding_sha256=exact_binding.content_sha256,
        supervisor_decision_sha256=exact_decision.content_sha256,
        prepared_order_sha256=exact_order.content_sha256,
        intent_sha256=exact_order.intent.content_sha256,
        intent_id=exact_order.intent.intent_id,
        account_id_sha256=account_alias_sha256(exact_order.intent.account_id),
        server=exact_order.intent.server,
        symbol=exact_order.intent.symbol,
        broker_symbol=exact_order.broker_symbol,
        side=exact_order.intent.side,
        requested_lot=exact_order.intent.requested_lot,
        journal_sha256=exact_candidate.journal_sha256,
        broker_spec_sha256=exact_order.broker_spec.content_sha256,
        permit_validation_sha256=exact_order.permit_validation.content_sha256,
        promotion_validation_sha256=(
            exact_order.promotion_validation.content_sha256
        ),
        environment_arm_sha256=exact_order.environment_arm.content_sha256,
        supervisor_checkpoint_sha256=exact_supervisor_checkpoint.content_sha256,
        journal_checkpoint_sha256=exact_journal_checkpoint.content_sha256,
        risk_receipt_sha256=exact_risk.content_sha256,
        reconciliation_sha256=exact_reconciliation.content_sha256,
        news_guard_sha256=exact_news.content_sha256,
        runtime_fact_receipt_sha256s=tuple(
            sorted(item.content_sha256 for item in exact_facts)
        ),
        _seal=_AUTHORIZATION_SEAL,
    )


def verify_live_canary_order_authorization(
    authorization: object,
    *,
    candidate: object,
    launch_session: object,
    supervisor_binding: object,
    supervisor_decision: object,
    prepared_order: object,
    supervisor_checkpoint: object,
    journal_checkpoint: object,
    risk_receipt: object,
    reconciliation: object,
    news_guard: object,
    runtime_facts: Sequence[object],
    now: datetime,
) -> LiveCanaryOrderAuthorization:
    """Independently verify a capability against the exact current evidence."""

    _require_central_live_policy()
    checked = require_utc("now", now)
    if not is_live_canary_order_authorization(authorization):
        _reject("LIVE_CANARY_ORDER_AUTHORIZATION_NOT_SEALED")
    evidence = _validate_exact_evidence(
        candidate=candidate,
        launch_session=launch_session,
        supervisor_binding=supervisor_binding,
        supervisor_decision=supervisor_decision,
        prepared_order=prepared_order,
        supervisor_checkpoint=supervisor_checkpoint,
        journal_checkpoint=journal_checkpoint,
        risk_receipt=risk_receipt,
        reconciliation=reconciliation,
        news_guard=news_guard,
        runtime_facts=runtime_facts,
        now=checked,
    )
    (
        exact_candidate,
        exact_session,
        exact_binding,
        exact_decision,
        exact_order,
        exact_supervisor_checkpoint,
        exact_journal_checkpoint,
        exact_risk,
        exact_reconciliation,
        exact_news,
        exact_facts,
    ) = evidence
    authorization.assert_current(
        now=checked,
        candidate=exact_candidate,
        launch_session=exact_session,
        prepared_order=exact_order,
    )
    expected = (
        authorization.supervisor_binding_sha256 == exact_binding.content_sha256,
        authorization.supervisor_decision_sha256 == exact_decision.content_sha256,
        authorization.supervisor_checkpoint_sha256
        == exact_supervisor_checkpoint.content_sha256,
        authorization.journal_checkpoint_sha256
        == exact_journal_checkpoint.content_sha256,
        authorization.risk_receipt_sha256 == exact_risk.content_sha256,
        authorization.reconciliation_sha256
        == exact_reconciliation.content_sha256,
        authorization.news_guard_sha256 == exact_news.content_sha256,
        authorization.permit_validation_sha256
        == exact_order.permit_validation.content_sha256,
        authorization.promotion_validation_sha256
        == exact_order.promotion_validation.content_sha256,
        authorization.environment_arm_sha256
        == exact_order.environment_arm.content_sha256,
        authorization.runtime_fact_receipt_sha256s
        == tuple(sorted(item.content_sha256 for item in exact_facts)),
    )
    if not all(expected):
        _reject("LIVE_CANARY_ORDER_AUTHORIZATION_BINDING_MISMATCH")
    return authorization


__all__ = [
    "LIVE_CANARY_LOT",
    "LIVE_CANARY_ORDER_AUTHORIZATION_SCHEMA",
    "LIVE_CANARY_ORDER_CAPABILITY",
    "LIVE_CANARY_ORDER_TTL",
    "LIVE_CANARY_PREPARED_ORDER_SCHEMA",
    "LIVE_CANARY_SYMBOL",
    "LiveCanaryOrderAuthorization",
    "LiveCanaryOrderAuthorizationError",
    "LiveCanaryPreparedOrder",
    "authorize_live_canary_order",
    "is_live_canary_order_authorization",
    "verify_live_canary_order_authorization",
    "verify_live_canary_order_execution_binding",
]
