"""Locked pre-execution half of the DEMO_AUTO runtime.

This module accepts only the one-use output of ``demo_auto_ipc_consumer``.  It
rechecks fresh sealed risk facts, creates a conservatively risk-sized immutable
``TradeIntent`` proposal, and atomically binds that proposal to the execution
journal in terminal ``RISK_REJECTED`` state.  Invalid or stale inputs are
atomically tombstoned as ``EXPIRED``.

There is intentionally no broker transport, execution coordinator, adapter,
preflight, or submission capability here.  The prepared intent is evidence for
soak/review only; it cannot be promoted out of its terminal journal state.
"""

from __future__ import annotations

from dataclasses import InitVar, dataclass
from datetime import datetime, timedelta, timezone
import math
from typing import Callable

import execution_policy

from .contracts import (
    ENTRY_WINDOW_SECONDS,
    BrokerSpec,
    CanonicalContract,
    TradeIntent,
    require_hash,
    require_text,
    require_utc,
)
from .demo_auto_ipc_consumer import DemoAutoIPCRiskIntentInput
from .health import RuntimeHealthFacts, evaluate_runtime_health
from .journal import ExecutionJournal
from .market_guard import MarketGuardDecision
from .model_governance import ModelArtifactManifest, ModelBindingDecision, verify_decision_model
from .permit import account_alias_sha256
from .risk import RiskDecision, evaluate_risk
from .risk_context_factory import (
    RiskContextVerificationError,
    VerifiedRiskContext,
    require_verified_risk_context,
)


UTC = timezone.utc
ORDER_CAPABILITY = "DISABLED"
MAX_PREPARATION_FACT_AGE_SECONDS = 1.0
DEFAULT_PREPARATION_TTL_SECONDS = 1.0
LOCKED_PREPARATION_SCHEMA_VERSION = "demo-auto-locked-risk-intent-v1"
SAFE_LOSS_SCHEMA_VERSION = "demo-auto-risk-intent-safe-loss-v1"
RISK_BASIS = "BROKER_SPEC_ESTIMATE_REQUIRES_FRESH_BROKER_RESIZING"
_PREPARATION_SEAL = object()
_SAFE_LOSS_SEAL = object()


class DemoAutoRiskIntentPipelineError(RuntimeError):
    """The locked preparation boundary could not produce durable evidence."""


def _now() -> datetime:
    return datetime.now(UTC)


def _locked_policy() -> bool:
    return (
        execution_policy.LIVE_ALLOWED is False
        and execution_policy.SAFE_TO_DEMO_AUTO_ORDER is False
    )


def _reason_codes(values: tuple[str, ...] | list[str]) -> tuple[str, ...]:
    return tuple(
        sorted({require_text("reason_code", item, upper=True) for item in values})
    )


@dataclass(frozen=True)
class DemoAutoLockedIntentPreparation(CanonicalContract):
    """Terminal, non-executable evidence for one risk-sized intent proposal."""

    ipc_input_sha256: str
    decision_snapshot_id: str
    decision_snapshot_sha256: str
    prepared_intent: TradeIntent
    risk_decision: RiskDecision
    broker_spec_sha256: str
    verified_risk_context_sha256: str
    health_facts_sha256: str
    market_guard_decision_sha256: str
    model_binding_sha256: str
    journal_sha256: str
    journal_intent_id: str
    journal_state: str
    prepared_at_utc: datetime
    valid_until_utc: datetime
    risk_basis: str = RISK_BASIS
    non_executable: bool = True
    execution_authorized: bool = False
    activation_authorized: bool = False
    live_allowed: bool = False
    safe_to_demo_auto_order: bool = False
    order_capability: str = ORDER_CAPABILITY
    schema_version: str = LOCKED_PREPARATION_SCHEMA_VERSION
    _seal: InitVar[object | None] = None

    def __post_init__(self, _seal: object | None) -> None:
        if _seal is not _PREPARATION_SEAL:
            raise TypeError("locked preparations can only be minted by the pipeline")
        if type(self.prepared_intent) is not TradeIntent:
            raise TypeError("prepared_intent must be an exact TradeIntent")
        if type(self.risk_decision) is not RiskDecision:
            raise TypeError("risk_decision must be an exact RiskDecision")
        for name in (
            "ipc_input_sha256",
            "decision_snapshot_sha256",
            "broker_spec_sha256",
            "verified_risk_context_sha256",
            "health_facts_sha256",
            "market_guard_decision_sha256",
            "model_binding_sha256",
            "journal_sha256",
        ):
            object.__setattr__(self, name, require_hash(name, getattr(self, name)))
        object.__setattr__(
            self,
            "decision_snapshot_id",
            require_text("decision_snapshot_id", self.decision_snapshot_id),
        )
        object.__setattr__(
            self,
            "journal_intent_id",
            require_text("journal_intent_id", self.journal_intent_id),
        )
        prepared_at = require_utc("prepared_at_utc", self.prepared_at_utc)
        valid_until = require_utc("valid_until_utc", self.valid_until_utc)
        if not prepared_at < valid_until:
            raise ValueError("locked preparation validity window is empty")
        if (
            self.decision_snapshot_id != self.prepared_intent.decision.snapshot_id
            or self.decision_snapshot_sha256
            != self.prepared_intent.decision.content_sha256
            or self.journal_intent_id != self.prepared_intent.intent_id
            or self.prepared_intent.mode != "DEMO_AUTO"
            or self.prepared_intent.created_at != prepared_at
            or self.prepared_intent.expires_at != valid_until
            or self.journal_state != "RISK_REJECTED"
            or self.risk_decision.allowed
            or self.risk_decision.reason_codes != ("DEMO_AUTO_ORDER_LOCKED",)
            or self.risk_decision.symbol != self.prepared_intent.symbol
            or abs(
                self.risk_decision.normalized_lot
                - self.prepared_intent.requested_lot
            )
            > 1e-12
            or self.risk_basis != RISK_BASIS
        ):
            raise ValueError("locked preparation provenance is inconsistent")
        if (
            self.non_executable is not True
            or self.execution_authorized
            or self.activation_authorized
            or self.live_allowed
            or self.safe_to_demo_auto_order
            or self.order_capability != ORDER_CAPABILITY
            or self.schema_version != LOCKED_PREPARATION_SCHEMA_VERSION
        ):
            raise ValueError("locked preparation cannot grant execution authority")


@dataclass(frozen=True)
class DemoAutoRiskIntentSafeLoss(CanonicalContract):
    """Durable proof that a consumed candidate cannot be retried."""

    ipc_input_sha256: str
    decision_snapshot_id: str
    decision_snapshot_sha256: str
    journal_sha256: str
    journal_binding_id: str
    journal_state: str
    reason_codes: tuple[str, ...]
    recorded_at_utc: datetime
    new_binding_created: bool
    prepared_intent_created: bool = False
    non_executable: bool = True
    execution_authorized: bool = False
    activation_authorized: bool = False
    live_allowed: bool = False
    safe_to_demo_auto_order: bool = False
    order_capability: str = ORDER_CAPABILITY
    schema_version: str = SAFE_LOSS_SCHEMA_VERSION
    _seal: InitVar[object | None] = None

    def __post_init__(self, _seal: object | None) -> None:
        if _seal is not _SAFE_LOSS_SEAL:
            raise TypeError("safe-loss receipts can only be minted by the pipeline")
        for name in (
            "ipc_input_sha256",
            "decision_snapshot_sha256",
            "journal_sha256",
        ):
            object.__setattr__(self, name, require_hash(name, getattr(self, name)))
        for name in ("decision_snapshot_id", "journal_binding_id"):
            object.__setattr__(self, name, require_text(name, getattr(self, name)))
        reasons = _reason_codes(list(self.reason_codes))
        if not reasons:
            raise ValueError("safe loss requires a reason")
        object.__setattr__(self, "reason_codes", reasons)
        require_utc("recorded_at_utc", self.recorded_at_utc)
        if type(self.new_binding_created) is not bool:
            raise TypeError("new_binding_created must be bool")
        if self.journal_state not in {"EXPIRED", "RISK_REJECTED"}:
            raise ValueError("safe loss must reference a terminal journal binding")
        if (
            self.prepared_intent_created
            or self.non_executable is not True
            or self.execution_authorized
            or self.activation_authorized
            or self.live_allowed
            or self.safe_to_demo_auto_order
            or self.order_capability != ORDER_CAPABILITY
            or self.schema_version != SAFE_LOSS_SCHEMA_VERSION
        ):
            raise ValueError("safe loss cannot grant execution authority")


@dataclass(frozen=True)
class DemoAutoLockedRiskIntentPipeline:
    """Prepare one terminal proposal from a consumed DEMO_AUTO IPC input."""

    journal: ExecutionJournal
    account_runtime_identity_sha256: str
    clock_provider: Callable[[], datetime] = _now
    intent_ttl_seconds: float = DEFAULT_PREPARATION_TTL_SECONDS

    def __post_init__(self) -> None:
        if type(self.journal) is not ExecutionJournal:
            raise TypeError("journal must be an exact ExecutionJournal")
        object.__setattr__(
            self,
            "account_runtime_identity_sha256",
            require_hash(
                "account_runtime_identity_sha256",
                self.account_runtime_identity_sha256,
            ),
        )
        if not callable(self.clock_provider):
            raise TypeError("clock_provider must be callable")
        if isinstance(self.intent_ttl_seconds, bool):
            raise TypeError("intent_ttl_seconds must be numeric")
        ttl = float(self.intent_ttl_seconds)
        if not math.isfinite(ttl) or ttl <= 0 or ttl > 1.0:
            raise ValueError("intent_ttl_seconds must be in (0, 1]")
        object.__setattr__(self, "intent_ttl_seconds", ttl)
        if not _locked_policy():
            raise DemoAutoRiskIntentPipelineError(
                "LOCKED_PREPARATION_REQUIRES_CLOSED_POLICY"
            )

    def _trusted_now(self) -> datetime:
        return require_utc("trusted preparation clock", self.clock_provider())

    def _safe_loss(
        self,
        source: DemoAutoIPCRiskIntentInput,
        reasons: tuple[str, ...] | list[str],
        *,
        now: datetime,
    ) -> DemoAutoRiskIntentSafeLoss:
        normalized = _reason_codes(list(reasons))
        record, created = self.journal.record_demo_auto_safe_loss(
            decision=source.decision,
            ipc_input_sha256=source.content_sha256,
            reason_codes=normalized,
            occurred_at=now,
        )
        if not created:
            normalized = _reason_codes([*normalized, "DECISION_ALREADY_BOUND"])
        return DemoAutoRiskIntentSafeLoss(
            ipc_input_sha256=source.content_sha256,
            decision_snapshot_id=source.decision.snapshot_id,
            decision_snapshot_sha256=source.decision.content_sha256,
            journal_sha256=self.journal.journal_sha256,
            journal_binding_id=record.intent_id,
            journal_state=record.state,
            reason_codes=normalized,
            recorded_at_utc=now,
            new_binding_created=created,
            _seal=_SAFE_LOSS_SEAL,
        )

    def prepare_locked_intent(
        self,
        *,
        source: DemoAutoIPCRiskIntentInput,
        broker_spec: BrokerSpec,
        verified_risk_context: VerifiedRiskContext,
        health_facts: RuntimeHealthFacts,
        market_guard: MarketGuardDecision,
        model_artifact: ModelArtifactManifest,
    ) -> DemoAutoLockedIntentPreparation | DemoAutoRiskIntentSafeLoss:
        """Create terminal evidence only; never route a broker request."""

        if type(source) is not DemoAutoIPCRiskIntentInput:
            raise TypeError("source must be exact DemoAutoIPCRiskIntentInput")
        if not _locked_policy():
            raise DemoAutoRiskIntentPipelineError(
                "LOCKED_PREPARATION_REQUIRES_CLOSED_POLICY"
            )
        now = self._trusted_now()
        if not self.journal.integrity_check():
            raise DemoAutoRiskIntentPipelineError("JOURNAL_INTEGRITY_FAILED")
        existing = self.journal.get_intent_by_decision(source.decision.snapshot_id)
        if existing is not None:
            return self._safe_loss(source, ["DECISION_ALREADY_BOUND"], now=now)

        preconditions: list[str] = []
        if type(broker_spec) is not BrokerSpec:
            preconditions.append("BROKER_SPEC_TYPE_INVALID")
        if type(verified_risk_context) is not VerifiedRiskContext:
            preconditions.append("VERIFIED_RISK_CONTEXT_TYPE_INVALID")
        if type(health_facts) is not RuntimeHealthFacts:
            preconditions.append("HEALTH_FACTS_TYPE_INVALID")
        if type(market_guard) is not MarketGuardDecision:
            preconditions.append("MARKET_GUARD_TYPE_INVALID")
        if type(model_artifact) is not ModelArtifactManifest:
            preconditions.append("MODEL_ARTIFACT_TYPE_INVALID")
        if preconditions:
            return self._safe_loss(source, preconditions, now=now)

        decision = source.decision
        stage = source.stage_binding
        if not source.verified_at_utc <= now < source.valid_until_utc:
            preconditions.append("IPC_INPUT_STALE_OR_FUTURE")
        if source.consumed_at_utc > now:
            preconditions.append("IPC_CONSUMPTION_IN_FUTURE")
        if source.execution_authorized or source.activation_authorized:
            preconditions.append("IPC_INPUT_AUTHORITY_INVALID")
        if source.order_capability != ORDER_CAPABILITY:
            preconditions.append("IPC_INPUT_CAPABILITY_INVALID")
        if stage.journal_sha256 != self.journal.journal_sha256:
            preconditions.append("STAGE_JOURNAL_MISMATCH")
        if broker_spec.content_sha256 != stage.broker_spec_sha256:
            preconditions.append("STAGE_BROKER_SPEC_MISMATCH")
        if (
            broker_spec.account_id != verified_risk_context.account_id
            or account_alias_sha256(broker_spec.account_id)
            != stage.account_alias_sha256
        ):
            preconditions.append("ACCOUNT_BINDING_MISMATCH")
        if broker_spec.server != stage.server:
            preconditions.append("SERVER_BINDING_MISMATCH")
        if broker_spec.environment != "DEMO":
            preconditions.append("BROKER_ENVIRONMENT_MISMATCH")
        if broker_spec.symbol != decision.symbol or broker_spec.symbol != stage.symbol:
            preconditions.append("BROKER_SYMBOL_BINDING_MISMATCH")
        if decision.timeframe != "M15":
            preconditions.append("DECISION_TIMEFRAME_NOT_EXECUTABLE")
        if not decision.source_aligned:
            preconditions.append("DECISION_SOURCE_MISMATCH")
        if not decision.data_fresh:
            preconditions.append("DECISION_DATA_STALE")
        if source.permit.mode != "DEMO_AUTO" or source.permit_validation.mode != "DEMO_AUTO":
            preconditions.append("PERMIT_MODE_MISMATCH")
        if not source.permit_validation.valid:
            preconditions.append("PERMIT_VALIDATION_INVALID")
        if source.permit.journal_sha256 != self.journal.journal_sha256:
            preconditions.append("PERMIT_JOURNAL_MISMATCH")
        if self.journal.kill_switch_status()["latched"]:
            preconditions.append("KILL_SWITCH_LATCHED")
        health = evaluate_runtime_health(health_facts)
        if not health.healthy:
            preconditions.extend(health.reason_codes)
        model_binding: ModelBindingDecision = verify_decision_model(
            decision,
            model_artifact,
            checked_at=now,
        )
        if not model_binding.bound:
            preconditions.extend(model_binding.reason_codes)

        for observed_at, reason in (
            (broker_spec.captured_at, "BROKER_SPEC_STALE"),
            (health_facts.observed_at, "HEALTH_FACTS_STALE"),
            (market_guard.evaluated_at, "MARKET_GUARD_STALE"),
            (verified_risk_context.evaluated_at_utc, "RISK_CONTEXT_STALE"),
        ):
            age = (now - observed_at).total_seconds()
            if age < 0 or age > MAX_PREPARATION_FACT_AGE_SECONDS:
                preconditions.append(reason)

        try:
            trusted_context = require_verified_risk_context(
                verified_risk_context,
                now=now,
                expected_account_id=broker_spec.account_id,
                expected_server=broker_spec.server,
                expected_environment="DEMO",
                expected_mode="DEMO_AUTO",
                expected_symbol=decision.symbol,
                expected_broker_symbol=broker_spec.broker_symbol,
                expected_account_runtime_identity_sha256=(
                    self.account_runtime_identity_sha256
                ),
                expected_journal_sha256=self.journal.journal_sha256,
                broker_spec=broker_spec,
                health_facts=health_facts,
                market_guard_decision=market_guard,
                expected_permit_id=source.permit.permit_id,
            )
        except RiskContextVerificationError as exc:
            preconditions.extend(
                f"RISK_CONTEXT_{reason}" for reason in exc.reason_codes
            )
            trusted_context = None
        if trusted_context is not None and (
            trusted_context.mode != "DEMO_AUTO"
            or not trusted_context.permit_valid
            or not trusted_context.data_fresh
            or not trusted_context.source_aligned
        ):
            preconditions.append("TRUSTED_RISK_CONTEXT_DENIED")

        entry_deadline = decision.bar_closed_at + timedelta(
            seconds=ENTRY_WINDOW_SECONDS
        )
        if now < decision.created_at or now >= entry_deadline:
            preconditions.append("ENTRY_WINDOW_EXPIRED")
        if preconditions:
            return self._safe_loss(source, preconditions, now=now)
        assert trusted_context is not None

        valid_until = min(
            now + timedelta(seconds=self.intent_ttl_seconds),
            entry_deadline,
            source.valid_until_utc,
            verified_risk_context.valid_until_utc,
            model_binding.valid_until,
        )
        if valid_until <= now:
            return self._safe_loss(source, ["PREPARATION_WINDOW_EMPTY"], now=now)

        initial_lot = min(0.01, broker_spec.volume_max)
        if initial_lot < broker_spec.volume_min:
            return self._safe_loss(
                source,
                ["BROKER_MINIMUM_LOT_EXCEEDS_CANARY_CAP"],
                now=now,
            )
        provisional = TradeIntent(
            mode="DEMO_AUTO",
            account_id=broker_spec.account_id,
            server=broker_spec.server,
            symbol=decision.symbol,
            side=decision.side,
            requested_lot=initial_lot,
            entry_reference=float(decision.entry_reference),
            stop_loss=float(decision.stop_loss),
            take_profit=float(decision.take_profit),
            created_at=now,
            expires_at=valid_until,
            decision=decision,
            permit_id=source.permit.permit_id,
        )
        sizing_probe = evaluate_risk(provisional, broker_spec, trusted_context)
        if sizing_probe.normalized_lot <= 0:
            return self._safe_loss(
                source,
                [*sizing_probe.reason_codes, "RISK_SIZING_UNAVAILABLE"],
                now=now,
            )

        intent = TradeIntent(
            mode="DEMO_AUTO",
            account_id=broker_spec.account_id,
            server=broker_spec.server,
            symbol=decision.symbol,
            side=decision.side,
            requested_lot=sizing_probe.normalized_lot,
            entry_reference=float(decision.entry_reference),
            stop_loss=float(decision.stop_loss),
            take_profit=float(decision.take_profit),
            created_at=now,
            expires_at=valid_until,
            decision=decision,
            permit_id=source.permit.permit_id,
        )
        risk_decision = evaluate_risk(intent, broker_spec, trusted_context)
        if (
            risk_decision.allowed
            or risk_decision.reason_codes != ("DEMO_AUTO_ORDER_LOCKED",)
        ):
            reasons = list(risk_decision.reason_codes)
            reasons.append("RISK_PREPARATION_NOT_LOCK_ONLY")
            return self._safe_loss(source, reasons, now=now)

        record, created = self.journal.record_locked_demo_auto_preparation(
            intent=intent,
            risk_decision=risk_decision,
            ipc_input_sha256=source.content_sha256,
            broker_spec_sha256=broker_spec.content_sha256,
            verified_risk_context_sha256=verified_risk_context.content_sha256,
            verified_risk_provenance=verified_risk_context.provenance_metadata(),
            health_facts_sha256=health_facts.content_sha256,
            market_guard_decision_sha256=market_guard.content_sha256,
            model_binding_sha256=model_binding.content_sha256,
            occurred_at=now,
        )
        if not created:
            return self._safe_loss(source, ["DECISION_ALREADY_BOUND"], now=now)
        if record.intent_id != intent.intent_id or record.state != "RISK_REJECTED":
            raise DemoAutoRiskIntentPipelineError(
                "DURABLE_PREPARATION_BINDING_MISMATCH"
            )
        return DemoAutoLockedIntentPreparation(
            ipc_input_sha256=source.content_sha256,
            decision_snapshot_id=decision.snapshot_id,
            decision_snapshot_sha256=decision.content_sha256,
            prepared_intent=intent,
            risk_decision=risk_decision,
            broker_spec_sha256=broker_spec.content_sha256,
            verified_risk_context_sha256=verified_risk_context.content_sha256,
            health_facts_sha256=health_facts.content_sha256,
            market_guard_decision_sha256=market_guard.content_sha256,
            model_binding_sha256=model_binding.content_sha256,
            journal_sha256=self.journal.journal_sha256,
            journal_intent_id=record.intent_id,
            journal_state=record.state,
            prepared_at_utc=now,
            valid_until_utc=valid_until,
            _seal=_PREPARATION_SEAL,
        )


__all__ = [
    "DEFAULT_PREPARATION_TTL_SECONDS",
    "DemoAutoLockedIntentPreparation",
    "DemoAutoLockedRiskIntentPipeline",
    "DemoAutoRiskIntentPipelineError",
    "DemoAutoRiskIntentSafeLoss",
    "LOCKED_PREPARATION_SCHEMA_VERSION",
    "MAX_PREPARATION_FACT_AGE_SECONDS",
    "ORDER_CAPABILITY",
    "RISK_BASIS",
    "SAFE_LOSS_SCHEMA_VERSION",
]
