"""One-shot composition service for the fail-closed Windows runtime.

The service deliberately exposes no loop and no process/bootstrap behavior.  It
joins already-validated domain contracts to the broker sizing adapter and then
delegates the only execution decision to :class:`ExecutionCoordinator`.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import math
from typing import Any, Callable

from execution_policy import validate_execution_symbol

from .controls import ManualDemoApproval, manual_demo_account_sha256
from .contracts import (
    ENTRY_WINDOW_SECONDS,
    BrokerSpec,
    DecisionSnapshot,
    TradeIntent,
    require_utc,
)
from .executor import ExecutionOutcome
from .health import RuntimeHealthFacts, evaluate_runtime_health
from .journal import ExecutionJournal
from .market_guard import MarketGuardDecision
from .model_governance import ModelArtifactManifest, verify_decision_model
from .mt5_adapter import BrokerSizingQuote
from .permit import PromotionPermit, account_alias_sha256
from .promotion_evidence import PromotionEvidenceReceipt
from .reconciliation import ReconciliationResult, reconcile_broker_state
from .risk import RiskContext


UTC = timezone.utc
MAX_COMPOSITION_FACT_AGE_SECONDS = 1.0
DEFAULT_INTENT_TTL_SECONDS = 1.0


def _utc_now() -> datetime:
    return datetime.now(UTC)


class RuntimeCompositionError(RuntimeError):
    """Raised when a dependency violates the one-shot composition contract."""


@dataclass(frozen=True)
class RuntimeCycleResult:
    status: str
    reason_codes: tuple[str, ...]
    decision_snapshot_id: str
    sizing_quote: BrokerSizingQuote | None = None
    intent: TradeIntent | None = None
    execution_outcome: ExecutionOutcome | None = None

    def __post_init__(self) -> None:
        normalized_status = str(self.status or "").strip().upper()
        if not normalized_status:
            raise ValueError("status is required")
        reasons = tuple(
            sorted({str(reason or "").strip().upper() for reason in self.reason_codes})
        )
        if any(not reason for reason in reasons):
            raise ValueError("reason_codes cannot contain empty values")
        if not str(self.decision_snapshot_id or "").strip():
            raise ValueError("decision_snapshot_id is required")
        if self.execution_outcome is not None and self.intent is None:
            raise ValueError("an execution outcome requires an immutable intent")
        object.__setattr__(self, "status", normalized_status)
        object.__setattr__(self, "reason_codes", reasons)


class LiveRuntimeService:
    """Compose exactly one decision cycle or one reconciliation cycle."""

    def __init__(
        self,
        *,
        adapter: Any,
        coordinator: Any,
        journal: ExecutionJournal,
        magic_number: int,
        clock_provider: Callable[[], datetime] = _utc_now,
        intent_ttl_seconds: float = DEFAULT_INTENT_TTL_SECONDS,
    ) -> None:
        required_adapter_methods = (
            "calculate_broker_sized_lot",
            "orders",
            "positions",
            "deals",
        )
        if any(
            not callable(getattr(adapter, method, None))
            for method in required_adapter_methods
        ):
            raise TypeError(
                "adapter must expose sizing and read-only reconciliation methods"
            )
        if not callable(getattr(coordinator, "execute_once", None)):
            raise TypeError("coordinator must expose execute_once")
        if not isinstance(journal, ExecutionJournal):
            raise TypeError("journal must be an ExecutionJournal")
        coordinator_journal = getattr(coordinator, "journal", None)
        if coordinator_journal is not journal:
            raise ValueError("execution and reconciliation must share one journal")
        if isinstance(magic_number, bool) or not isinstance(magic_number, int):
            raise TypeError("magic_number must be an integer")
        if magic_number <= 0:
            raise ValueError("magic_number must be positive")
        adapter_magic = getattr(adapter, "magic_number", magic_number)
        if adapter_magic != magic_number:
            raise ValueError("reconciliation magic does not match the adapter")
        if not callable(clock_provider):
            raise TypeError("clock_provider must be callable")
        if isinstance(intent_ttl_seconds, bool):
            raise TypeError("intent_ttl_seconds must be numeric")
        ttl = float(intent_ttl_seconds)
        if not math.isfinite(ttl) or ttl <= 0 or ttl > 1.0:
            raise ValueError("intent_ttl_seconds must be in the interval (0, 1]")

        self.adapter = adapter
        self.coordinator = coordinator
        self.journal = journal
        self.magic_number = magic_number
        self._clock_provider = clock_provider
        self.intent_ttl_seconds = ttl

    def _trusted_now(self, asserted: datetime | None = None) -> datetime:
        trusted = require_utc("trusted runtime clock", self._clock_provider())
        if asserted is not None:
            asserted = require_utc("now", asserted)
            if abs((asserted - trusted).total_seconds()) > 0.05:
                raise ValueError("caller timestamp disagrees with trusted runtime clock")
        return trusted

    @staticmethod
    def _wait(
        decision: DecisionSnapshot,
        *,
        status: str,
        reasons: tuple[str, ...],
        sizing_quote: BrokerSizingQuote | None = None,
        intent: TradeIntent | None = None,
    ) -> RuntimeCycleResult:
        return RuntimeCycleResult(
            status=status,
            reason_codes=reasons,
            decision_snapshot_id=decision.snapshot_id,
            sizing_quote=sizing_quote,
            intent=intent,
        )

    def execute_once(
        self,
        *,
        decision: DecisionSnapshot,
        broker_symbol: str,
        broker_spec: BrokerSpec,
        risk_context: RiskContext,
        permit: PromotionPermit,
        health_facts: RuntimeHealthFacts,
        market_guard: MarketGuardDecision,
        model_artifact: ModelArtifactManifest,
        owner_id: str,
        fence_token: int,
        manual_demo_approval_provider: (
            Callable[[TradeIntent], ManualDemoApproval | None] | None
        ),
        promotion_evidence: PromotionEvidenceReceipt | None,
        now: datetime | None = None,
    ) -> RuntimeCycleResult:
        """Size, build, and delegate at most one immutable trade intent."""

        now = self._trusted_now(now)
        if not isinstance(decision, DecisionSnapshot):
            raise TypeError("decision must be a sealed DecisionSnapshot")
        if not isinstance(broker_spec, BrokerSpec):
            raise TypeError("broker_spec must be a BrokerSpec")
        if not isinstance(risk_context, RiskContext):
            raise TypeError("risk_context must be a RiskContext")
        if not isinstance(permit, PromotionPermit):
            raise TypeError("permit must be a signed PromotionPermit")
        if not isinstance(health_facts, RuntimeHealthFacts):
            raise TypeError("health_facts must be RuntimeHealthFacts")
        if not isinstance(market_guard, MarketGuardDecision):
            raise TypeError("market_guard must be a sealed MarketGuardDecision")
        if not isinstance(model_artifact, ModelArtifactManifest):
            raise TypeError("model_artifact must be a ModelArtifactManifest")
        if (
            manual_demo_approval_provider is not None
            and not callable(manual_demo_approval_provider)
        ):
            raise TypeError("manual_demo_approval_provider must be callable or None")
        if promotion_evidence is not None and not isinstance(
            promotion_evidence,
            PromotionEvidenceReceipt,
        ):
            raise TypeError(
                "promotion_evidence must be a PromotionEvidenceReceipt or None"
            )
        if isinstance(fence_token, bool) or not isinstance(fence_token, int):
            raise TypeError("fence_token must be an integer")
        if fence_token < 0:
            raise ValueError("fence_token must be nonnegative")
        normalized_owner = str(owner_id or "").strip()
        normalized_broker_symbol = str(broker_symbol or "").strip()
        if not normalized_owner or not normalized_broker_symbol:
            raise ValueError("owner_id and broker_symbol are required")

        if decision.side == "WAIT":
            return self._wait(
                decision,
                status="WAIT_DECISION",
                reasons=("DECISION_WAIT",),
            )
        if self.journal.get_intent_by_decision(decision.snapshot_id) is not None:
            return self._wait(
                decision,
                status="DECISION_ALREADY_HAS_DURABLE_INTENT",
                reasons=("DECISION_IDEMPOTENCY_LOCKED",),
            )

        health_decision = evaluate_runtime_health(health_facts)
        model_binding = verify_decision_model(
            decision,
            model_artifact,
            checked_at=now,
        )
        precondition_reasons: list[str] = []
        if not decision.source_aligned:
            precondition_reasons.append("DECISION_SOURCE_MISMATCH")
        if not decision.data_fresh:
            precondition_reasons.append("DECISION_DATA_STALE")
        if not health_decision.healthy:
            precondition_reasons.extend(health_decision.reason_codes)
        if not model_binding.bound:
            precondition_reasons.extend(model_binding.reason_codes)
        if broker_spec.symbol != decision.symbol:
            precondition_reasons.append("BROKER_SPEC_SYMBOL_MISMATCH")
        if broker_spec.broker_symbol != normalized_broker_symbol:
            precondition_reasons.append("BROKER_SYMBOL_MISMATCH")
        if risk_context.mode != permit.mode:
            precondition_reasons.append("RISK_MODE_MISMATCH")
        if risk_context.account_id != broker_spec.account_id:
            precondition_reasons.append("RISK_ACCOUNT_MISMATCH")
        if risk_context.server != broker_spec.server:
            precondition_reasons.append("RISK_SERVER_MISMATCH")
        if not risk_context.data_fresh:
            precondition_reasons.append("RISK_DATA_STALE")
        if not risk_context.source_aligned:
            precondition_reasons.append("RISK_SOURCE_MISMATCH")
        if not risk_context.permit_valid:
            precondition_reasons.append("RISK_PERMIT_NOT_VALIDATED")
        if risk_context.news_clear != market_guard.news_clear:
            precondition_reasons.append("RISK_NEWS_GUARD_MISMATCH")
        if risk_context.rollover_clear != market_guard.rollover_clear:
            precondition_reasons.append("RISK_ROLLOVER_GUARD_MISMATCH")
        if market_guard.symbol != decision.symbol:
            precondition_reasons.append("MARKET_GUARD_SYMBOL_MISMATCH")
        if not market_guard.news_clear:
            precondition_reasons.extend(
                market_guard.reason_codes or ("NEWS_WINDOW_BLOCKED",)
            )
        if not market_guard.rollover_clear:
            precondition_reasons.extend(
                market_guard.reason_codes or ("ROLLOVER_WINDOW_BLOCKED",)
            )
        if permit.mode not in {"DEMO", "DEMO_AUTO", "LIVE"}:
            precondition_reasons.append("PERMIT_MODE_NOT_EXECUTABLE")
        expected_environment = "LIVE" if permit.mode == "LIVE" else "DEMO"
        if broker_spec.environment != expected_environment:
            precondition_reasons.append("BROKER_ENVIRONMENT_MISMATCH")
        symbol_allowed, _ = validate_execution_symbol(decision.symbol)
        if not symbol_allowed:
            precondition_reasons.append("SYMBOL_EXECUTION_POLICY_BLOCKED")
        if not permit.signature:
            precondition_reasons.append("PERMIT_UNSIGNED")
        if permit.server != broker_spec.server:
            precondition_reasons.append("PERMIT_SERVER_MISMATCH")
        if decision.symbol not in permit.symbols:
            precondition_reasons.append("PERMIT_SYMBOL_MISMATCH")
        if permit.account_alias_sha256 != account_alias_sha256(broker_spec.account_id):
            precondition_reasons.append("PERMIT_ACCOUNT_MISMATCH")
        if permit.commit_sha != decision.commit_sha:
            precondition_reasons.append("PERMIT_COMMIT_MISMATCH")
        if permit.config_sha256 != decision.config_sha256:
            precondition_reasons.append("PERMIT_CONFIG_MISMATCH")
        if permit.model_artifact_sha256 != decision.model_artifact_sha256:
            precondition_reasons.append("PERMIT_MODEL_MISMATCH")
        if permit.journal_sha256 != self.journal.journal_sha256:
            precondition_reasons.append("PERMIT_JOURNAL_MISMATCH")
        if not permit.issued_at <= now < permit.expires_at:
            precondition_reasons.append("PERMIT_TIME_INVALID")
        if permit.mode in {"DEMO_AUTO", "LIVE"}:
            if promotion_evidence is None:
                precondition_reasons.append("PROMOTION_EVIDENCE_REQUIRED")
            else:
                evidence_bindings = (
                    (
                        promotion_evidence.mode == permit.mode,
                        "PROMOTION_MODE_MISMATCH",
                    ),
                    (
                        promotion_evidence.account_alias_sha256
                        == account_alias_sha256(broker_spec.account_id),
                        "PROMOTION_ACCOUNT_MISMATCH",
                    ),
                    (
                        promotion_evidence.server == broker_spec.server,
                        "PROMOTION_SERVER_MISMATCH",
                    ),
                    (
                        promotion_evidence.journal_sha256
                        == self.journal.journal_sha256,
                        "PROMOTION_JOURNAL_MISMATCH",
                    ),
                    (
                        promotion_evidence.symbol == decision.symbol,
                        "PROMOTION_SYMBOL_MISMATCH",
                    ),
                    (
                        promotion_evidence.strategy == decision.strategy,
                        "PROMOTION_STRATEGY_MISMATCH",
                    ),
                    (
                        promotion_evidence.commit_sha == decision.commit_sha,
                        "PROMOTION_COMMIT_MISMATCH",
                    ),
                    (
                        promotion_evidence.config_sha256
                        == decision.config_sha256,
                        "PROMOTION_CONFIG_MISMATCH",
                    ),
                    (
                        promotion_evidence.model_artifact_sha256
                        == decision.model_artifact_sha256,
                        "PROMOTION_MODEL_MISMATCH",
                    ),
                    (
                        permit.promotion_evidence_sha256
                        == promotion_evidence.content_sha256,
                        "PROMOTION_PERMIT_BINDING_MISMATCH",
                    ),
                )
                precondition_reasons.extend(
                    reason for matched, reason in evidence_bindings if not matched
                )
                if not promotion_evidence.signature_hmac_sha256:
                    precondition_reasons.append("PROMOTION_EVIDENCE_UNSIGNED")
                if not (
                    promotion_evidence.issued_at
                    <= now
                    < promotion_evidence.expires_at
                ):
                    precondition_reasons.append("PROMOTION_EVIDENCE_TIME_INVALID")

        for observed_at, reason in (
            (risk_context.evaluated_at, "RISK_CONTEXT_STALE"),
            (broker_spec.captured_at, "BROKER_SPEC_STALE"),
            (health_facts.observed_at, "HEALTH_FACTS_STALE"),
            (market_guard.evaluated_at, "MARKET_GUARD_STALE"),
        ):
            age = (now - observed_at).total_seconds()
            if age < 0 or age > MAX_COMPOSITION_FACT_AGE_SECONDS:
                precondition_reasons.append(reason)

        entry_deadline = decision.bar_closed_at + timedelta(
            seconds=ENTRY_WINDOW_SECONDS
        )
        if now < decision.created_at or now >= entry_deadline:
            precondition_reasons.append("ENTRY_WINDOW_EXPIRED")
        if precondition_reasons:
            return self._wait(
                decision,
                status="WAIT_PRECONDITION",
                reasons=tuple(precondition_reasons),
            )

        stop_distance_points = abs(
            float(decision.entry_reference) - float(decision.stop_loss)
        ) / broker_spec.point
        allowed_slippage_points = max(
            0,
            int(
                math.floor(
                    min(
                        risk_context.p95_slippage_points,
                        0.10 * stop_distance_points,
                    )
                    + 1e-12
                )
            ),
        )
        quote = self.adapter.calculate_broker_sized_lot(
            canonical_symbol=decision.symbol,
            broker_symbol=normalized_broker_symbol,
            side=decision.side,
            entry_price=float(decision.entry_reference),
            stop_loss=float(decision.stop_loss),
            equity=risk_context.equity,
            allowed_slippage_points=allowed_slippage_points,
            now=now,
        )
        if not isinstance(quote, BrokerSizingQuote):
            raise RuntimeCompositionError(
                "sizing adapter must return a BrokerSizingQuote"
            )
        quote_age = (now - quote.evaluated_at_utc).total_seconds()
        quote_binding_reasons: list[str] = []
        if quote.symbol != decision.symbol:
            quote_binding_reasons.append("SIZING_SYMBOL_MISMATCH")
        if quote.broker_symbol != normalized_broker_symbol:
            quote_binding_reasons.append("SIZING_BROKER_SYMBOL_MISMATCH")
        if quote_age < 0 or quote_age > 0.05:
            quote_binding_reasons.append("SIZING_QUOTE_STALE")
        if quote.status != "SIZED":
            if quote.normalized_lot != 0:
                quote_binding_reasons.append("SIZING_STATUS_INCONSISTENT")
            return self._wait(
                decision,
                status="WAIT_SIZING",
                reasons=(quote.status, *quote_binding_reasons),
                sizing_quote=quote,
            )
        if quote.normalized_lot <= 0:
            quote_binding_reasons.append("SIZING_STATUS_INCONSISTENT")
        expected_risk_cap = min(
            0.0025 * risk_context.equity,
            0.20 if decision.symbol.startswith("XAU") else 0.25,
        )
        if abs(quote.max_risk_cash - expected_risk_cap) > 1e-12:
            quote_binding_reasons.append("SIZING_RISK_CAP_MISMATCH")
        if quote.actual_stop_risk_cash <= 0 or quote.margin_cash <= 0:
            quote_binding_reasons.append("SIZING_CASH_FACTS_INVALID")
        if quote.margin_cash > 0.10 * risk_context.equity + 1e-12:
            quote_binding_reasons.append("SIZING_MARGIN_CAP_EXCEEDED")
        if not (
            broker_spec.volume_min - 1e-12
            <= quote.normalized_lot
            <= min(broker_spec.volume_max, 0.01) + 1e-12
        ):
            quote_binding_reasons.append("SIZING_VOLUME_OUTSIDE_BROKER_GRID")
        volume_steps = quote.normalized_lot / broker_spec.volume_step
        if abs(volume_steps - round(volume_steps)) > 1e-9:
            quote_binding_reasons.append("SIZING_VOLUME_OUTSIDE_BROKER_GRID")
        if quote_binding_reasons:
            return self._wait(
                decision,
                status="WAIT_SIZING",
                reasons=tuple(quote_binding_reasons),
                sizing_quote=quote,
            )

        expires_at = min(
            now + timedelta(seconds=self.intent_ttl_seconds),
            entry_deadline,
        )
        if expires_at <= now:
            return self._wait(
                decision,
                status="WAIT_PRECONDITION",
                reasons=("ENTRY_WINDOW_EXPIRED",),
                sizing_quote=quote,
            )
        intent = TradeIntent(
            mode=permit.mode,
            account_id=broker_spec.account_id,
            server=broker_spec.server,
            symbol=decision.symbol,
            side=decision.side,
            requested_lot=quote.normalized_lot,
            entry_reference=float(decision.entry_reference),
            stop_loss=float(decision.stop_loss),
            take_profit=float(decision.take_profit),
            created_at=now,
            expires_at=expires_at,
            decision=decision,
            permit_id=permit.permit_id,
        )
        manual_demo_approval: ManualDemoApproval | None = None
        if permit.mode == "DEMO":
            if manual_demo_approval_provider is None:
                return self._wait(
                    decision,
                    status="WAIT_CONTROL",
                    reasons=("MANUAL_DEMO_APPROVAL_PROVIDER_REQUIRED",),
                    sizing_quote=quote,
                    intent=intent,
                )
            try:
                manual_demo_approval = manual_demo_approval_provider(intent)
            except Exception:
                return self._wait(
                    decision,
                    status="WAIT_CONTROL",
                    reasons=("MANUAL_DEMO_APPROVAL_PROVIDER_FAILED",),
                    sizing_quote=quote,
                    intent=intent,
                )
            approval_reasons: list[str] = []
            if not isinstance(manual_demo_approval, ManualDemoApproval):
                approval_reasons.append("MANUAL_DEMO_APPROVAL_INVALID_TYPE")
            else:
                approval_bindings = (
                    (
                        manual_demo_approval.intent_id == intent.intent_id,
                        "MANUAL_DEMO_INTENT_MISMATCH",
                    ),
                    (
                        manual_demo_approval.account_id_sha256
                        == manual_demo_account_sha256(intent.account_id),
                        "MANUAL_DEMO_ACCOUNT_MISMATCH",
                    ),
                    (
                        manual_demo_approval.server == intent.server,
                        "MANUAL_DEMO_SERVER_MISMATCH",
                    ),
                    (
                        manual_demo_approval.journal_sha256
                        == self.journal.journal_sha256,
                        "MANUAL_DEMO_JOURNAL_MISMATCH",
                    ),
                    (
                        manual_demo_approval.mode == "DEMO",
                        "MANUAL_DEMO_MODE_MISMATCH",
                    ),
                )
                approval_reasons.extend(
                    reason for matched, reason in approval_bindings if not matched
                )
                if not manual_demo_approval.signature:
                    approval_reasons.append("MANUAL_DEMO_APPROVAL_UNSIGNED")
                if not (
                    manual_demo_approval.issued_at_utc
                    <= now
                    < manual_demo_approval.expires_at_utc
                ):
                    approval_reasons.append("MANUAL_DEMO_APPROVAL_TIME_INVALID")
            if approval_reasons:
                return self._wait(
                    decision,
                    status="WAIT_CONTROL",
                    reasons=tuple(approval_reasons),
                    sizing_quote=quote,
                    intent=intent,
                )
        outcome = self.coordinator.execute_once(
            intent=intent,
            broker_symbol=normalized_broker_symbol,
            broker_spec=broker_spec,
            risk_context=risk_context,
            permit=permit,
            health_facts=health_facts,
            market_guard=market_guard,
            model_artifact=model_artifact,
            owner_id=normalized_owner,
            fence_token=fence_token,
            manual_demo_approval=manual_demo_approval,
            promotion_evidence=promotion_evidence,
            now=now,
        )
        if not isinstance(outcome, ExecutionOutcome):
            raise RuntimeCompositionError(
                "execution coordinator must return an ExecutionOutcome"
            )
        if outcome.intent_id != intent.intent_id:
            if outcome.status == "DECISION_ALREADY_HAS_DURABLE_INTENT":
                return self._wait(
                    decision,
                    status=outcome.status,
                    reasons=outcome.reason_codes,
                    sizing_quote=quote,
                )
            raise RuntimeCompositionError("execution outcome is bound to another intent")
        return RuntimeCycleResult(
            status=outcome.status,
            reason_codes=outcome.reason_codes,
            decision_snapshot_id=decision.snapshot_id,
            sizing_quote=quote,
            intent=intent,
            execution_outcome=outcome,
        )

    def reconcile_once(
        self,
        *,
        history_start_utc: datetime,
        now: datetime | None = None,
    ) -> ReconciliationResult:
        """Read one broker snapshot and reconcile it without retrying orders."""

        occurred_at = self._trusted_now(now)
        history_start = require_utc("history_start_utc", history_start_utc)
        if history_start >= occurred_at:
            raise ValueError("history_start_utc must precede reconciliation time")
        broker_orders = self.adapter.orders()
        broker_positions = self.adapter.positions()
        broker_deals = self.adapter.deals(history_start, occurred_at)
        return reconcile_broker_state(
            self.journal,
            broker_orders=broker_orders,
            broker_positions=broker_positions,
            broker_deals=broker_deals,
            magic_number=self.magic_number,
            occurred_at=occurred_at,
        )


__all__ = [
    "DEFAULT_INTENT_TTL_SECONDS",
    "LiveRuntimeService",
    "MAX_COMPOSITION_FACT_AGE_SECONDS",
    "RuntimeCompositionError",
    "RuntimeCycleResult",
]
