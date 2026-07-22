"""One-shot composition service for the fail-closed Windows runtime.

The service deliberately exposes no loop and no process/bootstrap behavior.  It
joins already-validated domain contracts to the broker sizing adapter and then
delegates the only execution decision to :class:`ExecutionCoordinator`.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import math
import threading
from typing import Any, Callable

from execution_policy import validate_execution_symbol

from .controls import ManualDemoApproval, manual_demo_account_sha256
from .contracts import (
    ENTRY_WINDOW_SECONDS,
    BrokerSpec,
    DecisionSnapshot,
    TradeIntent,
    canonical_sha256,
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
from .risk import (
    IDENTITY_CONVERSION_SHA256,
    MAX_RISK_CONVERSION_AGE_SECONDS,
    RISK_PERCENT_CAP,
    absolute_risk_cap_usd,
)
from .risk_context_factory import (
    RiskContextVerificationError,
    VerifiedRiskContext,
    require_verified_risk_context,
)


UTC = timezone.utc
MAX_COMPOSITION_FACT_AGE_SECONDS = 1.0
DEFAULT_INTENT_TTL_SECONDS = 1.0


def _utc_now() -> datetime:
    return datetime.now(UTC)


class RuntimeCompositionError(RuntimeError):
    """Raised when a dependency violates the one-shot composition contract."""


def _broker_spec_binding_sha256(spec: BrokerSpec) -> str:
    """Hash executable broker semantics while allowing a fresh capture time."""

    if type(spec) is not BrokerSpec:
        raise TypeError("spec must be an exact BrokerSpec")
    payload = spec.to_canonical_dict()
    payload.pop("captured_at", None)
    return canonical_sha256(payload)


@dataclass(frozen=True)
class FreshManualDemoContext:
    """Fresh, factory-sealed evidence rebuilt after human approval."""

    broker_spec: BrokerSpec
    risk_context: VerifiedRiskContext
    health_facts: RuntimeHealthFacts
    market_guard: MarketGuardDecision

    def __post_init__(self) -> None:
        if type(self.broker_spec) is not BrokerSpec:
            raise TypeError("broker_spec must be an exact BrokerSpec")
        if type(self.risk_context) is not VerifiedRiskContext:
            raise TypeError("risk_context must be an exact sealed VerifiedRiskContext")
        if type(self.health_facts) is not RuntimeHealthFacts:
            raise TypeError("health_facts must be exact RuntimeHealthFacts")
        if type(self.market_guard) is not MarketGuardDecision:
            raise TypeError("market_guard must be an exact sealed MarketGuardDecision")


@dataclass
class _PreparedManualDemoRecord:
    intent: TradeIntent
    broker_symbol: str
    broker_spec_binding_sha256: str
    permit_sha256: str
    model_artifact_sha256: str
    sizing_quote: BrokerSizingQuote
    state: str = "PREPARED"


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
        if not all(
            (
                callable(getattr(adapter, "calculate_broker_sized_lot", None)),
                callable(getattr(adapter, "orders", None)),
                callable(getattr(adapter, "positions", None)),
                callable(getattr(adapter, "deals", None)),
            )
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
        runtime_identity = str(
            getattr(coordinator, "account_runtime_identity_sha256", "") or ""
        ).lower()
        if len(runtime_identity) != 64 or any(
            character not in "0123456789abcdef" for character in runtime_identity
        ):
            raise TypeError(
                "coordinator must expose account_runtime_identity_sha256"
            )
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
        self._account_runtime_identity_sha256 = runtime_identity
        self._prepared_lock = threading.Lock()
        self._prepared_by_intent: dict[str, _PreparedManualDemoRecord] = {}
        self._prepared_intent_by_decision: dict[str, str] = {}

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

    def prepare_manual_demo(
        self,
        *,
        decision: DecisionSnapshot,
        broker_symbol: str,
        broker_spec: BrokerSpec,
        risk_context: VerifiedRiskContext,
        permit: PromotionPermit,
        health_facts: RuntimeHealthFacts,
        market_guard: MarketGuardDecision,
        model_artifact: ModelArtifactManifest,
        owner_id: str,
        fence_token: int,
        now: datetime | None = None,
    ) -> RuntimeCycleResult:
        """Phase 1: create one exact approval proposal without broker mutation."""

        if type(permit) is not PromotionPermit or permit.mode != "DEMO":
            raise ValueError("prepared manual execution requires a DEMO permit")
        return self.execute_once(
            decision=decision,
            broker_symbol=broker_symbol,
            broker_spec=broker_spec,
            risk_context=risk_context,
            permit=permit,
            health_facts=health_facts,
            market_guard=market_guard,
            model_artifact=model_artifact,
            owner_id=owner_id,
            fence_token=fence_token,
            manual_demo_approval_provider=None,
            promotion_evidence=None,
            now=now,
        )

    def execute_once(
        self,
        *,
        decision: DecisionSnapshot,
        broker_symbol: str,
        broker_spec: BrokerSpec,
        risk_context: VerifiedRiskContext,
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
        if type(risk_context) is not VerifiedRiskContext:
            raise TypeError("risk_context must be an exact sealed VerifiedRiskContext")
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

        trusted_context = require_verified_risk_context(
            risk_context,
            now=now,
            expected_account_id=broker_spec.account_id,
            expected_server=broker_spec.server,
            expected_environment=broker_spec.environment,
            expected_mode=permit.mode,
            expected_symbol=decision.symbol,
            expected_broker_symbol=normalized_broker_symbol,
            expected_account_runtime_identity_sha256=(
                self._account_runtime_identity_sha256
            ),
            expected_journal_sha256=self.journal.journal_sha256,
            broker_spec=broker_spec,
            health_facts=health_facts,
            market_guard_decision=market_guard,
            expected_permit_id=permit.permit_id,
        )

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
        if trusted_context.mode != permit.mode:
            precondition_reasons.append("RISK_MODE_MISMATCH")
        if trusted_context.account_id != broker_spec.account_id:
            precondition_reasons.append("RISK_ACCOUNT_MISMATCH")
        if trusted_context.server != broker_spec.server:
            precondition_reasons.append("RISK_SERVER_MISMATCH")
        conversion = trusted_context.usd_risk_cap_conversion
        if broker_spec.account_currency != "USD" and conversion is None:
            precondition_reasons.append("USD_RISK_CAP_CONVERSION_UNAVAILABLE")
        if conversion is not None:
            if (
                conversion.account_id != broker_spec.account_id
                or conversion.server != broker_spec.server
                or conversion.account_currency != broker_spec.account_currency
            ):
                precondition_reasons.append("USD_RISK_CAP_CONVERSION_MISMATCH")
            conversion_age = (
                trusted_context.evaluated_at - conversion.captured_at_utc
            ).total_seconds()
            if conversion_age < 0:
                precondition_reasons.append("USD_RISK_CAP_CONVERSION_FUTURE")
            if conversion_age > MAX_RISK_CONVERSION_AGE_SECONDS:
                precondition_reasons.append("USD_RISK_CAP_CONVERSION_STALE")
        if not trusted_context.data_fresh:
            precondition_reasons.append("RISK_DATA_STALE")
        if not trusted_context.source_aligned:
            precondition_reasons.append("RISK_SOURCE_MISMATCH")
        if not trusted_context.permit_valid:
            precondition_reasons.append("RISK_PERMIT_NOT_VALIDATED")
        if trusted_context.news_clear != market_guard.news_clear:
            precondition_reasons.append("RISK_NEWS_GUARD_MISMATCH")
        if trusted_context.rollover_clear != market_guard.rollover_clear:
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
            (trusted_context.evaluated_at, "RISK_CONTEXT_STALE"),
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
                        trusted_context.p95_slippage_points,
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
            equity=trusted_context.equity,
            allowed_slippage_points=allowed_slippage_points,
            usd_risk_cap_conversion=trusted_context.usd_risk_cap_conversion,
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
        conversion = trusted_context.usd_risk_cap_conversion
        expected_account_currency = broker_spec.account_currency
        expected_conversion_rate = (
            1.0
            if conversion is None and expected_account_currency == "USD"
            else (
                conversion.account_currency_per_usd
                if conversion is not None
                else 0.0
            )
        )
        expected_conversion_hash = (
            IDENTITY_CONVERSION_SHA256
            if conversion is None
            else conversion.content_sha256
        )
        expected_absolute_usd_cap = absolute_risk_cap_usd(decision.symbol)
        expected_absolute_account_cap = (
            expected_absolute_usd_cap * expected_conversion_rate
        )
        expected_risk_cap = min(
            RISK_PERCENT_CAP * trusted_context.equity,
            expected_absolute_account_cap,
        )
        if quote.account_currency != expected_account_currency:
            quote_binding_reasons.append("SIZING_ACCOUNT_CURRENCY_MISMATCH")
        if (
            abs(quote.absolute_risk_cap_usd - expected_absolute_usd_cap)
            > 1e-12
        ):
            quote_binding_reasons.append("SIZING_ABSOLUTE_USD_CAP_MISMATCH")
        if (
            abs(quote.usd_to_account_currency_rate - expected_conversion_rate)
            > 1e-12
        ):
            quote_binding_reasons.append("SIZING_CONVERSION_RATE_MISMATCH")
        if (
            abs(
                quote.absolute_risk_cap_account_currency
                - expected_absolute_account_cap
            )
            > 1e-12
        ):
            quote_binding_reasons.append("SIZING_ACCOUNT_CAP_MISMATCH")
        if quote.conversion_quote_sha256 != expected_conversion_hash:
            quote_binding_reasons.append("SIZING_CONVERSION_HASH_MISMATCH")
        if abs(quote.max_risk_cash - expected_risk_cap) > 1e-12:
            quote_binding_reasons.append("SIZING_RISK_CAP_MISMATCH")
        if quote.actual_stop_risk_cash <= 0 or quote.margin_cash <= 0:
            quote_binding_reasons.append("SIZING_CASH_FACTS_INVALID")
        if quote.margin_cash > 0.10 * trusted_context.equity + 1e-12:
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

        preparing_manual_demo = (
            permit.mode == "DEMO" and manual_demo_approval_provider is None
        )
        expires_at = (
            entry_deadline
            if preparing_manual_demo
            else min(
                now + timedelta(seconds=self.intent_ttl_seconds),
                entry_deadline,
            )
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
                record = _PreparedManualDemoRecord(
                    intent=intent,
                    broker_symbol=normalized_broker_symbol,
                    broker_spec_binding_sha256=(
                        _broker_spec_binding_sha256(broker_spec)
                    ),
                    permit_sha256=permit.content_sha256,
                    model_artifact_sha256=model_artifact.content_sha256,
                    sizing_quote=quote,
                )
                with self._prepared_lock:
                    existing_id = self._prepared_intent_by_decision.get(
                        decision.snapshot_id
                    )
                    if existing_id is not None:
                        existing = self._prepared_by_intent[existing_id]
                        return self._wait(
                            decision,
                            status=(
                                "MANUAL_DEMO_PREPARED"
                                if existing.state == "PREPARED"
                                else "WAIT_CONTROL"
                            ),
                            reasons=(
                                "MANUAL_DEMO_APPROVAL_REQUIRED"
                                if existing.state == "PREPARED"
                                else "PREPARED_INTENT_REPLAYED"
                            ,),
                            sizing_quote=existing.sizing_quote,
                            intent=existing.intent,
                        )
                    self._prepared_by_intent[intent.intent_id] = record
                    self._prepared_intent_by_decision[
                        decision.snapshot_id
                    ] = intent.intent_id
                return self._wait(
                    decision,
                    status="MANUAL_DEMO_PREPARED",
                    reasons=("MANUAL_DEMO_APPROVAL_REQUIRED",),
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

    def execute_prepared_manual_demo(
        self,
        *,
        prepared_intent: TradeIntent,
        manual_demo_approval: ManualDemoApproval,
        permit: PromotionPermit,
        fresh_context_provider: (
            Callable[[TradeIntent, datetime], FreshManualDemoContext]
        ),
        model_artifact: ModelArtifactManifest,
        owner_id: str,
        fence_token: int,
        now: datetime | None = None,
    ) -> RuntimeCycleResult:
        """Phase 2: refresh all sub-second proofs and execute the exact proposal."""

        checked_at = self._trusted_now(now)
        if type(prepared_intent) is not TradeIntent:
            raise TypeError("prepared_intent must be an exact TradeIntent")
        if type(manual_demo_approval) is not ManualDemoApproval:
            raise TypeError("manual_demo_approval must be an exact ManualDemoApproval")
        if type(permit) is not PromotionPermit:
            raise TypeError("permit must be an exact PromotionPermit")
        if type(model_artifact) is not ModelArtifactManifest:
            raise TypeError("model_artifact must be an exact ModelArtifactManifest")
        if not callable(fresh_context_provider):
            raise TypeError("fresh_context_provider must be callable")
        if isinstance(fence_token, bool) or not isinstance(fence_token, int):
            raise TypeError("fence_token must be an integer")
        normalized_owner = str(owner_id or "").strip()
        if not normalized_owner or fence_token < 0:
            raise ValueError("owner_id and nonnegative fence_token are required")

        decision = prepared_intent.decision
        with self._prepared_lock:
            record = self._prepared_by_intent.get(prepared_intent.intent_id)
            if record is None:
                known_id = self._prepared_intent_by_decision.get(
                    decision.snapshot_id
                )
                reason = (
                    "PREPARED_INTENT_CHANGED"
                    if known_id is not None
                    else "PREPARED_INTENT_UNKNOWN"
                )
                return self._wait(
                    decision,
                    status="WAIT_CONTROL",
                    reasons=(reason,),
                    intent=prepared_intent,
                )
            if record.state != "PREPARED":
                return self._wait(
                    decision,
                    status="WAIT_CONTROL",
                    reasons=("PREPARED_INTENT_REPLAYED",),
                    sizing_quote=record.sizing_quote,
                    intent=record.intent,
                )
            if (
                record.intent.content_sha256 != prepared_intent.content_sha256
                or record.intent.to_canonical_dict()
                != prepared_intent.to_canonical_dict()
            ):
                return self._wait(
                    decision,
                    status="WAIT_CONTROL",
                    reasons=("PREPARED_INTENT_CHANGED",),
                    sizing_quote=record.sizing_quote,
                    intent=record.intent,
                )

        deadline = min(
            prepared_intent.expires_at,
            decision.bar_closed_at + timedelta(seconds=ENTRY_WINDOW_SECONDS),
        )
        control_reasons: list[str] = []
        if prepared_intent.mode != "DEMO" or permit.mode != "DEMO":
            control_reasons.append("MANUAL_DEMO_MODE_MISMATCH")
        if checked_at < prepared_intent.created_at or checked_at >= deadline:
            control_reasons.append("PREPARED_INTENT_EXPIRED")
        if (
            permit.content_sha256 != record.permit_sha256
            or permit.permit_id != prepared_intent.permit_id
        ):
            control_reasons.append("PREPARED_PERMIT_MISMATCH")
        if not permit.issued_at <= checked_at < permit.expires_at:
            control_reasons.append("PERMIT_TIME_INVALID")
        if model_artifact.content_sha256 != record.model_artifact_sha256:
            control_reasons.append("PREPARED_MODEL_MISMATCH")
        approval_bindings = (
            (
                manual_demo_approval.intent_id == prepared_intent.intent_id,
                "MANUAL_DEMO_INTENT_MISMATCH",
            ),
            (
                manual_demo_approval.account_id_sha256
                == manual_demo_account_sha256(prepared_intent.account_id),
                "MANUAL_DEMO_ACCOUNT_MISMATCH",
            ),
            (
                manual_demo_approval.server == prepared_intent.server,
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
        control_reasons.extend(
            reason for matched, reason in approval_bindings if not matched
        )
        if not manual_demo_approval.signature:
            control_reasons.append("MANUAL_DEMO_APPROVAL_UNSIGNED")
        if manual_demo_approval.issued_at_utc < prepared_intent.created_at:
            control_reasons.append("MANUAL_DEMO_APPROVAL_PREDATES_PROPOSAL")
        if not (
            manual_demo_approval.issued_at_utc
            <= checked_at
            < manual_demo_approval.expires_at_utc
        ):
            control_reasons.append("MANUAL_DEMO_APPROVAL_TIME_INVALID")
        if control_reasons:
            return self._wait(
                decision,
                status="WAIT_CONTROL",
                reasons=tuple(control_reasons),
                sizing_quote=record.sizing_quote,
                intent=record.intent,
            )

        try:
            fresh = fresh_context_provider(record.intent, checked_at)
        except Exception:
            return self._wait(
                decision,
                status="WAIT_PRECONDITION",
                reasons=("FRESH_CONTEXT_PROVIDER_FAILED",),
                sizing_quote=record.sizing_quote,
                intent=record.intent,
            )
        if type(fresh) is not FreshManualDemoContext:
            return self._wait(
                decision,
                status="WAIT_PRECONDITION",
                reasons=("FRESH_CONTEXT_PROVIDER_INVALID",),
                sizing_quote=record.sizing_quote,
                intent=record.intent,
            )
        fresh_now = self._trusted_now()
        fresh_reasons: list[str] = []
        if fresh_now >= deadline:
            fresh_reasons.append("PREPARED_INTENT_EXPIRED")
        if (
            _broker_spec_binding_sha256(fresh.broker_spec)
            != record.broker_spec_binding_sha256
        ):
            fresh_reasons.append("BROKER_SPEC_BINDING_DRIFT")
        spec_age = (fresh_now - fresh.broker_spec.captured_at).total_seconds()
        if spec_age < 0 or spec_age > MAX_COMPOSITION_FACT_AGE_SECONDS:
            fresh_reasons.append("BROKER_SPEC_STALE")
        model_binding = verify_decision_model(
            decision,
            model_artifact,
            checked_at=fresh_now,
        )
        if not model_binding.bound:
            fresh_reasons.extend(model_binding.reason_codes)
        try:
            trusted_context = require_verified_risk_context(
                fresh.risk_context,
                now=fresh_now,
                expected_account_id=prepared_intent.account_id,
                expected_server=prepared_intent.server,
                expected_environment="DEMO",
                expected_mode="DEMO",
                expected_symbol=prepared_intent.symbol,
                expected_broker_symbol=record.broker_symbol,
                expected_account_runtime_identity_sha256=(
                    self._account_runtime_identity_sha256
                ),
                expected_journal_sha256=self.journal.journal_sha256,
                broker_spec=fresh.broker_spec,
                health_facts=fresh.health_facts,
                market_guard_decision=fresh.market_guard,
                expected_permit_id=permit.permit_id,
            )
        except RiskContextVerificationError as exc:
            fresh_reasons.extend(exc.reason_codes)
            trusted_context = None
        if fresh_reasons or trusted_context is None:
            return self._wait(
                decision,
                status="WAIT_PRECONDITION",
                reasons=tuple(fresh_reasons),
                sizing_quote=record.sizing_quote,
                intent=record.intent,
            )

        stop_distance_points = abs(
            prepared_intent.entry_reference - prepared_intent.stop_loss
        ) / fresh.broker_spec.point
        allowed_slippage_points = max(
            0,
            int(
                math.floor(
                    min(
                        trusted_context.p95_slippage_points,
                        0.10 * stop_distance_points,
                    )
                    + 1e-12
                )
            ),
        )
        quote = self.adapter.calculate_broker_sized_lot(
            canonical_symbol=prepared_intent.symbol,
            broker_symbol=record.broker_symbol,
            side=prepared_intent.side,
            entry_price=prepared_intent.entry_reference,
            stop_loss=prepared_intent.stop_loss,
            equity=trusted_context.equity,
            allowed_slippage_points=allowed_slippage_points,
            usd_risk_cap_conversion=trusted_context.usd_risk_cap_conversion,
            now=fresh_now,
        )
        delegate_now = self._trusted_now()
        sizing_reasons: list[str] = []
        if type(quote) is not BrokerSizingQuote:
            sizing_reasons.append("FRESH_SIZING_QUOTE_INVALID")
        else:
            quote_age = (delegate_now - quote.evaluated_at_utc).total_seconds()
            if quote_age < 0 or quote_age > 0.05:
                sizing_reasons.append("FRESH_SIZING_QUOTE_STALE")
            if quote.status != "SIZED":
                sizing_reasons.append(quote.status)
            if (
                quote.symbol != prepared_intent.symbol
                or quote.broker_symbol != record.broker_symbol
            ):
                sizing_reasons.append("FRESH_SIZING_LANE_MISMATCH")
            if quote.normalized_lot != prepared_intent.requested_lot:
                sizing_reasons.append("PREPARED_LOT_NO_LONGER_SAFE")
            if quote.actual_stop_risk_cash <= 0 or quote.margin_cash <= 0:
                sizing_reasons.append("FRESH_SIZING_CASH_FACTS_INVALID")
            if quote.margin_cash > 0.10 * trusted_context.equity + 1e-12:
                sizing_reasons.append("FRESH_SIZING_MARGIN_CAP_EXCEEDED")
        try:
            require_verified_risk_context(
                fresh.risk_context,
                now=delegate_now,
                expected_account_id=prepared_intent.account_id,
                expected_server=prepared_intent.server,
                expected_environment="DEMO",
                expected_mode="DEMO",
                expected_symbol=prepared_intent.symbol,
                expected_broker_symbol=record.broker_symbol,
                expected_account_runtime_identity_sha256=(
                    self._account_runtime_identity_sha256
                ),
                expected_journal_sha256=self.journal.journal_sha256,
                broker_spec=fresh.broker_spec,
                health_facts=fresh.health_facts,
                market_guard_decision=fresh.market_guard,
                expected_permit_id=permit.permit_id,
            )
        except RiskContextVerificationError as exc:
            sizing_reasons.extend(exc.reason_codes)
        if delegate_now >= deadline:
            sizing_reasons.append("PREPARED_INTENT_EXPIRED")
        if not permit.issued_at <= delegate_now < permit.expires_at:
            sizing_reasons.append("PERMIT_TIME_INVALID")
        if not (
            manual_demo_approval.issued_at_utc
            <= delegate_now
            < manual_demo_approval.expires_at_utc
        ):
            sizing_reasons.append("MANUAL_DEMO_APPROVAL_TIME_INVALID")
        if sizing_reasons:
            return self._wait(
                decision,
                status="WAIT_PRECONDITION",
                reasons=tuple(sizing_reasons),
                sizing_quote=quote if isinstance(quote, BrokerSizingQuote) else None,
                intent=record.intent,
            )

        with self._prepared_lock:
            current = self._prepared_by_intent.get(record.intent.intent_id)
            if current is not record or current.state != "PREPARED":
                return self._wait(
                    decision,
                    status="WAIT_CONTROL",
                    reasons=("PREPARED_INTENT_REPLAYED",),
                    sizing_quote=record.sizing_quote,
                    intent=record.intent,
                )
            # Claim before delegation.  Any exception is fail-closed and the
            # proposal can never be submitted a second time.
            current.state = "DELEGATED"
        outcome = self.coordinator.execute_once(
            intent=record.intent,
            broker_symbol=record.broker_symbol,
            broker_spec=fresh.broker_spec,
            risk_context=fresh.risk_context,
            permit=permit,
            health_facts=fresh.health_facts,
            market_guard=fresh.market_guard,
            model_artifact=model_artifact,
            owner_id=normalized_owner,
            fence_token=fence_token,
            manual_demo_approval=manual_demo_approval,
            promotion_evidence=None,
            now=delegate_now,
        )
        if not isinstance(outcome, ExecutionOutcome):
            raise RuntimeCompositionError(
                "execution coordinator must return an ExecutionOutcome"
            )
        if outcome.intent_id != record.intent.intent_id:
            raise RuntimeCompositionError(
                "execution outcome is bound to another prepared intent"
            )
        return RuntimeCycleResult(
            status=outcome.status,
            reason_codes=outcome.reason_codes,
            decision_snapshot_id=decision.snapshot_id,
            sizing_quote=quote,
            intent=record.intent,
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
