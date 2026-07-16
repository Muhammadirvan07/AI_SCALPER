"""Fenced, idempotent execution coordinator for the future Windows runtime.

Nothing imports or invokes this coordinator from the current AI_SCALPER
entrypoints.  Live and demo-auto policy flags remain hard-locked.  A manual
demo submission additionally requires a fresh signed permit, a process-bound
environment arm capability, a signed per-order approval, healthy runtime facts,
broker preflight, and an owned
executor fence.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import math
from typing import Any, Callable

from execution_policy import (
    LIVE_ALLOWED,
    SAFE_TO_DEMO_AUTO_ORDER,
    validate_execution_symbol,
)

from .account_fence import AccountRuntimeFence, AccountRuntimeFenceError

from .contracts import (
    BrokerSpec,
    CanonicalContract,
    TradeIntent,
    canonical_sha256,
    canonicalize,
    require_utc,
)
from .controls import (
    ManualDemoApproval,
    ManualDemoApprovalValidation,
    read_environment_arm,
    validate_manual_demo_approval,
)
from .health import RuntimeHealthDecision, RuntimeHealthFacts, evaluate_runtime_health
from .journal import (
    DuplicateIntentError,
    ExecutionJournal,
    ExecutorFenceError,
    IntentRecord,
    KillSwitchLatchedError,
    SubmissionLimitError,
)
from .market_guard import MarketGuardDecision
from .model_governance import (
    ModelArtifactManifest,
    ModelBindingDecision,
    verify_decision_model,
)
from .mt5_adapter import (
    AccountBindingError,
    ExecutionLockedError,
    MT5AdapterError,
    PreflightRejectedError,
    SubmissionUncertainError,
    _mint_execution_gate_capability,
    build_runtime_authorization,
)
from .permit import PromotionPermit, validate_permit
from .promotion_evidence import (
    PromotionEvidenceReceipt,
    PromotionEvidenceValidation,
    validate_promotion_evidence_receipt,
)
from .risk import MAX_MARGIN_FRACTION, RiskContext, RiskDecision, evaluate_risk


UTC = timezone.utc
MAX_RUNTIME_FACT_AGE_SECONDS = 1.0
RECONCILIATION_STATES = frozenset(
    {"SUBMITTING", "ACKNOWLEDGED", "PARTIAL", "FILLED", "UNCERTAIN"}
)
TERMINAL_STATES = frozenset({"RISK_REJECTED", "REJECTED", "EXPIRED", "CLOSED"})


def _utc_now() -> datetime:
    return datetime.now(UTC)


@dataclass(frozen=True)
class ExecutionOutcome(CanonicalContract):
    intent_id: str
    state: str
    status: str
    reason_codes: tuple[str, ...]
    execution_sent: bool
    reconciliation_required: bool
    risk_decision_id: str | None = None
    receipt_id: str | None = None
    live_allowed: bool = LIVE_ALLOWED
    safe_to_demo_auto_order: bool = SAFE_TO_DEMO_AUTO_ORDER

    def __post_init__(self) -> None:
        if not self.intent_id or not self.state or not self.status:
            raise ValueError("intent_id, state, and status are required")
        if type(self.execution_sent) is not bool or type(self.reconciliation_required) is not bool:
            raise TypeError("outcome flags must be bool")
        reasons = tuple(sorted(set(str(item).upper() for item in self.reason_codes)))
        if self.live_allowed or self.safe_to_demo_auto_order:
            raise ValueError("execution outcome cannot change hard policy locks")
        object.__setattr__(self, "reason_codes", reasons)


def _preflight_payload(preflight: Any) -> dict[str, Any]:
    return canonicalize(
        {
            "intent_id": preflight.intent_id,
            "passed": preflight.passed,
            "reason": preflight.reason,
            "broker_symbol": preflight.broker_symbol,
            "intent_sha256": preflight.intent_sha256,
            "broker_spec_sha256": preflight.broker_spec_sha256,
            "request": preflight.request,
            "request_sha256": preflight.request_sha256,
            "broker_retcode": preflight.broker_retcode,
            "checked_at_utc": preflight.checked_at_utc,
            "valid_until_utc": preflight.valid_until_utc,
            "current_bid": preflight.current_bid,
            "current_ask": preflight.current_ask,
            "tick_time_utc": preflight.tick_time_utc,
            "allowed_deviation_points": preflight.allowed_deviation_points,
            "estimated_stop_risk_cash": preflight.estimated_stop_risk_cash,
            "estimated_margin_cash": preflight.estimated_margin_cash,
        }
    )


class ExecutionCoordinator:
    """Coordinate one intent without ever retrying an uncertain submission."""

    def __init__(
        self,
        journal: ExecutionJournal,
        adapter: Any,
        *,
        permit_secret_provider: Callable[[], str | bytes],
        promotion_evidence_key_provider: Callable[[str], str | bytes] | None = None,
        manual_approval_key_provider: Callable[[str], str | bytes] | None = None,
        expected_manual_approver_id: str | None = None,
        expected_manual_approval_key_id: str | None = None,
        clock_provider: Callable[[], datetime] = _utc_now,
    ):
        if not isinstance(journal, ExecutionJournal):
            raise TypeError("journal must be an ExecutionJournal")
        required_methods = (
            "preflight",
            "submission_guard",
            "submit",
            "execution_fence_identity",
        )
        if any(not callable(getattr(adapter, name, None)) for name in required_methods):
            raise TypeError("adapter must expose preflight, submission_guard, and submit")
        if not callable(permit_secret_provider):
            raise TypeError("permit_secret_provider must be callable")
        if not callable(clock_provider):
            raise TypeError("clock_provider must be callable")
        if promotion_evidence_key_provider is not None and not callable(
            promotion_evidence_key_provider
        ):
            raise TypeError("promotion_evidence_key_provider must be callable")
        if manual_approval_key_provider is not None and not callable(
            manual_approval_key_provider
        ):
            raise TypeError("manual_approval_key_provider must be callable")
        self.journal = journal
        self.adapter = adapter
        runtime_identity = str(adapter.execution_fence_identity() or "").lower()
        if len(runtime_identity) != 64 or any(
            character not in "0123456789abcdef"
            for character in runtime_identity
        ):
            raise TypeError("adapter execution fence identity must be SHA-256")
        self._account_runtime_identity_sha256 = runtime_identity
        self.permit_secret_provider = permit_secret_provider
        self.promotion_evidence_key_provider = promotion_evidence_key_provider
        self.manual_approval_key_provider = manual_approval_key_provider
        self.expected_manual_approver_id = str(
            expected_manual_approver_id or ""
        ).strip()
        self.expected_manual_approval_key_id = str(
            expected_manual_approval_key_id or ""
        ).strip()
        self._clock_provider = clock_provider
        self._account_runtime_fence: AccountRuntimeFence | None = None

    def close(self) -> None:
        if self._account_runtime_fence is not None:
            self._account_runtime_fence.close()
            self._account_runtime_fence = None

    def __enter__(self) -> ExecutionCoordinator:
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        self.close()

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass

    def _claim_account_runtime_fence(self) -> None:
        if self._account_runtime_fence is None:
            candidate = AccountRuntimeFence(self._account_runtime_identity_sha256)
            candidate.acquire()
            self._account_runtime_fence = candidate
            return
        if self._account_runtime_fence.identity_sha256 != (
            self._account_runtime_identity_sha256
        ):
            raise AccountRuntimeFenceError(
                "one coordinator cannot cross broker account/server boundaries"
            )

    def _trusted_now(self, requested: datetime | None = None) -> datetime:
        trusted = require_utc("trusted clock", self._clock_provider())
        if requested is not None:
            requested = require_utc("now", requested)
            if abs((requested - trusted).total_seconds()) > 0.05:
                raise ValueError("caller timestamp disagrees with trusted clock")
        return trusted

    def _outcome(
        self,
        record: IntentRecord,
        *,
        status: str,
        reasons: tuple[str, ...] = (),
        execution_sent: bool = False,
        risk: RiskDecision | None = None,
        receipt_id: str | None = None,
    ) -> ExecutionOutcome:
        return ExecutionOutcome(
            intent_id=record.intent_id,
            state=record.state,
            status=status,
            reason_codes=reasons,
            execution_sent=execution_sent,
            reconciliation_required=record.state in RECONCILIATION_STATES,
            risk_decision_id=risk.decision_id if risk else None,
            receipt_id=receipt_id,
        )

    def _reject(
        self,
        record: IntentRecord,
        reasons: tuple[str, ...],
        *,
        now: datetime,
        risk: RiskDecision | None = None,
    ) -> ExecutionOutcome:
        target = "RISK_REJECTED" if record.state == "CREATED" else "REJECTED"
        updated = self.journal.transition(
            record.intent_id,
            target,
            expected_state=record.state,
            details={"reason_codes": list(reasons)},
            occurred_at=now,
            last_error=",".join(reasons),
        )
        return self._outcome(
            updated,
            status="EXECUTION_REJECTED",
            reasons=reasons,
            risk=risk,
        )

    def _existing_intent_outcome(
        self,
        intent: TradeIntent,
        record: IntentRecord,
        *,
        now: datetime,
    ) -> ExecutionOutcome:
        stored_intent = record.payload.get("intent")
        binding_valid = (
            record.intent_id == intent.intent_id
            and record.decision_id == intent.decision.snapshot_id
            and record.symbol == intent.symbol
            and isinstance(stored_intent, dict)
            and stored_intent == intent.to_canonical_dict()
        )
        if not binding_valid:
            self.journal.latch_kill_switch(
                f"journal intent binding mismatch for {intent.intent_id}",
                source="EXECUTION",
                occurred_at=now,
            )
            return self._outcome(
                record,
                status="JOURNAL_INTENT_BINDING_REJECTED",
                reasons=("JOURNAL_INTENT_BINDING_MISMATCH",),
            )
        if record.state in RECONCILIATION_STATES:
            return self._outcome(record, status="RECONCILIATION_REQUIRED")
        if record.state in TERMINAL_STATES:
            return self._outcome(record, status="IDEMPOTENT_TERMINAL")
        return self._outcome(
            record,
            status="IDEMPOTENT_INCOMPLETE_INTENT_REQUIRES_REVIEW",
            reasons=("INTENT_ALREADY_DURABLE",),
        )

    def execute_once(
        self,
        *,
        intent: TradeIntent,
        broker_symbol: str,
        broker_spec: BrokerSpec,
        risk_context: RiskContext,
        permit: PromotionPermit,
        health_facts: RuntimeHealthFacts,
        market_guard: MarketGuardDecision,
        model_artifact: ModelArtifactManifest,
        owner_id: str,
        fence_token: int,
        manual_demo_approval: ManualDemoApproval | None = None,
        promotion_evidence: PromotionEvidenceReceipt | None = None,
        now: datetime | None = None,
    ) -> ExecutionOutcome:
        """Evaluate, preflight, and at most once submit one immutable intent."""

        now = self._trusted_now(now)
        if not isinstance(intent, TradeIntent) or not isinstance(broker_spec, BrokerSpec):
            raise TypeError("validated intent and broker_spec are required")
        if not isinstance(risk_context, RiskContext):
            raise TypeError("risk_context must be RiskContext")
        if not isinstance(permit, PromotionPermit):
            raise TypeError("permit must be a signed PromotionPermit")
        if not isinstance(health_facts, RuntimeHealthFacts):
            raise TypeError("health_facts must be RuntimeHealthFacts")
        if not isinstance(market_guard, MarketGuardDecision):
            raise TypeError("market_guard must come from evaluate_market_guards")
        if not isinstance(model_artifact, ModelArtifactManifest):
            raise TypeError("model_artifact must be ModelArtifactManifest")
        self.journal.assert_executor_fence(owner_id, fence_token, now=now)
        existing_record = self.journal.get_intent(intent.intent_id)
        if existing_record is not None:
            return self._existing_intent_outcome(
                intent,
                existing_record,
                now=now,
            )
        health = evaluate_runtime_health(health_facts)
        model_binding = verify_decision_model(
            intent.decision,
            model_artifact,
            checked_at=now,
        )
        arm_decision = read_environment_arm(
            intent.account_id,
            intent.server,
            intent.mode,
            now,
            self.journal.journal_sha256,
        )
        manual_validation: ManualDemoApprovalValidation | None = None
        if (
            intent.mode == "DEMO"
            and isinstance(manual_demo_approval, ManualDemoApproval)
            and self.manual_approval_key_provider is not None
            and self.expected_manual_approver_id
            and self.expected_manual_approval_key_id
        ):
            manual_validation = validate_manual_demo_approval(
                manual_demo_approval,
                expected_intent_id=intent.intent_id,
                expected_account_id=intent.account_id,
                expected_server=intent.server,
                expected_approver_id=self.expected_manual_approver_id,
                expected_key_id=self.expected_manual_approval_key_id,
                expected_journal_sha256=self.journal.journal_sha256,
                key_provider=self.manual_approval_key_provider,
                clock_provider=lambda: now,
            )

        promotion_validation: PromotionEvidenceValidation | None = None
        promotion_required = intent.mode in {"DEMO_AUTO", "LIVE"}
        if (
            promotion_required
            and isinstance(promotion_evidence, PromotionEvidenceReceipt)
            and self.promotion_evidence_key_provider is not None
        ):
            promotion_validation = validate_promotion_evidence_receipt(
                promotion_evidence,
                self.promotion_evidence_key_provider,
                now=now,
                expected_mode=intent.mode,
                expected_account_alias=intent.account_id,
                expected_server=intent.server,
                expected_journal_sha256=self.journal.journal_sha256,
                expected_symbol=intent.symbol,
                expected_strategy=intent.decision.strategy,
                expected_commit_sha=intent.decision.commit_sha,
                expected_config_sha256=intent.decision.config_sha256,
                expected_model_artifact_sha256=(
                    intent.decision.model_artifact_sha256
                ),
            )
        promotion_evidence_sha256 = (
            promotion_validation.receipt_sha256
            if promotion_validation is not None and promotion_validation.valid
            else None
        )

        try:
            permit_validation = validate_permit(
                permit,
                self.permit_secret_provider(),
                now=now,
                expected_mode=intent.mode,
                expected_account_alias=intent.account_id,
                expected_server=intent.server,
                expected_symbols=(intent.symbol,),
                expected_commit_sha=intent.decision.commit_sha,
                expected_config_sha256=intent.decision.config_sha256,
                expected_model_artifact_sha256=(
                    intent.decision.model_artifact_sha256
                ),
                expected_journal_sha256=self.journal.journal_sha256,
                expected_promotion_evidence_sha256=promotion_evidence_sha256,
            )
        except (TypeError, ValueError):
            # A missing/invalid credential is a denial, never a reason to bypass
            # signed-permit validation.
            permit_validation = None
        payload = {
            "intent": intent.to_canonical_dict(),
            "broker_spec": broker_spec.to_canonical_dict(),
            "broker_spec_sha256": broker_spec.content_sha256,
            "broker_symbol": broker_symbol,
            "broker_comment": f"AIS:{intent.content_sha256[:20]}",
            "permit_id": permit.permit_id,
            "permit_journal_sha256": permit.journal_sha256,
            "model_artifact": model_artifact.to_canonical_dict(),
            "model_artifact_manifest_sha256": model_artifact.content_sha256,
            "promotion_evidence": (
                promotion_evidence.to_canonical_dict()
                if promotion_evidence is not None
                else None
            ),
            "promotion_evidence_sha256": promotion_evidence_sha256,
        }
        try:
            record = self.journal.create_intent(
                intent_id=intent.intent_id,
                decision_id=intent.decision.snapshot_id,
                symbol=intent.symbol,
                payload=payload,
                created_at=intent.created_at,
            )
        except DuplicateIntentError:
            raced_record = self.journal.get_intent(intent.intent_id)
            if raced_record is None:
                raise
            return self._existing_intent_outcome(
                intent,
                raced_record,
                now=now,
            )
        if record.intent_id != intent.intent_id:
            return self._outcome(
                record,
                status="DECISION_ALREADY_HAS_DURABLE_INTENT",
                reasons=("DECISION_IDEMPOTENCY_LOCKED",),
            )
        if record.state != "CREATED":
            return self._existing_intent_outcome(intent, record, now=now)

        safety_reasons: list[str] = []
        if intent.mode == "LIVE":
            safety_reasons.append("LIVE_MODE_LOCKED")
        if intent.mode == "DEMO_AUTO":
            safety_reasons.append("DEMO_AUTO_ORDER_LOCKED")
        if not arm_decision.armed:
            safety_reasons.extend(arm_decision.reason_codes)
        if intent.mode == "DEMO":
            if manual_validation is None:
                safety_reasons.append("MANUAL_DEMO_APPROVAL_REQUIRED")
            elif not manual_validation.valid:
                safety_reasons.extend(manual_validation.reason_codes)
        if promotion_required:
            if promotion_validation is None:
                safety_reasons.append("PROMOTION_EVIDENCE_REQUIRED")
            elif not promotion_validation.valid:
                safety_reasons.extend(promotion_validation.reason_codes)
            if permit.symbols != (intent.symbol,):
                safety_reasons.append("PROMOTION_PERMIT_MUST_BIND_ONE_LANE")
        symbol_allowed, _ = validate_execution_symbol(intent.symbol)
        if not symbol_allowed:
            safety_reasons.append("SYMBOL_EXECUTION_POLICY_BLOCKED")
        if broker_symbol != broker_spec.broker_symbol:
            safety_reasons.append("BROKER_SYMBOL_BINDING_MISMATCH")
        expected_environment = "LIVE" if intent.mode == "LIVE" else "DEMO"
        if intent.mode in {"DEMO", "DEMO_AUTO", "LIVE"} and (
            broker_spec.environment != expected_environment
        ):
            safety_reasons.append("BROKER_ENVIRONMENT_MISMATCH")
        if self.journal.kill_switch_status()["latched"]:
            safety_reasons.append("KILL_SWITCH_LATCHED")
        if health_facts.kill_switch_latched != self.journal.kill_switch_status()["latched"]:
            safety_reasons.append("HEALTH_KILL_SWITCH_STATE_MISMATCH")
        if market_guard.symbol != intent.symbol:
            safety_reasons.append("MARKET_GUARD_SYMBOL_MISMATCH")
        if not market_guard.news_clear:
            safety_reasons.extend(market_guard.reason_codes or ("NEWS_WINDOW_BLOCKED",))
        if not market_guard.rollover_clear:
            safety_reasons.extend(market_guard.reason_codes or ("ROLLOVER_WINDOW_BLOCKED",))
        if risk_context.news_clear != market_guard.news_clear:
            safety_reasons.append("RISK_NEWS_GUARD_MISMATCH")
        if risk_context.rollover_clear != market_guard.rollover_clear:
            safety_reasons.append("RISK_ROLLOVER_GUARD_MISMATCH")
        if not model_binding.bound:
            safety_reasons.extend(model_binding.reason_codes)
        for observed_at, stale_code in (
            (health.observed_at, "HEALTH_DECISION_STALE"),
            (risk_context.evaluated_at, "RISK_CONTEXT_STALE"),
            (broker_spec.captured_at, "BROKER_SPEC_STALE"),
            (market_guard.evaluated_at, "MARKET_GUARD_STALE"),
            (model_binding.checked_at, "MODEL_BINDING_STALE"),
        ):
            age = (now - observed_at).total_seconds()
            if age < 0 or age > MAX_RUNTIME_FACT_AGE_SECONDS:
                safety_reasons.append(stale_code)
        if not health.healthy:
            safety_reasons.extend(health.reason_codes)
        if permit_validation is None:
            safety_reasons.append("PERMIT_VALIDATION_FAILED")
        elif intent.permit_id != permit_validation.permit_id:
            safety_reasons.append("PERMIT_ID_MISMATCH")
        if permit_validation is not None and not permit_validation.valid:
            safety_reasons.extend(permit_validation.reason_codes)
        if risk_context.permit_valid != (
            permit_validation.valid if permit_validation is not None else False
        ):
            safety_reasons.append("PERMIT_CONTEXT_MISMATCH")
        if safety_reasons:
            return self._reject(
                record,
                tuple(sorted(set(safety_reasons))),
                now=now,
            )

        try:
            self._claim_account_runtime_fence()
        except AccountRuntimeFenceError:
            return self._reject(
                record,
                ("ACCOUNT_RUNTIME_FENCE_UNAVAILABLE",),
                now=now,
            )

        self.journal.append_receipt(
            intent.intent_id,
            "MARKET_GUARD",
            market_guard.to_canonical_dict(),
            now,
        )
        self.journal.append_receipt(
            intent.intent_id,
            "MODEL_BINDING",
            model_binding.to_canonical_dict(),
            now,
        )
        if promotion_validation is not None:
            self.journal.append_receipt(
                intent.intent_id,
                "PROMOTION_EVIDENCE_VALIDATION",
                promotion_validation.to_canonical_dict(),
                now,
            )
        self.journal.append_receipt(
            intent.intent_id,
            "ENVIRONMENT_ARM_DECISION",
            arm_decision.to_canonical_dict(),
            now,
        )
        if manual_validation is not None:
            self.journal.append_receipt(
                intent.intent_id,
                "MANUAL_DEMO_APPROVAL_VALIDATION",
                manual_validation.to_canonical_dict(),
                now,
            )

        risk = evaluate_risk(intent, broker_spec, risk_context)
        self.journal.append_receipt(
            intent.intent_id,
            "RISK_DECISION",
            risk.to_canonical_dict(),
            now,
        )
        if not risk.allowed:
            latched_reasons = {
                "DAILY_LOSS_LIMIT",
                "WEEKLY_LOSS_LIMIT",
                "DRAWDOWN_LIMIT",
                "LOSS_LATCH_ACTIVE",
            }.intersection(risk.reason_codes)
            if latched_reasons:
                self.journal.latch_kill_switch(
                    "risk stop: " + ",".join(sorted(latched_reasons)),
                    source="RISK_GOVERNOR",
                    occurred_at=now,
                )
            return self._reject(record, risk.reason_codes, now=now, risk=risk)
        if record.state == "CREATED":
            record = self.journal.transition(
                intent.intent_id,
                "RISK_APPROVED",
                expected_state="CREATED",
                details={"risk_decision_id": risk.decision_id},
                occurred_at=now,
            )

        try:
            preflight = self.adapter.preflight(
                intent,
                broker_symbol,
                allowed_deviation_points=max(
                    0, int(math.floor(risk.slippage_limit_points))
                ),
                now=now,
            )
        except (
            AccountBindingError,
            ExecutionLockedError,
            PreflightRejectedError,
            MT5AdapterError,
        ) as exc:
            return self._reject(
                record,
                (f"PREFLIGHT_EXCEPTION_{type(exc).__name__}".upper(),),
                now=now,
                risk=risk,
            )
        self.journal.append_receipt(
            intent.intent_id,
            "MT5_PREFLIGHT",
            _preflight_payload(preflight),
            now,
        )
        preflight_reasons: list[str] = []
        if not preflight.passed:
            preflight_reasons.append("BROKER_ORDER_CHECK_REJECTED")
        if preflight.estimated_stop_risk_cash > risk.max_risk_cash + 1e-12:
            preflight_reasons.append("BROKER_CALCULATED_RISK_EXCEEDED")
        if preflight.estimated_margin_cash > MAX_MARGIN_FRACTION * risk_context.equity:
            preflight_reasons.append("BROKER_CALCULATED_MARGIN_EXCEEDED")
        actual_spread_points = (
            float(preflight.current_ask) - float(preflight.current_bid)
        ) / broker_spec.point
        if (
            actual_spread_points >= risk.spread_p95_points
            or actual_spread_points
            > risk.spread_median_multiple_limit_points
        ):
            preflight_reasons.append("ACTUAL_BROKER_SPREAD_EXCEEDED")
        if preflight.broker_spec_sha256 != broker_spec.content_sha256:
            preflight_reasons.append("BROKER_SPEC_PREFLIGHT_MISMATCH")
        request = preflight.request
        expected_payload = {
            "symbol": broker_symbol,
            "volume": intent.requested_lot,
            "price": intent.entry_reference,
            "sl": intent.stop_loss,
            "tp": intent.take_profit,
        }
        if any(request.get(key) != value for key, value in expected_payload.items()):
            preflight_reasons.append("PREFLIGHT_PAYLOAD_MISMATCH")
        if preflight_reasons:
            return self._reject(
                record,
                tuple(preflight_reasons),
                now=now,
                risk=risk,
            )
        if record.state == "RISK_APPROVED":
            record = self.journal.transition(
                intent.intent_id,
                "PREFLIGHT_PASSED",
                expected_state="RISK_APPROVED",
                details={"broker_retcode": preflight.broker_retcode},
                occurred_at=now,
            )

        mode_policy_allows = arm_decision.armed and (
            (intent.mode == "DEMO" and manual_validation is not None and manual_validation.valid)
            or (intent.mode == "LIVE" and LIVE_ALLOWED)
            or (intent.mode == "DEMO_AUTO" and SAFE_TO_DEMO_AUTO_ORDER)
        )
        if not mode_policy_allows:
            return self._reject(
                record,
                ("EXECUTION_POLICY_LOCKED",),
                now=now,
                risk=risk,
            )

        try:
            guard = self.adapter.submission_guard(
                intent,
                broker_spec,
                expected_equity=risk_context.equity,
                now=now,
            )
            self.journal.append_receipt(
                intent.intent_id,
                "SUBMISSION_GUARD",
                canonicalize(guard),
                now,
            )
        except (
            AccountBindingError,
            ExecutionLockedError,
            PreflightRejectedError,
            MT5AdapterError,
        ) as exc:
            return self._reject(
                record,
                (f"SUBMISSION_GUARD_{type(exc).__name__}".upper(),),
                now=now,
                risk=risk,
            )
        reserve_now = self._trusted_now()
        refreshed_arm_decision = read_environment_arm(
            intent.account_id,
            intent.server,
            intent.mode,
            reserve_now,
            self.journal.journal_sha256,
        )
        refreshed_manual_validation: ManualDemoApprovalValidation | None = None
        if (
            intent.mode == "DEMO"
            and isinstance(manual_demo_approval, ManualDemoApproval)
            and self.manual_approval_key_provider is not None
            and self.expected_manual_approver_id
            and self.expected_manual_approval_key_id
        ):
            refreshed_manual_validation = validate_manual_demo_approval(
                manual_demo_approval,
                expected_intent_id=intent.intent_id,
                expected_account_id=intent.account_id,
                expected_server=intent.server,
                expected_approver_id=self.expected_manual_approver_id,
                expected_key_id=self.expected_manual_approval_key_id,
                expected_journal_sha256=self.journal.journal_sha256,
                key_provider=self.manual_approval_key_provider,
                clock_provider=lambda: reserve_now,
            )
        try:
            refreshed_validation = validate_permit(
                permit,
                self.permit_secret_provider(),
                now=reserve_now,
                expected_mode=intent.mode,
                expected_account_alias=intent.account_id,
                expected_server=intent.server,
                expected_symbols=(intent.symbol,),
                expected_commit_sha=intent.decision.commit_sha,
                expected_config_sha256=intent.decision.config_sha256,
                expected_model_artifact_sha256=(
                    intent.decision.model_artifact_sha256
                ),
                expected_journal_sha256=self.journal.journal_sha256,
                expected_promotion_evidence_sha256=promotion_evidence_sha256,
            )
        except (TypeError, ValueError):
            refreshed_validation = None
        refreshed_reasons: list[str] = []
        if not refreshed_arm_decision.armed:
            refreshed_reasons.extend(refreshed_arm_decision.reason_codes)
        if intent.mode == "DEMO" and (
            refreshed_manual_validation is None
            or not refreshed_manual_validation.valid
        ):
            refreshed_reasons.append("MANUAL_DEMO_APPROVAL_STALE_AT_RESERVATION")
        if refreshed_validation is None or not refreshed_validation.valid:
            refreshed_reasons.append("PERMIT_STALE_AT_RESERVATION")
        elif refreshed_validation.permit_id != intent.permit_id:
            refreshed_reasons.append("PERMIT_ID_MISMATCH_AT_RESERVATION")
        if reserve_now >= intent.expires_at:
            refreshed_reasons.append("INTENT_EXPIRED_AT_RESERVATION")
        for observed_at, reason in (
            (health.observed_at, "HEALTH_DECISION_STALE_AT_RESERVATION"),
            (risk.evaluated_at, "RISK_DECISION_STALE_AT_RESERVATION"),
            (broker_spec.captured_at, "BROKER_SPEC_STALE_AT_RESERVATION"),
            (market_guard.evaluated_at, "MARKET_GUARD_STALE_AT_RESERVATION"),
            (model_binding.checked_at, "MODEL_BINDING_STALE_AT_RESERVATION"),
            (preflight.checked_at_utc, "PREFLIGHT_STALE_AT_RESERVATION"),
        ):
            age = (reserve_now - observed_at).total_seconds()
            if age < 0 or age > MAX_RUNTIME_FACT_AGE_SECONDS:
                refreshed_reasons.append(reason)
        if reserve_now >= preflight.valid_until_utc:
            refreshed_reasons.append("PREFLIGHT_EXPIRED_AT_RESERVATION")
        if reserve_now >= model_binding.valid_until:
            refreshed_reasons.append("MODEL_BINDING_EXPIRED_AT_RESERVATION")
        guard_checked_at = guard.get("checked_at_utc")
        if not isinstance(guard_checked_at, datetime):
            refreshed_reasons.append("SUBMISSION_GUARD_TIMESTAMP_MISSING")
        else:
            guard_age = (reserve_now - require_utc(
                "submission guard checked_at", guard_checked_at
            )).total_seconds()
            if guard_age < 0 or guard_age > MAX_RUNTIME_FACT_AGE_SECONDS:
                refreshed_reasons.append("SUBMISSION_GUARD_STALE_AT_RESERVATION")
        if refreshed_reasons:
            return self._reject(
                record,
                tuple(sorted(set(refreshed_reasons))),
                now=reserve_now,
                risk=risk,
            )
        permit_validation = refreshed_validation
        try:
            record = self.journal.reserve_submission(
                intent.intent_id,
                owner_id=owner_id,
                fence_token=fence_token,
                details={"fence_token": fence_token, "owner_id": owner_id},
                occurred_at=reserve_now,
            )
        except KillSwitchLatchedError:
            return self._reject(
                record,
                ("KILL_SWITCH_LATCHED_AT_SUBMISSION",),
                now=reserve_now,
                risk=risk,
            )
        except SubmissionLimitError as exc:
            return self._reject(
                record,
                (exc.reason_code,),
                now=reserve_now,
                risk=risk,
            )
        except ExecutorFenceError:
            return self._outcome(
                record,
                status="EXECUTOR_FENCE_LOST_BEFORE_SUBMISSION",
                reasons=("EXECUTOR_FENCE_LOST",),
                risk=risk,
            )
        try:
            gate_capability = _mint_execution_gate_capability(
                intent=intent,
                risk_decision=risk,
                health_decision=health,
                market_guard_decision=market_guard,
                model_binding_decision=model_binding,
                preflight=preflight,
                submission_guard=guard,
                broker_spec=broker_spec,
                reservation=record,
                journal_sha256=self.journal.journal_sha256,
                now=reserve_now,
            )
            authorization = build_runtime_authorization(
                intent=intent,
                permit_validation=permit_validation,
                risk_decision=risk,
                broker_spec=broker_spec,
                reservation=record,
                gate_capability=gate_capability,
                journal_sha256=self.journal.journal_sha256,
                environment_arm_decision=refreshed_arm_decision,
                manual_demo_approval_validation=refreshed_manual_validation,
                now=reserve_now,
            )
        except (ExecutionLockedError, TypeError, ValueError):
            return self._reject(
                record,
                ("EXECUTION_CAPABILITY_BINDING_FAILED",),
                now=reserve_now,
                risk=risk,
            )
        submission_now = self._trusted_now()
        if (
            not authorization.allows_order_send(now=submission_now)
            or submission_now >= preflight.valid_until_utc
            or submission_now >= intent.expires_at
        ):
            rejected = self.journal.transition(
                intent.intent_id,
                "REJECTED",
                expected_state="SUBMITTING",
                details={"reason_codes": ["EXECUTION_EVIDENCE_EXPIRED_BEFORE_SEND"]},
                occurred_at=submission_now,
                last_error="EXECUTION_EVIDENCE_EXPIRED_BEFORE_SEND",
            )
            return self._outcome(
                rejected,
                status="SUBMISSION_REJECTED_BEFORE_SEND",
                reasons=("EXECUTION_EVIDENCE_EXPIRED_BEFORE_SEND",),
                risk=risk,
            )
        try:
            with self.journal.final_submission_guard(
                intent.intent_id,
                owner_id=owner_id,
                fence_token=fence_token,
                execution_gate_sha256=authorization.execution_gate_sha256,
                authorization_sha256=canonical_sha256(authorization),
                occurred_at=submission_now,
            ) as submission_lease:
                receipt = self.adapter.submit(
                    intent,
                    preflight,
                    authorization,
                    submission_lease,
                    now=submission_now,
                )
        except KillSwitchLatchedError as exc:
            rejected = self.journal.transition(
                intent.intent_id,
                "REJECTED",
                expected_state="SUBMITTING",
                details={"error": type(exc).__name__},
                occurred_at=submission_now,
                last_error=str(exc),
            )
            return self._outcome(
                rejected,
                status="FINAL_SUBMISSION_GUARD_REJECTED",
                reasons=("KILL_SWITCH_LATCHED_AT_FINAL_GUARD",),
                risk=risk,
            )
        except (ExecutorFenceError, SubmissionLimitError) as exc:
            return self._outcome(
                self.journal.get_intent(intent.intent_id),
                status="FINAL_SUBMISSION_GUARD_REJECTED",
                reasons=(
                    exc.reason_code
                    if isinstance(exc, SubmissionLimitError)
                    else "EXECUTOR_FENCE_LOST_AT_FINAL_GUARD",
                ),
                risk=risk,
            )
        except SubmissionUncertainError as exc:
            uncertain = self.journal.transition(
                intent.intent_id,
                "UNCERTAIN",
                expected_state="SUBMITTING",
                details={"error": type(exc).__name__, "retry_allowed": False},
                occurred_at=submission_now,
                last_error=str(exc),
            )
            return self._outcome(
                uncertain,
                status="SUBMISSION_UNCERTAIN",
                reasons=("RECONCILIATION_REQUIRED_BEFORE_RETRY",),
                execution_sent=True,
                risk=risk,
            )
        except (ExecutionLockedError, PreflightRejectedError, AccountBindingError) as exc:
            rejected = self.journal.transition(
                intent.intent_id,
                "REJECTED",
                expected_state="SUBMITTING",
                details={"error": type(exc).__name__},
                occurred_at=submission_now,
                last_error=str(exc),
            )
            return self._outcome(
                rejected,
                status="SUBMISSION_REJECTED_BEFORE_SEND",
                reasons=(type(exc).__name__.upper(),),
                risk=risk,
            )
        except Exception as exc:
            uncertain = self.journal.transition(
                intent.intent_id,
                "UNCERTAIN",
                expected_state="SUBMITTING",
                details={"error": type(exc).__name__, "retry_allowed": False},
                occurred_at=submission_now,
                last_error=str(exc),
            )
            return self._outcome(
                uncertain,
                status="SUBMISSION_UNCERTAIN",
                reasons=("UNKNOWN_SUBMISSION_OUTCOME",),
                execution_sent=True,
                risk=risk,
            )

        self.journal.append_receipt(
            intent.intent_id,
            "EXECUTION_RECEIPT",
            receipt.to_canonical_dict(),
            submission_now,
        )
        next_state = receipt.state
        if next_state not in {"ACKNOWLEDGED", "PARTIAL", "FILLED", "REJECTED"}:
            next_state = "UNCERTAIN"
        updated = self.journal.transition(
            intent.intent_id,
            next_state,
            expected_state="SUBMITTING",
            details={"receipt_id": receipt.receipt_id},
            occurred_at=submission_now,
            broker_order_ticket=receipt.order_ticket,
            filled_volume=receipt.filled_volume,
            protective_sl_tp_confirmed=False,
        )
        realized_slippage_points = (
            max(0.0, float(receipt.slippage_price or 0.0)) / broker_spec.point
        )
        slippage_breach = realized_slippage_points > risk.slippage_limit_points + 1e-12
        if slippage_breach:
            self.journal.latch_kill_switch(
                f"realized slippage {realized_slippage_points:.6f} exceeded "
                f"limit {risk.slippage_limit_points:.6f} for {intent.intent_id}",
                source="EXECUTION",
                occurred_at=submission_now,
            )
        return self._outcome(
            updated,
            status=(
                "BROKER_RESPONSE_REQUIRES_RECONCILIATION"
                if next_state != "REJECTED"
                else "BROKER_REJECTED"
            ),
            reasons=("REALIZED_SLIPPAGE_LIMIT_BREACH",) if slippage_breach else (),
            execution_sent=True,
            risk=risk,
            receipt_id=receipt.receipt_id,
        )


__all__ = ["ExecutionCoordinator", "ExecutionOutcome"]
