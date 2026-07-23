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

import execution_policy
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
    require_utc,
)
from .controls import (
    ManualDemoApproval,
    ManualDemoApprovalValidation,
    manual_demo_account_sha256,
    read_environment_arm,
    validate_manual_demo_approval,
)
from .decision_ipc import VerifiedDecisionIPCEnvelope
from .demo_auto_ipc_consumer import DemoAutoIPCRiskIntentInput
from .demo_auto_session_capability import (
    DemoAutoSessionCapabilityStore,
    DemoAutoSessionDispatchVerification,
    DemoAutoSessionLease,
)
from .health import RuntimeHealthDecision, RuntimeHealthFacts, evaluate_runtime_health
from .journal import (
    DuplicateIntentError,
    ExecutionJournal,
    ExecutorFenceError,
    InvalidTransitionError,
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
from .risk import MAX_MARGIN_FRACTION, RiskDecision, evaluate_risk
from .risk_context_factory import (
    RiskContextVerificationError,
    VerifiedRiskContext,
    require_verified_risk_context,
)


UTC = timezone.utc
MAX_RUNTIME_FACT_AGE_SECONDS = 1.0
RECONCILIATION_STATES = frozenset(
    {"SUBMITTING", "ACKNOWLEDGED", "PARTIAL", "FILLED", "UNCERTAIN"}
)
TERMINAL_STATES = frozenset({"RISK_REJECTED", "REJECTED", "EXPIRED", "CLOSED"})


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _demo_auto_control_reasons(
    *,
    intent: TradeIntent,
    ipc_input: DemoAutoIPCRiskIntentInput | None,
    session_lease: DemoAutoSessionLease | None,
    session_store: DemoAutoSessionCapabilityStore | None,
    session_dispatch_verification: DemoAutoSessionDispatchVerification | None,
    now: datetime,
    journal_sha256: str,
) -> tuple[str, ...]:
    """Validate dormant DEMO_AUTO-only capabilities without granting authority."""

    if type(ipc_input) is not DemoAutoIPCRiskIntentInput:
        return ("DEMO_AUTO_IPC_INPUT_REQUIRED",)
    if type(session_lease) is not DemoAutoSessionLease:
        return ("DEMO_AUTO_SESSION_LEASE_REQUIRED",)
    if type(session_store) is not DemoAutoSessionCapabilityStore:
        return ("DEMO_AUTO_SESSION_STORE_REQUIRED",)
    if type(session_dispatch_verification) is not DemoAutoSessionDispatchVerification:
        return ("DEMO_AUTO_SESSION_DISPATCH_VERIFICATION_REQUIRED",)
    reasons: list[str] = []
    try:
        verified_dispatch = session_store.verify_dispatch_verification(
            session_dispatch_verification,
            session_lease,
            expected_intent_id=intent.intent_id,
        )
    except Exception:
        return ("DEMO_AUTO_SESSION_LEASE_INVALID",)
    if verified_dispatch is not session_dispatch_verification:
        reasons.append("DEMO_AUTO_SESSION_LEASE_INVALID")
    envelope = ipc_input.verified_envelope
    if type(envelope) is not VerifiedDecisionIPCEnvelope:
        reasons.append("DEMO_AUTO_IPC_CONSUMPTION_INVALID")
    decision = ipc_input.decision
    expected_account_sha256 = manual_demo_account_sha256(intent.account_id)
    if (
        intent.mode != "DEMO_AUTO"
        or decision.content_sha256 != intent.decision.content_sha256
        or decision.snapshot_id != intent.decision.snapshot_id
        or ipc_input.supervisor_binding.content_sha256
        != session_lease.supervisor_binding_sha256
        or ipc_input.stage_binding.binding_sha256
        != session_lease.stage_binding_sha256
        or ipc_input.stage_binding.lane_id != session_lease.lane_id
        or session_store.binding.content_sha256
        != session_dispatch_verification.binding_sha256
        or session_dispatch_verification.lease_sha256
        != session_lease.content_sha256
        or session_dispatch_verification.intent_id != intent.intent_id
        or expected_account_sha256 != session_lease.account_alias_sha256
        or intent.server != session_lease.server
        or journal_sha256 != session_lease.journal_sha256
        or intent.decision.commit_sha != session_lease.commit_sha
        or intent.decision.config_sha256 != session_lease.config_sha256
        or intent.decision.model_artifact_sha256
        != session_lease.model_artifact_sha256
        or ipc_input.permit.permit_id != intent.permit_id
        or ipc_input.permit_validation.permit_id != intent.permit_id
        or ipc_input.permit_validation.journal_sha256 != journal_sha256
        or ipc_input.permit_validation.symbols != (intent.symbol,)
        or ipc_input.permit_validation.mode != "DEMO_AUTO"
    ):
        reasons.append("DEMO_AUTO_CONTROL_BINDING_MISMATCH")
    if (
        not ipc_input.permit_validation.valid
        or not ipc_input.environment_arm.is_fresh(now)
        or not ipc_input.consumed_at_utc <= now < ipc_input.valid_until_utc
        or not session_lease.issued_at_utc <= now < session_lease.expires_at_utc
        or not session_dispatch_verification.verified_at_utc
        <= now
        < session_dispatch_verification.valid_until_utc
    ):
        reasons.append("DEMO_AUTO_CONTROL_STALE")
    if (
        ipc_input.live_allowed
        or ipc_input.safe_to_demo_auto_order
        or ipc_input.execution_authorized
        or ipc_input.activation_authorized
        or ipc_input.order_capability != "DISABLED"
        or session_lease.live_allowed
        or session_lease.safe_to_demo_auto_order
        or session_lease.execution_authorized
        or session_lease.activation_authorized
        or session_lease.order_capability != "DISABLED"
    ):
        reasons.append("DEMO_AUTO_CONTROL_ESCALATION_DETECTED")
    return tuple(sorted(set(reasons)))


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
        if type(journal) is not ExecutionJournal:
            raise TypeError("journal must be exact ExecutionJournal")
        if not all(
            (
                callable(getattr(adapter, "preflight", None)),
                callable(getattr(adapter, "submission_guard", None)),
                callable(getattr(adapter, "submit", None)),
                callable(getattr(adapter, "execution_fence_identity", None)),
            )
        ):
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

    @property
    def account_runtime_identity_sha256(self) -> str:
        """Public, non-secret identity used to bind trusted runtime proofs."""

        return self._account_runtime_identity_sha256

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

    def _settle_demo_auto_dispatch(
        self,
        store: DemoAutoSessionCapabilityStore,
        verification: DemoAutoSessionDispatchVerification,
    ) -> bool:
        """Close or quarantine one reservation from sealed journal evidence."""

        try:
            settlement = self.journal.demo_auto_dispatch_settlement(
                verification.intent_id,
                dispatch_verification_sha256=verification.content_sha256,
            )
            store.apply_dispatch_journal_settlement(settlement)
            return True
        except Exception as exc:
            self.journal.latch_kill_switch(
                "DEMO_AUTO dispatch settlement failed for "
                f"{verification.intent_id}: {type(exc).__name__}",
                source="EXECUTION",
                occurred_at=self._trusted_now(),
            )
            return False

    def _abort_demo_auto_before_send(
        self,
        *,
        intent: TradeIntent,
        store: DemoAutoSessionCapabilityStore,
        verification: DemoAutoSessionDispatchVerification,
        reason_code: str,
        risk: RiskDecision | None,
        occurred_at: datetime | None = None,
    ) -> ExecutionOutcome:
        rejected = self.journal.record_submission_not_sent(
            intent.intent_id,
            dispatch_verification_sha256=verification.content_sha256,
            reason_code=reason_code,
            occurred_at=occurred_at,
        )
        settled = self._settle_demo_auto_dispatch(store, verification)
        return self._outcome(
            rejected,
            status=(
                "SUBMISSION_HELD_BEFORE_SEND"
                if settled
                else "DEMO_AUTO_SETTLEMENT_FAILED"
            ),
            reasons=(
                (reason_code,)
                if settled
                else tuple(sorted((reason_code, "DEMO_AUTO_SETTLEMENT_FAILED")))
            ),
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
        risk_context: VerifiedRiskContext,
        permit: PromotionPermit,
        health_facts: RuntimeHealthFacts,
        market_guard: MarketGuardDecision,
        model_artifact: ModelArtifactManifest,
        owner_id: str,
        fence_token: int,
        manual_demo_approval: ManualDemoApproval | None = None,
        promotion_evidence: PromotionEvidenceReceipt | None = None,
        demo_auto_ipc_input: DemoAutoIPCRiskIntentInput | None = None,
        demo_auto_session_lease: DemoAutoSessionLease | None = None,
        demo_auto_session_store: DemoAutoSessionCapabilityStore | None = None,
        demo_auto_session_dispatch_verification: (
            DemoAutoSessionDispatchVerification | None
        ) = None,
        now: datetime | None = None,
    ) -> ExecutionOutcome:
        """Evaluate, preflight, and at most once submit one immutable intent."""

        now = self._trusted_now(now)
        if type(intent) is not TradeIntent or type(broker_spec) is not BrokerSpec:
            raise TypeError("exact validated intent and broker_spec are required")
        if type(risk_context) is not VerifiedRiskContext:
            raise TypeError("risk_context must be an exact sealed VerifiedRiskContext")
        if type(permit) is not PromotionPermit:
            raise TypeError("permit must be an exact signed PromotionPermit")
        if type(health_facts) is not RuntimeHealthFacts:
            raise TypeError("health_facts must be exact RuntimeHealthFacts")
        if type(market_guard) is not MarketGuardDecision:
            raise TypeError("market_guard must be an exact evaluated decision")
        if type(model_artifact) is not ModelArtifactManifest:
            raise TypeError("model_artifact must be exact ModelArtifactManifest")
        trusted_context = require_verified_risk_context(
            risk_context,
            now=now,
            expected_account_id=intent.account_id,
            expected_server=intent.server,
            expected_environment=broker_spec.environment,
            expected_mode=intent.mode,
            expected_symbol=intent.symbol,
            expected_broker_symbol=broker_symbol,
            expected_account_runtime_identity_sha256=(
                self._account_runtime_identity_sha256
            ),
            expected_journal_sha256=self.journal.journal_sha256,
            broker_spec=broker_spec,
            health_facts=health_facts,
            market_guard_decision=market_guard,
            expected_permit_id=permit.permit_id,
        )
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
            and type(manual_demo_approval) is ManualDemoApproval
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
            and type(promotion_evidence) is PromotionEvidenceReceipt
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
        mode_policy_allowed, mode_policy_reasons = (
            execution_policy.execution_mode_policy_decision(intent.mode)
        )
        demo_auto_control_reasons: tuple[str, ...] = ()
        if intent.mode == "DEMO_AUTO" and mode_policy_allowed:
            demo_auto_control_reasons = _demo_auto_control_reasons(
                intent=intent,
                ipc_input=demo_auto_ipc_input,
                session_lease=demo_auto_session_lease,
                session_store=demo_auto_session_store,
                session_dispatch_verification=(
                    demo_auto_session_dispatch_verification
                ),
                now=now,
                journal_sha256=self.journal.journal_sha256,
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
            "verified_risk_context_sha256": risk_context.content_sha256,
            "verified_risk_context": risk_context.provenance_metadata(),
            "demo_auto_ipc_input_sha256": (
                demo_auto_ipc_input.content_sha256
                if type(demo_auto_ipc_input) is DemoAutoIPCRiskIntentInput
                else None
            ),
            "demo_auto_ipc_consumption_hmac_sha256": (
                demo_auto_ipc_input.verified_envelope.consumption_hmac_sha256
                if type(demo_auto_ipc_input) is DemoAutoIPCRiskIntentInput
                else None
            ),
            "demo_auto_ipc_post_checkpoint_sha256": (
                demo_auto_ipc_input.verified_envelope.post_checkpoint_sha256
                if type(demo_auto_ipc_input) is DemoAutoIPCRiskIntentInput
                else None
            ),
            "demo_auto_session_lease_sha256": (
                demo_auto_session_lease.content_sha256
                if type(demo_auto_session_lease) is DemoAutoSessionLease
                else None
            ),
            "demo_auto_session_store_binding_sha256": (
                demo_auto_session_store.binding.content_sha256
                if type(demo_auto_session_store)
                is DemoAutoSessionCapabilityStore
                else None
            ),
            "demo_auto_session_dispatch_verification_sha256": (
                demo_auto_session_dispatch_verification.content_sha256
                if type(demo_auto_session_dispatch_verification)
                is DemoAutoSessionDispatchVerification
                else None
            ),
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
        if not mode_policy_allowed:
            safety_reasons.extend(mode_policy_reasons)
        safety_reasons.extend(demo_auto_control_reasons)
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
        symbol_allowed, _ = validate_execution_symbol(
            intent.symbol,
            mode=intent.mode,
        )
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
        if trusted_context.news_clear != market_guard.news_clear:
            safety_reasons.append("RISK_NEWS_GUARD_MISMATCH")
        if trusted_context.rollover_clear != market_guard.rollover_clear:
            safety_reasons.append("RISK_ROLLOVER_GUARD_MISMATCH")
        if not model_binding.bound:
            safety_reasons.extend(model_binding.reason_codes)
        for observed_at, stale_code in (
            (health.observed_at, "HEALTH_DECISION_STALE"),
            (trusted_context.evaluated_at, "RISK_CONTEXT_STALE"),
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
        if trusted_context.permit_valid != (
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

        risk = evaluate_risk(intent, broker_spec, trusted_context)
        self.journal.record_risk_decision(
            intent.intent_id,
            risk,
            occurred_at=now,
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

        preflight_now = self._trusted_now()
        try:
            preflight = self.adapter.preflight(
                intent,
                broker_symbol,
                allowed_deviation_points=max(
                    0, int(math.floor(risk.slippage_limit_points))
                ),
                now=preflight_now,
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
        self.journal.record_mt5_preflight(
            intent.intent_id,
            preflight,
            occurred_at=now,
        )
        preflight_reasons: list[str] = []
        if not preflight.passed:
            preflight_reasons.append("BROKER_ORDER_CHECK_REJECTED")
        if preflight.estimated_stop_risk_cash > risk.max_risk_cash + 1e-12:
            preflight_reasons.append("BROKER_CALCULATED_RISK_EXCEEDED")
        if preflight.estimated_margin_cash > MAX_MARGIN_FRACTION * trusted_context.equity:
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

        refreshed_mode_policy_allowed, _mode_policy_reasons = (
            execution_policy.execution_mode_policy_decision(intent.mode)
        )
        mode_policy_allows = arm_decision.armed and (
            (
                intent.mode == "DEMO"
                and manual_validation is not None
                and manual_validation.valid
            )
            or (
                intent.mode in {"LIVE", "DEMO_AUTO"}
                and refreshed_mode_policy_allowed
            )
        )
        if not mode_policy_allows:
            return self._reject(
                record,
                ("EXECUTION_POLICY_LOCKED",),
                now=now,
                risk=risk,
            )

        guard_now = self._trusted_now()
        try:
            guard = self.adapter.submission_guard(
                intent,
                broker_spec,
                expected_equity=trusted_context.equity,
                now=guard_now,
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
        try:
            require_verified_risk_context(
                risk_context,
                now=reserve_now,
                expected_account_id=intent.account_id,
                expected_server=intent.server,
                expected_environment=broker_spec.environment,
                expected_mode=intent.mode,
                expected_symbol=intent.symbol,
                expected_broker_symbol=broker_symbol,
                expected_account_runtime_identity_sha256=(
                    self._account_runtime_identity_sha256
                ),
                expected_journal_sha256=self.journal.journal_sha256,
                broker_spec=broker_spec,
                health_facts=health_facts,
                market_guard_decision=market_guard,
                expected_permit_id=permit.permit_id,
            )
        except RiskContextVerificationError as exc:
            return self._reject(
                record,
                exc.reason_codes,
                now=reserve_now,
                risk=risk,
            )
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
            and type(manual_demo_approval) is ManualDemoApproval
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
        refreshed_promotion_validation: PromotionEvidenceValidation | None = None
        if (
            promotion_required
            and type(promotion_evidence) is PromotionEvidenceReceipt
            and self.promotion_evidence_key_provider is not None
        ):
            refreshed_promotion_validation = validate_promotion_evidence_receipt(
                promotion_evidence,
                self.promotion_evidence_key_provider,
                now=reserve_now,
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
        refreshed_reasons: list[str] = []
        refreshed_mode_allowed, refreshed_mode_reasons = (
            execution_policy.execution_mode_policy_decision(intent.mode)
        )
        if not refreshed_mode_allowed:
            refreshed_reasons.extend(refreshed_mode_reasons)
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
        if promotion_required and (
            refreshed_promotion_validation is None
            or not refreshed_promotion_validation.valid
            or refreshed_promotion_validation.receipt_sha256
            != promotion_evidence_sha256
        ):
            refreshed_reasons.append("PROMOTION_EVIDENCE_STALE_AT_RESERVATION")
        if intent.mode == "DEMO_AUTO" and refreshed_mode_allowed:
            refreshed_reasons.extend(
                _demo_auto_control_reasons(
                    intent=intent,
                    ipc_input=demo_auto_ipc_input,
                    session_lease=demo_auto_session_lease,
                    session_store=demo_auto_session_store,
                    session_dispatch_verification=(
                        demo_auto_session_dispatch_verification
                    ),
                    now=reserve_now,
                    journal_sha256=self.journal.journal_sha256,
                )
            )
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
        guard_age = (
            reserve_now
            - require_utc(
                "submission guard checked_at",
                guard.checked_at_utc,
            )
        ).total_seconds()
        if guard_age < 0 or guard_age > MAX_RUNTIME_FACT_AGE_SECONDS:
            refreshed_reasons.append("SUBMISSION_GUARD_STALE_AT_RESERVATION")
        if refreshed_reasons:
            return self._reject(
                record,
                tuple(sorted(set(refreshed_reasons))),
                now=reserve_now,
                risk=risk,
            )
        # The execution journal deliberately treats SUBMITTING as broker-exposed.
        # Therefore every DEMO_AUTO authority that can fail without broker facts
        # is rechecked while the intent is still PREFLIGHT_PASSED.  Only a fully
        # current control set may acquire the global submission reservation.
        if intent.mode == "DEMO_AUTO":
            final_check_now = self._trusted_now()
            final_reasons: list[str] = list(
                _demo_auto_control_reasons(
                    intent=intent,
                    ipc_input=demo_auto_ipc_input,
                    session_lease=demo_auto_session_lease,
                    session_store=demo_auto_session_store,
                    session_dispatch_verification=(
                        demo_auto_session_dispatch_verification
                    ),
                    now=final_check_now,
                    journal_sha256=self.journal.journal_sha256,
                )
            )
            final_mode_allowed, final_mode_reasons = (
                execution_policy.execution_mode_policy_decision(intent.mode)
            )
            if not final_mode_allowed:
                final_reasons.extend(final_mode_reasons)
            final_arm = read_environment_arm(
                intent.account_id,
                intent.server,
                intent.mode,
                final_check_now,
                self.journal.journal_sha256,
            )
            if (
                not final_arm.armed
                or final_arm.binding_sha256
                != refreshed_arm_decision.binding_sha256
                or final_arm.observed_value_sha256
                != refreshed_arm_decision.observed_value_sha256
            ):
                final_reasons.append("DEMO_AUTO_ARM_STALE_BEFORE_RESERVATION")
            try:
                final_permit_validation = validate_permit(
                    permit,
                    self.permit_secret_provider(),
                    now=final_check_now,
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
                    expected_promotion_evidence_sha256=(
                        promotion_evidence_sha256
                    ),
                )
            except (TypeError, ValueError):
                final_permit_validation = None
            if (
                final_permit_validation is None
                or not final_permit_validation.valid
                or final_permit_validation.permit_id != intent.permit_id
            ):
                final_reasons.append("DEMO_AUTO_PERMIT_STALE_BEFORE_RESERVATION")
            final_promotion_validation = None
            if (
                type(promotion_evidence) is PromotionEvidenceReceipt
                and self.promotion_evidence_key_provider is not None
            ):
                final_promotion_validation = validate_promotion_evidence_receipt(
                    promotion_evidence,
                    self.promotion_evidence_key_provider,
                    now=final_check_now,
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
            if (
                final_promotion_validation is None
                or not final_promotion_validation.valid
                or final_promotion_validation.receipt_sha256
                != promotion_evidence_sha256
            ):
                final_reasons.append(
                    "DEMO_AUTO_PROMOTION_EVIDENCE_STALE_BEFORE_RESERVATION"
                )
            final_record = self.journal.get_intent(intent.intent_id)
            if (
                final_record is None
                or final_record.decision_id != intent.decision.snapshot_id
                or final_record.state != "PREFLIGHT_PASSED"
                or final_record.payload.get("demo_auto_ipc_input_sha256")
                != (
                    demo_auto_ipc_input.content_sha256
                    if type(demo_auto_ipc_input) is DemoAutoIPCRiskIntentInput
                    else None
                )
                or final_record.payload.get("demo_auto_session_lease_sha256")
                != (
                    demo_auto_session_lease.content_sha256
                    if type(demo_auto_session_lease) is DemoAutoSessionLease
                    else None
                )
                or final_record.payload.get(
                    "demo_auto_session_store_binding_sha256"
                )
                != (
                    demo_auto_session_store.binding.content_sha256
                    if type(demo_auto_session_store)
                    is DemoAutoSessionCapabilityStore
                    else None
                )
                or final_record.payload.get(
                    "demo_auto_session_dispatch_verification_sha256"
                )
                != (
                    demo_auto_session_dispatch_verification.content_sha256
                    if type(demo_auto_session_dispatch_verification)
                    is DemoAutoSessionDispatchVerification
                    else None
                )
            ):
                final_reasons.append("DEMO_AUTO_JOURNAL_BINDING_MISMATCH")
            if final_reasons:
                reason_codes = tuple(sorted(set(final_reasons)))
                rejected = self.journal.transition(
                    intent.intent_id,
                    "REJECTED",
                    expected_state="PREFLIGHT_PASSED",
                    details={
                        "reason_codes": list(reason_codes),
                        "retry_allowed": False,
                        "broker_submit_called": False,
                        "reconciliation_required": False,
                    },
                    occurred_at=final_check_now,
                    last_error="DEMO_AUTO_FINAL_DISPATCH_REJECTED",
                )
                return self._outcome(
                    rejected,
                    status="SUBMISSION_HELD_BEFORE_SEND",
                    reasons=reason_codes,
                    risk=risk,
                )
        permit_validation = refreshed_validation
        try:
            submission_evidence = self.journal.authorize_submission_evidence(
                intent.intent_id,
                risk_decision=risk,
                preflight=preflight,
                submission_guard=guard,
                broker_spec=broker_spec,
                occurred_at=reserve_now,
            )
        except (InvalidTransitionError, TypeError, ValueError):
            return self._reject(
                record,
                ("SUBMISSION_EVIDENCE_BINDING_FAILED",),
                now=reserve_now,
                risk=risk,
            )
        if intent.mode == "DEMO_AUTO":
            try:
                assert type(demo_auto_session_store) is DemoAutoSessionCapabilityStore
                assert type(demo_auto_session_lease) is DemoAutoSessionLease
                assert (
                    type(demo_auto_session_dispatch_verification)
                    is DemoAutoSessionDispatchVerification
                )
                demo_auto_session_store.reserve_dispatch_verification(
                    demo_auto_session_dispatch_verification,
                    demo_auto_session_lease,
                    expected_intent_id=intent.intent_id,
                )
            except Exception:
                return self._reject(
                    record,
                    ("DEMO_AUTO_SESSION_RESERVATION_FAILED",),
                    now=reserve_now,
                    risk=risk,
                )
        try:
            record = self.journal.reserve_submission(
                intent.intent_id,
                owner_id=owner_id,
                fence_token=fence_token,
                submission_evidence=submission_evidence,
                details={"fence_token": fence_token, "owner_id": owner_id},
                occurred_at=reserve_now,
            )
        except KillSwitchLatchedError:
            reasons = ("KILL_SWITCH_LATCHED_AT_SUBMISSION",)
        except SubmissionLimitError as exc:
            reasons = (exc.reason_code,)
        except ExecutorFenceError:
            reasons = ("EXECUTOR_FENCE_LOST",)
        except Exception as exc:
            reasons = (f"SUBMISSION_RESERVATION_{type(exc).__name__.upper()}",)
        else:
            reasons = ()
        if reasons:
            if intent.mode != "DEMO_AUTO":
                if reasons == ("EXECUTOR_FENCE_LOST",):
                    return self._outcome(
                        record,
                        status="EXECUTOR_FENCE_LOST_BEFORE_SUBMISSION",
                        reasons=reasons,
                        risk=risk,
                    )
                return self._reject(
                    record,
                    reasons,
                    now=reserve_now,
                    risk=risk,
                )
            assert type(demo_auto_session_store) is DemoAutoSessionCapabilityStore
            assert (
                type(demo_auto_session_dispatch_verification)
                is DemoAutoSessionDispatchVerification
            )
            settled = self._settle_demo_auto_dispatch(
                demo_auto_session_store,
                demo_auto_session_dispatch_verification,
            )
            current = self.journal.get_intent(intent.intent_id)
            if current is None:
                raise RuntimeError("journal intent disappeared during dispatch abort")
            return self._outcome(
                current,
                status=(
                    "SUBMISSION_HELD_BEFORE_SEND"
                    if settled
                    else "DEMO_AUTO_SETTLEMENT_FAILED"
                ),
                reasons=(
                    reasons
                    if settled
                    else tuple(sorted((*reasons, "DEMO_AUTO_SETTLEMENT_FAILED")))
                ),
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
                verified_risk_context=risk_context,
                reservation=record,
                gate_capability=gate_capability,
                journal_sha256=self.journal.journal_sha256,
                environment_arm_decision=refreshed_arm_decision,
                manual_demo_approval_validation=refreshed_manual_validation,
                now=reserve_now,
                additional_valid_until_utc=(
                    min(
                        demo_auto_ipc_input.valid_until_utc,
                        demo_auto_session_lease.expires_at_utc,
                        demo_auto_session_dispatch_verification.valid_until_utc,
                        refreshed_promotion_validation.expires_at,
                    )
                    if intent.mode == "DEMO_AUTO"
                    and type(demo_auto_ipc_input) is DemoAutoIPCRiskIntentInput
                    and type(demo_auto_session_lease) is DemoAutoSessionLease
                    and type(demo_auto_session_dispatch_verification)
                    is DemoAutoSessionDispatchVerification
                    and type(refreshed_promotion_validation)
                    is PromotionEvidenceValidation
                    else None
                ),
            )
        except (ExecutionLockedError, TypeError, ValueError) as exc:
            if intent.mode == "DEMO_AUTO":
                assert type(demo_auto_session_store) is DemoAutoSessionCapabilityStore
                assert (
                    type(demo_auto_session_dispatch_verification)
                    is DemoAutoSessionDispatchVerification
                )
                rejected = self.journal.record_submission_not_sent(
                    intent.intent_id,
                    dispatch_verification_sha256=(
                        demo_auto_session_dispatch_verification.content_sha256
                    ),
                    reason_code="EXECUTION_CAPABILITY_BINDING_FAILED",
                    occurred_at=reserve_now,
                )
                settled = self._settle_demo_auto_dispatch(
                    demo_auto_session_store,
                    demo_auto_session_dispatch_verification,
                )
                return self._outcome(
                    rejected,
                    status=(
                        "SUBMISSION_HELD_BEFORE_SEND"
                        if settled
                        else "DEMO_AUTO_SETTLEMENT_FAILED"
                    ),
                    reasons=(
                        ("EXECUTION_CAPABILITY_BINDING_FAILED",)
                        if settled
                        else (
                            "DEMO_AUTO_SETTLEMENT_FAILED",
                            "EXECUTION_CAPABILITY_BINDING_FAILED",
                        )
                    ),
                    risk=risk,
                )
            uncertain = self.journal.transition(
                intent.intent_id,
                "UNCERTAIN",
                expected_state="SUBMITTING",
                details={
                    "reason_codes": ["EXECUTION_CAPABILITY_BINDING_FAILED"],
                    "error": type(exc).__name__,
                    "retry_allowed": False,
                },
                occurred_at=reserve_now,
                last_error="EXECUTION_CAPABILITY_BINDING_FAILED",
            )
            return self._outcome(
                uncertain,
                status="SUBMISSION_HELD_BEFORE_SEND",
                reasons=("EXECUTION_CAPABILITY_BINDING_FAILED",),
                risk=risk,
            )
        submission_now = self._trusted_now()
        if (
            not authorization.allows_order_send(now=submission_now)
            or submission_now >= preflight.valid_until_utc
            or submission_now >= intent.expires_at
        ):
            if intent.mode == "DEMO_AUTO":
                assert type(demo_auto_session_store) is DemoAutoSessionCapabilityStore
                assert (
                    type(demo_auto_session_dispatch_verification)
                    is DemoAutoSessionDispatchVerification
                )
                rejected = self.journal.record_submission_not_sent(
                    intent.intent_id,
                    dispatch_verification_sha256=(
                        demo_auto_session_dispatch_verification.content_sha256
                    ),
                    reason_code="EXECUTION_EVIDENCE_EXPIRED_BEFORE_SEND",
                    occurred_at=None,
                )
                settled = self._settle_demo_auto_dispatch(
                    demo_auto_session_store,
                    demo_auto_session_dispatch_verification,
                )
                return self._outcome(
                    rejected,
                    status=(
                        "SUBMISSION_HELD_BEFORE_SEND"
                        if settled
                        else "DEMO_AUTO_SETTLEMENT_FAILED"
                    ),
                    reasons=(
                        ("EXECUTION_EVIDENCE_EXPIRED_BEFORE_SEND",)
                        if settled
                        else (
                            "DEMO_AUTO_SETTLEMENT_FAILED",
                            "EXECUTION_EVIDENCE_EXPIRED_BEFORE_SEND",
                        )
                    ),
                    risk=risk,
                )
            uncertain = self.journal.transition(
                intent.intent_id,
                "UNCERTAIN",
                expected_state="SUBMITTING",
                details={
                    "reason_codes": ["EXECUTION_EVIDENCE_EXPIRED_BEFORE_SEND"],
                    "retry_allowed": False,
                },
                # The execution journal is the timestamp authority for its own
                # state machine.  The coordinator clock is used to decide that
                # evidence expired, but is not allowed to forge journal time if
                # independently configured clocks disagree.
                occurred_at=None,
                last_error="EXECUTION_EVIDENCE_EXPIRED_BEFORE_SEND",
            )
            return self._outcome(
                uncertain,
                status="SUBMISSION_HELD_BEFORE_SEND",
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
                broker_request_sha256=preflight.request_sha256,
                occurred_at=submission_now,
            ) as submission_lease:
                if intent.mode == "DEMO_AUTO":
                    assert (
                        type(demo_auto_session_store)
                        is DemoAutoSessionCapabilityStore
                    )
                    assert type(demo_auto_session_lease) is DemoAutoSessionLease
                    assert (
                        type(demo_auto_session_dispatch_verification)
                        is DemoAutoSessionDispatchVerification
                    )
                    send_now = self._trusted_now()
                    send_reasons = list(
                        _demo_auto_control_reasons(
                            intent=intent,
                            ipc_input=demo_auto_ipc_input,
                            session_lease=demo_auto_session_lease,
                            session_store=demo_auto_session_store,
                            session_dispatch_verification=(
                                demo_auto_session_dispatch_verification
                            ),
                            now=send_now,
                            journal_sha256=self.journal.journal_sha256,
                        )
                    )
                    try:
                        demo_auto_session_store.verify_reserved_dispatch(
                            demo_auto_session_dispatch_verification,
                            demo_auto_session_lease,
                            expected_intent_id=intent.intent_id,
                        )
                        send_permit = validate_permit(
                            permit,
                            self.permit_secret_provider(),
                            now=send_now,
                            expected_mode=intent.mode,
                            expected_account_alias=intent.account_id,
                            expected_server=intent.server,
                            expected_symbols=(intent.symbol,),
                            expected_commit_sha=intent.decision.commit_sha,
                            expected_config_sha256=(
                                intent.decision.config_sha256
                            ),
                            expected_model_artifact_sha256=(
                                intent.decision.model_artifact_sha256
                            ),
                            expected_journal_sha256=self.journal.journal_sha256,
                            expected_promotion_evidence_sha256=(
                                promotion_evidence_sha256
                            ),
                        )
                        send_promotion = (
                            validate_promotion_evidence_receipt(
                                promotion_evidence,
                                self.promotion_evidence_key_provider,
                                now=send_now,
                                expected_mode=intent.mode,
                                expected_account_alias=intent.account_id,
                                expected_server=intent.server,
                                expected_journal_sha256=(
                                    self.journal.journal_sha256
                                ),
                                expected_symbol=intent.symbol,
                                expected_strategy=intent.decision.strategy,
                                expected_commit_sha=intent.decision.commit_sha,
                                expected_config_sha256=(
                                    intent.decision.config_sha256
                                ),
                                expected_model_artifact_sha256=(
                                    intent.decision.model_artifact_sha256
                                ),
                            )
                            if type(promotion_evidence)
                            is PromotionEvidenceReceipt
                            and self.promotion_evidence_key_provider is not None
                            else None
                        )
                        send_arm = read_environment_arm(
                            intent.account_id,
                            intent.server,
                            intent.mode,
                            send_now,
                            self.journal.journal_sha256,
                        )
                    except Exception:
                        send_reasons.append(
                            "DEMO_AUTO_FINAL_AUTHORITY_REVALIDATION_FAILED"
                        )
                    else:
                        if not send_permit.valid:
                            send_reasons.append(
                                "DEMO_AUTO_PERMIT_STALE_AT_SEND"
                            )
                        if (
                            send_promotion is None
                            or not send_promotion.valid
                            or send_promotion.receipt_sha256
                            != promotion_evidence_sha256
                        ):
                            send_reasons.append(
                                "DEMO_AUTO_PROMOTION_STALE_AT_SEND"
                            )
                        if (
                            not send_arm.armed
                            or send_arm.binding_sha256
                            != refreshed_arm_decision.binding_sha256
                            or send_arm.observed_value_sha256
                            != refreshed_arm_decision.observed_value_sha256
                        ):
                            send_reasons.append("DEMO_AUTO_ARM_STALE_AT_SEND")
                    if send_reasons:
                        raise ExecutionLockedError(
                            ",".join(sorted(set(send_reasons)))
                        )
                receipt = self.adapter.submit(
                    intent,
                    preflight,
                    authorization,
                    submission_lease,
                    now=submission_now,
                )
        except KillSwitchLatchedError as exc:
            if intent.mode == "DEMO_AUTO":
                assert type(demo_auto_session_store) is DemoAutoSessionCapabilityStore
                assert (
                    type(demo_auto_session_dispatch_verification)
                    is DemoAutoSessionDispatchVerification
                )
                return self._abort_demo_auto_before_send(
                    intent=intent,
                    store=demo_auto_session_store,
                    verification=demo_auto_session_dispatch_verification,
                    reason_code="KILL_SWITCH_LATCHED_AT_FINAL_GUARD",
                    risk=risk,
                    occurred_at=None,
                )
            event_now = self._trusted_now()
            uncertain = self.journal.transition(
                intent.intent_id,
                "UNCERTAIN",
                expected_state="SUBMITTING",
                details={
                    "error": type(exc).__name__,
                    "retry_allowed": False,
                },
                occurred_at=event_now,
                last_error=str(exc),
            )
            return self._outcome(
                uncertain,
                status="FINAL_SUBMISSION_GUARD_HOLD",
                reasons=("KILL_SWITCH_LATCHED_AT_FINAL_GUARD",),
                risk=risk,
            )
        except (ExecutorFenceError, SubmissionLimitError) as exc:
            if intent.mode == "DEMO_AUTO":
                assert type(demo_auto_session_store) is DemoAutoSessionCapabilityStore
                assert (
                    type(demo_auto_session_dispatch_verification)
                    is DemoAutoSessionDispatchVerification
                )
                reason = (
                    exc.reason_code
                    if isinstance(exc, SubmissionLimitError)
                    else "EXECUTOR_FENCE_LOST_AT_FINAL_GUARD"
                )
                return self._abort_demo_auto_before_send(
                    intent=intent,
                    store=demo_auto_session_store,
                    verification=demo_auto_session_dispatch_verification,
                    reason_code=reason,
                    risk=risk,
                    occurred_at=None,
                )
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
            event_now = self._trusted_now()
            uncertain = self.journal.transition(
                intent.intent_id,
                "UNCERTAIN",
                expected_state="SUBMITTING",
                details={"error": type(exc).__name__, "retry_allowed": False},
                occurred_at=event_now,
                last_error=str(exc),
            )
            settlement_failed = False
            if intent.mode == "DEMO_AUTO":
                assert type(demo_auto_session_store) is DemoAutoSessionCapabilityStore
                assert (
                    type(demo_auto_session_dispatch_verification)
                    is DemoAutoSessionDispatchVerification
                )
                settlement_failed = not self._settle_demo_auto_dispatch(
                    demo_auto_session_store,
                    demo_auto_session_dispatch_verification,
                )
            return self._outcome(
                uncertain,
                status="SUBMISSION_UNCERTAIN",
                reasons=(
                    (
                        "DEMO_AUTO_SETTLEMENT_FAILED",
                        "RECONCILIATION_REQUIRED_BEFORE_RETRY",
                    )
                    if settlement_failed
                    else ("RECONCILIATION_REQUIRED_BEFORE_RETRY",)
                ),
                execution_sent=True,
                risk=risk,
            )
        except (ExecutionLockedError, PreflightRejectedError, AccountBindingError) as exc:
            if intent.mode == "DEMO_AUTO":
                assert type(demo_auto_session_store) is DemoAutoSessionCapabilityStore
                assert (
                    type(demo_auto_session_dispatch_verification)
                    is DemoAutoSessionDispatchVerification
                )
                return self._abort_demo_auto_before_send(
                    intent=intent,
                    store=demo_auto_session_store,
                    verification=demo_auto_session_dispatch_verification,
                    reason_code=type(exc).__name__.upper(),
                    risk=risk,
                    occurred_at=None,
                )
            event_now = self._trusted_now()
            uncertain = self.journal.transition(
                intent.intent_id,
                "UNCERTAIN",
                expected_state="SUBMITTING",
                details={
                    "error": type(exc).__name__,
                    "broker_submit_called": False,
                    "reconciliation_required": True,
                    "retry_allowed": False,
                },
                occurred_at=event_now,
                last_error=str(exc),
            )
            return self._outcome(
                uncertain,
                status="SUBMISSION_HELD_BEFORE_SEND",
                reasons=(type(exc).__name__.upper(),),
                risk=risk,
            )
        except Exception as exc:
            event_now = self._trusted_now()
            uncertain = self.journal.transition(
                intent.intent_id,
                "UNCERTAIN",
                expected_state="SUBMITTING",
                details={"error": type(exc).__name__, "retry_allowed": False},
                occurred_at=event_now,
                last_error=str(exc),
            )
            settlement_failed = False
            if intent.mode == "DEMO_AUTO":
                assert type(demo_auto_session_store) is DemoAutoSessionCapabilityStore
                assert (
                    type(demo_auto_session_dispatch_verification)
                    is DemoAutoSessionDispatchVerification
                )
                settlement_failed = not self._settle_demo_auto_dispatch(
                    demo_auto_session_store,
                    demo_auto_session_dispatch_verification,
                )
            return self._outcome(
                uncertain,
                status="SUBMISSION_UNCERTAIN",
                reasons=(
                    (
                        "DEMO_AUTO_SETTLEMENT_FAILED",
                        "UNKNOWN_SUBMISSION_OUTCOME",
                    )
                    if settlement_failed
                    else ("UNKNOWN_SUBMISSION_OUTCOME",)
                ),
                execution_sent=True,
                risk=risk,
            )

        updated = self.journal.record_execution_receipt(
            receipt,
            # The sealed receipt keeps its broker-bound receive time; the
            # journal independently timestamps the durable state transition.
            occurred_at=None,
        )
        session_completion_failed = False
        if intent.mode == "DEMO_AUTO":
            try:
                assert (
                    type(demo_auto_session_store)
                    is DemoAutoSessionCapabilityStore
                )
                assert type(demo_auto_session_lease) is DemoAutoSessionLease
                assert (
                    type(demo_auto_session_dispatch_verification)
                    is DemoAutoSessionDispatchVerification
                )
                settlement = self.journal.demo_auto_dispatch_settlement(
                    intent.intent_id,
                    dispatch_verification_sha256=(
                        demo_auto_session_dispatch_verification.content_sha256
                    ),
                )
                demo_auto_session_store.apply_dispatch_journal_settlement(
                    settlement
                )
            except Exception:
                session_completion_failed = True
                self.journal.latch_kill_switch(
                    "DEMO_AUTO session reservation completion failed for "
                    f"{intent.intent_id}",
                    source="EXECUTION",
                    occurred_at=self._trusted_now(),
                )
        next_state = updated.state
        realized_slippage_points = (
            max(0.0, float(receipt.slippage_price or 0.0)) / broker_spec.point
        )
        slippage_breach = realized_slippage_points > risk.slippage_limit_points + 1e-12
        if slippage_breach:
            event_now = self._trusted_now()
            self.journal.latch_kill_switch(
                f"realized slippage {realized_slippage_points:.6f} exceeded "
                f"limit {risk.slippage_limit_points:.6f} for {intent.intent_id}",
                source="EXECUTION",
                occurred_at=event_now,
            )
        return self._outcome(
            updated,
            status=(
                "BROKER_RESPONSE_REQUIRES_RECONCILIATION"
                if next_state != "REJECTED"
                else "BROKER_REJECTED"
            ),
            reasons=tuple(
                reason
                for reason, active in (
                    ("REALIZED_SLIPPAGE_LIMIT_BREACH", slippage_breach),
                    (
                        "DEMO_AUTO_SESSION_RESERVATION_COMPLETION_FAILED",
                        session_completion_failed,
                    ),
                )
                if active
            ),
            execution_sent=True,
            risk=risk,
            receipt_id=receipt.receipt_id,
        )


__all__ = ["ExecutionCoordinator", "ExecutionOutcome"]
