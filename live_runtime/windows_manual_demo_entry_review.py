"""Derive a deny-only review for entering controlled manual-demo.

The full three-service external-acceptance dossier intentionally includes the
result of ten controlled manual-demo lifecycles.  This module identifies the
safe pre-run state: every other externally signed gate is accepted and the
manual-demo result observation is still absent.  It cannot issue authority,
materialize a provider, initialize MT5, or mutate Windows or broker state.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
import re
from types import MappingProxyType
from typing import Callable, Mapping, Sequence

from .contracts import (
    CanonicalContract,
    require_currency,
    require_hash,
    require_int,
    require_text,
    require_utc,
)
from .demo_soak_three_service_operations import (
    EXTERNAL_READINESS_BLOCKERS,
)
from .demo_soak_three_service_operations_artifacts import (
    ThreeServiceOperationsArtifactError,
    verify_windows_three_service_demo_soak_review_bundle,
)
from .three_service_external_acceptance import (
    ThreeServiceAcceptanceObservation,
    ThreeServiceAcceptanceTrustPolicy,
    assess_three_service_external_acceptance,
)


SCHEMA_VERSION = "windows-manual-demo-entry-review-v1"
MANUAL_DEMO_RESULT_GATE = "MANUAL_DEMO_10_CONTROLLED_ORDERS_REQUIRED"
PRE_MANUAL_GATE_INVENTORY = tuple(
    sorted(
        set(EXTERNAL_READINESS_BLOCKERS)
        - {MANUAL_DEMO_RESULT_GATE}
    )
)
TARGET_CONTROLLED_LIFECYCLES = 10
ORDER_CAPABILITY = "DISABLED"
MAX_LOT = 0.01

COMPLETE_STATUS = (
    "PRE_MANUAL_DEMO_EXTERNAL_PRECONDITIONS_COMPLETE_"
    "ACTIVATION_REVIEW_REQUIRED"
)
BLOCKED_STATUS = "BLOCKED_PRE_MANUAL_DEMO_EXTERNAL_PRECONDITIONS"

REQUIRED_PER_INTENT_CONTROLS = (
    "STAGE_READINESS_AUTHORIZATION",
    "HUMAN_PER_INTENT_APPROVAL",
    "PROCESS_ENVIRONMENT_ARM",
    "SIGNED_NEWS_AND_ROLLOVER_GUARD",
    "BROKER_NATIVE_RISK_AND_MARGIN",
    "ACCOUNT_WIDE_POSITION_FENCE",
    "JOURNAL_IDEMPOTENCY",
    "BROKER_PREFLIGHT",
    "SERVER_SIDE_SL_TP_CONFIRMATION",
    "RECONCILIATION_AND_EXTERNAL_MONITOR_ACK",
)

_GIT_SHA_RE = re.compile(r"^[0-9a-f]{40}$")


class WindowsManualDemoEntryReviewError(RuntimeError):
    """A pre-manual review invariant failed with one stable reason code."""

    def __init__(self, reason_code: str) -> None:
        self.reason_code = require_text(
            "reason_code",
            reason_code,
            upper=True,
        )
        super().__init__(self.reason_code)


def _nonzero_hash(name: str, value: object) -> str:
    normalized = require_hash(name, value)
    if normalized == "0" * 64:
        raise ValueError(f"{name} cannot be the zero hash")
    return normalized


def _git_sha(name: str, value: object) -> str:
    normalized = require_text(name, value).lower()
    if _GIT_SHA_RE.fullmatch(normalized) is None:
        raise ValueError(f"{name} must be an exact 40-character Git SHA")
    return normalized


def _exact_false(name: str, value: object) -> bool:
    if type(value) is not bool:
        raise TypeError(f"{name} must be bool")
    if value is not False:
        raise ValueError(f"{name} must remain false")
    return value


@dataclass(frozen=True)
class WindowsManualDemoEntryReview(CanonicalContract):
    """Content-addressed pre-run evidence without activation capability."""

    plan_sha256: str
    review_bundle_sha256: str
    trust_policy_sha256: str
    external_assessment_sha256: str
    checked_at_utc: datetime
    decision_release_identity_sha256: str
    execution_release_identity_sha256: str
    status_monitor_release_identity_sha256: str
    git_commit: str
    git_tree: str
    candidate_id: str
    broker_server: str
    account_alias_sha256: str
    account_currency: str
    canonical_symbol: str
    broker_symbol: str
    broker_specification_sha256: str
    decision_ipc_binding_sha256: str
    failure_drill_manifest_sha256: str
    accepted_pre_manual_gates: tuple[str, ...]
    pending_pre_manual_gates: tuple[str, ...]
    pending_reasons: Mapping[str, str]
    manual_demo_result_gate: str
    target_controlled_lifecycles: int
    required_per_intent_controls: tuple[str, ...]
    status: str
    external_preconditions_complete: bool
    manual_demo_activation_review_required: bool
    full_external_acceptance_complete: bool = field(
        default=False,
        init=False,
    )
    manual_demo_authorized: bool = field(default=False, init=False)
    activation_authorized: bool = field(default=False, init=False)
    execution_enabled: bool = field(default=False, init=False)
    ready_for_demo_auto_soak: bool = field(default=False, init=False)
    safe_to_demo_auto_order: bool = field(default=False, init=False)
    live_allowed: bool = field(default=False, init=False)
    promotion_eligible: bool = field(default=False, init=False)
    order_capability: str = field(
        default=ORDER_CAPABILITY,
        init=False,
    )
    max_lot: float = field(default=MAX_LOT, init=False)
    schema_version: str = field(default=SCHEMA_VERSION, init=False)

    def __post_init__(self) -> None:
        for name in (
            "plan_sha256",
            "review_bundle_sha256",
            "trust_policy_sha256",
            "external_assessment_sha256",
            "decision_release_identity_sha256",
            "execution_release_identity_sha256",
            "status_monitor_release_identity_sha256",
            "account_alias_sha256",
            "broker_specification_sha256",
            "decision_ipc_binding_sha256",
            "failure_drill_manifest_sha256",
        ):
            object.__setattr__(
                self,
                name,
                _nonzero_hash(name, getattr(self, name)),
            )
        require_utc("checked_at_utc", self.checked_at_utc)
        object.__setattr__(
            self,
            "git_commit",
            _git_sha("git_commit", self.git_commit),
        )
        object.__setattr__(
            self,
            "git_tree",
            _git_sha("git_tree", self.git_tree),
        )
        object.__setattr__(
            self,
            "candidate_id",
            require_text("candidate_id", self.candidate_id),
        )
        object.__setattr__(
            self,
            "broker_server",
            require_text("broker_server", self.broker_server),
        )
        object.__setattr__(
            self,
            "account_currency",
            require_currency("account_currency", self.account_currency),
        )
        canonical_symbol = require_text(
            "canonical_symbol",
            self.canonical_symbol,
            upper=True,
        )
        if canonical_symbol != "XAUUSD":
            raise ValueError("manual-demo entry review is XAUUSD-only")
        object.__setattr__(self, "canonical_symbol", canonical_symbol)
        object.__setattr__(
            self,
            "broker_symbol",
            require_text("broker_symbol", self.broker_symbol),
        )

        accepted = tuple(
            sorted(
                require_text("accepted_gate", gate, upper=True)
                for gate in self.accepted_pre_manual_gates
            )
        )
        pending = tuple(
            sorted(
                require_text("pending_gate", gate, upper=True)
                for gate in self.pending_pre_manual_gates
            )
        )
        required = tuple(sorted(PRE_MANUAL_GATE_INVENTORY))
        if (
            len(accepted) != len(set(accepted))
            or len(pending) != len(set(pending))
            or set(accepted) & set(pending)
            or tuple(sorted(accepted + pending)) != required
        ):
            raise ValueError("pre-manual gate partition is invalid")
        object.__setattr__(self, "accepted_pre_manual_gates", accepted)
        object.__setattr__(self, "pending_pre_manual_gates", pending)
        if not isinstance(self.pending_reasons, Mapping):
            raise TypeError("pending_reasons must be a mapping")
        reasons = {
            require_text("pending_gate", gate, upper=True): require_text(
                "pending_reason",
                reason,
                upper=True,
            )
            for gate, reason in self.pending_reasons.items()
        }
        if set(reasons) != set(pending):
            raise ValueError("pending reasons do not match pending gates")
        object.__setattr__(
            self,
            "pending_reasons",
            MappingProxyType(dict(sorted(reasons.items()))),
        )
        result_gate = require_text(
            "manual_demo_result_gate",
            self.manual_demo_result_gate,
            upper=True,
        )
        if result_gate != MANUAL_DEMO_RESULT_GATE:
            raise ValueError("manual-demo result gate is invalid")
        object.__setattr__(self, "manual_demo_result_gate", result_gate)
        if (
            require_int(
                "target_controlled_lifecycles",
                self.target_controlled_lifecycles,
                minimum=TARGET_CONTROLLED_LIFECYCLES,
                maximum=TARGET_CONTROLLED_LIFECYCLES,
            )
            != TARGET_CONTROLLED_LIFECYCLES
        ):
            raise ValueError("manual-demo lifecycle target must remain ten")
        controls = tuple(
            require_text("per_intent_control", item, upper=True)
            for item in self.required_per_intent_controls
        )
        if controls != REQUIRED_PER_INTENT_CONTROLS:
            raise ValueError("per-intent control inventory is invalid")
        object.__setattr__(
            self,
            "required_per_intent_controls",
            REQUIRED_PER_INTENT_CONTROLS,
        )

        complete = not pending
        if type(self.external_preconditions_complete) is not bool:
            raise TypeError("external_preconditions_complete must be bool")
        if self.external_preconditions_complete is not complete:
            raise ValueError("external precondition status is inconsistent")
        expected_status = COMPLETE_STATUS if complete else BLOCKED_STATUS
        if self.status != expected_status:
            raise ValueError("manual-demo entry review status is inconsistent")
        if type(self.manual_demo_activation_review_required) is not bool:
            raise TypeError(
                "manual_demo_activation_review_required must be bool"
            )
        if self.manual_demo_activation_review_required is not complete:
            raise ValueError(
                "manual-demo activation review flag is inconsistent"
            )
        for name in (
            "full_external_acceptance_complete",
            "manual_demo_authorized",
            "activation_authorized",
            "execution_enabled",
            "ready_for_demo_auto_soak",
            "safe_to_demo_auto_order",
            "live_allowed",
            "promotion_eligible",
        ):
            _exact_false(name, getattr(self, name))
        if self.order_capability != ORDER_CAPABILITY:
            raise ValueError("order_capability must remain DISABLED")
        if self.max_lot != MAX_LOT:
            raise ValueError("max_lot must remain exactly 0.01")
        if self.schema_version != SCHEMA_VERSION:
            raise ValueError("manual-demo entry review schema is invalid")


def assess_windows_manual_demo_entry_review(
    *,
    review_bundle: Mapping[str, object],
    trust_policy: ThreeServiceAcceptanceTrustPolicy,
    observations: Sequence[ThreeServiceAcceptanceObservation],
    expected_policy_sha256: str,
    clock_provider: Callable[[], datetime],
) -> WindowsManualDemoEntryReview:
    """Verify the signed dossier and classify only the pre-manual phase."""

    assessment = assess_three_service_external_acceptance(
        review_bundle=review_bundle,
        trust_policy=trust_policy,
        observations=observations,
        expected_policy_sha256=expected_policy_sha256,
        clock_provider=clock_provider,
    )
    if assessment.external_acceptance_complete:
        raise WindowsManualDemoEntryReviewError(
            "MANUAL_DEMO_RESULT_ALREADY_PRESENT"
        )
    if MANUAL_DEMO_RESULT_GATE in assessment.observation_sha256s:
        raise WindowsManualDemoEntryReviewError(
            "MANUAL_DEMO_RESULT_OBSERVATION_NOT_ALLOWED"
        )
    if (
        assessment.pending_reasons.get(MANUAL_DEMO_RESULT_GATE)
        != "MISSING"
    ):
        raise WindowsManualDemoEntryReviewError(
            "MANUAL_DEMO_RESULT_PROVENANCE_INVALID"
        )

    try:
        plan = verify_windows_three_service_demo_soak_review_bundle(
            review_bundle
        )
        review_hash = _nonzero_hash(
            "review_bundle_sha256",
            review_bundle["content_sha256"],
        )
        failure_drill_hash = _nonzero_hash(
            "failure_drill_manifest_sha256",
            review_bundle["failure_drill_manifest_sha256"],
        )
    except (
        KeyError,
        ThreeServiceOperationsArtifactError,
        TypeError,
        ValueError,
    ) as exc:
        raise WindowsManualDemoEntryReviewError(
            "PRE_MANUAL_REVIEW_BUNDLE_RECONSTRUCTION_FAILED"
        ) from exc
    if (
        assessment.plan_sha256 != plan.plan_sha256
        or assessment.review_bundle_sha256 != review_hash
        or assessment.trust_policy_sha256 != trust_policy.content_sha256
    ):
        raise WindowsManualDemoEntryReviewError(
            "PRE_MANUAL_EXTERNAL_ASSESSMENT_BINDING_MISMATCH"
        )

    accepted = tuple(
        sorted(
            set(assessment.accepted_gates)
            & set(PRE_MANUAL_GATE_INVENTORY)
        )
    )
    pending = tuple(
        sorted(set(PRE_MANUAL_GATE_INVENTORY) - set(accepted))
    )
    reasons = {
        gate: assessment.pending_reasons[gate]
        for gate in pending
    }
    symbol_bindings = tuple(plan.broker.symbol_bindings)
    if len(symbol_bindings) != 1 or symbol_bindings[0][0] != "XAUUSD":
        raise WindowsManualDemoEntryReviewError(
            "PRE_MANUAL_XAUUSD_BINDING_INVALID"
        )
    canonical_symbol, broker_symbol, specification_sha256 = (
        symbol_bindings[0]
    )
    complete = not pending
    return WindowsManualDemoEntryReview(
        plan_sha256=plan.plan_sha256,
        review_bundle_sha256=review_hash,
        trust_policy_sha256=trust_policy.content_sha256,
        external_assessment_sha256=assessment.content_sha256,
        checked_at_utc=assessment.checked_at_utc,
        decision_release_identity_sha256=(
            plan.decision.configured_release_identity_sha256
        ),
        execution_release_identity_sha256=(
            plan.execution.configured_release_identity_sha256
        ),
        status_monitor_release_identity_sha256=(
            plan.status_monitor.configured_release_identity_sha256
        ),
        git_commit=plan.decision.release.git_commit,
        git_tree=plan.decision.release.git_tree,
        candidate_id=plan.broker.candidate_id,
        broker_server=plan.broker.server,
        account_alias_sha256=plan.broker.account_alias_sha256,
        account_currency=plan.broker.account_currency,
        canonical_symbol=canonical_symbol,
        broker_symbol=broker_symbol,
        broker_specification_sha256=specification_sha256,
        decision_ipc_binding_sha256=plan.ipc.binding_sha256,
        failure_drill_manifest_sha256=failure_drill_hash,
        accepted_pre_manual_gates=accepted,
        pending_pre_manual_gates=pending,
        pending_reasons=reasons,
        manual_demo_result_gate=MANUAL_DEMO_RESULT_GATE,
        target_controlled_lifecycles=TARGET_CONTROLLED_LIFECYCLES,
        required_per_intent_controls=REQUIRED_PER_INTENT_CONTROLS,
        status=COMPLETE_STATUS if complete else BLOCKED_STATUS,
        external_preconditions_complete=complete,
        manual_demo_activation_review_required=complete,
    )


__all__ = [
    "BLOCKED_STATUS",
    "COMPLETE_STATUS",
    "MANUAL_DEMO_RESULT_GATE",
    "PRE_MANUAL_GATE_INVENTORY",
    "REQUIRED_PER_INTENT_CONTROLS",
    "SCHEMA_VERSION",
    "TARGET_CONTROLLED_LIFECYCLES",
    "WindowsManualDemoEntryReview",
    "WindowsManualDemoEntryReviewError",
    "assess_windows_manual_demo_entry_review",
]
