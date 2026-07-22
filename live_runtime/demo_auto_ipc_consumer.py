"""Locked DEMO_AUTO decision-IPC consumer boundary.

The decision process may publish only a sealed :class:`DecisionSnapshot`.  This
module consumes that snapshot exactly once and verifies the independent stage,
supervisor, environment-arm, and permit bindings before it emits a sealed input
for the existing risk/intent pipeline.

The emitted object is deliberately *not* an execution capability.  This module
has no broker adapter, no execution callback, and no policy-unlock surface.  A
stage authorization is consumed once to start a renewable session; later IPC
decisions retain that immutable root binding without inheriting its short
startup expiry. Broker mutation still requires the current session, permit,
arm, risk, journal, and independently reviewed execution policy.
"""

from __future__ import annotations

from dataclasses import InitVar, dataclass
from datetime import datetime, timezone
import hashlib
import hmac
from typing import Callable

from .contracts import CanonicalContract, DecisionSnapshot, require_hash, require_text, require_utc
from .controls import (
    DEFAULT_ENVIRONMENT_ARM_VARIABLE,
    EnvironmentArmDecision,
    read_environment_arm,
)
from .decision_ipc import (
    DecisionIPCBinding,
    DecisionIPCConsumerPort,
    DiscardedDecisionIPCEnvelope,
    VerifiedDecisionIPCEnvelope,
)
from .permit import (
    LIVE_ALLOWED,
    PermitValidation,
    PromotionPermit,
    account_alias_sha256,
    validate_permit,
)
from .runtime_supervisor import RuntimeSupervisorBinding
from .stage_authorization import (
    StageAuthorizationValidation,
    StageBinding,
    StageReadinessAuthorization,
)


UTC = timezone.utc
ORDER_CAPABILITY = "DISABLED"
DEMO_AUTO_IPC_PIPELINE_REQUEST_SCHEMA_VERSION = (
    "demo-auto-ipc-risk-intent-input-v1"
)
DEMO_AUTO_IPC_NO_ACTION_SCHEMA_VERSION = "demo-auto-ipc-no-action-v1"
_PIPELINE_REQUEST_SEAL = object()
_NO_ACTION_SEAL = object()


class DemoAutoIPCConsumerError(RuntimeError):
    """Base fail-closed consumer error."""


class DemoAutoIPCBindingError(DemoAutoIPCConsumerError):
    """A stage, supervisor, permit, or queue binding does not match."""


class DemoAutoIPCControlError(DemoAutoIPCConsumerError):
    """A signed control is invalid, stale, unavailable, or unarmed."""


def _now() -> datetime:
    return datetime.now(UTC)


def _require_locked_policy() -> None:
    # This object is non-executable and remains valid in a separately reviewed
    # DEMO_AUTO release. LIVE is a different release boundary.
    if LIVE_ALLOWED is not False:
        raise DemoAutoIPCControlError("DEMO_AUTO_CONSUMER_REQUIRES_NON_LIVE_POLICY")


def _permit_secret(
    provider: Callable[[str], str | bytes],
    key_id: str,
    expected_fingerprint_sha256: str,
) -> bytes:
    try:
        value = provider(key_id)
    except Exception as exc:
        raise DemoAutoIPCControlError("PERMIT_SECRET_UNAVAILABLE") from exc
    if isinstance(value, str):
        secret = value.encode("utf-8")
    elif isinstance(value, bytes):
        secret = value
    else:
        raise DemoAutoIPCControlError("PERMIT_SECRET_TYPE_INVALID")
    if len(secret) < 32:
        raise DemoAutoIPCControlError("PERMIT_SECRET_TOO_SHORT")
    observed = hashlib.sha256(secret).hexdigest()
    if not hmac.compare_digest(observed, expected_fingerprint_sha256):
        raise DemoAutoIPCBindingError("PERMIT_SECRET_FINGERPRINT_MISMATCH")
    return secret


def _require_exact_stage_validation(
    *,
    authorization: StageReadinessAuthorization,
    validation: StageAuthorizationValidation,
    stage_binding: StageBinding,
) -> None:
    if type(authorization) is not StageReadinessAuthorization:
        raise TypeError("authorization must be exact StageReadinessAuthorization")
    if type(validation) is not StageAuthorizationValidation:
        raise TypeError("validation must be exact StageAuthorizationValidation")
    if type(stage_binding) is not StageBinding:
        raise TypeError("stage_binding must be exact StageBinding")
    request = authorization.request
    if (
        request.mode != "DEMO_AUTO"
        or request.binding != stage_binding
        or not validation.valid
        or not validation.consumed_once
        or not validation.evidence_eligible_for_review
        or validation.mode != "DEMO_AUTO"
        or validation.authorization_id != authorization.authorization_id
        or validation.authorization_sha256 != authorization.content_sha256
        or validation.request_sha256 != request.request_sha256
        or validation.binding_sha256 != stage_binding.binding_sha256
        or not request.issued_at <= validation.checked_at < request.expires_at
        or validation.execution_authorized
        or validation.activation_authorized
        or validation.safe_to_demo_auto_order
        or validation.live_allowed
        or validation.order_capability != ORDER_CAPABILITY
        or authorization.execution_authorized
        or authorization.activation_authorized
        or authorization.safe_to_demo_auto_order
        or authorization.live_allowed
        or authorization.order_capability != ORDER_CAPABILITY
    ):
        raise DemoAutoIPCControlError("DEMO_AUTO_STAGE_VALIDATION_INVALID")


def _require_static_bindings(
    *,
    queue_binding: DecisionIPCBinding,
    stage_binding: StageBinding,
    supervisor_binding: RuntimeSupervisorBinding,
    account_alias: str,
) -> None:
    expected_account = account_alias_sha256(account_alias)
    if (
        queue_binding.account_id_sha256 != expected_account
        or stage_binding.account_alias_sha256 != expected_account
        or supervisor_binding.account_id_sha256 != expected_account
    ):
        raise DemoAutoIPCBindingError("ACCOUNT_BINDING_MISMATCH")
    if (
        queue_binding.server != stage_binding.server
        or queue_binding.server != supervisor_binding.server
    ):
        raise DemoAutoIPCBindingError("SERVER_BINDING_MISMATCH")
    if (
        queue_binding.environment != "DEMO"
        or stage_binding.environment != "DEMO"
        or supervisor_binding.environment != "DEMO"
        or supervisor_binding.mode != "DEMO_AUTO"
    ):
        raise DemoAutoIPCBindingError("DEMO_AUTO_ENVIRONMENT_BINDING_MISMATCH")
    if (
        queue_binding.journal_sha256 != stage_binding.journal_sha256
        or queue_binding.journal_sha256 != supervisor_binding.journal_sha256
    ):
        raise DemoAutoIPCBindingError("JOURNAL_BINDING_MISMATCH")
    if (
        queue_binding.commit_sha != stage_binding.commit_sha
        or queue_binding.commit_sha != supervisor_binding.commit_sha
    ):
        raise DemoAutoIPCBindingError("COMMIT_BINDING_MISMATCH")
    if (
        queue_binding.config_sha256 != stage_binding.config_sha256
        or queue_binding.config_sha256 != supervisor_binding.config_sha256
    ):
        raise DemoAutoIPCBindingError("CONFIG_BINDING_MISMATCH")
    if queue_binding.model_artifact_sha256 != stage_binding.model_artifact_sha256:
        raise DemoAutoIPCBindingError("MODEL_BINDING_MISMATCH")
    if supervisor_binding.stage_binding_sha256 != stage_binding.binding_sha256:
        raise DemoAutoIPCBindingError("SUPERVISOR_STAGE_BINDING_MISMATCH")


@dataclass(frozen=True)
class DemoAutoIPCRiskIntentInput(CanonicalContract):
    """Sealed, non-executable input for the trusted risk/intent pipeline.

    Exact control objects are retained so the downstream pure pipeline can
    re-check every binding without trusting a lossy boolean projection.
    """

    verified_envelope: VerifiedDecisionIPCEnvelope
    stage_authorization: StageReadinessAuthorization
    stage_validation: StageAuthorizationValidation
    stage_binding: StageBinding
    supervisor_binding: RuntimeSupervisorBinding
    permit: PromotionPermit
    permit_validation: PermitValidation
    permit_key_id: str
    permit_secret_fingerprint_sha256: str
    pre_consume_environment_arm: EnvironmentArmDecision
    environment_arm: EnvironmentArmDecision
    consumed_at_utc: datetime
    verified_at_utc: datetime
    valid_until_utc: datetime
    live_allowed: bool = False
    safe_to_demo_auto_order: bool = False
    execution_authorized: bool = False
    activation_authorized: bool = False
    order_capability: str = ORDER_CAPABILITY
    schema_version: str = DEMO_AUTO_IPC_PIPELINE_REQUEST_SCHEMA_VERSION
    _seal: InitVar[object | None] = None

    def __post_init__(self, _seal: object | None) -> None:
        if _seal is not _PIPELINE_REQUEST_SEAL:
            raise TypeError("risk/intent inputs require the locked IPC consumer")
        for name, expected_type in (
            ("verified_envelope", VerifiedDecisionIPCEnvelope),
            ("stage_authorization", StageReadinessAuthorization),
            ("stage_validation", StageAuthorizationValidation),
            ("stage_binding", StageBinding),
            ("supervisor_binding", RuntimeSupervisorBinding),
            ("permit", PromotionPermit),
            ("permit_validation", PermitValidation),
            ("pre_consume_environment_arm", EnvironmentArmDecision),
            ("environment_arm", EnvironmentArmDecision),
        ):
            if type(getattr(self, name)) is not expected_type:
                raise TypeError(f"{name} must be exact {expected_type.__name__}")
        consumed = require_utc("consumed_at_utc", self.consumed_at_utc)
        verified = require_utc("verified_at_utc", self.verified_at_utc)
        valid_until = require_utc("valid_until_utc", self.valid_until_utc)
        object.__setattr__(
            self,
            "permit_key_id",
            require_text("permit_key_id", self.permit_key_id),
        )
        object.__setattr__(
            self,
            "permit_secret_fingerprint_sha256",
            require_hash(
                "permit_secret_fingerprint_sha256",
                self.permit_secret_fingerprint_sha256,
            ),
        )
        if not consumed <= verified < valid_until:
            raise ValueError("risk/intent input must retain a positive validity window")
        envelope = self.verified_envelope.envelope
        decision = envelope.decision
        if envelope.action != "CANDIDATE" or decision.side not in {"BUY", "SELL"}:
            raise ValueError("risk/intent input requires an actionable envelope")
        if (
            self.verified_envelope.consumed_at_utc != consumed
            or self.stage_authorization.request.binding != self.stage_binding
            or self.stage_validation.authorization_sha256
            != self.stage_authorization.content_sha256
            or self.stage_validation.binding_sha256
            != self.stage_binding.binding_sha256
            or self.supervisor_binding.stage_binding_sha256
            != self.stage_binding.binding_sha256
            or self.permit_validation.permit_id != self.permit.permit_id
            or self.permit_key_id != envelope.binding.permit_key_id
            or self.permit_secret_fingerprint_sha256
            != envelope.binding.permit_key_fingerprint_sha256
            or not self.permit_validation.valid
            or not self.pre_consume_environment_arm.armed
            or not self.environment_arm.armed
            or not self.pre_consume_environment_arm.is_fresh(consumed)
            or not self.environment_arm.is_fresh(verified)
            or self.pre_consume_environment_arm.env_var_name
            != self.environment_arm.env_var_name
            or self.pre_consume_environment_arm.binding_sha256
            != self.environment_arm.binding_sha256
            or self.pre_consume_environment_arm.journal_sha256
            != self.environment_arm.journal_sha256
            or self.pre_consume_environment_arm.observed_value_sha256
            != self.environment_arm.observed_value_sha256
            or valid_until
            != min(
                envelope.expires_at_utc,
                self.permit.expires_at,
                self.pre_consume_environment_arm.valid_until_utc,
                self.environment_arm.valid_until_utc,
            )
            or decision.symbol != self.stage_binding.symbol
            or decision.strategy != self.stage_binding.strategy
        ):
            raise ValueError("risk/intent input control binding is inconsistent")
        if (
            self.live_allowed
            or self.safe_to_demo_auto_order
            or self.execution_authorized
            or self.activation_authorized
            or self.order_capability != ORDER_CAPABILITY
        ):
            raise ValueError("risk/intent input cannot grant execution authority")
        if self.schema_version != DEMO_AUTO_IPC_PIPELINE_REQUEST_SCHEMA_VERSION:
            raise ValueError("unsupported DEMO_AUTO risk/intent input schema")

    @property
    def decision(self) -> DecisionSnapshot:
        return self.verified_envelope.envelope.decision


@dataclass(frozen=True)
class DemoAutoIPCNoActionReceipt(CanonicalContract):
    """Sealed proof that one fresh WAIT decision was consumed without dispatch."""

    envelope_sequence: int
    envelope_sha256: str
    decision_snapshot_sha256: str
    consumed_at_utc: datetime
    reason_code: str = "WAIT_DECISION"
    live_allowed: bool = False
    safe_to_demo_auto_order: bool = False
    order_capability: str = ORDER_CAPABILITY
    schema_version: str = DEMO_AUTO_IPC_NO_ACTION_SCHEMA_VERSION
    _seal: InitVar[object | None] = None

    def __post_init__(self, _seal: object | None) -> None:
        if _seal is not _NO_ACTION_SEAL:
            raise TypeError("no-action receipts require the locked IPC consumer")
        if isinstance(self.envelope_sequence, bool) or not isinstance(
            self.envelope_sequence, int
        ) or self.envelope_sequence < 1:
            raise ValueError("envelope_sequence must be a positive integer")
        for name in ("envelope_sha256", "decision_snapshot_sha256"):
            object.__setattr__(self, name, require_hash(name, getattr(self, name)))
        require_utc("consumed_at_utc", self.consumed_at_utc)
        if require_text("reason_code", self.reason_code, upper=True) != "WAIT_DECISION":
            raise ValueError("unsupported no-action reason")
        if (
            self.live_allowed
            or self.safe_to_demo_auto_order
            or self.order_capability != ORDER_CAPABILITY
        ):
            raise ValueError("no-action receipt cannot grant execution authority")
        if self.schema_version != DEMO_AUTO_IPC_NO_ACTION_SCHEMA_VERSION:
            raise ValueError("unsupported DEMO_AUTO no-action schema")


@dataclass(frozen=True)
class DemoAutoDecisionIPCConsumer:
    """One-way, no-broker consumer port for a supervisor-bound DEMO_AUTO lane."""

    decision_port: DecisionIPCConsumerPort
    account_alias: str
    stage_authorization: StageReadinessAuthorization
    stage_validation: StageAuthorizationValidation
    stage_binding: StageBinding
    supervisor_binding: RuntimeSupervisorBinding
    permit_key_provider: Callable[[str], str | bytes]
    clock_provider: Callable[[], datetime] = _now
    environment_arm_variable: str = DEFAULT_ENVIRONMENT_ARM_VARIABLE

    def __post_init__(self) -> None:
        _require_locked_policy()
        if type(self.decision_port) is not DecisionIPCConsumerPort:
            raise TypeError("decision_port must be exact DecisionIPCConsumerPort")
        account_alias = require_text("account_alias", self.account_alias)
        object.__setattr__(self, "account_alias", account_alias)
        if type(self.supervisor_binding) is not RuntimeSupervisorBinding:
            raise TypeError("supervisor_binding must be exact RuntimeSupervisorBinding")
        if not callable(self.permit_key_provider) or not callable(
            self.clock_provider
        ):
            raise TypeError("permit key and clock providers must be callable")
        object.__setattr__(
            self,
            "environment_arm_variable",
            require_text("environment_arm_variable", self.environment_arm_variable),
        )
        _require_exact_stage_validation(
            authorization=self.stage_authorization,
            validation=self.stage_validation,
            stage_binding=self.stage_binding,
        )
        _require_static_bindings(
            queue_binding=self.decision_port.binding,
            stage_binding=self.stage_binding,
            supervisor_binding=self.supervisor_binding,
            account_alias=account_alias,
        )
        _permit_secret(
            self.permit_key_provider,
            self.decision_port.binding.permit_key_id,
            self.decision_port.binding.permit_key_fingerprint_sha256,
        )

    def _validate_permit(self, permit: PromotionPermit, now: datetime) -> PermitValidation:
        if type(permit) is not PromotionPermit:
            raise TypeError("permit must be exact PromotionPermit")
        # Stage promotion evidence authorizes session startup only.  Each
        # later decision carries a newly signed permit bound to the current
        # promotion receipt; the executor verifies that exact receipt before
        # reservation and again at send.  Reusing the startup receipt hash
        # here would silently turn a short stage request into a permanent
        # session cap.
        promotion_sha = permit.promotion_evidence_sha256
        if not promotion_sha:
            raise DemoAutoIPCBindingError("PROMOTION_EVIDENCE_BINDING_MISSING")
        try:
            validation = validate_permit(
                permit,
                _permit_secret(
                    self.permit_key_provider,
                    self.decision_port.binding.permit_key_id,
                    self.decision_port.binding.permit_key_fingerprint_sha256,
                ),
                now=now,
                expected_mode="DEMO_AUTO",
                expected_account_alias=self.account_alias,
                expected_server=self.stage_binding.server,
                expected_symbols=(self.stage_binding.symbol,),
                expected_commit_sha=self.stage_binding.commit_sha,
                expected_config_sha256=self.stage_binding.config_sha256,
                expected_model_artifact_sha256=(
                    self.stage_binding.model_artifact_sha256
                ),
                expected_journal_sha256=self.stage_binding.journal_sha256,
                expected_promotion_evidence_sha256=promotion_sha,
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise DemoAutoIPCControlError("PERMIT_VALIDATION_FAILED") from exc
        if (
            type(validation) is not PermitValidation
            or not validation.valid
            or validation.mode != "DEMO_AUTO"
            or validation.execution_authorized
            or validation.can_unlock
            or validation.live_allowed
            or validation.safe_to_demo_auto_order
        ):
            reasons = ",".join(validation.reason_codes) if validation.reason_codes else "INVALID"
            raise DemoAutoIPCControlError(f"PERMIT_DENIED:{reasons}")
        return validation

    def consume_for_risk_intent_pipeline(
        self,
        *,
        permit: PromotionPermit,
    ) -> (
        DemoAutoIPCRiskIntentInput
        | DemoAutoIPCNoActionReceipt
        | DiscardedDecisionIPCEnvelope
    ):
        """Consume one exact queue head and return only a non-executable result.

        Static identities and dynamic controls are checked before the durable
        consume.  After the queue's external CAS succeeds, the real clock is
        sampled again so an arm or permit that expired during custody I/O can
        never produce a risk/intent input.  In that case the envelope remains
        consumed (safe loss, never replay).
        """

        _require_locked_policy()
        _require_exact_stage_validation(
            authorization=self.stage_authorization,
            validation=self.stage_validation,
            stage_binding=self.stage_binding,
        )
        _require_static_bindings(
            queue_binding=self.decision_port.binding,
            stage_binding=self.stage_binding,
            supervisor_binding=self.supervisor_binding,
            account_alias=self.account_alias,
        )
        before = require_utc("trusted consumer clock", self.clock_provider())
        permit_validation = self._validate_permit(permit, before)
        pre_arm = read_environment_arm(
            self.account_alias,
            self.stage_binding.server,
            "DEMO_AUTO",
            before,
            self.stage_binding.journal_sha256,
            env_var_name=self.environment_arm_variable,
        )
        if not pre_arm.armed or not pre_arm.is_fresh(before):
            reasons = ",".join(pre_arm.reason_codes) or "ENVIRONMENT_ARM_DENIED"
            raise DemoAutoIPCControlError(reasons)

        consumed = self.decision_port.consume_next(consumed_at_utc=before)
        if type(consumed) not in (
            VerifiedDecisionIPCEnvelope,
            DiscardedDecisionIPCEnvelope,
        ):
            raise DemoAutoIPCControlError("DECISION_IPC_CONSUMPTION_NOT_VERIFIED")

        after = require_utc("trusted post-consume clock", self.clock_provider())
        if after < before:
            raise DemoAutoIPCControlError("TRUSTED_CLOCK_REGRESSION_AFTER_CONSUME")
        post_arm = read_environment_arm(
            self.account_alias,
            self.stage_binding.server,
            "DEMO_AUTO",
            after,
            self.stage_binding.journal_sha256,
            env_var_name=self.environment_arm_variable,
        )
        if (
            not post_arm.armed
            or not post_arm.is_fresh(after)
            or post_arm.env_var_name != pre_arm.env_var_name
            or post_arm.binding_sha256 != pre_arm.binding_sha256
            or post_arm.journal_sha256 != pre_arm.journal_sha256
            or post_arm.observed_value_sha256 != pre_arm.observed_value_sha256
        ):
            raise DemoAutoIPCControlError("ENVIRONMENT_ARM_CHANGED_DURING_CONSUME")
        if type(consumed) is DiscardedDecisionIPCEnvelope:
            return consumed
        assert type(consumed) is VerifiedDecisionIPCEnvelope
        envelope = consumed.envelope
        decision = envelope.decision
        valid_until = min(
            envelope.expires_at_utc,
            permit.expires_at,
            pre_arm.valid_until_utc,
            post_arm.valid_until_utc,
        )
        if not after < valid_until:
            raise DemoAutoIPCControlError("CONTROL_EXPIRED_DURING_IPC_CONSUMPTION")
        if (
            envelope.binding != self.decision_port.binding
            or decision.symbol != self.stage_binding.symbol
            or decision.commit_sha != self.stage_binding.commit_sha
            or decision.config_sha256 != self.stage_binding.config_sha256
            or decision.model_artifact_sha256
            != self.stage_binding.model_artifact_sha256
        ):
            raise DemoAutoIPCBindingError("DECISION_LANE_BINDING_MISMATCH")

        if envelope.action == "WAIT":
            return DemoAutoIPCNoActionReceipt(
                envelope_sequence=envelope.sequence,
                envelope_sha256=envelope.content_sha256,
                decision_snapshot_sha256=decision.content_sha256,
                consumed_at_utc=consumed.consumed_at_utc,
                _seal=_NO_ACTION_SEAL,
            )
        if envelope.action != "CANDIDATE" or decision.side not in {"BUY", "SELL"}:
            raise DemoAutoIPCControlError("DECISION_ACTION_INVALID")
        if decision.strategy != self.stage_binding.strategy:
            raise DemoAutoIPCBindingError("DECISION_LANE_BINDING_MISMATCH")
        return DemoAutoIPCRiskIntentInput(
            verified_envelope=consumed,
            stage_authorization=self.stage_authorization,
            stage_validation=self.stage_validation,
            stage_binding=self.stage_binding,
            supervisor_binding=self.supervisor_binding,
            permit=permit,
            permit_validation=permit_validation,
            permit_key_id=self.decision_port.binding.permit_key_id,
            permit_secret_fingerprint_sha256=(
                self.decision_port.binding.permit_key_fingerprint_sha256
            ),
            pre_consume_environment_arm=pre_arm,
            environment_arm=post_arm,
            consumed_at_utc=consumed.consumed_at_utc,
            verified_at_utc=after,
            valid_until_utc=valid_until,
            _seal=_PIPELINE_REQUEST_SEAL,
        )


__all__ = [
    "DEMO_AUTO_IPC_NO_ACTION_SCHEMA_VERSION",
    "DEMO_AUTO_IPC_PIPELINE_REQUEST_SCHEMA_VERSION",
    "DemoAutoDecisionIPCConsumer",
    "DemoAutoIPCBindingError",
    "DemoAutoIPCConsumerError",
    "DemoAutoIPCControlError",
    "DemoAutoIPCNoActionReceipt",
    "DemoAutoIPCRiskIntentInput",
    "ORDER_CAPABILITY",
]
