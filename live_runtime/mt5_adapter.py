"""Fail-closed MetaTrader 5 adapter for the Windows live runtime.

Importing this module never imports or starts MetaTrader5 automatically.
Order submission requires an injected module, a valid preflight result, and an
explicit runtime authorization.  The current repository policy remains locked;
no existing AI_SCALPER entrypoint constructs this adapter for execution.
"""

from __future__ import annotations

import math
import threading
from dataclasses import InitVar, dataclass
from datetime import datetime, timedelta, timezone
from decimal import Decimal, ROUND_FLOOR
from types import ModuleType
from types import MappingProxyType
from typing import Any, Callable, Mapping

import execution_policy

from live_runtime.contracts import (
    BrokerSpec,
    CanonicalContract,
    ExecutionReceipt,
    TradeIntent,
    _mint_execution_receipt,
    canonical_sha256,
    require_currency,
    require_hash,
    require_utc,
)
from live_runtime.account_fence import account_runtime_identity
from live_runtime.controls import (
    EnvironmentArmDecision,
    ManualDemoApprovalValidation,
    environment_arm_binding_sha256,
    manual_demo_account_sha256,
)
from live_runtime.health import RuntimeHealthDecision
from live_runtime.permit import PermitValidation, account_alias_sha256
from live_runtime.journal import DurableSubmissionLease, IntentRecord
from live_runtime.risk import (
    IDENTITY_CONVERSION_SHA256,
    MAX_RISK_CONVERSION_AGE_SECONDS,
    RISK_PERCENT_CAP,
    RiskDecision,
    USDRiskCapConversion,
    _mint_usd_risk_cap_conversion,
    absolute_risk_cap_usd,
)
from live_runtime.market_guard import MarketGuardDecision
from live_runtime.model_governance import ModelBindingDecision
from live_runtime.risk_context_factory import VerifiedRiskContext
from live_runtime.mt5_module_attestation import (
    VerifiedMT5Installation,
    VerifiedMT5ModuleAttestation,
    require_clean_mt5_import_namespace,
    verify_imported_mt5_module,
)


UTC = timezone.utc
DEFAULT_MAX_TICK_AGE_SECONDS = 10
DEFAULT_PREFLIGHT_TTL_SECONDS = 3
MAX_AUTHORIZATION_AGE_SECONDS = 1
CLOCK_OVERRIDE_TOLERANCE_SECONDS = 0.05
_AUTHORIZATION_SEAL = object()
_PREFLIGHT_SEAL = object()
_SUBMISSION_GUARD_SEAL = object()
_EXECUTION_GATE_SEAL = object()


class MT5AdapterError(RuntimeError):
    pass


class MT5UnavailableError(MT5AdapterError):
    pass


class AccountBindingError(MT5AdapterError):
    pass


class PreflightRejectedError(MT5AdapterError):
    pass


class ExecutionLockedError(MT5AdapterError):
    pass


class SubmissionUncertainError(MT5AdapterError):
    """Raised when an order-send call may have reached the broker."""


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _asdict(value: Any) -> dict[str, Any]:
    if value is None:
        return {}
    if isinstance(value, Mapping):
        return dict(value)
    method = getattr(value, "_asdict", None)
    if callable(method):
        return dict(method())
    field_names = getattr(getattr(value, "dtype", None), "names", None)
    if field_names:
        result: dict[str, Any] = {}
        for name in field_names:
            item = value[name]
            scalar = getattr(item, "item", None)
            result[name] = scalar() if callable(scalar) else item
        return result
    return {
        key: getattr(value, key)
        for key in dir(value)
        if not key.startswith("_") and not callable(getattr(value, key))
    }


def _finite(value: Any, field: str, *, positive: bool = False) -> float:
    try:
        numeric = float(value)
    except (TypeError, ValueError) as exc:
        raise MT5AdapterError(f"{field} is not numeric") from exc
    if not math.isfinite(numeric) or (positive and numeric <= 0):
        raise MT5AdapterError(f"{field} is invalid")
    return numeric


@dataclass(frozen=True)
class RuntimeAuthorization:
    mode: str
    intent_id: str
    permit_id: str
    risk_decision_id: str
    journal_sha256: str
    broker_spec_sha256: str
    verified_risk_context_sha256: str
    verified_risk_context_valid_until_utc: datetime
    preflight_sha256: str
    execution_gate_sha256: str
    environment_arm_sha256: str
    manual_demo_approval_sha256: str
    max_risk_cash: float
    max_margin_cash: float
    spread_limit_points: float
    spread_p95_points: float
    spread_median_multiple_limit_points: float
    broker_point: float
    checked_at_utc: datetime
    valid_until_utc: datetime
    _seal: InitVar[object | None] = None

    def __post_init__(self, _seal: object | None) -> None:
        if _seal is not _AUTHORIZATION_SEAL:
            raise TypeError(
                "RuntimeAuthorization can only be minted from a verified signed permit"
            )
        require_utc("checked_at_utc", self.checked_at_utc)
        require_utc("valid_until_utc", self.valid_until_utc)
        require_utc(
            "verified_risk_context_valid_until_utc",
            self.verified_risk_context_valid_until_utc,
        )
        if self.valid_until_utc <= self.checked_at_utc:
            raise ValueError("authorization validity window is empty")
        if self.valid_until_utc > self.verified_risk_context_valid_until_utc:
            raise ValueError("authorization outlives verified risk context")
        object.__setattr__(
            self,
            "max_risk_cash",
            _finite(self.max_risk_cash, "max_risk_cash", positive=True),
        )
        object.__setattr__(
            self,
            "max_margin_cash",
            _finite(self.max_margin_cash, "max_margin_cash", positive=True),
        )
        object.__setattr__(
            self,
            "spread_limit_points",
            _finite(self.spread_limit_points, "spread_limit_points"),
        )
        object.__setattr__(
            self,
            "spread_p95_points",
            _finite(self.spread_p95_points, "spread_p95_points", positive=True),
        )
        object.__setattr__(
            self,
            "spread_median_multiple_limit_points",
            _finite(
                self.spread_median_multiple_limit_points,
                "spread_median_multiple_limit_points",
                positive=True,
            ),
        )
        object.__setattr__(
            self,
            "broker_point",
            _finite(self.broker_point, "broker_point", positive=True),
        )
        for field_name in (
            "journal_sha256",
            "broker_spec_sha256",
            "verified_risk_context_sha256",
            "preflight_sha256",
            "execution_gate_sha256",
            "environment_arm_sha256",
            "manual_demo_approval_sha256",
        ):
            value = str(getattr(self, field_name) or "").lower()
            if len(value) != 64 or any(
                char not in "0123456789abcdef" for char in value
            ):
                raise ValueError(f"{field_name} must be a SHA-256 hash")
            object.__setattr__(self, field_name, value)
        if self.spread_limit_points < 0:
            raise ValueError("spread_limit_points must be nonnegative")
        if self.spread_limit_points != min(
            self.spread_p95_points,
            self.spread_median_multiple_limit_points,
        ):
            raise ValueError("spread limit provenance is inconsistent")

    def allows_order_send(self, *, now: datetime) -> bool:
        require_utc("now", now)
        mode = self.mode.strip().upper()
        if now >= self.valid_until_utc:
            return False
        if mode in {"LIVE", "DEMO_AUTO"}:
            allowed, _reason_codes = (
                execution_policy.execution_mode_policy_decision(mode)
            )
            return allowed
        if mode == "DEMO":
            return self.manual_demo_approval_sha256 != "0" * 64
        return False


@dataclass(frozen=True)
class ExecutionGateCapability(CanonicalContract):
    """Sealed provenance joining evaluator and adapter outputs for one intent."""

    intent_id: str
    reservation_intent_id: str
    journal_sha256: str
    risk_decision_sha256: str
    health_decision_sha256: str
    market_guard_decision_sha256: str
    model_binding_decision_sha256: str
    preflight_sha256: str
    guard_sha256: str
    broker_spec_sha256: str
    checked_at_utc: datetime
    _seal: InitVar[object | None] = None

    def __post_init__(self, _seal: object | None) -> None:
        if _seal is not _EXECUTION_GATE_SEAL:
            raise TypeError(
                "ExecutionGateCapability can only be minted by the runtime coordinator"
            )
        require_utc("checked_at_utc", self.checked_at_utc)
        for field_name in (
            "risk_decision_sha256",
            "health_decision_sha256",
            "market_guard_decision_sha256",
            "model_binding_decision_sha256",
            "preflight_sha256",
            "guard_sha256",
            "broker_spec_sha256",
            "journal_sha256",
        ):
            value = str(getattr(self, field_name) or "").lower()
            if len(value) != 64 or any(char not in "0123456789abcdef" for char in value):
                raise ValueError(f"{field_name} must be a SHA-256 hash")
            object.__setattr__(self, field_name, value)

def build_runtime_authorization(
    *,
    intent: TradeIntent,
    permit_validation: PermitValidation,
    risk_decision: RiskDecision,
    broker_spec: BrokerSpec,
    verified_risk_context: VerifiedRiskContext,
    reservation: IntentRecord,
    gate_capability: ExecutionGateCapability,
    journal_sha256: str,
    environment_arm_decision: EnvironmentArmDecision,
    manual_demo_approval_validation: ManualDemoApprovalValidation | None,
    now: datetime,
    additional_valid_until_utc: datetime | None = None,
) -> RuntimeAuthorization:
    """Mint a short-lived capability from an HMAC-verified permit result."""

    if type(intent) is not TradeIntent:
        raise TypeError("intent must be an exact TradeIntent")
    if type(permit_validation) is not PermitValidation:
        raise TypeError("permit_validation must come from validate_permit")
    if type(risk_decision) is not RiskDecision or not risk_decision.allowed:
        raise ExecutionLockedError("an approved independent risk decision is required")
    if type(broker_spec) is not BrokerSpec:
        raise TypeError("broker_spec must be a BrokerSpec")
    if type(verified_risk_context) is not VerifiedRiskContext:
        raise ExecutionLockedError("sealed verified risk context is required")
    if type(reservation) is not IntentRecord:
        raise TypeError("reservation must be an IntentRecord")
    if type(gate_capability) is not ExecutionGateCapability:
        raise ExecutionLockedError("sealed execution gate capability is required")
    normalized_journal_sha256 = str(journal_sha256 or "").lower()
    if len(normalized_journal_sha256) != 64 or any(
        char not in "0123456789abcdef" for char in normalized_journal_sha256
    ):
        raise ValueError("journal_sha256 must be a lowercase SHA-256 hash")
    now = require_utc("now", now)
    if type(environment_arm_decision) is not EnvironmentArmDecision:
        raise ExecutionLockedError("sealed environment arm decision is required")
    expected_arm_binding = environment_arm_binding_sha256(
        intent.account_id,
        intent.server,
        intent.mode,
        normalized_journal_sha256,
    )
    arm_valid = (
        environment_arm_decision.is_fresh(now)
        and environment_arm_decision.binding_sha256 == expected_arm_binding
        and environment_arm_decision.journal_sha256 == normalized_journal_sha256
    )
    if not arm_valid:
        raise ExecutionLockedError("environment arm is stale or mismatched")
    manual_validation_bound = False
    manual_approval_sha256 = "0" * 64
    if intent.mode == "DEMO":
        validation = manual_demo_approval_validation
        manual_validation_bound = (
            type(validation) is ManualDemoApprovalValidation
            and validation.is_fresh(now)
            and validation.intent_id == intent.intent_id
            and validation.account_id_sha256
            == manual_demo_account_sha256(intent.account_id)
            and validation.server == intent.server
            and validation.journal_sha256 == normalized_journal_sha256
            and validation.mode == "DEMO"
        )
        if not manual_validation_bound:
            raise ExecutionLockedError("manual demo approval is stale or mismatched")
        manual_approval_sha256 = validation.content_sha256
    bindings_match = (
        permit_validation.valid
        and intent.permit_id == permit_validation.permit_id
        and intent.mode == permit_validation.mode
        and account_alias_sha256(intent.account_id)
        == permit_validation.account_alias_sha256
        and intent.server == permit_validation.server
        and intent.symbol in permit_validation.symbols
        and intent.decision.commit_sha == permit_validation.commit_sha
        and intent.decision.config_sha256 == permit_validation.config_sha256
        and intent.decision.model_artifact_sha256
        == permit_validation.model_artifact_sha256
        and permit_validation.journal_sha256 == normalized_journal_sha256
    )
    age = (now - permit_validation.checked_at).total_seconds()
    if not bindings_match or age < 0 or age > MAX_AUTHORIZATION_AGE_SECONDS:
        raise ExecutionLockedError("signed permit validation is stale or mismatched")
    if not permit_validation.issued_at <= now < permit_validation.expires_at:
        raise ExecutionLockedError("signed permit is outside its validity window")
    risk_age = (now - risk_decision.evaluated_at).total_seconds()
    risk_matches = (
        risk_decision.symbol == intent.symbol
        and abs(risk_decision.normalized_lot - intent.requested_lot) <= 1e-12
        and 0 <= risk_age <= MAX_AUTHORIZATION_AGE_SECONDS
        and gate_capability.risk_decision_sha256 == risk_decision.content_sha256
    )
    broker_matches = (
        broker_spec.account_id == intent.account_id
        and broker_spec.server == intent.server
        and broker_spec.symbol == intent.symbol
    )
    reserved_payload = reservation.payload.get("intent")
    reservation_matches = (
        reservation.intent_id == intent.intent_id
        and reservation.state == "SUBMITTING"
        and isinstance(reserved_payload, Mapping)
        and reserved_payload == intent.to_canonical_dict()
        and reservation.payload.get("broker_spec_sha256")
        == broker_spec.content_sha256
        and reservation.payload.get("verified_risk_context_sha256")
        == verified_risk_context.content_sha256
    )
    if not risk_matches or not broker_matches or not reservation_matches:
        raise ExecutionLockedError("risk, broker, or journal reservation binding failed")
    gate_age = (now - gate_capability.checked_at_utc).total_seconds()
    gate_matches = (
        gate_capability.intent_id == intent.intent_id
        and gate_capability.reservation_intent_id == reservation.intent_id
        and gate_capability.journal_sha256 == normalized_journal_sha256
        and gate_capability.broker_spec_sha256 == broker_spec.content_sha256
        and 0 <= gate_age <= MAX_AUTHORIZATION_AGE_SECONDS
    )
    if not gate_matches:
        raise ExecutionLockedError("execution gate capability is stale or mismatched")
    if (
        now < verified_risk_context.evaluated_at_utc
        or now >= verified_risk_context.valid_until_utc
        or verified_risk_context.account_id != intent.account_id
        or verified_risk_context.server != intent.server
        or verified_risk_context.environment != broker_spec.environment
        or verified_risk_context.symbol != intent.symbol
        or verified_risk_context.broker_symbol != broker_spec.broker_symbol
        or verified_risk_context.mode != intent.mode
        or verified_risk_context.broker_spec_sha256 != broker_spec.content_sha256
        or verified_risk_context.journal_sha256 != normalized_journal_sha256
        or verified_risk_context.permit_id != permit_validation.permit_id
    ):
        raise ExecutionLockedError("verified risk context is stale or mismatched")
    authorization_expiry = min(
        permit_validation.expires_at,
        environment_arm_decision.valid_until_utc,
        verified_risk_context.valid_until_utc,
        now + timedelta(seconds=MAX_AUTHORIZATION_AGE_SECONDS),
    )
    if intent.mode == "DEMO_AUTO":
        if additional_valid_until_utc is None:
            raise ExecutionLockedError(
                "DEMO_AUTO authorization requires the aggregate control expiry"
            )
        aggregate_expiry = require_utc(
            "additional_valid_until_utc",
            additional_valid_until_utc,
        )
        if aggregate_expiry <= now:
            raise ExecutionLockedError(
                "DEMO_AUTO aggregate control expiry is stale"
            )
        authorization_expiry = min(authorization_expiry, aggregate_expiry)
    if intent.mode == "DEMO" and manual_demo_approval_validation is not None:
        authorization_expiry = min(
            authorization_expiry,
            manual_demo_approval_validation.valid_until_utc,
        )
    return RuntimeAuthorization(
        mode=intent.mode,
        intent_id=intent.intent_id,
        permit_id=permit_validation.permit_id,
        risk_decision_id=risk_decision.decision_id,
        journal_sha256=normalized_journal_sha256,
        broker_spec_sha256=broker_spec.content_sha256,
        verified_risk_context_sha256=verified_risk_context.content_sha256,
        verified_risk_context_valid_until_utc=(
            verified_risk_context.valid_until_utc
        ),
        preflight_sha256=gate_capability.preflight_sha256,
        execution_gate_sha256=gate_capability.content_sha256,
        environment_arm_sha256=environment_arm_decision.content_sha256,
        manual_demo_approval_sha256=manual_approval_sha256,
        max_risk_cash=risk_decision.max_risk_cash,
        max_margin_cash=risk_decision.margin_limit_cash,
        spread_limit_points=risk_decision.spread_limit_points,
        spread_p95_points=risk_decision.spread_p95_points,
        spread_median_multiple_limit_points=(
            risk_decision.spread_median_multiple_limit_points
        ),
        broker_point=broker_spec.point,
        checked_at_utc=now,
        valid_until_utc=authorization_expiry,
        _seal=_AUTHORIZATION_SEAL,
    )


@dataclass(frozen=True)
class MT5Preflight(CanonicalContract):
    intent_id: str
    passed: bool
    reason: str
    broker_symbol: str
    intent_sha256: str
    broker_spec_sha256: str
    request: Mapping[str, Any]
    request_sha256: str
    broker_retcode: str
    checked_at_utc: datetime
    valid_until_utc: datetime
    current_bid: float
    current_ask: float
    tick_time_utc: datetime
    allowed_deviation_points: int
    estimated_stop_risk_cash: float
    estimated_margin_cash: float
    _seal: InitVar[object | None] = None

    def __post_init__(self, _seal: object | None) -> None:
        if _seal is not _PREFLIGHT_SEAL:
            raise TypeError("MT5Preflight can only be created by MT5Adapter.preflight")
        require_utc("checked_at_utc", self.checked_at_utc)
        require_utc("valid_until_utc", self.valid_until_utc)
        require_utc("tick_time_utc", self.tick_time_utc)
        if self.valid_until_utc <= self.checked_at_utc:
            raise ValueError("preflight validity window is empty")
        if (
            isinstance(self.allowed_deviation_points, bool)
            or not isinstance(self.allowed_deviation_points, int)
            or self.allowed_deviation_points < 0
        ):
            raise ValueError("allowed_deviation_points must be a nonnegative integer")
        immutable_request = MappingProxyType(dict(self.request))
        object.__setattr__(self, "request", immutable_request)
        if canonical_sha256(immutable_request) != self.request_sha256:
            raise ValueError("request_sha256 does not match the preflight request")


def _mint_mt5_preflight(**values: Any) -> MT5Preflight:
    """Internal/test-adapter boundary; direct MT5Preflight construction is denied."""

    return MT5Preflight(**values, _seal=_PREFLIGHT_SEAL)


@dataclass(frozen=True)
class MT5SubmissionGuard(CanonicalContract):
    """Sealed last-moment account/exposure observation from MT5Adapter."""

    intent_id: str
    account_id: str
    server: str
    symbol: str
    account_equity: float
    active_order_count: int
    active_position_count: int
    broker_spec_sha256: str
    checked_at_utc: datetime
    _seal: InitVar[object | None] = None

    def __post_init__(self, _seal: object | None) -> None:
        if _seal is not _SUBMISSION_GUARD_SEAL:
            raise TypeError(
                "MT5SubmissionGuard can only be created by MT5Adapter"
            )
        if not str(self.intent_id or "").strip():
            raise ValueError("submission guard intent_id is required")
        if not str(self.account_id or "").strip() or not str(self.server or "").strip():
            raise ValueError("submission guard account binding is required")
        normalized_symbol = str(self.symbol or "").strip().upper()
        if not normalized_symbol:
            raise ValueError("submission guard symbol is required")
        object.__setattr__(self, "symbol", normalized_symbol)
        object.__setattr__(
            self,
            "account_equity",
            _finite(self.account_equity, "account_equity", positive=True),
        )
        for field in ("active_order_count", "active_position_count"):
            value = getattr(self, field)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError(f"{field} must be a nonnegative integer")
        normalized_hash = str(self.broker_spec_sha256 or "").lower()
        if len(normalized_hash) != 64 or any(
            character not in "0123456789abcdef"
            for character in normalized_hash
        ):
            raise ValueError("broker_spec_sha256 must be a SHA-256 hash")
        object.__setattr__(self, "broker_spec_sha256", normalized_hash)
        require_utc("checked_at_utc", self.checked_at_utc)


def _mint_mt5_submission_guard(**values: Any) -> MT5SubmissionGuard:
    """Internal/test adapter boundary; direct guard construction is denied."""

    return MT5SubmissionGuard(**values, _seal=_SUBMISSION_GUARD_SEAL)


def _mint_execution_gate_capability(
    *,
    intent: TradeIntent,
    risk_decision: RiskDecision,
    health_decision: RuntimeHealthDecision,
    market_guard_decision: MarketGuardDecision,
    model_binding_decision: ModelBindingDecision,
    preflight: MT5Preflight,
    submission_guard: MT5SubmissionGuard,
    broker_spec: BrokerSpec,
    reservation: IntentRecord,
    journal_sha256: str,
    now: datetime,
) -> ExecutionGateCapability:
    """Join outputs from independent gates after the durable reservation."""

    now = require_utc("now", now)
    if type(risk_decision) is not RiskDecision or not risk_decision.allowed:
        raise ExecutionLockedError("approved risk evaluator output is required")
    if type(health_decision) is not RuntimeHealthDecision or not health_decision.healthy:
        raise ExecutionLockedError("healthy runtime evaluator output is required")
    if (
        type(market_guard_decision) is not MarketGuardDecision
        or not market_guard_decision.news_clear
        or not market_guard_decision.rollover_clear
        or market_guard_decision.symbol != intent.symbol
    ):
        raise ExecutionLockedError("clear sealed market guard output is required")
    if (
        type(model_binding_decision) is not ModelBindingDecision
        or not model_binding_decision.bound
        or model_binding_decision.role != "CHAMPION"
        or model_binding_decision.decision_snapshot_id != intent.decision.snapshot_id
        or model_binding_decision.model_artifact_sha256
        != intent.decision.model_artifact_sha256
    ):
        raise ExecutionLockedError("exact sealed champion binding is required")
    if type(preflight) is not MT5Preflight or not preflight.passed:
        raise ExecutionLockedError("sealed passed MT5 preflight is required")
    if type(reservation) is not IntentRecord or reservation.state != "SUBMITTING":
        raise ExecutionLockedError("durable SUBMITTING reservation is required")
    normalized_journal_sha256 = str(journal_sha256 or "").lower()
    if len(normalized_journal_sha256) != 64 or any(
        char not in "0123456789abcdef" for char in normalized_journal_sha256
    ):
        raise ExecutionLockedError("durable journal identity is invalid")
    ages = (
        (now - risk_decision.evaluated_at).total_seconds(),
        (now - health_decision.observed_at).total_seconds(),
        (now - market_guard_decision.evaluated_at).total_seconds(),
        (now - model_binding_decision.checked_at).total_seconds(),
        (now - preflight.checked_at_utc).total_seconds(),
    )
    if any(age < 0 or age > MAX_AUTHORIZATION_AGE_SECONDS for age in ages):
        raise ExecutionLockedError("execution gate evidence is stale")
    if now >= model_binding_decision.valid_until:
        raise ExecutionLockedError("champion binding expired")
    if type(submission_guard) is not MT5SubmissionGuard:
        raise ExecutionLockedError("sealed MT5 submission guard is required")
    guard_age = (
        now
        - require_utc(
            "guard checked_at_utc",
            submission_guard.checked_at_utc,
        )
    ).total_seconds()
    guard_matches = (
        0 <= guard_age <= MAX_AUTHORIZATION_AGE_SECONDS
        and submission_guard.intent_id == intent.intent_id
        and submission_guard.account_id == intent.account_id
        and submission_guard.server == intent.server
        and submission_guard.symbol == intent.symbol
        and submission_guard.active_order_count == 0
        and submission_guard.active_position_count == 0
        and submission_guard.broker_spec_sha256 == broker_spec.content_sha256
    )
    if (
        not guard_matches
        or preflight.intent_id != intent.intent_id
        or reservation.intent_id != intent.intent_id
        or preflight.broker_spec_sha256 != broker_spec.content_sha256
    ):
        raise ExecutionLockedError("execution gate evidence binding failed")
    return ExecutionGateCapability(
        intent_id=intent.intent_id,
        reservation_intent_id=reservation.intent_id,
        journal_sha256=normalized_journal_sha256,
        risk_decision_sha256=risk_decision.content_sha256,
        health_decision_sha256=health_decision.content_sha256,
        market_guard_decision_sha256=market_guard_decision.content_sha256,
        model_binding_decision_sha256=model_binding_decision.content_sha256,
        preflight_sha256=preflight.content_sha256,
        guard_sha256=submission_guard.content_sha256,
        broker_spec_sha256=broker_spec.content_sha256,
        checked_at_utc=now,
        _seal=_EXECUTION_GATE_SEAL,
    )


@dataclass(frozen=True)
class BrokerSizingQuote:
    symbol: str
    broker_symbol: str
    evaluated_at_utc: datetime
    normalized_lot: float
    max_risk_cash: float
    actual_stop_risk_cash: float
    margin_cash: float
    status: str
    account_currency: str
    absolute_risk_cap_usd: float
    usd_to_account_currency_rate: float
    absolute_risk_cap_account_currency: float
    conversion_quote_sha256: str

    def __post_init__(self) -> None:
        require_utc("evaluated_at_utc", self.evaluated_at_utc)
        for field_name in (
            "normalized_lot",
            "max_risk_cash",
            "actual_stop_risk_cash",
            "margin_cash",
        ):
            object.__setattr__(
                self,
                field_name,
                _finite(getattr(self, field_name), field_name),
            )
        if self.normalized_lot < 0 or self.normalized_lot > 0.01:
            raise ValueError("normalized_lot is outside the canary boundary")
        if min(self.max_risk_cash, self.actual_stop_risk_cash, self.margin_cash) < 0:
            raise ValueError("sizing cash values must be nonnegative")
        if self.actual_stop_risk_cash > self.max_risk_cash + 1e-12:
            raise ValueError("sizing quote exceeds its cash risk cap")
        if self.status not in {"SIZED", "WAIT_MINIMUM_LOT_EXCEEDS_RISK_CAP"}:
            raise ValueError("unsupported sizing status")
        account_currency = require_currency(
            "account_currency",
            self.account_currency,
        )
        object.__setattr__(self, "account_currency", account_currency)
        for field_name in (
            "absolute_risk_cap_usd",
            "usd_to_account_currency_rate",
            "absolute_risk_cap_account_currency",
        ):
            object.__setattr__(
                self,
                field_name,
                _finite(getattr(self, field_name), field_name, positive=True),
            )
        expected_account_cap = (
            self.absolute_risk_cap_usd * self.usd_to_account_currency_rate
        )
        if not math.isclose(
            self.absolute_risk_cap_account_currency,
            expected_account_cap,
            rel_tol=0.0,
            abs_tol=1e-12,
        ):
            raise ValueError("converted absolute risk cap is inconsistent")
        if self.max_risk_cash > self.absolute_risk_cap_account_currency + 1e-12:
            raise ValueError("max_risk_cash exceeds the converted absolute cap")
        object.__setattr__(
            self,
            "conversion_quote_sha256",
            require_hash(
                "conversion_quote_sha256",
                self.conversion_quote_sha256,
            ),
        )


class MT5Adapter:
    """Thin adapter around the official MetaTrader5 Python module."""

    def __init__(
        self,
        *,
        account_alias: str,
        broker_legal_name: str,
        expected_login: int,
        expected_server: str,
        environment: str,
        session_calendar_sha256: str,
        symbol_map: Mapping[str, str],
        usd_account_currency_symbols: Mapping[str, str] | None = None,
        mt5_module: ModuleType | Any | None = None,
        mt5_installation: VerifiedMT5Installation | None = None,
        expected_installed_environment_sha256: str | None = None,
        expected_module_file_sha256: str | None = None,
        expected_module_relative_path_sha256: str | None = None,
        max_tick_age_seconds: int = DEFAULT_MAX_TICK_AGE_SECONDS,
        magic_number: int = 260615,
        deviation_points: int = 30,
        clock_provider: Callable[[], datetime] = _utc_now,
    ):
        if (
            not account_alias.strip()
            or not broker_legal_name.strip()
            or not expected_server.strip()
        ):
            raise ValueError(
                "account_alias, broker_legal_name, and expected_server are required"
            )
        environment = environment.strip().upper()
        if environment not in {"DEMO", "LIVE", "LIVE_READ_ONLY"}:
            raise ValueError("unsupported broker environment")
        if len(session_calendar_sha256) != 64 or any(
            character not in "0123456789abcdefABCDEF"
            for character in session_calendar_sha256
        ):
            raise ValueError("session_calendar_sha256 must be a SHA-256 hash")
        if isinstance(expected_login, bool) or int(expected_login) <= 0:
            raise ValueError("expected_login must be a positive integer")
        if max_tick_age_seconds <= 0:
            raise ValueError("max_tick_age_seconds must be positive")
        if not isinstance(symbol_map, Mapping) or not symbol_map:
            raise ValueError("a non-empty canonical-to-broker symbol_map is required")
        if not callable(clock_provider):
            raise TypeError("clock_provider must be callable")
        normalized_symbol_map: dict[str, str] = {}
        for canonical, broker_symbol in symbol_map.items():
            canonical_name = str(canonical or "").strip().upper()
            broker_name = str(broker_symbol or "").strip()
            if not canonical_name or not broker_name:
                raise ValueError("symbol_map cannot contain empty symbols")
            normalized_symbol_map[canonical_name] = broker_name
        if len(set(normalized_symbol_map.values())) != len(normalized_symbol_map):
            raise ValueError("one broker symbol cannot map to multiple canonical symbols")
        if usd_account_currency_symbols is None:
            usd_account_currency_symbols = {}
        if not isinstance(usd_account_currency_symbols, Mapping):
            raise TypeError("usd_account_currency_symbols must be a mapping or None")
        normalized_conversion_symbols: dict[str, str] = {}
        for canonical, broker_symbol in usd_account_currency_symbols.items():
            canonical_pair = str(canonical or "").strip().upper()
            broker_name = str(broker_symbol or "").strip()
            if (
                len(canonical_pair) != 6
                or not canonical_pair.isalpha()
                or (
                    not canonical_pair.startswith("USD")
                    and not canonical_pair.endswith("USD")
                )
                or not broker_name
            ):
                raise ValueError(
                    "USD conversion mappings require an exact six-letter currency pair"
                )
            normalized_conversion_symbols[canonical_pair] = broker_name
        self.account_alias = account_alias.strip()
        self.broker_legal_name = broker_legal_name.strip()
        self.expected_login = int(expected_login)
        self.expected_server = expected_server.strip()
        self.environment = environment
        self.session_calendar_sha256 = session_calendar_sha256.lower()
        self.symbol_map = MappingProxyType(normalized_symbol_map)
        self.usd_account_currency_symbols = MappingProxyType(
            normalized_conversion_symbols
        )
        self.mt5 = mt5_module
        if mt5_installation is not None:
            if type(mt5_installation) is not VerifiedMT5Installation:
                raise TypeError(
                    "mt5_installation must be exact VerifiedMT5Installation"
                )
            if self.mt5 is not None:
                raise MT5UnavailableError(
                    "module injection is forbidden with verified MT5 installation"
                )
            expected_hashes = (
                expected_installed_environment_sha256,
                expected_module_file_sha256,
                expected_module_relative_path_sha256,
            )
            if any(value is None for value in expected_hashes):
                raise ValueError(
                    "verified MT5 installation requires every expected module hash"
                )
        elif any(
            value is not None
            for value in (
                expected_installed_environment_sha256,
                expected_module_file_sha256,
                expected_module_relative_path_sha256,
            )
        ):
            raise ValueError("expected MT5 hashes require verified installation")
        self._mt5_installation = mt5_installation
        self._expected_installed_environment_sha256 = (
            require_hash(
                "expected_installed_environment_sha256",
                expected_installed_environment_sha256,
            )
            if expected_installed_environment_sha256 is not None
            else None
        )
        self._expected_module_file_sha256 = (
            require_hash(
                "expected_module_file_sha256", expected_module_file_sha256
            )
            if expected_module_file_sha256 is not None
            else None
        )
        self._expected_module_relative_path_sha256 = (
            require_hash(
                "expected_module_relative_path_sha256",
                expected_module_relative_path_sha256,
            )
            if expected_module_relative_path_sha256 is not None
            else None
        )
        self._module_attestation: VerifiedMT5ModuleAttestation | None = None
        self.max_tick_age_seconds = int(max_tick_age_seconds)
        self.magic_number = int(magic_number)
        self.deviation_points = int(deviation_points)
        self._clock_provider = clock_provider
        self._authorization_lock = threading.Lock()
        self._initialized = False

    def execution_fence_identity(self) -> str:
        """Return the exact configured MT5 login/server/environment identity."""

        return account_runtime_identity(
            self.expected_login,
            self.expected_server,
            self.environment,
        )

    def _trusted_now(self, requested: datetime | None = None) -> datetime:
        """Read the configured clock; a caller timestamp is only an assertion."""

        trusted = require_utc("trusted clock", self._clock_provider())
        if requested is not None:
            requested = require_utc("now", requested)
            drift = abs((requested - trusted).total_seconds())
            if drift > CLOCK_OVERRIDE_TOLERANCE_SECONDS:
                raise ValueError("caller timestamp disagrees with trusted clock")
        return trusted

    def _assert_symbol_binding(self, canonical_symbol: str, broker_symbol: str) -> None:
        canonical = str(canonical_symbol or "").strip().upper()
        expected = self.symbol_map.get(canonical)
        if expected is None or expected != str(broker_symbol or "").strip():
            raise AccountBindingError("canonical/broker symbol is not adapter-allowlisted")

    def load_and_attest_module(self) -> VerifiedMT5ModuleAttestation | None:
        """Import only the official package and attest it without broker I/O."""

        if self.mt5 is None:
            if self._mt5_installation is not None:
                require_clean_mt5_import_namespace()
            try:
                import MetaTrader5 as module  # type: ignore[import-not-found]
            except ImportError as exc:
                raise MT5UnavailableError(
                    "MetaTrader5 is unavailable; use Windows x86-64 live runtime"
                ) from exc
            if self._mt5_installation is not None:
                attestation = verify_imported_mt5_module(
                    module, self._mt5_installation
                )
                self._require_expected_module_attestation(attestation)
                self._module_attestation = attestation
            self.mt5 = module
        return self.verify_module_attestation()

    def _require_expected_module_attestation(
        self,
        attestation: VerifiedMT5ModuleAttestation,
    ) -> None:
        if type(attestation) is not VerifiedMT5ModuleAttestation:
            raise MT5UnavailableError("MT5 module attestation is not sealed")
        if (
            attestation.installed_environment_sha256
            != self._expected_installed_environment_sha256
            or attestation.module_file_sha256
            != self._expected_module_file_sha256
            or attestation.module_relative_path_sha256
            != self._expected_module_relative_path_sha256
        ):
            raise MT5UnavailableError("MT5 module attestation binding mismatch")

    def verify_module_attestation(
        self,
    ) -> VerifiedMT5ModuleAttestation | None:
        """Recheck the module origin and file before every external proof gate."""

        if self._mt5_installation is None:
            return None
        if self.mt5 is None:
            raise MT5UnavailableError("official MT5 module has not been loaded")
        current = verify_imported_mt5_module(self.mt5, self._mt5_installation)
        self._require_expected_module_attestation(current)
        prior = self._module_attestation
        if prior is None or current.content_sha256 != prior.content_sha256:
            raise MT5UnavailableError("MT5 module attestation changed after import")
        return current

    def initialize(self, **kwargs: Any) -> None:
        self.load_and_attest_module()
        if not bool(self.mt5.initialize(**kwargs)):
            raise MT5UnavailableError(f"MT5 initialize failed: {self.mt5.last_error()}")
        self._initialized = True
        self.assert_account_binding()

    def shutdown(self) -> None:
        if self._initialized and self.mt5 is not None:
            self.mt5.shutdown()
        self._initialized = False

    def _require_initialized(self) -> None:
        if not self._initialized or self.mt5 is None:
            raise MT5UnavailableError("MT5 adapter is not initialized")
        self.verify_module_attestation()

    def assert_account_binding(self) -> dict[str, Any]:
        self._require_initialized()
        account = _asdict(self.mt5.account_info())
        if not account:
            raise AccountBindingError("MT5 account_info is unavailable")
        actual_login = int(account.get("login", 0) or 0)
        actual_server = str(account.get("server", "") or "")
        if actual_login != self.expected_login or actual_server != self.expected_server:
            raise AccountBindingError("MT5 account login/server does not match allowlist")
        try:
            trade_mode = int(account["trade_mode"])
        except (KeyError, TypeError, ValueError) as exc:
            raise AccountBindingError("MT5 account trade_mode is unavailable") from exc
        demo_mode = int(getattr(self.mt5, "ACCOUNT_TRADE_MODE_DEMO", 0))
        real_mode = int(getattr(self.mt5, "ACCOUNT_TRADE_MODE_REAL", 2))
        expected_trade_mode = demo_mode if self.environment == "DEMO" else real_mode
        if trade_mode != expected_trade_mode:
            raise AccountBindingError("MT5 account environment does not match adapter binding")
        return {
            "account_alias": self.account_alias,
            "server": actual_server,
            "currency": str(account.get("currency", "") or ""),
            "balance": _finite(account.get("balance", 0), "balance"),
            "equity": _finite(account.get("equity", 0), "equity"),
            "margin": _finite(account.get("margin", 0), "margin"),
            "margin_free": _finite(account.get("margin_free", 0), "margin_free"),
            "margin_level": _finite(account.get("margin_level", 0), "margin_level"),
            "trade_allowed": account.get("trade_allowed") is True,
            "trade_expert": account.get("trade_expert") is True,
            "captured_at_utc": self._trusted_now(),
        }

    def get_broker_spec(
        self,
        canonical_symbol: str,
        broker_symbol: str,
        *,
        now: datetime | None = None,
    ) -> BrokerSpec:
        self._require_initialized()
        captured_at = self._trusted_now(now)
        self._assert_symbol_binding(canonical_symbol, broker_symbol)
        account = self.assert_account_binding()
        info = _asdict(self.mt5.symbol_info(broker_symbol))
        if not info:
            raise MT5AdapterError(f"symbol_info unavailable for {broker_symbol}")
        tick_size = _finite(
            info.get("trade_tick_size", info.get("point")), "trade_tick_size", positive=True
        )
        tick_value = _finite(
            info.get("trade_tick_value", info.get("trade_tick_value_profit")),
            "trade_tick_value",
            positive=True,
        )
        margin_per_lot = self.mt5.order_calc_margin(
            getattr(self.mt5, "ORDER_TYPE_BUY"),
            broker_symbol,
            1.0,
            self.current_tick(broker_symbol, now=captured_at)["ask"],
        )
        return BrokerSpec(
            account_id=self.account_alias,
            broker_legal_name=self.broker_legal_name,
            server=self.expected_server,
            environment=self.environment,
            symbol=canonical_symbol,
            broker_symbol=broker_symbol,
            account_currency=account["currency"],
            digits=int(info.get("digits", 0)),
            point=_finite(info.get("point"), "point", positive=True),
            tick_size=tick_size,
            tick_value=tick_value,
            contract_size=_finite(info.get("trade_contract_size"), "contract_size", positive=True),
            volume_min=_finite(info.get("volume_min"), "volume_min", positive=True),
            volume_max=_finite(info.get("volume_max"), "volume_max", positive=True),
            volume_step=_finite(info.get("volume_step"), "volume_step", positive=True),
            stops_level_points=int(info.get("trade_stops_level", 0) or 0),
            freeze_level_points=int(info.get("trade_freeze_level", 0) or 0),
            margin_per_lot=_finite(margin_per_lot, "margin_per_lot", positive=True),
            session_calendar_sha256=self.session_calendar_sha256,
            captured_at=captured_at,
        )

    def current_tick(self, broker_symbol: str, *, now: datetime | None = None) -> dict[str, Any]:
        self._require_initialized()
        raw = _asdict(self.mt5.symbol_info_tick(broker_symbol))
        if not raw:
            raise MT5AdapterError(f"tick unavailable for {broker_symbol}")
        bid = _finite(raw.get("bid"), "bid", positive=True)
        ask = _finite(raw.get("ask"), "ask", positive=True)
        if ask < bid:
            raise MT5AdapterError("ask is below bid")
        time_msc = int(raw.get("time_msc", 0) or 0)
        tick_at = datetime.fromtimestamp(time_msc / 1000.0, tz=UTC)
        now = self._trusted_now(now)
        age = (now - tick_at).total_seconds()
        if age < -1.0 or age > self.max_tick_age_seconds:
            raise MT5AdapterError(f"tick is stale or future-dated: age={age:.3f}s")
        return {"bid": bid, "ask": ask, "time_utc": tick_at, "age_seconds": age}

    def quote_usd_risk_cap_conversion(
        self,
        *,
        now: datetime | None = None,
    ) -> USDRiskCapConversion:
        """Mint a conservative, sealed USD-to-account-currency broker fact."""

        self._require_initialized()
        captured_at = self._trusted_now(now)
        account = self.assert_account_binding()
        try:
            account_currency = require_currency(
                "MT5 account currency",
                account.get("currency"),
            )
        except ValueError as exc:
            raise AccountBindingError(
                "MT5 account currency is not a three-letter currency code"
            ) from exc
        if account_currency == "USD":
            return _mint_usd_risk_cap_conversion(
                account_id=self.account_alias,
                server=self.expected_server,
                account_currency="USD",
                account_currency_per_usd=1.0,
                source="ACCOUNT_CURRENCY_IDENTITY",
                broker_symbol="USD",
                direction="IDENTITY",
                bid=1.0,
                ask=1.0,
                captured_at_utc=captured_at,
            )

        direct_pair = f"USD{account_currency}"
        inverse_pair = f"{account_currency}USD"
        configured = tuple(
            pair
            for pair in (direct_pair, inverse_pair)
            if pair in self.usd_account_currency_symbols
        )
        if not configured:
            raise MT5AdapterError(
                f"no USD risk-cap conversion symbol is configured for {account_currency}"
            )
        if len(configured) != 1:
            raise MT5AdapterError(
                f"ambiguous USD risk-cap conversion symbols for {account_currency}"
            )
        canonical_pair = configured[0]
        broker_symbol = self.usd_account_currency_symbols[canonical_pair]
        expected_base = canonical_pair[:3]
        expected_profit = canonical_pair[3:]
        info = _asdict(self.mt5.symbol_info(broker_symbol))
        if not info:
            raise MT5AdapterError(
                f"conversion symbol_info unavailable for {broker_symbol}"
            )
        observed_base = str(info.get("currency_base", "") or "").strip().upper()
        observed_profit = str(info.get("currency_profit", "") or "").strip().upper()
        if (observed_base, observed_profit) != (expected_base, expected_profit):
            raise MT5AdapterError(
                "conversion symbol currency metadata does not match configured pair"
            )
        tick = self.current_tick(broker_symbol, now=captured_at)
        conversion_tick_age = float(tick["age_seconds"])
        if (
            conversion_tick_age < 0
            or conversion_tick_age > MAX_RISK_CONVERSION_AGE_SECONDS
        ):
            raise MT5AdapterError(
                "USD risk-cap conversion tick is stale or future-dated"
            )
        direction = "DIRECT" if canonical_pair == direct_pair else "INVERSE"
        rate = (
            float(tick["bid"])
            if direction == "DIRECT"
            else 1.0 / float(tick["ask"])
        )
        return _mint_usd_risk_cap_conversion(
            account_id=self.account_alias,
            server=self.expected_server,
            account_currency=account_currency,
            account_currency_per_usd=rate,
            source="MT5_BID_ASK",
            broker_symbol=broker_symbol,
            direction=direction,
            bid=float(tick["bid"]),
            ask=float(tick["ask"]),
            captured_at_utc=tick["time_utc"],
        )

    def estimate_stop_risk_cash(
        self,
        intent: TradeIntent,
        broker_symbol: str,
        *,
        entry_price: float | None = None,
    ) -> float:
        self._require_initialized()
        order_type = (
            getattr(self.mt5, "ORDER_TYPE_BUY")
            if intent.side == "BUY"
            else getattr(self.mt5, "ORDER_TYPE_SELL")
        )
        value = self.mt5.order_calc_profit(
            order_type,
            broker_symbol,
            intent.requested_lot,
            intent.entry_reference if entry_price is None else float(entry_price),
            intent.stop_loss,
        )
        return abs(_finite(value, "order_calc_profit"))

    def calculate_broker_sized_lot(
        self,
        *,
        canonical_symbol: str,
        broker_symbol: str,
        side: str,
        entry_price: float,
        stop_loss: float,
        equity: float,
        allowed_slippage_points: int,
        usd_risk_cap_conversion: USDRiskCapConversion | None = None,
        now: datetime | None = None,
    ) -> BrokerSizingQuote:
        """Size from MT5 order_calc_profit, never a hard-coded pip value."""

        self._require_initialized()
        now = self._trusted_now(now)
        normalized_side = str(side or "").strip().upper()
        if normalized_side not in {"BUY", "SELL"}:
            raise ValueError("side must be BUY or SELL")
        if (
            isinstance(allowed_slippage_points, bool)
            or not isinstance(allowed_slippage_points, int)
            or allowed_slippage_points < 0
        ):
            raise ValueError("allowed_slippage_points must be a nonnegative integer")
        entry = _finite(entry_price, "entry_price", positive=True)
        stop = _finite(stop_loss, "stop_loss", positive=True)
        account_equity = _finite(equity, "equity", positive=True)
        if (normalized_side == "BUY" and stop >= entry) or (
            normalized_side == "SELL" and stop <= entry
        ):
            raise ValueError("stop geometry does not match side")
        spec = self.get_broker_spec(canonical_symbol, broker_symbol, now=now)
        account_currency = str(spec.account_currency).strip().upper()
        conversion_hash = IDENTITY_CONVERSION_SHA256
        if account_currency == "USD" and usd_risk_cap_conversion is None:
            conversion_rate = 1.0
        else:
            conversion = usd_risk_cap_conversion
            if not isinstance(conversion, USDRiskCapConversion):
                raise MT5AdapterError(
                    "a sealed USD risk-cap conversion is required for non-USD sizing"
                )
            conversion_hash = conversion.content_sha256
            conversion_age = (now - conversion.captured_at_utc).total_seconds()
            if (
                conversion.account_id != spec.account_id
                or conversion.server != spec.server
            ):
                raise MT5AdapterError(
                    "USD risk-cap conversion account or server mismatch"
                )
            if conversion.account_currency != account_currency:
                raise MT5AdapterError(
                    "USD risk-cap conversion account currency mismatch"
                )
            if (
                conversion_age < 0
                or conversion_age > MAX_RISK_CONVERSION_AGE_SECONDS
            ):
                raise MT5AdapterError("USD risk-cap conversion is stale or future-dated")
            if account_currency == "USD" and not (
                conversion.source == "ACCOUNT_CURRENCY_IDENTITY"
                and conversion.direction == "IDENTITY"
                and conversion.account_currency_per_usd == 1.0
            ):
                raise MT5AdapterError("USD account conversion is not identity")
            if account_currency != "USD" and not (
                conversion.source == "MT5_BID_ASK"
                and conversion.direction in {"DIRECT", "INVERSE"}
            ):
                raise MT5AdapterError("non-USD conversion source is invalid")
            if account_currency != "USD":
                expected_pair = (
                    f"USD{account_currency}"
                    if conversion.direction == "DIRECT"
                    else f"{account_currency}USD"
                )
                expected_conversion_symbol = self.usd_account_currency_symbols.get(
                    expected_pair
                )
                if expected_conversion_symbol != conversion.broker_symbol:
                    raise MT5AdapterError(
                        "USD risk-cap conversion symbol binding mismatch"
                    )
            conversion_rate = conversion.account_currency_per_usd
        order_type = (
            getattr(self.mt5, "ORDER_TYPE_BUY")
            if normalized_side == "BUY"
            else getattr(self.mt5, "ORDER_TYPE_SELL")
        )
        adverse_entry = entry + (
            allowed_slippage_points * spec.point
            if normalized_side == "BUY"
            else -allowed_slippage_points * spec.point
        )
        one_lot_risk = abs(
            _finite(
                self.mt5.order_calc_profit(
                    order_type,
                    broker_symbol,
                    1.0,
                    adverse_entry,
                    stop,
                ),
                "order_calc_profit",
            )
        )
        if one_lot_risk <= 0:
            raise MT5AdapterError("broker returned zero stop risk")
        absolute_cap_usd = absolute_risk_cap_usd(canonical_symbol)
        absolute_cap_account_currency = absolute_cap_usd * conversion_rate
        max_risk = min(
            RISK_PERCENT_CAP * account_equity,
            absolute_cap_account_currency,
        )
        lot_limit = min(
            0.01,
            spec.volume_max,
            max_risk / one_lot_risk,
            (0.10 * account_equity) / spec.margin_per_lot,
        )
        minimum = Decimal(str(spec.volume_min))
        step = Decimal(str(spec.volume_step))
        limit = Decimal(str(lot_limit))
        if limit < minimum:
            normalized_lot = 0.0
        else:
            steps = ((limit - minimum) / step).to_integral_value(rounding=ROUND_FLOOR)
            normalized_lot = float(minimum + steps * step)

        actual_risk = 0.0
        margin = 0.0
        while normalized_lot >= spec.volume_min - 1e-12:
            actual_risk = abs(
                _finite(
                    self.mt5.order_calc_profit(
                        order_type,
                        broker_symbol,
                        normalized_lot,
                        adverse_entry,
                        stop,
                    ),
                    "order_calc_profit",
                )
            )
            margin = _finite(
                self.mt5.order_calc_margin(
                    order_type,
                    broker_symbol,
                    normalized_lot,
                    adverse_entry,
                ),
                "order_calc_margin",
                positive=True,
            )
            if actual_risk <= max_risk + 1e-12 and margin <= 0.10 * account_equity + 1e-12:
                break
            normalized_lot = float(
                Decimal(str(normalized_lot)) - Decimal(str(spec.volume_step))
            )
        if normalized_lot < spec.volume_min - 1e-12:
            normalized_lot = 0.0
            actual_risk = 0.0
            margin = 0.0
        return BrokerSizingQuote(
            symbol=canonical_symbol.upper(),
            broker_symbol=broker_symbol,
            evaluated_at_utc=now,
            normalized_lot=normalized_lot,
            max_risk_cash=max_risk,
            actual_stop_risk_cash=actual_risk,
            margin_cash=margin,
            account_currency=account_currency,
            absolute_risk_cap_usd=absolute_cap_usd,
            usd_to_account_currency_rate=conversion_rate,
            absolute_risk_cap_account_currency=absolute_cap_account_currency,
            conversion_quote_sha256=conversion_hash,
            status=(
                "SIZED"
                if normalized_lot > 0
                else "WAIT_MINIMUM_LOT_EXCEEDS_RISK_CAP"
            ),
        )

    def _first_eligible_tick(
        self,
        broker_symbol: str,
        *,
        bar_closed_at: datetime,
        now: datetime,
    ) -> dict[str, Any]:
        """Return the earliest broker tick after close, never merely the latest tick."""

        self._require_initialized()
        start = require_utc("bar_closed_at", bar_closed_at)
        end = require_utc("now", now)
        if end <= start:
            raise PreflightRejectedError("no post-candle interval is available")
        copy_ticks = getattr(self.mt5, "copy_ticks_range", None)
        if not callable(copy_ticks):
            raise MT5AdapterError("MT5 copy_ticks_range is unavailable")
        raw_ticks = copy_ticks(
            broker_symbol,
            start,
            end,
            getattr(self.mt5, "COPY_TICKS_ALL"),
        )
        if raw_ticks is None:
            raise MT5AdapterError(f"copy_ticks_range failed: {self.mt5.last_error()}")
        eligible: list[dict[str, Any]] = []
        close_msc = int(start.timestamp() * 1000)
        deadline_msc = close_msc + DEFAULT_MAX_TICK_AGE_SECONDS * 1000
        end_msc = int(end.timestamp() * 1000)
        for item in raw_ticks:
            tick = _asdict(item)
            time_msc = int(tick.get("time_msc", 0) or 0)
            if close_msc < time_msc <= min(deadline_msc, end_msc):
                bid = _finite(tick.get("bid"), "bid", positive=True)
                ask = _finite(tick.get("ask"), "ask", positive=True)
                if ask < bid:
                    raise MT5AdapterError("ask is below bid in tick history")
                eligible.append(
                    {
                        "bid": bid,
                        "ask": ask,
                        "time_msc": time_msc,
                        "time_utc": datetime.fromtimestamp(time_msc / 1000.0, tz=UTC),
                    }
                )
        if not eligible:
            raise PreflightRejectedError("no eligible broker tick exists after candle close")
        return min(eligible, key=lambda tick: tick["time_msc"])

    def _filling_policy(self, info: Mapping[str, Any]) -> int:
        """Map SYMBOL_FILLING flags to an ORDER_FILLING enum for market orders."""

        flags = int(info.get("filling_mode", -1))
        fok_flag = int(getattr(self.mt5, "SYMBOL_FILLING_FOK", 1))
        ioc_flag = int(getattr(self.mt5, "SYMBOL_FILLING_IOC", 2))
        if flags >= 0 and flags & fok_flag:
            return int(getattr(self.mt5, "ORDER_FILLING_FOK"))
        if flags >= 0 and flags & ioc_flag:
            return int(getattr(self.mt5, "ORDER_FILLING_IOC"))
        raise PreflightRejectedError("broker exposes no supported FOK/IOC filling policy")

    def _request(
        self,
        intent: TradeIntent,
        broker_symbol: str,
        tick: Mapping[str, Any],
        *,
        allowed_deviation_points: int,
    ) -> dict[str, Any]:
        self._require_initialized()
        info = _asdict(self.mt5.symbol_info(broker_symbol))
        if not info:
            raise MT5AdapterError(f"symbol_info unavailable for {broker_symbol}")
        order_type = (
            getattr(self.mt5, "ORDER_TYPE_BUY")
            if intent.side == "BUY"
            else getattr(self.mt5, "ORDER_TYPE_SELL")
        )
        price = float(tick["ask"] if intent.side == "BUY" else tick["bid"])
        return {
            "action": getattr(self.mt5, "TRADE_ACTION_DEAL"),
            "symbol": broker_symbol,
            "volume": intent.requested_lot,
            "type": order_type,
            "price": price,
            "sl": intent.stop_loss,
            "tp": intent.take_profit,
            "deviation": min(self.deviation_points, allowed_deviation_points),
            "magic": self.magic_number,
            "comment": f"AIS:{intent.content_sha256[:20]}",
            "type_time": getattr(self.mt5, "ORDER_TIME_GTC"),
            "type_filling": self._filling_policy(info),
        }

    def preflight(
        self,
        intent: TradeIntent,
        broker_symbol: str,
        *,
        allowed_deviation_points: int,
        now: datetime | None = None,
    ) -> MT5Preflight:
        self._require_initialized()
        started_at = self._trusted_now(now)
        if isinstance(allowed_deviation_points, bool) or not isinstance(
            allowed_deviation_points, int
        ) or allowed_deviation_points < 0:
            raise ValueError("allowed_deviation_points must be a nonnegative integer")
        if intent.account_id != self.account_alias or intent.server != self.expected_server:
            raise AccountBindingError("intent account/server does not match adapter binding")
        self._assert_symbol_binding(intent.symbol, broker_symbol)
        symbol_allowed, symbol_reason = execution_policy.validate_execution_symbol(
            intent.symbol,
            mode=intent.mode,
        )
        if not symbol_allowed:
            raise ExecutionLockedError(symbol_reason)
        lot_allowed, lot_reason = execution_policy.validate_execution_lot(
            intent.requested_lot
        )
        if not lot_allowed:
            raise ExecutionLockedError(lot_reason)
        expected_environment = "LIVE" if intent.mode == "LIVE" else "DEMO"
        if intent.mode not in {"DEMO", "DEMO_AUTO", "LIVE"}:
            raise ExecutionLockedError("MT5 execution adapter rejects non-order modes")
        if self.environment != expected_environment:
            raise AccountBindingError("intent mode does not match broker environment")
        if intent.expires_at <= started_at:
            raise PreflightRejectedError("intent is expired")
        self.assert_account_binding()
        spec = self.get_broker_spec(intent.symbol, broker_symbol, now=started_at)
        if intent.requested_lot < spec.volume_min or intent.requested_lot > min(spec.volume_max, 0.01):
            raise PreflightRejectedError("requested lot violates broker or canary bounds")
        steps = intent.requested_lot / spec.volume_step
        if abs(steps - round(steps)) > 1e-9:
            raise PreflightRejectedError("requested lot is not aligned to broker volume_step")
        minimum_distance = spec.stops_level_points * spec.point
        if intent.stop_distance + 1e-12 < minimum_distance:
            raise PreflightRejectedError("stop distance violates broker stops level")
        tick = self._first_eligible_tick(
            broker_symbol,
            bar_closed_at=intent.decision.bar_closed_at,
            now=started_at,
        )
        tick_entry_reference = float(
            tick["ask"] if intent.side == "BUY" else tick["bid"]
        )
        if tick["time_utc"] != intent.decision.created_at:
            raise PreflightRejectedError(
                "first eligible broker tick time does not match decision snapshot"
            )
        if tick_entry_reference != intent.entry_reference:
            raise PreflightRejectedError(
                "first eligible broker tick price does not match entry reference"
            )
        request = self._request(
            intent,
            broker_symbol,
            tick,
            allowed_deviation_points=allowed_deviation_points,
        )
        check = self.mt5.order_check(request)
        check_dict = _asdict(check)
        retcode = str(check_dict.get("retcode", "MISSING"))
        passed = check is not None and int(check_dict.get("retcode", -1)) == 0
        margin = self.mt5.order_calc_margin(
            request["type"], broker_symbol, intent.requested_lot, request["price"]
        )
        adverse_entry = request["price"] + (
            request["deviation"] * spec.point
            if intent.side == "BUY"
            else -request["deviation"] * spec.point
        )
        risk = self.estimate_stop_risk_cash(
            intent,
            broker_symbol,
            entry_price=adverse_entry,
        )
        completed_at = self._trusted_now()
        if intent.expires_at <= completed_at:
            raise PreflightRejectedError("intent expired during broker preflight")
        valid_until = min(
            intent.expires_at,
            completed_at + timedelta(seconds=DEFAULT_PREFLIGHT_TTL_SECONDS),
        )
        reason = str(check_dict.get("comment", "") or "")
        return _mint_mt5_preflight(
            intent_id=intent.intent_id,
            passed=passed,
            reason=reason or ("PREFLIGHT_PASSED" if passed else "PREFLIGHT_REJECTED"),
            broker_symbol=broker_symbol,
            intent_sha256=intent.content_sha256,
            broker_spec_sha256=spec.content_sha256,
            request=request,
            request_sha256=canonical_sha256(request),
            broker_retcode=retcode,
            checked_at_utc=completed_at,
            valid_until_utc=valid_until,
            current_bid=float(tick["bid"]),
            current_ask=float(tick["ask"]),
            tick_time_utc=tick["time_utc"],
            allowed_deviation_points=allowed_deviation_points,
            estimated_stop_risk_cash=risk,
            estimated_margin_cash=_finite(margin, "order_calc_margin", positive=True),
        )

    def submission_guard(
        self,
        intent: TradeIntent,
        broker_spec: BrokerSpec,
        *,
        expected_equity: float,
        now: datetime,
    ) -> MT5SubmissionGuard:
        """Refresh broker/account/exposure facts immediately before reservation."""

        started_at = self._trusted_now(now)
        if type(broker_spec) is not BrokerSpec:
            raise TypeError("broker_spec must be a BrokerSpec")
        self._assert_symbol_binding(intent.symbol, broker_spec.broker_symbol)
        account = self.assert_account_binding()
        if not account["trade_allowed"] or not account["trade_expert"]:
            raise PreflightRejectedError("broker account does not allow expert trading")
        active_orders = self.orders()
        active_positions = self.positions()
        if active_orders or active_positions:
            raise PreflightRejectedError(
                "global exposure guard requires no active broker order or position"
            )
        if abs(float(account["equity"]) - float(expected_equity)) > 0.01:
            raise PreflightRejectedError("account equity changed after risk evaluation")
        current_spec = self.get_broker_spec(
            intent.symbol,
            broker_spec.broker_symbol,
            now=started_at,
        )
        bound_fields = (
            "account_id",
            "broker_legal_name",
            "server",
            "environment",
            "symbol",
            "broker_symbol",
            "account_currency",
            "digits",
            "point",
            "tick_size",
            "tick_value",
            "contract_size",
            "volume_min",
            "volume_max",
            "volume_step",
            "stops_level_points",
            "freeze_level_points",
            "margin_per_lot",
            "session_calendar_sha256",
        )
        drifted = [
            field
            for field in bound_fields
            if getattr(current_spec, field) != getattr(broker_spec, field)
        ]
        if drifted:
            raise PreflightRejectedError(
                "broker specification drifted: " + ",".join(drifted)
            )
        completed_at = self._trusted_now()
        return _mint_mt5_submission_guard(
            intent_id=intent.intent_id,
            account_id=intent.account_id,
            server=intent.server,
            symbol=intent.symbol,
            account_equity=account["equity"],
            active_order_count=0,
            active_position_count=0,
            broker_spec_sha256=broker_spec.content_sha256,
            checked_at_utc=completed_at,
        )

    def submit(
        self,
        intent: TradeIntent,
        preflight: MT5Preflight,
        authorization: RuntimeAuthorization,
        submission_lease: DurableSubmissionLease,
        *,
        now: datetime | None = None,
    ) -> ExecutionReceipt:
        self._require_initialized()
        now = self._trusted_now(now)
        if type(authorization) is not RuntimeAuthorization:
            raise ExecutionLockedError("sealed runtime authorization is required")
        if type(submission_lease) is not DurableSubmissionLease:
            raise ExecutionLockedError(
                "durable one-use journal submission lease is required"
            )
        if (
            not authorization.allows_order_send(now=now)
            or authorization.mode.upper() != intent.mode
            or authorization.intent_id != intent.intent_id
            or authorization.permit_id != intent.permit_id
        ):
            raise ExecutionLockedError("runtime authorization does not allow order_send")
        if type(preflight) is not MT5Preflight:
            raise PreflightRejectedError("validated MT5 preflight is required")
        if (
            not preflight.passed
            or preflight.intent_id != intent.intent_id
            or preflight.intent_sha256 != intent.content_sha256
            or authorization.broker_spec_sha256 != preflight.broker_spec_sha256
            or authorization.preflight_sha256 != preflight.content_sha256
        ):
            raise PreflightRejectedError("valid matching preflight is required")
        if submission_lease.journal_sha256 != authorization.journal_sha256:
            raise ExecutionLockedError(
                "submission lease journal does not match runtime authorization"
            )
        if now >= preflight.valid_until_utc or now >= intent.expires_at:
            raise PreflightRejectedError("preflight or intent expired before submission")
        self._assert_symbol_binding(intent.symbol, preflight.broker_symbol)
        symbol_allowed, symbol_reason = execution_policy.validate_execution_symbol(
            intent.symbol,
            mode=intent.mode,
        )
        lot_allowed, lot_reason = execution_policy.validate_execution_lot(
            intent.requested_lot
        )
        if not symbol_allowed:
            raise ExecutionLockedError(symbol_reason)
        if not lot_allowed:
            raise ExecutionLockedError(lot_reason)
        expected_environment = "LIVE" if intent.mode == "LIVE" else "DEMO"
        if self.environment != expected_environment:
            raise AccountBindingError("intent mode does not match broker environment")
        self.assert_account_binding()
        expected_request = self._request(
            intent,
            preflight.broker_symbol,
            {
                "bid": preflight.current_bid,
                "ask": preflight.current_ask,
                "time_utc": preflight.tick_time_utc,
            },
            allowed_deviation_points=preflight.allowed_deviation_points,
        )
        if (
            canonical_sha256(preflight.request) != preflight.request_sha256
            or canonical_sha256(expected_request) != preflight.request_sha256
        ):
            raise PreflightRejectedError("preflight request no longer matches immutable intent")
        with self._authorization_lock:
            final_stop_risk_cash = preflight.estimated_stop_risk_cash
            final_now = self._trusted_now()
            if (
                not authorization.allows_order_send(now=final_now)
                or final_now >= preflight.valid_until_utc
                or final_now >= intent.expires_at
            ):
                raise PreflightRejectedError(
                    "authorization, preflight, or intent expired at order_send boundary"
                )
            # Account and global exposure are refreshed immediately before send.
            # The durable journal lease has already committed its one-use marker,
            # so no SQLite transaction remains open across these broker calls.
            account = self.assert_account_binding()
            if not account["trade_allowed"] or not account["trade_expert"]:
                raise PreflightRejectedError(
                    "broker account no longer allows expert trading"
                )
            if self.orders() or self.positions():
                raise PreflightRejectedError(
                    "global exposure appeared at final order_send boundary"
                )
            tick = self.current_tick(preflight.broker_symbol, now=final_now)
            spread_points = (float(tick["ask"]) - float(tick["bid"])) / (
                authorization.broker_point
            )
            if (
                spread_points >= authorization.spread_p95_points
                or spread_points
                > authorization.spread_median_multiple_limit_points
            ):
                raise PreflightRejectedError(
                    "actual broker spread exceeds risk-governor limit"
                )
            current_entry = float(
                tick["ask"] if intent.side == "BUY" else tick["bid"]
            )
            requested_entry = float(preflight.request["price"])
            if intent.side == "BUY":
                adverse_entry = max(requested_entry, current_entry) + (
                    preflight.request["deviation"] * authorization.broker_point
                )
            else:
                adverse_entry = min(requested_entry, current_entry) - (
                    preflight.request["deviation"] * authorization.broker_point
                )
            final_stop_risk_cash = self.estimate_stop_risk_cash(
                intent,
                preflight.broker_symbol,
                entry_price=adverse_entry,
            )
            final_margin_cash = _finite(
                self.mt5.order_calc_margin(
                    preflight.request["type"],
                    preflight.broker_symbol,
                    intent.requested_lot,
                    adverse_entry,
                ),
                "final order_calc_margin",
                positive=True,
            )
            if final_stop_risk_cash > authorization.max_risk_cash + 1e-12:
                raise PreflightRejectedError(
                    "actual stop risk exceeds risk-governor limit"
                )
            if final_margin_cash > authorization.max_margin_cash + 1e-12:
                raise PreflightRejectedError(
                    "actual margin exceeds risk-governor limit"
                )
            # Broker calculations are synchronous and may block.  Re-sample
            # the trusted clock after the *last* calculation so an expired
            # authorization can never be consumed merely because it was fresh
            # before the broker calls began.
            send_boundary_now = self._trusted_now()
            if (
                not authorization.allows_order_send(now=send_boundary_now)
                or send_boundary_now >= preflight.valid_until_utc
                or send_boundary_now >= intent.expires_at
            ):
                raise PreflightRejectedError(
                    "authorization, preflight, or intent expired at final send boundary"
                )
            account_age = (
                send_boundary_now
                - require_utc(
                    "final account fact captured_at_utc",
                    account["captured_at_utc"],
                )
            ).total_seconds()
            tick_age = (
                send_boundary_now
                - require_utc("final tick time_utc", tick["time_utc"])
            ).total_seconds()
            if (
                account_age < 0
                or account_age > MAX_AUTHORIZATION_AGE_SECONDS
                or tick_age < 0
                or tick_age > self.max_tick_age_seconds
            ):
                raise PreflightRejectedError(
                    "final account or tick facts are stale at send boundary"
                )
            # SQLite commits the one-use record before this context is opened.
            # The in-process lease can be consumed once and is deactivated when
            # the journal final guard exits, including on exceptions.
            submission_proof = submission_lease.consume(
                journal_sha256=authorization.journal_sha256,
                intent_id=intent.intent_id,
                execution_gate_sha256=authorization.execution_gate_sha256,
                authorization_sha256=canonical_sha256(authorization),
                broker_request_sha256=preflight.request_sha256,
            )
            try:
                result = self.mt5.order_send(dict(expected_request))
            except Exception as exc:
                raise SubmissionUncertainError(
                    "order_send raised after submission began"
                ) from exc
            # The broker call may block for materially longer than the 50 ms
            # trusted-clock assertion tolerance.  Receipt time is therefore
            # sampled after the call returns, never copied from the pre-send
            # authorization boundary.
            received_at = self._trusted_now()
        if result is None:
            raise SubmissionUncertainError("order_send returned no result")
        payload = _asdict(result)
        retcode = int(payload.get("retcode", -1))
        done_code = int(getattr(self.mt5, "TRADE_RETCODE_DONE", 10009))
        placed_code = int(getattr(self.mt5, "TRADE_RETCODE_PLACED", 10008))
        partial_code = int(getattr(self.mt5, "TRADE_RETCODE_DONE_PARTIAL", 10010))
        definitive_rejects = {
            int(getattr(self.mt5, "TRADE_RETCODE_REQUOTE", 10004)),
            int(getattr(self.mt5, "TRADE_RETCODE_REJECT", 10006)),
            int(getattr(self.mt5, "TRADE_RETCODE_CANCEL", 10007)),
            int(getattr(self.mt5, "TRADE_RETCODE_INVALID", 10013)),
            int(getattr(self.mt5, "TRADE_RETCODE_INVALID_VOLUME", 10014)),
            int(getattr(self.mt5, "TRADE_RETCODE_INVALID_PRICE", 10015)),
            int(getattr(self.mt5, "TRADE_RETCODE_INVALID_STOPS", 10016)),
            int(getattr(self.mt5, "TRADE_RETCODE_TRADE_DISABLED", 10017)),
            int(getattr(self.mt5, "TRADE_RETCODE_MARKET_CLOSED", 10018)),
            int(getattr(self.mt5, "TRADE_RETCODE_NO_MONEY", 10019)),
            int(getattr(self.mt5, "TRADE_RETCODE_PRICE_CHANGED", 10020)),
            int(getattr(self.mt5, "TRADE_RETCODE_PRICE_OFF", 10021)),
            int(getattr(self.mt5, "TRADE_RETCODE_INVALID_EXPIRATION", 10022)),
            int(getattr(self.mt5, "TRADE_RETCODE_ORDER_CHANGED", 10023)),
            int(getattr(self.mt5, "TRADE_RETCODE_TOO_MANY_REQUESTS", 10024)),
            int(getattr(self.mt5, "TRADE_RETCODE_INVALID_ORDER", 10035)),
            int(getattr(self.mt5, "TRADE_RETCODE_LIMIT_ORDERS", 10033)),
            int(getattr(self.mt5, "TRADE_RETCODE_LIMIT_VOLUME", 10034)),
        }
        requested = intent.requested_lot
        filled = float(payload.get("volume", 0.0) or 0.0)
        if not math.isfinite(filled) or filled < 0 or filled > requested + 1e-12:
            raise SubmissionUncertainError("broker returned an impossible filled volume")
        fill_price = float(payload.get("price")) if payload.get("price") else None
        if filled > 0 and (fill_price is None or not math.isfinite(fill_price)):
            raise SubmissionUncertainError("broker omitted fill price for nonzero volume")
        requested_price = float(expected_request["price"])
        slippage_price = None
        if fill_price is not None:
            slippage_price = (
                fill_price - requested_price
                if intent.side == "BUY"
                else requested_price - fill_price
            )
        if retcode == partial_code:
            state = "PARTIAL"
        elif retcode == done_code and filled > 0:
            state = "FILLED"
        elif retcode in {done_code, placed_code}:
            state = "ACKNOWLEDGED"
        elif retcode in definitive_rejects:
            state = "REJECTED"
        else:
            state = "UNCERTAIN"
        return _mint_execution_receipt(
            submission_proof=submission_proof,
            intent_id=intent.intent_id,
            state=state,
            account_id=self.account_alias,
            server=self.expected_server,
            symbol=intent.symbol,
            requested_volume=requested,
            filled_volume=filled,
            received_at=received_at,
            broker_retcode=str(retcode),
            message=str(payload.get("comment", "") or ""),
            order_ticket=str(payload.get("order")) if payload.get("order") else None,
            deal_ticket=str(payload.get("deal")) if payload.get("deal") else None,
            requested_price=requested_price,
            fill_price=fill_price,
            slippage_price=slippage_price,
            broker_time_msc=(
                int(payload.get("time_msc")) if payload.get("time_msc") else None
            ),
            stop_loss=intent.stop_loss,
            take_profit=intent.take_profit,
            actual_risk_cash=final_stop_risk_cash,
        )

    def orders(self) -> list[dict[str, Any]]:
        self._require_initialized()
        self.assert_account_binding()
        result = self.mt5.orders_get()
        if result is None:
            raise MT5AdapterError(f"orders_get failed: {self.mt5.last_error()}")
        return [_asdict(item) for item in result]

    def positions(self) -> list[dict[str, Any]]:
        self._require_initialized()
        self.assert_account_binding()
        result = self.mt5.positions_get()
        if result is None:
            raise MT5AdapterError(f"positions_get failed: {self.mt5.last_error()}")
        return [_asdict(item) for item in result]

    def deals(self, start_utc: datetime, end_utc: datetime) -> list[dict[str, Any]]:
        self._require_initialized()
        self.assert_account_binding()
        require_utc("start_utc", start_utc)
        require_utc("end_utc", end_utc)
        if end_utc <= start_utc:
            raise ValueError("history end must be after start")
        result = self.mt5.history_deals_get(start_utc, end_utc)
        if result is None:
            raise MT5AdapterError(f"history_deals_get failed: {self.mt5.last_error()}")
        return [_asdict(item) for item in result]
