"""Fail-closed construction boundary for execution-sensitive risk context.

``RiskContext`` remains a pure value used by replay and the risk governor.  This
module is the production boundary which proves where every mutable value came
from before wrapping that value in :class:`VerifiedRiskContext`.  The module is
deny-only: it imports no broker API and cannot submit, permit, or unlock an
order.
"""

from __future__ import annotations

from dataclasses import InitVar, dataclass, replace
from datetime import datetime, timedelta
import hashlib
import hmac
from typing import Callable, Iterable

from .contracts import (
    BrokerSpec,
    CanonicalContract,
    canonical_json,
    require_finite,
    require_hash,
    require_int,
    require_text,
    require_utc,
)
from .market_guard import MarketGuardDecision
from .health import RuntimeHealthFacts, evaluate_runtime_health
from .permit import PermitValidation, account_alias_sha256
from .risk import IDENTITY_CONVERSION_SHA256, RiskContext, USDRiskCapConversion
from .risk_ledger import RiskStateReceipt, verify_risk_state_receipt
from .runtime_fact_collector import (
    RuntimeFactReceipt,
    RuntimeFactVerificationError,
    verify_runtime_fact_receipt,
)


LIVE_ALLOWED = False
SAFE_TO_DEMO_AUTO_ORDER = False
EXPOSURE_RECEIPT_SCHEMA_VERSION = "trusted-exposure-receipt-v1"
CALIBRATION_RECEIPT_SCHEMA_VERSION = "trusted-risk-calibration-receipt-v1"
VERIFIED_RISK_CONTEXT_SCHEMA_VERSION = "verified-risk-context-v1"
SHORT_LIVED_RECEIPT_MAX_AGE = timedelta(seconds=1)
CALIBRATION_RECEIPT_MAX_AGE = timedelta(hours=24)
MINIMUM_CALIBRATION_SESSIONS = 20
MINIMUM_CALIBRATION_WINDOW = timedelta(days=19)

_EXPOSURE_HMAC_DOMAIN = b"AI_SCALPER_TRUSTED_EXPOSURE_RECEIPT_V1\x00"
_CALIBRATION_HMAC_DOMAIN = b"AI_SCALPER_RISK_CALIBRATION_RECEIPT_V1\x00"
_VERIFIED_CONTEXT_SEAL = object()


class RiskContextVerificationError(RuntimeError):
    """One or more required proofs failed closed."""

    def __init__(self, reason_codes: Iterable[str]) -> None:
        normalized = tuple(
            sorted(
                {
                    require_text("reason_code", reason, upper=True)
                    for reason in reason_codes
                }
            )
        )
        if not normalized:
            raise ValueError("verification failure requires a reason code")
        self.reason_codes = normalized
        super().__init__(",".join(normalized))


def _require_bool(name: str, value: object) -> bool:
    if type(value) is not bool:
        raise TypeError(f"{name} must be bool")
    return value


def _secret_bytes(secret: str | bytes) -> bytes:
    if isinstance(secret, str):
        normalized = secret.encode("utf-8")
    elif isinstance(secret, bytes):
        normalized = secret
    else:
        raise TypeError("receipt HMAC secret must be str or bytes")
    if len(normalized) < 32:
        raise ValueError("receipt HMAC secret must contain at least 32 bytes")
    return normalized


def _normalize_symbols(symbols: Iterable[str]) -> tuple[str, ...]:
    normalized = tuple(
        sorted(require_text("canonical symbol", symbol, upper=True) for symbol in symbols)
    )
    if len(normalized) != len(set(normalized)):
        raise ValueError("canonical symbols cannot contain duplicates")
    return normalized


def _normalize_exposures(
    name: str,
    values: Iterable["BrokerExposure"],
    *,
    expected_kind: str,
) -> tuple["BrokerExposure", ...]:
    normalized = tuple(values)
    if any(type(value) is not BrokerExposure for value in normalized):
        raise TypeError(f"{name} must contain BrokerExposure values")
    if any(value.kind != expected_kind for value in normalized):
        raise ValueError(f"{name} contains the wrong exposure kind")
    ordered = tuple(sorted(normalized, key=lambda value: value.exposure_id))
    identifiers = tuple(value.exposure_id for value in ordered)
    if len(identifiers) != len(set(identifiers)):
        raise ValueError(f"{name} cannot contain duplicate broker identifiers")
    return ordered


def _signing_hmac(
    *,
    secret: str | bytes,
    domain: bytes,
    payload: dict[str, object],
) -> str:
    return hmac.new(
        _secret_bytes(secret),
        domain + canonical_json(payload).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


@dataclass(frozen=True)
class BrokerExposure(CanonicalContract):
    """One exact active broker order or position."""

    exposure_id: str
    kind: str
    canonical_symbol: str
    broker_symbol: str
    side: str
    volume: float

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "exposure_id",
            require_text("exposure_id", self.exposure_id),
        )
        kind = require_text("kind", self.kind, upper=True)
        if kind not in {"ORDER", "POSITION"}:
            raise ValueError("kind must be ORDER or POSITION")
        object.__setattr__(self, "kind", kind)
        object.__setattr__(
            self,
            "canonical_symbol",
            require_text("canonical_symbol", self.canonical_symbol, upper=True),
        )
        object.__setattr__(
            self,
            "broker_symbol",
            require_text("broker_symbol", self.broker_symbol),
        )
        side = require_text("side", self.side, upper=True)
        if side not in {"BUY", "SELL"}:
            raise ValueError("side must be BUY or SELL")
        object.__setattr__(self, "side", side)
        object.__setattr__(
            self,
            "volume",
            require_finite("volume", self.volume, positive=True),
        )


@dataclass(frozen=True)
class ExposureReceipt(CanonicalContract):
    """Short-lived signed reconciliation view of global broker exposure."""

    account_id: str
    server: str
    environment: str
    account_runtime_identity_sha256: str
    journal_sha256: str
    active_orders: tuple[BrokerExposure, ...]
    active_positions: tuple[BrokerExposure, ...]
    active_order_count: int
    active_position_count: int
    reserved_canonical_symbols: tuple[str, ...]
    reconciliation_clean: bool
    key_id: str
    observed_at_utc: datetime
    valid_until_utc: datetime
    signature: str = ""
    live_allowed: bool = LIVE_ALLOWED
    safe_to_demo_auto_order: bool = SAFE_TO_DEMO_AUTO_ORDER
    schema_version: str = EXPOSURE_RECEIPT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        object.__setattr__(self, "account_id", require_text("account_id", self.account_id))
        object.__setattr__(self, "server", require_text("server", self.server))
        environment = require_text("environment", self.environment, upper=True)
        if environment not in {"DEMO", "LIVE", "LIVE_READ_ONLY"}:
            raise ValueError("unsupported exposure environment")
        object.__setattr__(self, "environment", environment)
        object.__setattr__(
            self,
            "account_runtime_identity_sha256",
            require_hash(
                "account_runtime_identity_sha256",
                self.account_runtime_identity_sha256,
            ),
        )
        object.__setattr__(
            self,
            "journal_sha256",
            require_hash("journal_sha256", self.journal_sha256),
        )
        orders = _normalize_exposures(
            "active_orders", self.active_orders, expected_kind="ORDER"
        )
        positions = _normalize_exposures(
            "active_positions", self.active_positions, expected_kind="POSITION"
        )
        all_ids = tuple(item.exposure_id for item in orders + positions)
        if len(all_ids) != len(set(all_ids)):
            raise ValueError("broker exposure identifiers must be globally unique")
        object.__setattr__(self, "active_orders", orders)
        object.__setattr__(self, "active_positions", positions)
        require_int("active_order_count", self.active_order_count, minimum=0)
        require_int("active_position_count", self.active_position_count, minimum=0)
        if self.active_order_count != len(orders):
            raise ValueError("active_order_count does not match active_orders")
        if self.active_position_count != len(positions):
            raise ValueError("active_position_count does not match active_positions")
        reserved = _normalize_symbols(self.reserved_canonical_symbols)
        observed_symbols = {item.canonical_symbol for item in orders + positions}
        if not observed_symbols.issubset(set(reserved)):
            raise ValueError("every broker exposure must have a symbol reservation")
        object.__setattr__(self, "reserved_canonical_symbols", reserved)
        _require_bool("reconciliation_clean", self.reconciliation_clean)
        object.__setattr__(self, "key_id", require_text("key_id", self.key_id))
        require_utc("observed_at_utc", self.observed_at_utc)
        require_utc("valid_until_utc", self.valid_until_utc)
        lifetime = self.valid_until_utc - self.observed_at_utc
        if not timedelta(0) < lifetime <= SHORT_LIVED_RECEIPT_MAX_AGE:
            raise ValueError("exposure receipt validity cannot exceed one second")
        signature = str(self.signature or "").strip().lower()
        if signature:
            signature = require_hash("signature", signature)
        object.__setattr__(self, "signature", signature)
        _require_bool("live_allowed", self.live_allowed)
        _require_bool("safe_to_demo_auto_order", self.safe_to_demo_auto_order)
        if self.live_allowed or self.safe_to_demo_auto_order:
            raise ValueError("exposure receipts cannot unlock execution")
        if self.schema_version != EXPOSURE_RECEIPT_SCHEMA_VERSION:
            raise ValueError("unsupported exposure receipt schema")

    @property
    def signing_payload(self) -> dict[str, object]:
        payload = self.to_canonical_dict()
        payload.pop("signature")
        return payload

    def sign(self, secret: str | bytes) -> "ExposureReceipt":
        return replace(
            self,
            signature=_signing_hmac(
                secret=secret,
                domain=_EXPOSURE_HMAC_DOMAIN,
                payload=self.signing_payload,
            ),
        )

    def verify_signature(self, secret: str | bytes) -> bool:
        if not self.signature:
            return False
        expected = _signing_hmac(
            secret=secret,
            domain=_EXPOSURE_HMAC_DOMAIN,
            payload=self.signing_payload,
        )
        return hmac.compare_digest(self.signature, expected)


@dataclass(frozen=True)
class RiskCalibrationReceipt(CanonicalContract):
    """Signed spread/slippage calibration bound to one exact broker lane."""

    account_id: str
    server: str
    environment: str
    symbol: str
    broker_symbol: str
    account_runtime_identity_sha256: str
    broker_spec_sha256: str
    config_sha256: str
    data_window_sha256: str
    data_window_start_utc: datetime
    data_window_end_utc: datetime
    session_count: int
    sample_count: int
    median_spread_points: float
    p95_spread_points: float
    p95_slippage_points: float
    key_id: str
    issued_at_utc: datetime
    valid_until_utc: datetime
    signature: str = ""
    live_allowed: bool = LIVE_ALLOWED
    safe_to_demo_auto_order: bool = SAFE_TO_DEMO_AUTO_ORDER
    schema_version: str = CALIBRATION_RECEIPT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        object.__setattr__(self, "account_id", require_text("account_id", self.account_id))
        object.__setattr__(self, "server", require_text("server", self.server))
        environment = require_text("environment", self.environment, upper=True)
        if environment not in {"DEMO", "LIVE", "LIVE_READ_ONLY"}:
            raise ValueError("unsupported calibration environment")
        object.__setattr__(self, "environment", environment)
        object.__setattr__(self, "symbol", require_text("symbol", self.symbol, upper=True))
        object.__setattr__(
            self, "broker_symbol", require_text("broker_symbol", self.broker_symbol)
        )
        for name in (
            "account_runtime_identity_sha256",
            "broker_spec_sha256",
            "config_sha256",
            "data_window_sha256",
        ):
            object.__setattr__(self, name, require_hash(name, getattr(self, name)))
        require_utc("data_window_start_utc", self.data_window_start_utc)
        require_utc("data_window_end_utc", self.data_window_end_utc)
        require_utc("issued_at_utc", self.issued_at_utc)
        require_utc("valid_until_utc", self.valid_until_utc)
        if not self.data_window_start_utc < self.data_window_end_utc <= self.issued_at_utc:
            raise ValueError("calibration data window is invalid")
        lifetime = self.valid_until_utc - self.issued_at_utc
        if not timedelta(0) < lifetime <= CALIBRATION_RECEIPT_MAX_AGE:
            raise ValueError("calibration receipt validity exceeds 24 hours")
        require_int("session_count", self.session_count, minimum=1)
        require_int("sample_count", self.sample_count, minimum=1)
        if self.sample_count < self.session_count:
            raise ValueError("sample_count cannot be below session_count")
        object.__setattr__(
            self,
            "median_spread_points",
            require_finite(
                "median_spread_points", self.median_spread_points, positive=True
            ),
        )
        object.__setattr__(
            self,
            "p95_spread_points",
            require_finite("p95_spread_points", self.p95_spread_points, positive=True),
        )
        object.__setattr__(
            self,
            "p95_slippage_points",
            require_finite(
                "p95_slippage_points", self.p95_slippage_points, nonnegative=True
            ),
        )
        if self.p95_spread_points < self.median_spread_points:
            raise ValueError("p95 spread cannot be below median spread")
        object.__setattr__(self, "key_id", require_text("key_id", self.key_id))
        signature = str(self.signature or "").strip().lower()
        if signature:
            signature = require_hash("signature", signature)
        object.__setattr__(self, "signature", signature)
        _require_bool("live_allowed", self.live_allowed)
        _require_bool("safe_to_demo_auto_order", self.safe_to_demo_auto_order)
        if self.live_allowed or self.safe_to_demo_auto_order:
            raise ValueError("calibration receipts cannot unlock execution")
        if self.schema_version != CALIBRATION_RECEIPT_SCHEMA_VERSION:
            raise ValueError("unsupported calibration receipt schema")

    @property
    def signing_payload(self) -> dict[str, object]:
        payload = self.to_canonical_dict()
        payload.pop("signature")
        return payload

    def sign(self, secret: str | bytes) -> "RiskCalibrationReceipt":
        return replace(
            self,
            signature=_signing_hmac(
                secret=secret,
                domain=_CALIBRATION_HMAC_DOMAIN,
                payload=self.signing_payload,
            ),
        )

    def verify_signature(self, secret: str | bytes) -> bool:
        if not self.signature:
            return False
        expected = _signing_hmac(
            secret=secret,
            domain=_CALIBRATION_HMAC_DOMAIN,
            payload=self.signing_payload,
        )
        return hmac.compare_digest(self.signature, expected)


@dataclass(frozen=True)
class VerifiedRiskContext(CanonicalContract):
    """Sealed risk context plus hashes of every verified input proof."""

    context: RiskContext
    account_id: str
    server: str
    environment: str
    symbol: str
    broker_symbol: str
    mode: str
    account_runtime_identity_sha256: str
    journal_sha256: str
    broker_spec_sha256: str
    health_facts_sha256: str
    health_decision_sha256: str
    permit_id: str
    permit_symbols: tuple[str, ...]
    evaluated_at_utc: datetime
    valid_until_utc: datetime
    risk_state_receipt_sha256: str
    runtime_fact_receipt_sha256: str
    exposure_receipt_sha256: str
    calibration_receipt_sha256: str
    market_guard_decision_sha256: str
    permit_validation_sha256: str
    conversion_sha256: str
    live_allowed: bool = LIVE_ALLOWED
    safe_to_demo_auto_order: bool = SAFE_TO_DEMO_AUTO_ORDER
    schema_version: str = VERIFIED_RISK_CONTEXT_SCHEMA_VERSION
    _seal: InitVar[object | None] = None

    def __post_init__(self, _seal: object | None) -> None:
        if _seal is not _VERIFIED_CONTEXT_SEAL:
            raise TypeError("VerifiedRiskContext can only be created by its factory")
        if type(self.context) is not RiskContext:
            raise TypeError("context must be an exact RiskContext")
        object.__setattr__(self, "account_id", require_text("account_id", self.account_id))
        object.__setattr__(self, "server", require_text("server", self.server))
        environment = require_text("environment", self.environment, upper=True)
        object.__setattr__(self, "environment", environment)
        object.__setattr__(self, "symbol", require_text("symbol", self.symbol, upper=True))
        object.__setattr__(
            self, "broker_symbol", require_text("broker_symbol", self.broker_symbol)
        )
        object.__setattr__(self, "mode", require_text("mode", self.mode, upper=True))
        for name in (
            "account_runtime_identity_sha256",
            "journal_sha256",
            "broker_spec_sha256",
            "health_facts_sha256",
            "health_decision_sha256",
        ):
            object.__setattr__(self, name, require_hash(name, getattr(self, name)))
        object.__setattr__(self, "permit_id", require_text("permit_id", self.permit_id))
        permit_symbols = _normalize_symbols(self.permit_symbols)
        if not permit_symbols:
            raise ValueError("permit_symbols cannot be empty")
        object.__setattr__(self, "permit_symbols", permit_symbols)
        require_utc("evaluated_at_utc", self.evaluated_at_utc)
        require_utc("valid_until_utc", self.valid_until_utc)
        if self.valid_until_utc <= self.evaluated_at_utc:
            raise ValueError("verified context validity window is empty")
        for name in (
            "risk_state_receipt_sha256",
            "runtime_fact_receipt_sha256",
            "exposure_receipt_sha256",
            "calibration_receipt_sha256",
            "market_guard_decision_sha256",
            "permit_validation_sha256",
            "conversion_sha256",
        ):
            object.__setattr__(self, name, require_hash(name, getattr(self, name)))
        _require_bool("live_allowed", self.live_allowed)
        _require_bool("safe_to_demo_auto_order", self.safe_to_demo_auto_order)
        if self.live_allowed or self.safe_to_demo_auto_order:
            raise ValueError("verified contexts cannot unlock execution")
        if self.schema_version != VERIFIED_RISK_CONTEXT_SCHEMA_VERSION:
            raise ValueError("unsupported verified context schema")
        if (
            self.context.account_id != self.account_id
            or self.context.server != self.server
            or self.context.mode != self.mode
            or self.context.evaluated_at != self.evaluated_at_utc
        ):
            raise ValueError("wrapped context does not match verified binding")

    def provenance_metadata(self) -> dict[str, object]:
        """Return canonical non-secret metadata suitable for an intent journal."""

        evaluated_at = self.evaluated_at_utc.isoformat(
            timespec="microseconds"
        ).replace("+00:00", "Z")
        valid_until = self.valid_until_utc.isoformat(
            timespec="microseconds"
        ).replace("+00:00", "Z")

        return {
            "schema_version": self.schema_version,
            "verified_risk_context_sha256": self.content_sha256,
            "account_id": self.account_id,
            "server": self.server,
            "environment": self.environment,
            "symbol": self.symbol,
            "broker_symbol": self.broker_symbol,
            "mode": self.mode,
            "account_runtime_identity_sha256": self.account_runtime_identity_sha256,
            "journal_sha256": self.journal_sha256,
            "broker_spec_sha256": self.broker_spec_sha256,
            "health_facts_sha256": self.health_facts_sha256,
            "health_decision_sha256": self.health_decision_sha256,
            "permit_id": self.permit_id,
            "permit_symbols": self.permit_symbols,
            "evaluated_at_utc": evaluated_at,
            "valid_until_utc": valid_until,
            "risk_state_receipt_sha256": self.risk_state_receipt_sha256,
            "runtime_fact_receipt_sha256": self.runtime_fact_receipt_sha256,
            "exposure_receipt_sha256": self.exposure_receipt_sha256,
            "calibration_receipt_sha256": self.calibration_receipt_sha256,
            "market_guard_decision_sha256": self.market_guard_decision_sha256,
            "permit_validation_sha256": self.permit_validation_sha256,
            "conversion_sha256": self.conversion_sha256,
            "live_allowed": False,
            "safe_to_demo_auto_order": False,
        }


def require_verified_risk_context(
    verified: VerifiedRiskContext,
    *,
    now: datetime,
    expected_account_id: str,
    expected_server: str,
    expected_environment: str,
    expected_mode: str,
    expected_symbol: str,
    expected_broker_symbol: str,
    expected_account_runtime_identity_sha256: str,
    expected_journal_sha256: str,
    broker_spec: BrokerSpec,
    health_facts: RuntimeHealthFacts,
    market_guard_decision: MarketGuardDecision,
    expected_permit_id: str,
) -> RiskContext:
    """Recheck a sealed wrapper at a broker-executable use boundary."""

    if type(verified) is not VerifiedRiskContext:
        raise TypeError("an exact sealed VerifiedRiskContext is required")
    checked_at = require_utc("verified risk context use clock", now)
    account_id = require_text("expected_account_id", expected_account_id)
    server = require_text("expected_server", expected_server)
    environment = require_text("expected_environment", expected_environment, upper=True)
    mode = require_text("expected_mode", expected_mode, upper=True)
    symbol = require_text("expected_symbol", expected_symbol, upper=True)
    broker_symbol = require_text("expected_broker_symbol", expected_broker_symbol)
    identity = require_hash(
        "expected_account_runtime_identity_sha256",
        expected_account_runtime_identity_sha256,
    )
    journal_sha = require_hash("expected_journal_sha256", expected_journal_sha256)
    permit_id = require_text("expected_permit_id", expected_permit_id)
    reasons: list[str] = []
    if checked_at < verified.evaluated_at_utc:
        reasons.append("VERIFIED_RISK_CONTEXT_NOT_YET_VALID")
    if checked_at >= verified.valid_until_utc:
        reasons.append("VERIFIED_RISK_CONTEXT_EXPIRED")
    if (
        verified.account_id != account_id
        or verified.context.account_id != account_id
        or verified.server != server
        or verified.context.server != server
        or verified.environment != environment
        or verified.mode != mode
        or verified.context.mode != mode
        or verified.symbol != symbol
        or verified.broker_symbol != broker_symbol
    ):
        reasons.append("VERIFIED_RISK_CONTEXT_LANE_MISMATCH")
    if verified.account_runtime_identity_sha256 != identity:
        reasons.append("VERIFIED_RISK_CONTEXT_ACCOUNT_IDENTITY_MISMATCH")
    if verified.journal_sha256 != journal_sha:
        reasons.append("VERIFIED_RISK_CONTEXT_JOURNAL_MISMATCH")
    if verified.permit_id != permit_id:
        reasons.append("VERIFIED_RISK_CONTEXT_PERMIT_MISMATCH")
    if symbol not in verified.permit_symbols:
        reasons.append("VERIFIED_RISK_CONTEXT_PERMIT_SYMBOL_MISMATCH")
    broker_spec_hash = getattr(broker_spec, "content_sha256", None)
    if (
        type(broker_spec) is not BrokerSpec
        or not isinstance(broker_spec_hash, str)
        or broker_spec_hash != verified.broker_spec_sha256
        or getattr(broker_spec, "account_id", None) != account_id
        or getattr(broker_spec, "server", None) != server
        or getattr(broker_spec, "environment", None) != environment
        or getattr(broker_spec, "symbol", None) != symbol
        or getattr(broker_spec, "broker_symbol", None) != broker_symbol
    ):
        reasons.append("VERIFIED_RISK_CONTEXT_BROKER_SPEC_MISMATCH")
    if type(health_facts) is not RuntimeHealthFacts:
        reasons.append("VERIFIED_RISK_CONTEXT_HEALTH_FACTS_TYPE_INVALID")
    else:
        health_decision = evaluate_runtime_health(health_facts)
        if (
            health_facts.content_sha256 != verified.health_facts_sha256
            or health_decision.content_sha256 != verified.health_decision_sha256
            or not health_decision.healthy
        ):
            reasons.append("VERIFIED_RISK_CONTEXT_HEALTH_MISMATCH")
    if type(market_guard_decision) is not MarketGuardDecision:
        reasons.append("VERIFIED_RISK_CONTEXT_MARKET_GUARD_TYPE_INVALID")
    elif (
        market_guard_decision.content_sha256
        != verified.market_guard_decision_sha256
        or market_guard_decision.symbol != symbol
        or not market_guard_decision.news_clear
        or not market_guard_decision.rollover_clear
        or not market_guard_decision.feed_fresh
    ):
        reasons.append("VERIFIED_RISK_CONTEXT_MARKET_GUARD_MISMATCH")
    conversion = verified.context.usd_risk_cap_conversion
    conversion_sha = (
        IDENTITY_CONVERSION_SHA256
        if conversion is None
        else conversion.content_sha256
    )
    if conversion_sha != verified.conversion_sha256:
        reasons.append("VERIFIED_RISK_CONTEXT_CONVERSION_MISMATCH")
    elif conversion is not None and (
        conversion.account_id != account_id
        or conversion.server != server
        or getattr(broker_spec, "account_currency", None)
        != conversion.account_currency
        or not 0
        <= (checked_at - conversion.captured_at_utc).total_seconds()
        <= SHORT_LIVED_RECEIPT_MAX_AGE.total_seconds()
    ):
        reasons.append("VERIFIED_RISK_CONTEXT_CONVERSION_MISMATCH")
    elif conversion is None and getattr(broker_spec, "account_currency", None) != "USD":
        reasons.append("VERIFIED_RISK_CONTEXT_CONVERSION_MISSING")
    if reasons:
        raise RiskContextVerificationError(reasons)
    return verified.context


def _receipt_signature_valid(
    receipt: ExposureReceipt | RiskCalibrationReceipt,
    *,
    key_provider: Callable[[str], str | bytes],
) -> bool:
    if not callable(key_provider):
        return False
    try:
        return receipt.verify_signature(key_provider(receipt.key_id))
    except Exception:
        return False


def create_verified_risk_context(
    *,
    risk_state_receipt: RiskStateReceipt,
    runtime_fact_receipt: RuntimeFactReceipt,
    exposure_receipt: ExposureReceipt,
    calibration_receipt: RiskCalibrationReceipt,
    market_guard_decision: MarketGuardDecision,
    permit_validation: PermitValidation,
    usd_risk_cap_conversion: USDRiskCapConversion | None,
    expected_account_id: str,
    expected_server: str,
    expected_environment: str,
    expected_symbol: str,
    expected_broker_symbol: str,
    expected_mode: str,
    expected_permit_symbols: Iterable[str],
    expected_account_runtime_identity_sha256: str,
    expected_broker_spec_sha256: str,
    expected_journal_sha256: str,
    expected_commit_sha: str,
    expected_config_sha256: str,
    expected_model_artifact_sha256: str,
    expected_promotion_evidence_sha256: str,
    expected_calibration_data_window_sha256: str,
    expected_runtime_fact_key_id: str,
    expected_exposure_key_id: str,
    expected_calibration_key_id: str,
    risk_state_key_provider: Callable[[str], str | bytes],
    runtime_fact_key_provider: Callable[[str], str | bytes],
    exposure_key_provider: Callable[[str], str | bytes],
    calibration_key_provider: Callable[[str], str | bytes],
    clock_provider: Callable[[], datetime],
) -> VerifiedRiskContext:
    """Verify all mutable proofs and construct one sub-second risk context."""

    required_types = (
        (risk_state_receipt, RiskStateReceipt, "RISK_STATE_RECEIPT_TYPE_INVALID"),
        (runtime_fact_receipt, RuntimeFactReceipt, "RUNTIME_FACT_RECEIPT_TYPE_INVALID"),
        (exposure_receipt, ExposureReceipt, "EXPOSURE_RECEIPT_TYPE_INVALID"),
        (
            calibration_receipt,
            RiskCalibrationReceipt,
            "CALIBRATION_RECEIPT_TYPE_INVALID",
        ),
        (
            market_guard_decision,
            MarketGuardDecision,
            "MARKET_GUARD_DECISION_TYPE_INVALID",
        ),
        (permit_validation, PermitValidation, "PERMIT_VALIDATION_TYPE_INVALID"),
    )
    type_reasons = [code for value, expected, code in required_types if type(value) is not expected]
    if usd_risk_cap_conversion is not None and type(usd_risk_cap_conversion) is not USDRiskCapConversion:
        type_reasons.append("USD_CONVERSION_TYPE_INVALID")
    if type_reasons:
        raise RiskContextVerificationError(type_reasons)
    if not callable(clock_provider):
        raise RiskContextVerificationError(["TRUSTED_CLOCK_PROVIDER_INVALID"])
    try:
        now = require_utc("trusted clock", clock_provider())
    except Exception as exc:
        raise RiskContextVerificationError(
            ["TRUSTED_CLOCK_PROVIDER_UNAVAILABLE"]
        ) from exc

    account_id = require_text("expected_account_id", expected_account_id)
    server = require_text("expected_server", expected_server)
    environment = require_text("expected_environment", expected_environment, upper=True)
    symbol = require_text("expected_symbol", expected_symbol, upper=True)
    broker_symbol = require_text("expected_broker_symbol", expected_broker_symbol)
    mode = require_text("expected_mode", expected_mode, upper=True)
    if mode not in {"DRY_RUN", "PAPER", "DEMO", "DEMO_AUTO", "LIVE"}:
        raise ValueError("expected_mode is unsupported")
    permit_symbols = _normalize_symbols(expected_permit_symbols)
    identity_sha = require_hash(
        "expected_account_runtime_identity_sha256",
        expected_account_runtime_identity_sha256,
    )
    broker_spec_sha = require_hash(
        "expected_broker_spec_sha256", expected_broker_spec_sha256
    )
    journal_sha = require_hash("expected_journal_sha256", expected_journal_sha256)
    commit_sha = require_hash("expected_commit_sha", expected_commit_sha, minimum_length=7)
    config_sha = require_hash("expected_config_sha256", expected_config_sha256)
    model_sha = require_hash(
        "expected_model_artifact_sha256", expected_model_artifact_sha256
    )
    promotion_sha = require_hash(
        "expected_promotion_evidence_sha256",
        expected_promotion_evidence_sha256,
    )
    data_window_sha = require_hash(
        "expected_calibration_data_window_sha256",
        expected_calibration_data_window_sha256,
    )
    runtime_key_id = require_text(
        "expected_runtime_fact_key_id", expected_runtime_fact_key_id
    )
    exposure_key_id = require_text("expected_exposure_key_id", expected_exposure_key_id)
    calibration_key_id = require_text(
        "expected_calibration_key_id", expected_calibration_key_id
    )
    reasons: list[str] = []

    if not verify_risk_state_receipt(risk_state_receipt, risk_state_key_provider):
        reasons.append("RISK_STATE_SIGNATURE_INVALID")
    risk_age = (now - risk_state_receipt.issued_at_utc).total_seconds()
    if risk_age < 0:
        reasons.append("RISK_STATE_RECEIPT_NOT_YET_VALID")
    elif risk_age > SHORT_LIVED_RECEIPT_MAX_AGE.total_seconds():
        reasons.append("RISK_STATE_RECEIPT_STALE")

    try:
        verify_runtime_fact_receipt(
            runtime_fact_receipt,
            expected_account_id=account_id,
            expected_server=server,
            expected_environment=environment,
            expected_symbol=symbol,
            expected_broker_symbol=broker_symbol,
            expected_account_runtime_identity_sha256=identity_sha,
            expected_broker_spec_sha256=broker_spec_sha,
            expected_journal_sha256=journal_sha,
            expected_key_id=runtime_key_id,
            key_provider=runtime_fact_key_provider,
            clock_provider=lambda: now,
        )
    except RuntimeFactVerificationError as exc:
        reasons.extend(f"RUNTIME_FACT_{code}" for code in exc.reason_codes)
    except Exception:
        reasons.append("RUNTIME_FACT_RECEIPT_INVALID")

    exposure_bindings = (
        exposure_receipt.account_id == account_id,
        exposure_receipt.server == server,
        exposure_receipt.environment == environment,
        exposure_receipt.account_runtime_identity_sha256 == identity_sha,
        exposure_receipt.journal_sha256 == journal_sha,
        exposure_receipt.key_id == exposure_key_id,
    )
    if not all(exposure_bindings):
        reasons.append("EXPOSURE_BINDING_MISMATCH")
    if not _receipt_signature_valid(
        exposure_receipt, key_provider=exposure_key_provider
    ):
        reasons.append("EXPOSURE_SIGNATURE_INVALID")
    if not exposure_receipt.reconciliation_clean:
        reasons.append("EXPOSURE_RECONCILIATION_NOT_CLEAN")
    if not exposure_receipt.observed_at_utc <= now < exposure_receipt.valid_until_utc:
        reasons.append("EXPOSURE_RECEIPT_STALE_OR_FUTURE")
    observed_ids = {
        item.exposure_id
        for item in exposure_receipt.active_orders + exposure_receipt.active_positions
    }
    if len(observed_ids) != (
        exposure_receipt.active_order_count + exposure_receipt.active_position_count
    ):
        reasons.append("EXPOSURE_COUNT_MISMATCH")
    for item in exposure_receipt.active_orders + exposure_receipt.active_positions:
        if item.canonical_symbol == symbol and item.broker_symbol != broker_symbol:
            reasons.append("EXPOSURE_BROKER_SYMBOL_MISMATCH")

    calibration_bindings = (
        calibration_receipt.account_id == account_id,
        calibration_receipt.server == server,
        calibration_receipt.environment == environment,
        calibration_receipt.symbol == symbol,
        calibration_receipt.broker_symbol == broker_symbol,
        calibration_receipt.account_runtime_identity_sha256 == identity_sha,
        calibration_receipt.broker_spec_sha256 == broker_spec_sha,
        calibration_receipt.config_sha256 == config_sha,
        calibration_receipt.data_window_sha256 == data_window_sha,
        calibration_receipt.key_id == calibration_key_id,
    )
    if not all(calibration_bindings):
        reasons.append("CALIBRATION_BINDING_MISMATCH")
    if not _receipt_signature_valid(
        calibration_receipt, key_provider=calibration_key_provider
    ):
        reasons.append("CALIBRATION_SIGNATURE_INVALID")
    if not calibration_receipt.issued_at_utc <= now < calibration_receipt.valid_until_utc:
        reasons.append("CALIBRATION_RECEIPT_STALE_OR_FUTURE")
    if calibration_receipt.session_count < MINIMUM_CALIBRATION_SESSIONS:
        reasons.append("CALIBRATION_SESSIONS_INSUFFICIENT")
    if (
        calibration_receipt.data_window_end_utc
        - calibration_receipt.data_window_start_utc
        < MINIMUM_CALIBRATION_WINDOW
    ):
        reasons.append("CALIBRATION_WINDOW_INSUFFICIENT")
    if calibration_receipt.sample_count < calibration_receipt.session_count:
        reasons.append("CALIBRATION_SAMPLE_COUNT_INVALID")
    if calibration_receipt.p95_spread_points < calibration_receipt.median_spread_points:
        reasons.append("CALIBRATION_PERCENTILES_INVALID")

    guard_age = (now - market_guard_decision.evaluated_at).total_seconds()
    if market_guard_decision.symbol != symbol:
        reasons.append("MARKET_GUARD_SYMBOL_MISMATCH")
    if guard_age < 0:
        reasons.append("MARKET_GUARD_NOT_YET_VALID")
    elif guard_age > SHORT_LIVED_RECEIPT_MAX_AGE.total_seconds():
        reasons.append("MARKET_GUARD_STALE")
    if (
        not market_guard_decision.news_clear
        or not market_guard_decision.rollover_clear
        or not market_guard_decision.feed_fresh
        or market_guard_decision.reason_codes
        or not market_guard_decision.news_feed_signature_hmac_sha256
        or not market_guard_decision.news_provider_name
        or not market_guard_decision.news_signing_key_id
    ):
        reasons.append("MARKET_GUARD_NOT_CLEAR")

    permit_age = (now - permit_validation.checked_at).total_seconds()
    permit_bindings = (
        permit_validation.valid,
        permit_validation.signature_valid,
        permit_validation.binding_valid,
        permit_validation.time_valid,
        not permit_validation.execution_authorized,
        not permit_validation.can_unlock,
        not permit_validation.live_allowed,
        not permit_validation.safe_to_demo_auto_order,
        permit_validation.mode == mode,
        permit_validation.account_alias_sha256 == account_alias_sha256(account_id),
        permit_validation.server == server,
        permit_validation.symbols == permit_symbols,
        permit_validation.commit_sha == commit_sha,
        permit_validation.config_sha256 == config_sha,
        permit_validation.model_artifact_sha256 == model_sha,
        permit_validation.journal_sha256 == journal_sha,
        permit_validation.promotion_evidence_sha256 == promotion_sha,
        permit_validation.issued_at <= permit_validation.checked_at,
        now < permit_validation.expires_at,
    )
    if not all(permit_bindings):
        reasons.append("PERMIT_VALIDATION_BINDING_INVALID")
    if permit_age < 0:
        reasons.append("PERMIT_VALIDATION_NOT_YET_VALID")
    elif permit_age > SHORT_LIVED_RECEIPT_MAX_AGE.total_seconds():
        reasons.append("PERMIT_VALIDATION_STALE")

    spec = runtime_fact_receipt.broker_spec
    account_fact = runtime_fact_receipt.account_fact
    risk_bindings = (
        risk_state_receipt.binding.account_id_sha256
        == account_alias_sha256(account_id),
        risk_state_receipt.binding.server == server,
        risk_state_receipt.binding.environment == environment,
        risk_state_receipt.binding.journal_sha256 == journal_sha,
        risk_state_receipt.binding.broker_spec_sha256 == spec.content_sha256,
        risk_state_receipt.binding.account_currency == account_fact.currency,
        spec.account_id == account_id,
        spec.server == server,
        spec.environment == environment,
        spec.symbol == symbol,
        spec.broker_symbol == broker_symbol,
        spec.content_sha256 == broker_spec_sha,
    )
    if not all(risk_bindings):
        reasons.append("RISK_STATE_BINDING_MISMATCH")
    if risk_state_receipt.current_equity != account_fact.equity:
        reasons.append("RISK_STATE_RUNTIME_EQUITY_MISMATCH")
    if not runtime_fact_receipt.health_decision.healthy:
        reasons.append("RUNTIME_HEALTH_NOT_HEALTHY")

    if usd_risk_cap_conversion is None:
        if account_fact.currency != "USD":
            reasons.append("USD_CONVERSION_MISSING")
        conversion_sha256 = IDENTITY_CONVERSION_SHA256
        conversion_valid_until = now + SHORT_LIVED_RECEIPT_MAX_AGE
    else:
        conversion_age = (
            now - usd_risk_cap_conversion.captured_at_utc
        ).total_seconds()
        if (
            usd_risk_cap_conversion.account_id != account_id
            or usd_risk_cap_conversion.server != server
            or usd_risk_cap_conversion.account_currency != account_fact.currency
        ):
            reasons.append("USD_CONVERSION_BINDING_MISMATCH")
        if conversion_age < 0:
            reasons.append("USD_CONVERSION_NOT_YET_VALID")
        elif conversion_age > SHORT_LIVED_RECEIPT_MAX_AGE.total_seconds():
            reasons.append("USD_CONVERSION_STALE")
        conversion_sha256 = usd_risk_cap_conversion.content_sha256
        conversion_valid_until = (
            usd_risk_cap_conversion.captured_at_utc + SHORT_LIVED_RECEIPT_MAX_AGE
        )

    if reasons:
        raise RiskContextVerificationError(reasons)

    spread_points = (runtime_fact_receipt.tick.ask - runtime_fact_receipt.tick.bid) / spec.point
    open_exposure_count = (
        exposure_receipt.active_order_count + exposure_receipt.active_position_count
    )
    context = RiskContext(
        evaluated_at=now,
        mode=mode,
        account_id=account_id,
        server=server,
        equity=risk_state_receipt.current_equity,
        daily_start_equity=risk_state_receipt.daily_baseline_equity,
        weekly_start_equity=risk_state_receipt.weekly_baseline_equity,
        high_water_equity=risk_state_receipt.high_water_equity,
        daily_pnl_cash=(
            risk_state_receipt.current_equity
            - risk_state_receipt.daily_baseline_equity
        ),
        weekly_pnl_cash=(
            risk_state_receipt.current_equity
            - risk_state_receipt.weekly_baseline_equity
        ),
        open_position_count=open_exposure_count,
        entries_today=risk_state_receipt.entries_today,
        consecutive_losses=risk_state_receipt.consecutive_losses,
        loss_latch_active=risk_state_receipt.loss_latch_active,
        reserved_symbols=exposure_receipt.reserved_canonical_symbols,
        current_spread_points=spread_points,
        median_spread_points=calibration_receipt.median_spread_points,
        p95_spread_points=calibration_receipt.p95_spread_points,
        estimated_slippage_points=calibration_receipt.p95_slippage_points,
        p95_slippage_points=calibration_receipt.p95_slippage_points,
        news_clear=market_guard_decision.news_clear,
        rollover_clear=market_guard_decision.rollover_clear,
        data_fresh=True,
        source_aligned=True,
        permit_valid=True,
        usd_risk_cap_conversion=usd_risk_cap_conversion,
    )
    valid_until = min(
        risk_state_receipt.issued_at_utc + SHORT_LIVED_RECEIPT_MAX_AGE,
        runtime_fact_receipt.valid_until_utc,
        exposure_receipt.valid_until_utc,
        calibration_receipt.valid_until_utc,
        market_guard_decision.evaluated_at + SHORT_LIVED_RECEIPT_MAX_AGE,
        permit_validation.expires_at,
        permit_validation.checked_at + SHORT_LIVED_RECEIPT_MAX_AGE,
        conversion_valid_until,
    )
    if valid_until <= now:
        raise RiskContextVerificationError(["VERIFIED_CONTEXT_WINDOW_EMPTY"])
    return VerifiedRiskContext(
        context=context,
        account_id=account_id,
        server=server,
        environment=environment,
        symbol=symbol,
        broker_symbol=broker_symbol,
        mode=mode,
        account_runtime_identity_sha256=identity_sha,
        journal_sha256=journal_sha,
        broker_spec_sha256=broker_spec_sha,
        health_facts_sha256=runtime_fact_receipt.health_facts_sha256,
        health_decision_sha256=runtime_fact_receipt.health_decision_sha256,
        permit_id=permit_validation.permit_id,
        permit_symbols=permit_validation.symbols,
        evaluated_at_utc=now,
        valid_until_utc=valid_until,
        risk_state_receipt_sha256=risk_state_receipt.content_sha256,
        runtime_fact_receipt_sha256=runtime_fact_receipt.content_sha256,
        exposure_receipt_sha256=exposure_receipt.content_sha256,
        calibration_receipt_sha256=calibration_receipt.content_sha256,
        market_guard_decision_sha256=market_guard_decision.content_sha256,
        permit_validation_sha256=permit_validation.content_sha256,
        conversion_sha256=conversion_sha256,
        _seal=_VERIFIED_CONTEXT_SEAL,
    )


__all__ = [
    "BrokerExposure",
    "CALIBRATION_RECEIPT_SCHEMA_VERSION",
    "EXPOSURE_RECEIPT_SCHEMA_VERSION",
    "ExposureReceipt",
    "LIVE_ALLOWED",
    "MINIMUM_CALIBRATION_SESSIONS",
    "RiskCalibrationReceipt",
    "RiskContextVerificationError",
    "SAFE_TO_DEMO_AUTO_ORDER",
    "VERIFIED_RISK_CONTEXT_SCHEMA_VERSION",
    "VerifiedRiskContext",
    "create_verified_risk_context",
    "require_verified_risk_context",
]
