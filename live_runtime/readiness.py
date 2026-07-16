"""Strict per-lane evidence gates for AI_SCALPER live-grade review."""

from __future__ import annotations

import math
import re
from dataclasses import InitVar, dataclass
from typing import Iterable

from .contracts import CanonicalContract, require_hash


MIN_OOS_TRADES = 100
MIN_FORWARD_TRADES = 50
MIN_FORWARD_WEEKS = 8.0
MIN_POSITIVE_ROLLING_FOLDS = 3
MIN_TOTAL_ROLLING_FOLDS = 5
MIN_OOS_PROFIT_FACTOR = 1.20
MIN_FORWARD_PROFIT_FACTOR = 1.15
MAX_VALIDATION_DRAWDOWN_PERCENT = 8.0

LIVE_ALLOWED = False
SAFE_TO_DEMO_AUTO_ORDER = False
PROMOTION_ELIGIBLE = False
MAX_LOT = 0.01
SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
_LANE_READINESS_SEAL = object()


def _require_text(value: object, field: str) -> str:
    if type(value) is not str or not value.strip():
        raise ValueError(f"{field} must be a non-empty string")
    return value.strip()


def _require_bool(value: object, field: str) -> bool:
    if type(value) is not bool:
        raise ValueError(f"{field} must be a bool")
    return value


def _require_nonnegative_int(value: object, field: str) -> int:
    if type(value) is not int:
        raise ValueError(f"{field} must be an int")
    if value < 0:
        raise ValueError(f"{field} cannot be negative")
    return value


def _finite(value: object, field: str) -> float:
    if type(value) is bool:
        raise ValueError(f"{field} must be numeric")
    try:
        numeric = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{field} must be numeric") from exc
    if not math.isfinite(numeric):
        raise ValueError(f"{field} must be finite")
    return numeric


@dataclass(frozen=True)
class LaneEvidence(CanonicalContract):
    symbol: str
    strategy: str
    config_sha256: str
    oos_closed_trades: int
    broker_forward_closed_trades: int
    broker_forward_weeks: float
    positive_rolling_folds: int
    total_rolling_folds: int
    oos_profit_factor: float
    broker_forward_profit_factor: float
    cost_adjusted_expectancy_ci95_low: float
    max_validation_drawdown_percent: float
    stressed_cost_1_5x_expectancy: float
    stressed_cost_2x_expectancy: float
    deterministic_runtime_parity_percent: float
    immutable_snapshot_verified: bool
    forward_contract_verified: bool
    broker_source_aligned: bool
    ruleset_drift_detected: bool

    def __post_init__(self) -> None:
        symbol = _require_text(self.symbol, "symbol").upper()
        strategy = _require_text(self.strategy, "strategy").upper()
        config_sha256 = _require_text(self.config_sha256, "config_sha256")
        if SHA256_RE.fullmatch(config_sha256) is None:
            raise ValueError("config_sha256 must be a 64-character SHA-256 hex digest")
        object.__setattr__(self, "symbol", symbol)
        object.__setattr__(self, "strategy", strategy)
        object.__setattr__(self, "config_sha256", config_sha256.lower())

        for field in (
            "oos_closed_trades",
            "broker_forward_closed_trades",
            "positive_rolling_folds",
            "total_rolling_folds",
        ):
            _require_nonnegative_int(getattr(self, field), field)
        if self.positive_rolling_folds > self.total_rolling_folds:
            raise ValueError("positive_rolling_folds cannot exceed total_rolling_folds")

        for field in (
            "broker_forward_weeks",
            "oos_profit_factor",
            "broker_forward_profit_factor",
            "cost_adjusted_expectancy_ci95_low",
            "max_validation_drawdown_percent",
            "stressed_cost_1_5x_expectancy",
            "stressed_cost_2x_expectancy",
            "deterministic_runtime_parity_percent",
        ):
            object.__setattr__(self, field, _finite(getattr(self, field), field))

        if self.broker_forward_weeks < 0.0:
            raise ValueError("broker_forward_weeks cannot be negative")
        if self.oos_profit_factor < 0.0:
            raise ValueError("oos_profit_factor cannot be negative")
        if self.broker_forward_profit_factor < 0.0:
            raise ValueError("broker_forward_profit_factor cannot be negative")
        if not 0.0 <= self.max_validation_drawdown_percent <= 100.0:
            raise ValueError("max_validation_drawdown_percent must be between 0 and 100")
        if not 0.0 <= self.deterministic_runtime_parity_percent <= 100.0:
            raise ValueError("deterministic_runtime_parity_percent must be between 0 and 100")

        for field in (
            "immutable_snapshot_verified",
            "forward_contract_verified",
            "broker_source_aligned",
            "ruleset_drift_detected",
        ):
            _require_bool(getattr(self, field), field)


@dataclass(frozen=True)
class LaneReadiness(CanonicalContract):
    lane_id: str
    evidence_sha256: str
    evidence_complete: bool
    status: str
    failures: tuple[str, ...]
    diagnostics: tuple[str, ...] = ()
    manual_ship_gate_required: bool = True
    live_allowed: bool = LIVE_ALLOWED
    safe_to_demo_auto_order: bool = SAFE_TO_DEMO_AUTO_ORDER
    promotion_eligible: bool = PROMOTION_ELIGIBLE
    max_lot: float = MAX_LOT
    _seal: InitVar[object | None] = None

    def __post_init__(self, _seal: object | None) -> None:
        if _seal is not _LANE_READINESS_SEAL:
            raise TypeError("LaneReadiness can only be created by evaluate_lane")
        _require_text(self.lane_id, "lane_id")
        object.__setattr__(
            self,
            "evidence_sha256",
            require_hash("evidence_sha256", self.evidence_sha256),
        )
        _require_text(self.status, "status")
        for field in (
            "evidence_complete",
            "manual_ship_gate_required",
            "live_allowed",
            "safe_to_demo_auto_order",
            "promotion_eligible",
        ):
            _require_bool(getattr(self, field), field)
        if type(self.failures) is not tuple or any(
            type(item) is not str or not item for item in self.failures
        ):
            raise ValueError("failures must be a tuple of non-empty strings")
        if len(set(self.failures)) != len(self.failures):
            raise ValueError("failures cannot contain duplicate reason codes")
        if type(self.diagnostics) is not tuple or any(
            type(item) is not str or not item for item in self.diagnostics
        ):
            raise ValueError("diagnostics must be a tuple of non-empty strings")
        if len(set(self.diagnostics)) != len(self.diagnostics):
            raise ValueError("diagnostics cannot contain duplicate reason codes")

        max_lot = _finite(self.max_lot, "max_lot")
        object.__setattr__(self, "max_lot", max_lot)
        if (
            not self.manual_ship_gate_required
            or self.live_allowed
            or self.safe_to_demo_auto_order
            or self.promotion_eligible
            or max_lot != MAX_LOT
        ):
            raise ValueError("readiness safety locks cannot be overridden")
        expected_status = (
            "EVIDENCE_COMPLETE_MANUAL_SHIP_GATE_REQUIRED"
            if self.evidence_complete
            else "VALIDATION_HOLD"
        )
        if self.status != expected_status:
            raise ValueError("status is inconsistent with evidence_complete")
        if self.evidence_complete == bool(self.failures):
            raise ValueError("failures are inconsistent with evidence_complete")


def evaluate_lane(evidence: LaneEvidence) -> LaneReadiness:
    if type(evidence) is not LaneEvidence:
        raise TypeError("evidence must be LaneEvidence")
    checks = (
        (evidence.oos_closed_trades >= MIN_OOS_TRADES, "INSUFFICIENT_OOS_TRADES"),
        (
            evidence.broker_forward_closed_trades >= MIN_FORWARD_TRADES,
            "INSUFFICIENT_BROKER_FORWARD_TRADES",
        ),
        (
            evidence.broker_forward_weeks >= MIN_FORWARD_WEEKS,
            "INSUFFICIENT_BROKER_FORWARD_DURATION",
        ),
        (
            evidence.total_rolling_folds == MIN_TOTAL_ROLLING_FOLDS,
            "INSUFFICIENT_ROLLING_FOLDS",
        ),
        (
            evidence.positive_rolling_folds >= MIN_POSITIVE_ROLLING_FOLDS,
            "ROLLING_STABILITY_FAILED",
        ),
        (evidence.oos_profit_factor >= MIN_OOS_PROFIT_FACTOR, "OOS_PF_BELOW_1_20"),
        (
            evidence.broker_forward_profit_factor >= MIN_FORWARD_PROFIT_FACTOR,
            "FORWARD_PF_BELOW_1_15",
        ),
        (
            evidence.cost_adjusted_expectancy_ci95_low > 0.0,
            "EXPECTANCY_CI95_LOW_NOT_POSITIVE",
        ),
        (
            evidence.max_validation_drawdown_percent <= MAX_VALIDATION_DRAWDOWN_PERCENT,
            "VALIDATION_DRAWDOWN_ABOVE_8_PERCENT",
        ),
        (
            evidence.stressed_cost_1_5x_expectancy > 0.0,
            "COST_STRESS_1_5X_NOT_POSITIVE",
        ),
        (
            evidence.deterministic_runtime_parity_percent == 100.0,
            "FULL_RUNTIME_PARITY_NOT_100_PERCENT",
        ),
        (evidence.immutable_snapshot_verified, "IMMUTABLE_SNAPSHOT_UNVERIFIED"),
        (evidence.forward_contract_verified, "FORWARD_CONTRACT_UNVERIFIED"),
        (evidence.broker_source_aligned, "BROKER_SOURCE_NOT_ALIGNED"),
        (not evidence.ruleset_drift_detected, "RULESET_DRIFT_DETECTED"),
    )
    failures = tuple(reason for passed, reason in checks if not passed)
    diagnostics = (
        ("COST_STRESS_2X_NOT_POSITIVE_DIAGNOSTIC",)
        if evidence.stressed_cost_2x_expectancy <= 0.0
        else ()
    )
    evidence_complete = not failures
    status = (
        "EVIDENCE_COMPLETE_MANUAL_SHIP_GATE_REQUIRED"
        if evidence_complete
        else "VALIDATION_HOLD"
    )
    return LaneReadiness(
        lane_id=f"{evidence.symbol}:{evidence.strategy}:{evidence.config_sha256}",
        evidence_sha256=evidence.content_sha256,
        evidence_complete=evidence_complete,
        status=status,
        failures=failures,
        diagnostics=diagnostics,
        _seal=_LANE_READINESS_SEAL,
    )


def evaluate_portfolio(lanes: Iterable[LaneEvidence]) -> dict:
    results = [evaluate_lane(lane) for lane in lanes]
    lane_ids = [result.lane_id for result in results]
    if len(lane_ids) != len(set(lane_ids)):
        raise ValueError("portfolio cannot contain duplicate lanes")
    return {
        "status": (
            "ALL_LANES_EVIDENCE_COMPLETE_MANUAL_SHIP_GATE_REQUIRED"
            if results and all(item.evidence_complete for item in results)
            else "PORTFOLIO_VALIDATION_HOLD"
        ),
        "lanes": results,
        "live_allowed": False,
        "safe_to_demo_auto_order": False,
        "promotion_eligible": False,
        "max_lot": MAX_LOT,
    }
