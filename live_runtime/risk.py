"""Deterministic, fail-closed risk governor for execution intents.

This module performs no broker I/O and grants no live/demo execution rights.
It only calculates a bounded lot size and records every failed safety gate.
"""

from __future__ import annotations

from dataclasses import InitVar, dataclass
from datetime import datetime
from decimal import Decimal, ROUND_FLOOR
import math
from typing import Iterable

import execution_policy

from .contracts import (
    BrokerSpec,
    CanonicalContract,
    TradeIntent,
    require_currency,
    require_finite,
    require_hash,
    require_int,
    require_text,
    require_utc,
)


GLOBAL_MAX_LOT = 0.01
RISK_PERCENT_CAP = 0.0025
XAU_ABSOLUTE_RISK_CAP = 0.20
FX_ABSOLUTE_RISK_CAP = 0.25
MAX_OPEN_POSITIONS = 1
MAX_ENTRIES_PER_DAY = 4
DAILY_LOSS_LIMIT = 0.01
WEEKLY_LOSS_LIMIT = 0.025
DRAWDOWN_LIMIT = 0.05
LOSS_LATCH_COUNT = 2
MAX_MARGIN_FRACTION = 0.10
SPREAD_MEDIAN_MULTIPLIER = 1.5
MAX_SLIPPAGE_STOP_FRACTION = 0.10

# Hard policy locks.  No risk result or promotion permit may override these.
LIVE_ALLOWED = False
SAFE_TO_DEMO_AUTO_ORDER = False
_RISK_DECISION_SEAL = object()
_USD_RISK_CAP_CONVERSION_SEAL = object()
MAX_RISK_CONVERSION_AGE_SECONDS = 1.0
IDENTITY_CONVERSION_SHA256 = "0" * 64


def _require_bool(name: str, value: object) -> bool:
    if type(value) is not bool:
        raise TypeError(f"{name} must be bool")
    return value


def _normalize_symbols(symbols: Iterable[str]) -> tuple[str, ...]:
    normalized = tuple(
        sorted(require_text("reserved symbol", item, upper=True) for item in symbols)
    )
    if len(normalized) != len(set(normalized)):
        raise ValueError("reserved_symbols cannot contain duplicates")
    return normalized


def _currency(value: object, field: str = "account_currency") -> str:
    return require_currency(field, value)


@dataclass(frozen=True)
class USDRiskCapConversion(CanonicalContract):
    """Sealed broker fact expressing account-currency units per one USD."""

    account_id: str
    server: str
    account_currency: str
    account_currency_per_usd: float
    source: str
    broker_symbol: str
    direction: str
    bid: float
    ask: float
    captured_at_utc: datetime
    _seal: InitVar[object | None] = None

    def __post_init__(self, _seal: object | None) -> None:
        if _seal is not _USD_RISK_CAP_CONVERSION_SEAL:
            raise TypeError(
                "USDRiskCapConversion can only be created from broker facts"
            )
        account_id = require_text("account_id", self.account_id)
        server = require_text("server", self.server)
        currency = _currency(self.account_currency)
        rate = require_finite(
            "account_currency_per_usd",
            self.account_currency_per_usd,
            positive=True,
        )
        source = require_text("source", self.source, upper=True)
        direction = require_text("direction", self.direction, upper=True)
        broker_symbol = require_text("broker_symbol", self.broker_symbol)
        bid = require_finite("bid", self.bid, positive=True)
        ask = require_finite("ask", self.ask, positive=True)
        if ask < bid:
            raise ValueError("conversion ask cannot be below bid")
        require_utc("captured_at_utc", self.captured_at_utc)

        if currency == "USD":
            if (
                source != "ACCOUNT_CURRENCY_IDENTITY"
                or direction != "IDENTITY"
                or broker_symbol != "USD"
                or rate != 1.0
                or bid != 1.0
                or ask != 1.0
            ):
                raise ValueError("USD conversion must be exact identity")
        else:
            if source != "MT5_BID_ASK":
                raise ValueError("non-USD conversion must use MT5 bid/ask")
            if direction not in {"DIRECT", "INVERSE"}:
                raise ValueError("non-USD conversion direction is invalid")
            expected_rate = bid if direction == "DIRECT" else 1.0 / ask
            if not math.isclose(rate, expected_rate, rel_tol=0.0, abs_tol=1e-15):
                raise ValueError("conversion rate does not match conservative quote side")

        object.__setattr__(self, "account_id", account_id)
        object.__setattr__(self, "server", server)
        object.__setattr__(self, "account_currency", currency)
        object.__setattr__(self, "account_currency_per_usd", rate)
        object.__setattr__(self, "source", source)
        object.__setattr__(self, "broker_symbol", broker_symbol)
        object.__setattr__(self, "direction", direction)
        object.__setattr__(self, "bid", bid)
        object.__setattr__(self, "ask", ask)


def _mint_usd_risk_cap_conversion(
    *,
    account_id: str,
    server: str,
    account_currency: str,
    account_currency_per_usd: float,
    source: str,
    broker_symbol: str,
    direction: str,
    bid: float,
    ask: float,
    captured_at_utc: datetime,
) -> USDRiskCapConversion:
    """Internal mint used only after an adapter has validated broker facts."""

    return USDRiskCapConversion(
        account_id=account_id,
        server=server,
        account_currency=account_currency,
        account_currency_per_usd=account_currency_per_usd,
        source=source,
        broker_symbol=broker_symbol,
        direction=direction,
        bid=bid,
        ask=ask,
        captured_at_utc=captured_at_utc,
        _seal=_USD_RISK_CAP_CONVERSION_SEAL,
    )


@dataclass(frozen=True)
class RiskContext(CanonicalContract):
    """Immutable account and market facts used by one risk evaluation."""

    evaluated_at: datetime
    mode: str
    account_id: str
    server: str
    equity: float
    daily_start_equity: float
    weekly_start_equity: float
    high_water_equity: float
    daily_pnl_cash: float
    weekly_pnl_cash: float
    open_position_count: int
    entries_today: int
    consecutive_losses: int
    loss_latch_active: bool
    reserved_symbols: tuple[str, ...]
    current_spread_points: float
    median_spread_points: float
    p95_spread_points: float
    estimated_slippage_points: float
    p95_slippage_points: float
    news_clear: bool
    rollover_clear: bool
    data_fresh: bool
    source_aligned: bool
    permit_valid: bool
    usd_risk_cap_conversion: USDRiskCapConversion | None = None

    def __post_init__(self) -> None:
        require_utc("evaluated_at", self.evaluated_at)
        mode = require_text("mode", self.mode, upper=True)
        if mode not in {"DRY_RUN", "PAPER", "DEMO", "DEMO_AUTO", "LIVE"}:
            raise ValueError("unsupported execution mode")
        object.__setattr__(self, "mode", mode)
        object.__setattr__(self, "account_id", require_text("account_id", self.account_id))
        object.__setattr__(self, "server", require_text("server", self.server))
        for name in (
            "equity",
            "daily_start_equity",
            "weekly_start_equity",
            "high_water_equity",
        ):
            object.__setattr__(
                self,
                name,
                require_finite(name, getattr(self, name), positive=True),
            )
        if self.high_water_equity < self.equity:
            raise ValueError("high_water_equity cannot be below current equity")
        for name in ("daily_pnl_cash", "weekly_pnl_cash"):
            object.__setattr__(self, name, require_finite(name, getattr(self, name)))
        for name in ("open_position_count", "entries_today", "consecutive_losses"):
            require_int(name, getattr(self, name), minimum=0)
        object.__setattr__(self, "reserved_symbols", _normalize_symbols(self.reserved_symbols))
        for name in (
            "current_spread_points",
            "estimated_slippage_points",
            "p95_slippage_points",
        ):
            object.__setattr__(
                self,
                name,
                require_finite(name, getattr(self, name), nonnegative=True),
            )
        for name in ("median_spread_points", "p95_spread_points"):
            object.__setattr__(
                self,
                name,
                require_finite(name, getattr(self, name), positive=True),
            )
        if self.p95_spread_points < self.median_spread_points:
            raise ValueError("p95_spread_points cannot be below median_spread_points")
        for name in (
            "loss_latch_active",
            "news_clear",
            "rollover_clear",
            "data_fresh",
            "source_aligned",
            "permit_valid",
        ):
            _require_bool(name, getattr(self, name))
        if self.usd_risk_cap_conversion is not None and not isinstance(
            self.usd_risk_cap_conversion,
            USDRiskCapConversion,
        ):
            raise TypeError(
                "usd_risk_cap_conversion must be a sealed USDRiskCapConversion or None"
            )


@dataclass(frozen=True)
class RiskDecision(CanonicalContract):
    """Auditable output from the risk governor."""

    allowed: bool
    reason_codes: tuple[str, ...]
    evaluated_at: datetime
    symbol: str
    max_risk_cash: float
    normalized_lot: float
    estimated_risk_cash: float
    estimated_margin_cash: float
    spread_points: float
    spread_limit_points: float
    spread_p95_points: float
    spread_median_multiple_limit_points: float
    slippage_points: float
    slippage_limit_points: float
    open_position_count: int
    exposure_symbols: tuple[str, ...]
    news_clear: bool
    rollover_clear: bool
    data_fresh: bool
    source_aligned: bool
    account_currency: str
    absolute_risk_cap_usd: float
    usd_to_account_currency_rate: float
    absolute_risk_cap_account_currency: float
    conversion_quote_sha256: str
    _seal: InitVar[object | None] = None

    def __post_init__(self, _seal: object | None) -> None:
        if _seal is not _RISK_DECISION_SEAL:
            raise TypeError("RiskDecision can only be created by evaluate_risk")
        _require_bool("allowed", self.allowed)
        require_utc("evaluated_at", self.evaluated_at)
        object.__setattr__(self, "symbol", require_text("symbol", self.symbol, upper=True))
        reasons = tuple(sorted({require_text("reason code", item, upper=True) for item in self.reason_codes}))
        object.__setattr__(self, "reason_codes", reasons)
        if self.allowed and reasons:
            raise ValueError("an allowed decision cannot contain reason codes")
        if not self.allowed and not reasons:
            raise ValueError("a rejected decision requires at least one reason code")
        for name in (
            "max_risk_cash",
            "normalized_lot",
            "estimated_risk_cash",
            "estimated_margin_cash",
            "spread_points",
            "spread_limit_points",
            "spread_p95_points",
            "spread_median_multiple_limit_points",
            "slippage_points",
            "slippage_limit_points",
        ):
            object.__setattr__(
                self,
                name,
                require_finite(name, getattr(self, name), nonnegative=True),
            )
        if self.normalized_lot > GLOBAL_MAX_LOT:
            raise ValueError("normalized_lot exceeds the global maximum")
        if self.estimated_risk_cash > self.max_risk_cash + 1e-12:
            raise ValueError("estimated_risk_cash exceeds max_risk_cash")
        require_int("open_position_count", self.open_position_count, minimum=0)
        object.__setattr__(
            self,
            "exposure_symbols",
            _normalize_symbols(self.exposure_symbols),
        )
        for name in ("news_clear", "rollover_clear", "data_fresh", "source_aligned"):
            _require_bool(name, getattr(self, name))
        object.__setattr__(
            self,
            "account_currency",
            _currency(self.account_currency),
        )
        object.__setattr__(
            self,
            "absolute_risk_cap_usd",
            require_finite(
                "absolute_risk_cap_usd",
                self.absolute_risk_cap_usd,
                positive=True,
            ),
        )
        object.__setattr__(
            self,
            "usd_to_account_currency_rate",
            require_finite(
                "usd_to_account_currency_rate",
                self.usd_to_account_currency_rate,
                nonnegative=True,
            ),
        )
        object.__setattr__(
            self,
            "absolute_risk_cap_account_currency",
            require_finite(
                "absolute_risk_cap_account_currency",
                self.absolute_risk_cap_account_currency,
                nonnegative=True,
            ),
        )
        object.__setattr__(
            self,
            "conversion_quote_sha256",
            require_hash(
                "conversion_quote_sha256",
                self.conversion_quote_sha256,
            ),
        )

    @property
    def approved(self) -> bool:
        return self.allowed

    @property
    def reasons(self) -> tuple[str, ...]:
        return self.reason_codes

    @property
    def decision_id(self) -> str:
        return f"risk_{self.content_sha256[:32]}"


def _volume_floor(limit: float, broker: BrokerSpec) -> float:
    """Floor a volume to the broker grid without rounding risk upward."""

    limit_d = Decimal(str(min(limit, broker.volume_max, GLOBAL_MAX_LOT)))
    minimum_d = Decimal(str(broker.volume_min))
    step_d = Decimal(str(broker.volume_step))
    if limit_d < minimum_d:
        return 0.0
    steps = ((limit_d - minimum_d) / step_d).to_integral_value(rounding=ROUND_FLOOR)
    result = minimum_d + steps * step_d
    return float(min(result, Decimal(str(GLOBAL_MAX_LOT))))


def _uses_usd(symbol: str) -> bool:
    return "USD" in symbol.upper()


def _is_xau(symbol: str) -> bool:
    normalized = symbol.upper()
    return normalized.startswith("XAU") or "GOLD" in normalized


def absolute_risk_cap_usd(symbol: str) -> float:
    """Return the single policy source for a symbol's USD absolute cap."""

    normalized = require_text("symbol", symbol, upper=True)
    return XAU_ABSOLUTE_RISK_CAP if _is_xau(normalized) else FX_ABSOLUTE_RISK_CAP


def _append(reasons: list[str], condition: bool, code: str) -> None:
    if condition and code not in reasons:
        reasons.append(code)


def _resolve_risk_cap_conversion(
    *,
    broker: BrokerSpec,
    context: RiskContext,
    reasons: list[str],
) -> tuple[float, str]:
    """Return an applied account-currency-per-USD rate and evidence hash."""

    account_currency = _currency(broker.account_currency)
    conversion = context.usd_risk_cap_conversion
    if account_currency == "USD" and conversion is None:
        return 1.0, IDENTITY_CONVERSION_SHA256
    if conversion is None:
        _append(reasons, True, "USD_RISK_CAP_CONVERSION_UNAVAILABLE")
        return 0.0, IDENTITY_CONVERSION_SHA256

    conversion_hash = conversion.content_sha256
    mismatch = (
        conversion.account_id != broker.account_id
        or conversion.server != broker.server
        or conversion.account_currency != account_currency
    )
    if account_currency == "USD":
        mismatch = mismatch or not (
            conversion.source == "ACCOUNT_CURRENCY_IDENTITY"
            and conversion.direction == "IDENTITY"
            and conversion.account_currency_per_usd == 1.0
        )
    else:
        mismatch = mismatch or not (
            conversion.source == "MT5_BID_ASK"
            and conversion.direction in {"DIRECT", "INVERSE"}
        )
    _append(reasons, mismatch, "USD_RISK_CAP_CONVERSION_MISMATCH")

    age = (context.evaluated_at - conversion.captured_at_utc).total_seconds()
    _append(reasons, age < 0, "USD_RISK_CAP_CONVERSION_FUTURE")
    _append(
        reasons,
        age > MAX_RISK_CONVERSION_AGE_SECONDS,
        "USD_RISK_CAP_CONVERSION_STALE",
    )
    if mismatch or age < 0 or age > MAX_RISK_CONVERSION_AGE_SECONDS:
        return 0.0, conversion_hash
    return conversion.account_currency_per_usd, conversion_hash


def evaluate_risk(
    intent: TradeIntent,
    broker: BrokerSpec,
    context: RiskContext,
) -> RiskDecision:
    """Evaluate all safety gates and return a deterministic decision.

    Every execution-sensitive input is supplied explicitly.  Missing or stale
    facts cannot accidentally fall back to permissive defaults because the
    validated ``RiskContext`` requires them.
    """

    if not isinstance(intent, TradeIntent):
        raise TypeError("intent must be a TradeIntent")
    if not isinstance(broker, BrokerSpec):
        raise TypeError("broker must be a BrokerSpec")
    if not isinstance(context, RiskContext):
        raise TypeError("context must be a RiskContext")

    reasons: list[str] = []
    symbol_allowed, _ = execution_policy.validate_execution_symbol(intent.symbol)
    if not symbol_allowed:
        if intent.symbol in execution_policy.EXECUTION_BLOCKED_SYMBOLS:
            reasons.append("SYMBOL_BLOCKED")
        elif intent.symbol in execution_policy.SHADOW_ONLY_SYMBOLS:
            reasons.append("SYMBOL_SHADOW_ONLY")
        else:
            reasons.append("SYMBOL_NOT_EXECUTION_APPROVED")
    _append(reasons, context.mode != intent.mode, "MODE_MISMATCH")
    _append(reasons, intent.mode == "LIVE", "LIVE_MODE_LOCKED")
    _append(reasons, intent.mode == "DEMO_AUTO", "DEMO_AUTO_ORDER_LOCKED")
    _append(reasons, not context.permit_valid, "PERMIT_INVALID")

    account_matches = (
        intent.account_id == broker.account_id == context.account_id
    )
    server_matches = intent.server == broker.server == context.server
    _append(reasons, not account_matches, "ACCOUNT_MISMATCH")
    _append(reasons, not server_matches, "SERVER_MISMATCH")
    _append(reasons, intent.symbol != broker.symbol, "BROKER_SYMBOL_MISMATCH")

    _append(reasons, not context.news_clear, "NEWS_WINDOW_BLOCKED")
    _append(reasons, not context.rollover_clear, "ROLLOVER_WINDOW_BLOCKED")
    _append(
        reasons,
        not context.data_fresh or not intent.decision.data_fresh,
        "DATA_NOT_FRESH",
    )
    _append(
        reasons,
        not context.source_aligned or not intent.decision.source_aligned,
        "SOURCE_NOT_ALIGNED",
    )
    _append(reasons, context.evaluated_at < intent.created_at, "CLOCK_BEFORE_INTENT")
    _append(reasons, context.evaluated_at >= intent.expires_at, "INTENT_EXPIRED")

    _append(
        reasons,
        context.open_position_count >= MAX_OPEN_POSITIONS,
        "GLOBAL_POSITION_LIMIT",
    )
    _append(reasons, context.entries_today >= MAX_ENTRIES_PER_DAY, "DAILY_ENTRY_LIMIT")

    daily_loss = max(
        -context.daily_pnl_cash,
        context.daily_start_equity - context.equity,
    )
    weekly_loss = max(
        -context.weekly_pnl_cash,
        context.weekly_start_equity - context.equity,
    )
    _append(
        reasons,
        daily_loss >= DAILY_LOSS_LIMIT * context.daily_start_equity,
        "DAILY_LOSS_LIMIT",
    )
    _append(
        reasons,
        weekly_loss >= WEEKLY_LOSS_LIMIT * context.weekly_start_equity,
        "WEEKLY_LOSS_LIMIT",
    )
    drawdown = (context.high_water_equity - context.equity) / context.high_water_equity
    _append(reasons, drawdown >= DRAWDOWN_LIMIT, "DRAWDOWN_LIMIT")
    _append(
        reasons,
        context.loss_latch_active or context.consecutive_losses >= LOSS_LATCH_COUNT,
        "LOSS_LATCH_ACTIVE",
    )
    _append(
        reasons,
        _uses_usd(intent.symbol)
        and any(_uses_usd(symbol) for symbol in context.reserved_symbols),
        "USD_CORRELATION_LIMIT",
    )
    _append(reasons, intent.requested_lot > GLOBAL_MAX_LOT, "LOT_ABOVE_GLOBAL_MAX")

    spread_limit = min(
        context.p95_spread_points,
        SPREAD_MEDIAN_MULTIPLIER * context.median_spread_points,
    )
    _append(
        reasons,
        context.current_spread_points >= context.p95_spread_points,
        "SPREAD_ABOVE_P95",
    )
    _append(
        reasons,
        context.current_spread_points
        > SPREAD_MEDIAN_MULTIPLIER * context.median_spread_points,
        "SPREAD_ABOVE_MEDIAN_MULTIPLE",
    )

    stop_points = intent.stop_distance / broker.point
    broker_stop_floor = max(broker.stops_level_points, broker.freeze_level_points)
    _append(
        reasons,
        stop_points < broker_stop_floor,
        "STOP_DISTANCE_BELOW_BROKER_MINIMUM",
    )
    slippage_limit = min(
        context.p95_slippage_points,
        MAX_SLIPPAGE_STOP_FRACTION * stop_points,
    )
    _append(
        reasons,
        context.estimated_slippage_points > slippage_limit,
        "SLIPPAGE_LIMIT",
    )

    absolute_cap_usd = absolute_risk_cap_usd(intent.symbol)
    conversion_rate, conversion_quote_sha256 = _resolve_risk_cap_conversion(
        broker=broker,
        context=context,
        reasons=reasons,
    )
    absolute_cap_account_currency = absolute_cap_usd * conversion_rate
    max_risk_cash = min(
        RISK_PERCENT_CAP * context.equity,
        absolute_cap_account_currency,
    )
    effective_stop_distance = intent.stop_distance + slippage_limit * broker.point
    risk_per_lot = effective_stop_distance / broker.tick_size * broker.tick_value
    if risk_per_lot <= 0:  # Defensive: validated inputs should make this unreachable.
        normalized_lot = 0.0
        estimated_risk = 0.0
        reasons.append("INVALID_RISK_GEOMETRY")
    else:
        risk_limited_lot = max_risk_cash / risk_per_lot
        normalized_lot = _volume_floor(min(intent.requested_lot, risk_limited_lot), broker)
        estimated_risk = normalized_lot * risk_per_lot

    _append(
        reasons,
        normalized_lot < broker.volume_min,
        "RISK_CAP_BELOW_BROKER_MIN_LOT",
    )
    _append(
        reasons,
        normalized_lot > 0
        and abs(normalized_lot - intent.requested_lot) > 1e-12,
        "INTENT_LOT_NOT_RISK_SIZED",
    )
    _append(
        reasons,
        estimated_risk > max_risk_cash + 1e-12,
        "RISK_CAP_EXCEEDED",
    )
    estimated_margin = normalized_lot * broker.margin_per_lot
    _append(
        reasons,
        estimated_margin > MAX_MARGIN_FRACTION * context.equity,
        "MARGIN_LIMIT",
    )

    unique_reasons = tuple(sorted(set(reasons)))
    return RiskDecision(
        allowed=not unique_reasons,
        reason_codes=unique_reasons,
        evaluated_at=context.evaluated_at,
        symbol=intent.symbol,
        max_risk_cash=max_risk_cash,
        normalized_lot=normalized_lot,
        estimated_risk_cash=estimated_risk,
        estimated_margin_cash=estimated_margin,
        spread_points=context.current_spread_points,
        spread_limit_points=spread_limit,
        spread_p95_points=context.p95_spread_points,
        spread_median_multiple_limit_points=(
            SPREAD_MEDIAN_MULTIPLIER * context.median_spread_points
        ),
        slippage_points=context.estimated_slippage_points,
        slippage_limit_points=slippage_limit,
        open_position_count=context.open_position_count,
        exposure_symbols=context.reserved_symbols,
        news_clear=context.news_clear,
        rollover_clear=context.rollover_clear,
        data_fresh=context.data_fresh and intent.decision.data_fresh,
        source_aligned=context.source_aligned and intent.decision.source_aligned,
        account_currency=broker.account_currency,
        absolute_risk_cap_usd=absolute_cap_usd,
        usd_to_account_currency_rate=conversion_rate,
        absolute_risk_cap_account_currency=absolute_cap_account_currency,
        conversion_quote_sha256=conversion_quote_sha256,
        _seal=_RISK_DECISION_SEAL,
    )


class RiskGovernor:
    """Small injectable facade for callers that prefer an object boundary."""

    def evaluate(
        self,
        intent: TradeIntent,
        broker: BrokerSpec,
        context: RiskContext,
    ) -> RiskDecision:
        return evaluate_risk(intent, broker, context)


__all__ = [
    "DAILY_LOSS_LIMIT",
    "DRAWDOWN_LIMIT",
    "FX_ABSOLUTE_RISK_CAP",
    "GLOBAL_MAX_LOT",
    "IDENTITY_CONVERSION_SHA256",
    "LIVE_ALLOWED",
    "LOSS_LATCH_COUNT",
    "MAX_RISK_CONVERSION_AGE_SECONDS",
    "MAX_ENTRIES_PER_DAY",
    "MAX_MARGIN_FRACTION",
    "MAX_OPEN_POSITIONS",
    "MAX_SLIPPAGE_STOP_FRACTION",
    "RISK_PERCENT_CAP",
    "RiskContext",
    "RiskDecision",
    "RiskGovernor",
    "SAFE_TO_DEMO_AUTO_ORDER",
    "SPREAD_MEDIAN_MULTIPLIER",
    "WEEKLY_LOSS_LIMIT",
    "XAU_ABSOLUTE_RISK_CAP",
    "USDRiskCapConversion",
    "_mint_usd_risk_cap_conversion",
    "absolute_risk_cap_usd",
    "evaluate_risk",
]
