"""Symbol-aware strategy and validation profiles.

The profiles normalize decisions by ATR instead of absolute price.  They do
not grant execution permission; execution_policy.py remains authoritative.
"""

from __future__ import annotations

from dataclasses import dataclass, replace


RUNTIME_ALLOWED_STRATEGIES = frozenset(
    {"BREAKOUT", "MEAN_REVERSION", "MOMENTUM_PULLBACK"}
)


@dataclass(frozen=True)
class StrategyProfile:
    asset_class: str
    allowed_strategies: frozenset[str]
    preferred_strategy: str
    min_strategy_score: int
    breakout_buffer_atr: float
    pullback_touch_atr: float
    min_breakout_adx: float
    min_momentum_adx: float
    max_mean_reversion_adx: float
    max_atr_ratio: float
    estimated_round_trip_cost_bps: float
    stop_atr: float
    target_atr: float
    max_holding_bars: int


FX_PROFILE = StrategyProfile(
    asset_class="FOREX",
    allowed_strategies=RUNTIME_ALLOWED_STRATEGIES,
    preferred_strategy="BREAKOUT",
    min_strategy_score=4,
    breakout_buffer_atr=0.08,
    pullback_touch_atr=0.15,
    min_breakout_adx=20.0,
    min_momentum_adx=20.0,
    max_mean_reversion_adx=18.0,
    max_atr_ratio=1.80,
    estimated_round_trip_cost_bps=0.80,
    stop_atr=1.50,
    target_atr=3.00,
    max_holding_bars=32,
)


CRYPTO_PROFILE = replace(
    FX_PROFILE,
    asset_class="CRYPTO",
    allowed_strategies=frozenset({"BREAKOUT", "MOMENTUM_PULLBACK"}),
    preferred_strategy="BREAKOUT",
    min_strategy_score=5,
    breakout_buffer_atr=0.15,
    pullback_touch_atr=0.20,
    min_breakout_adx=22.0,
    min_momentum_adx=22.0,
    max_atr_ratio=1.60,
    estimated_round_trip_cost_bps=5.00,
    stop_atr=1.75,
    target_atr=3.50,
    max_holding_bars=24,
)


# Challenger baseline: preserve the six-hour M15 wall-clock horizon while
# leaving ATR-normalized decision thresholds unchanged for an honest cadence
# comparison. It is shadow-only and must be validated before any promotion.
CRYPTO_M5_CHALLENGER_PROFILE = replace(
    CRYPTO_PROFILE,
    max_holding_bars=72,
)


SYMBOL_PROFILES = {
    "XAUUSD": replace(
        FX_PROFILE,
        asset_class="METAL_GOLD",
        allowed_strategies=frozenset({"BREAKOUT", "MOMENTUM_PULLBACK"}),
        preferred_strategy="MOMENTUM_PULLBACK",
        min_strategy_score=5,
        breakout_buffer_atr=0.12,
        pullback_touch_atr=0.20,
        min_breakout_adx=22.0,
        min_momentum_adx=22.0,
        max_atr_ratio=1.70,
        estimated_round_trip_cost_bps=1.20,
    ),
    "XAGUSD": replace(
        FX_PROFILE,
        asset_class="METAL_SILVER",
        allowed_strategies=frozenset({"BREAKOUT", "MOMENTUM_PULLBACK"}),
        preferred_strategy="BREAKOUT",
        min_strategy_score=5,
        breakout_buffer_atr=0.15,
        pullback_touch_atr=0.20,
        min_breakout_adx=22.0,
        min_momentum_adx=22.0,
        max_atr_ratio=1.65,
        estimated_round_trip_cost_bps=2.00,
    ),
    "USOIL": replace(
        FX_PROFILE,
        asset_class="ENERGY",
        allowed_strategies=frozenset({"BREAKOUT", "MOMENTUM_PULLBACK"}),
        preferred_strategy="BREAKOUT",
        min_strategy_score=5,
        breakout_buffer_atr=0.15,
        pullback_touch_atr=0.20,
        min_breakout_adx=22.0,
        min_momentum_adx=22.0,
        max_atr_ratio=1.65,
        estimated_round_trip_cost_bps=2.00,
    ),
    "BTCUSD": CRYPTO_PROFILE,
    "ETHUSD": CRYPTO_PROFILE,
}


def normalize_symbol(symbol: object) -> str:
    return str(symbol or "UNKNOWN").strip().upper() or "UNKNOWN"


def get_strategy_profile(
    symbol: object,
    *,
    timeframe: object = "M15",
) -> StrategyProfile:
    """Return an explicit symbol profile, falling back to normalized FX."""

    canonical_symbol = normalize_symbol(symbol)
    normalized_timeframe = str(timeframe or "").strip().upper()
    if normalized_timeframe not in {"M5", "M15"}:
        raise ValueError("strategy timeframe must be M5 or M15")
    profile = SYMBOL_PROFILES.get(canonical_symbol, FX_PROFILE)
    if normalized_timeframe == "M5":
        if profile.asset_class != "CRYPTO":
            raise ValueError("M5 challenger profile is restricted to crypto")
        return CRYPTO_M5_CHALLENGER_PROFILE
    return profile
