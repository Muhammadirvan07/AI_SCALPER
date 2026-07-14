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
    "BTCUSD": replace(
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
    ),
}


def normalize_symbol(symbol: object) -> str:
    return str(symbol or "UNKNOWN").strip().upper() or "UNKNOWN"


def get_strategy_profile(symbol: object) -> StrategyProfile:
    """Return an explicit symbol profile, falling back to normalized FX."""

    return SYMBOL_PROFILES.get(normalize_symbol(symbol), FX_PROFILE)
