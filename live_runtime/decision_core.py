"""Pure, mode-agnostic decision core and thin runtime snapshot adapter.

Replay, shadow, demo, and live callers must provide the same finalized M15
bars and the first eligible broker quote.  This module performs no file,
clock, network, broker, permit, or execution-policy I/O.  Strategy thresholds
remain owned by :mod:`strategy.strategy_selector` and
:mod:`strategy.strategy_profiles`.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Mapping

import pandas as pd

from agents.market_status import classify_market
from agents.supervisor_agent import SupervisorAgent
from strategy.strategy_profiles import get_strategy_profile, normalize_symbol
from strategy.strategy_selector import MIN_REQUIRED_ROWS, select_best_strategy

from .contracts import (
    ENTRY_WINDOW_SECONDS,
    CanonicalContract,
    DecisionSnapshot,
    _mint_decision_snapshot,
    require_finite,
    require_hash,
    require_int,
    require_text,
    require_utc,
)


DECISION_CORE_VERSION = "decision-core-v1"
M15_SECONDS = 15 * 60
_TIMESTAMP_COLUMNS = ("Datetime", "open_time_utc")
_OHLC_COLUMNS = ("Open", "High", "Low", "Close")


def _normalize_score_components(
    raw_components: object,
    expected_score: int,
) -> tuple[tuple[str, int], ...]:
    if not isinstance(raw_components, Mapping):
        raise TypeError("selector score_components must be a mapping")
    normalized: list[tuple[str, int]] = []
    seen: set[str] = set()
    for raw_name, raw_component in raw_components.items():
        name = require_text("score component name", raw_name)
        if name in seen:
            raise ValueError(f"duplicate score component: {name}")
        if isinstance(raw_component, Mapping):
            passed = raw_component.get("passed") is True
            raw_points = raw_component.get("points", 0) if passed else 0
        else:
            raw_points = raw_component
        points = require_int(f"score component {name}", raw_points, minimum=0)
        normalized.append((name, points))
        seen.add(name)
    components = tuple(sorted(normalized))
    if sum(points for _, points in components) != expected_score:
        raise ValueError("selector score does not match structured components")
    return components


@dataclass(frozen=True)
class DecisionCoreResult(CanonicalContract):
    """Deterministic strategy result before mode-specific risk or execution."""

    symbol: str
    selector_signal: str
    action: str
    strategy: str
    score: int
    score_components: tuple[tuple[str, int], ...]
    market_regime: str
    market_status: str
    volatility_percent: float
    decision_price: float | None
    atr: float | None
    reasons: tuple[str, ...]
    core_version: str = DECISION_CORE_VERSION

    def __post_init__(self) -> None:
        object.__setattr__(self, "symbol", require_text("symbol", self.symbol, upper=True))
        selector_signal = require_text(
            "selector_signal",
            self.selector_signal,
            upper=True,
        )
        if selector_signal not in {"BUY", "SELL", "SIDEWAYS", "WAIT"}:
            raise ValueError("selector_signal is unsupported")
        object.__setattr__(self, "selector_signal", selector_signal)
        action = require_text("action", self.action, upper=True)
        if action not in {"BUY", "SELL", "WAIT"}:
            raise ValueError("action is unsupported")
        if action in {"BUY", "SELL"} and action != selector_signal:
            raise ValueError("trade action must preserve selector direction")
        object.__setattr__(self, "action", action)
        object.__setattr__(
            self,
            "strategy",
            require_text("strategy", self.strategy, upper=True),
        )
        require_int("score", self.score, minimum=0)
        normalized_components: list[tuple[str, int]] = []
        seen_components: set[str] = set()
        for component in self.score_components:
            if not isinstance(component, tuple) or len(component) != 2:
                raise TypeError("score_components must contain name/point tuples")
            name = require_text("score component name", component[0])
            if name in seen_components:
                raise ValueError(f"duplicate score component: {name}")
            points = require_int(
                f"score component {name}",
                component[1],
                minimum=0,
            )
            normalized_components.append((name, points))
            seen_components.add(name)
        components = tuple(sorted(normalized_components))
        if sum(points for _, points in components) != self.score:
            raise ValueError("score must equal structured score components")
        object.__setattr__(self, "score_components", components)
        object.__setattr__(
            self,
            "market_regime",
            require_text("market_regime", self.market_regime, upper=True),
        )
        market_status = require_text("market_status", self.market_status, upper=True)
        if market_status not in {"HIGH", "NORMAL", "LOW", "NOT_EVALUATED"}:
            raise ValueError("market_status is unsupported")
        object.__setattr__(self, "market_status", market_status)
        object.__setattr__(
            self,
            "volatility_percent",
            require_finite(
                "volatility_percent",
                self.volatility_percent,
                nonnegative=True,
            ),
        )
        if self.decision_price is not None:
            object.__setattr__(
                self,
                "decision_price",
                require_finite("decision_price", self.decision_price, positive=True),
            )
        if self.atr is not None:
            object.__setattr__(
                self,
                "atr",
                require_finite("atr", self.atr, positive=True),
            )
        if action in {"BUY", "SELL"} and (
            self.decision_price is None or self.atr is None
        ):
            raise ValueError("trade actions require finite decision price and ATR")
        object.__setattr__(
            self,
            "reasons",
            tuple(str(reason) for reason in self.reasons),
        )
        if self.core_version != DECISION_CORE_VERSION:
            raise ValueError("decision core version mismatch")


@dataclass(frozen=True)
class DecisionProvenance(CanonicalContract):
    """Explicit immutable provenance supplied equally by every mode adapter."""

    decision_run_id: str
    model_version: str
    model_artifact_sha256: str
    commit_sha: str
    config_sha256: str
    data_sha256: str
    source_name: str
    source_aligned: bool
    data_fresh: bool
    bar_closed_at: datetime
    created_at: datetime

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "decision_run_id",
            require_text("decision_run_id", self.decision_run_id),
        )
        object.__setattr__(
            self,
            "model_version",
            require_text("model_version", self.model_version),
        )
        for field, minimum_length in (
            ("model_artifact_sha256", 64),
            ("commit_sha", 7),
            ("config_sha256", 64),
            ("data_sha256", 64),
        ):
            object.__setattr__(
                self,
                field,
                require_hash(field, getattr(self, field), minimum_length=minimum_length),
            )
        object.__setattr__(
            self,
            "source_name",
            require_text("source_name", self.source_name),
        )
        if type(self.source_aligned) is not bool or type(self.data_fresh) is not bool:
            raise TypeError("source_aligned and data_fresh must be bool")
        require_utc("bar_closed_at", self.bar_closed_at)
        require_utc("created_at", self.created_at)
        if pd.Timestamp(self.bar_closed_at).value % (M15_SECONDS * 1_000_000_000):
            raise ValueError("bar_closed_at must align to an M15 boundary")
        if not self.bar_closed_at < self.created_at <= self.bar_closed_at + timedelta(
            seconds=ENTRY_WINDOW_SECONDS
        ):
            raise ValueError("created_at is outside the first-tick entry window")


@dataclass(frozen=True)
class FirstEligibleQuote(CanonicalContract):
    """First broker tick eligible after the finalized candle boundary."""

    bid: float
    ask: float
    observed_at: datetime

    def __post_init__(self) -> None:
        object.__setattr__(self, "bid", require_finite("bid", self.bid, positive=True))
        object.__setattr__(self, "ask", require_finite("ask", self.ask, positive=True))
        if self.ask < self.bid:
            raise ValueError("ask cannot be below bid")
        require_utc("observed_at", self.observed_at)


def _selector_frame(finalized_bars: pd.DataFrame) -> pd.DataFrame:
    if not isinstance(finalized_bars, pd.DataFrame):
        raise TypeError("finalized_bars must be a pandas DataFrame")
    missing = [column for column in _OHLC_COLUMNS if column not in finalized_bars]
    if missing:
        raise ValueError(f"finalized bars are missing OHLC columns: {missing}")
    # Removing timestamps is deliberate: the legacy selector otherwise asks
    # the wall clock whether a candle is complete.  Completion is proven by the
    # strict snapshot adapter, so the pure core must not read current time.
    return finalized_bars.loc[:, _OHLC_COLUMNS].copy()


def evaluate_decision_core(
    finalized_bars: pd.DataFrame,
    symbol: str,
) -> DecisionCoreResult:
    """Evaluate existing selector, volatility, and supervisor semantics purely."""

    core, _ = _evaluate_decision_core_selection(finalized_bars, symbol)
    return core


def _evaluate_decision_core_selection(
    finalized_bars: pd.DataFrame,
    symbol: str,
) -> tuple[DecisionCoreResult, Mapping[str, object]]:
    canonical_symbol = normalize_symbol(symbol)
    selection = select_best_strategy(
        _selector_frame(finalized_bars),
        symbol=canonical_symbol,
    )
    signal = str(selection.get("signal", "SIDEWAYS") or "SIDEWAYS").upper()
    score = require_int("selector score", selection.get("score", 0), minimum=0)
    components = _normalize_score_components(
        selection.get("score_components", {}),
        score,
    )
    raw_context = selection.get("decision_context", {})
    context = dict(raw_context) if isinstance(raw_context, Mapping) else {}
    price = context.get("price")
    atr = context.get("atr")
    if price is not None:
        price = require_finite("selector decision price", price, positive=True)
    if atr is not None:
        atr = require_finite("selector ATR", atr, positive=True)
    if price is None or atr is None:
        market_status = "NOT_EVALUATED"
    else:
        market_status = classify_market(atr, price, symbol=canonical_symbol)
    action = (
        "WAIT"
        if market_status == "NOT_EVALUATED"
        else SupervisorAgent().make_decision(signal, market_status)
    )
    core = DecisionCoreResult(
        symbol=canonical_symbol,
        selector_signal=signal,
        action=action,
        strategy=str(selection.get("strategy", "NO_STRATEGY")),
        score=score,
        score_components=components,
        market_regime=str(selection.get("market_regime", "NO_TRADE")),
        market_status=market_status,
        volatility_percent=selection.get("volatility_percent", 0.0),
        decision_price=price,
        atr=atr,
        reasons=tuple(selection.get("reasons", ())),
    )
    return core, selection


def explain_decision_core(
    finalized_bars: pd.DataFrame,
    symbol: str,
) -> dict[str, object]:
    """Expose deterministic diagnostic context without changing the snapshot."""

    core, selection = _evaluate_decision_core_selection(finalized_bars, symbol)
    raw_context = selection.get("decision_context", {})
    context = dict(raw_context) if isinstance(raw_context, Mapping) else {}
    raw_candidates = selection.get("all_strategies", ())
    candidates: list[dict[str, object]] = []
    if isinstance(raw_candidates, (list, tuple)):
        for raw_candidate in raw_candidates:
            if not isinstance(raw_candidate, Mapping):
                continue
            candidates.append(
                {
                    "strategy": str(
                        raw_candidate.get("strategy", "UNKNOWN")
                    ).upper(),
                    "signal": str(
                        raw_candidate.get("signal", "SIDEWAYS")
                    ).upper(),
                    "score": int(raw_candidate.get("score", 0) or 0),
                    "eligible": raw_candidate.get("eligible") is True,
                    "reasons": [
                        str(reason)
                        for reason in raw_candidate.get("reasons", ())
                    ],
                }
            )
    return {
        "schema_version": "decision-explanation-v1",
        "symbol": core.symbol,
        "selector_signal": core.selector_signal,
        "action": core.action,
        "selected_strategy": core.strategy,
        "score": core.score,
        "score_components": dict(core.score_components),
        "market_regime": core.market_regime,
        "market_status": core.market_status,
        "volatility_percent": core.volatility_percent,
        "indicators": {
            "price": context.get("price"),
            "atr": context.get("atr"),
            "adx": context.get("adx"),
            "rsi": context.get("rsi"),
            "atr_ratio": context.get("atr_ratio"),
            "candle_body_ratio": context.get("candle_body_ratio"),
            "regime_confidence": context.get("regime_confidence"),
            "regime_direction": context.get("regime_direction"),
            "regime_trade_allowed": context.get("regime_trade_allowed"),
        },
        "reasons": list(core.reasons),
        "strategy_candidates": candidates,
    }


def _validated_finalized_m15_bars(
    finalized_bars: pd.DataFrame,
    bar_closed_at: datetime,
) -> pd.DataFrame:
    if not isinstance(finalized_bars, pd.DataFrame):
        raise TypeError("finalized_bars must be a pandas DataFrame")
    if len(finalized_bars) < MIN_REQUIRED_ROWS:
        raise ValueError(
            f"not enough finalized M15 bars: {len(finalized_bars)}/{MIN_REQUIRED_ROWS}"
        )
    timestamp_columns = [
        column for column in _TIMESTAMP_COLUMNS if column in finalized_bars.columns
    ]
    if len(timestamp_columns) != 1:
        raise ValueError("finalized bars require exactly one supported UTC timestamp column")
    if "is_final" not in finalized_bars:
        raise ValueError("finalized bars require an is_final proof column")
    if not all(value is True for value in finalized_bars["is_final"].tolist()):
        raise ValueError("every decision bar must be explicitly finalized")

    normalized_timestamps: list[pd.Timestamp] = []
    for raw_timestamp in finalized_bars[timestamp_columns[0]].tolist():
        timestamp = pd.Timestamp(raw_timestamp)
        if timestamp.tzinfo is None or timestamp.utcoffset() is None:
            raise ValueError("decision bar timestamps must be timezone-aware UTC")
        if timestamp.utcoffset().total_seconds() != 0:
            raise ValueError("decision bar timestamps must use UTC")
        timestamp = timestamp.tz_convert("UTC")
        if timestamp.value % (M15_SECONDS * 1_000_000_000):
            raise ValueError("decision bar timestamps must align to M15")
        normalized_timestamps.append(timestamp)
    timestamp_index = pd.DatetimeIndex(normalized_timestamps)
    if timestamp_index.has_duplicates or not timestamp_index.is_monotonic_increasing:
        raise ValueError("decision bar timestamps must be unique and increasing")
    expected_close = timestamp_index[-1].to_pydatetime() + timedelta(
        seconds=M15_SECONDS
    )
    if expected_close != bar_closed_at:
        raise ValueError("latest finalized M15 bar does not match bar_closed_at")
    return _selector_frame(finalized_bars)


def build_decision_snapshot(
    finalized_m15_bars: pd.DataFrame,
    *,
    symbol: str,
    first_eligible_quote: FirstEligibleQuote,
    provenance: DecisionProvenance,
) -> DecisionSnapshot:
    """Build one deterministic snapshot shared by every execution mode."""

    if type(first_eligible_quote) is not FirstEligibleQuote:
        raise TypeError("first_eligible_quote must be FirstEligibleQuote")
    if type(provenance) is not DecisionProvenance:
        raise TypeError("provenance must be DecisionProvenance")
    if first_eligible_quote.observed_at != provenance.created_at:
        raise ValueError("snapshot creation must bind the first eligible quote time")
    selector_bars = _validated_finalized_m15_bars(
        finalized_m15_bars,
        provenance.bar_closed_at,
    )
    core = evaluate_decision_core(selector_bars, symbol)

    entry_reference = None
    stop_loss = None
    take_profit = None
    if core.action in {"BUY", "SELL"}:
        profile = get_strategy_profile(core.symbol)
        direction = 1.0 if core.action == "BUY" else -1.0
        entry_reference = (
            first_eligible_quote.ask
            if core.action == "BUY"
            else first_eligible_quote.bid
        )
        stop_loss = entry_reference - direction * profile.stop_atr * core.atr
        take_profit = entry_reference + direction * profile.target_atr * core.atr

    return _mint_decision_snapshot(
        decision_run_id=provenance.decision_run_id,
        symbol=core.symbol,
        side=core.action,
        strategy=core.strategy,
        score=core.score,
        score_components=core.score_components,
        entry_reference=entry_reference,
        stop_loss=stop_loss,
        take_profit=take_profit,
        model_version=provenance.model_version,
        model_artifact_sha256=provenance.model_artifact_sha256,
        commit_sha=provenance.commit_sha,
        config_sha256=provenance.config_sha256,
        data_sha256=provenance.data_sha256,
        source_name=provenance.source_name,
        source_aligned=provenance.source_aligned,
        data_fresh=provenance.data_fresh,
        bar_closed_at=provenance.bar_closed_at,
        created_at=provenance.created_at,
    )


def build_runtime_decision_snapshot(
    finalized_m15_bars: pd.DataFrame,
    *,
    symbol: str,
    first_eligible_bid: float,
    first_eligible_ask: float,
    first_eligible_tick_at: datetime,
    provenance: DecisionProvenance,
) -> DecisionSnapshot:
    """Thin shadow/demo/live adapter into the shared pure core."""

    return build_decision_snapshot(
        finalized_m15_bars,
        symbol=symbol,
        first_eligible_quote=FirstEligibleQuote(
            bid=first_eligible_bid,
            ask=first_eligible_ask,
            observed_at=first_eligible_tick_at,
        ),
        provenance=provenance,
    )


__all__ = [
    "DECISION_CORE_VERSION",
    "DecisionCoreResult",
    "DecisionProvenance",
    "FirstEligibleQuote",
    "build_decision_snapshot",
    "build_runtime_decision_snapshot",
    "evaluate_decision_core",
    "explain_decision_core",
]
