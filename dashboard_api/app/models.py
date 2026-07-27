from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


SourceState = Literal["fresh", "stale", "partial", "unavailable", "invalid"]
ConnectionStatus = Literal["connected", "stale", "partial", "disconnected"]


class ApiModel(BaseModel):
    model_config = ConfigDict(extra="ignore")


class SourceMeta(ApiModel):
    key: str
    path: str | None = None
    status: SourceState = "unavailable"
    source_timestamp: datetime | None = None
    received_at: datetime
    age_seconds: float | None = None
    stale: bool = False
    size_bytes: int | None = None
    from_last_known_good: bool = False
    error: str | None = None


class ConnectionInfo(ApiModel):
    status: ConnectionStatus
    mode: Literal["realtime_file_watch"] = "realtime_file_watch"
    latency_ms: float = 0
    stale: bool = False
    watcher_running: bool = False
    snapshot_version: int = 0
    stale_source_count: int = 0


class SafetyState(ApiModel):
    live_allowed: Literal[False] = False
    live_trading: Literal["LOCKED"] = "LOCKED"
    display_status: str = "LOCKED"
    mode: Literal["DRY_RUN_SIMULATOR", "PAPER"] = "DRY_RUN_SIMULATOR"
    paper_trading: Literal["ACTIVE"] = "ACTIVE"
    max_lot: Literal[0.01] = 0.01
    safe_to_demo_observe: Literal[True] = True
    safe_to_demo_auto_order: Literal[False] = False
    demo_auto_order: Literal["OUT_OF_SCOPE"] = "OUT_OF_SCOPE"
    bridge_mode: str | None = None
    guard_enabled: bool | None = None
    order_capability: str | None = None
    safety_violation: bool = False
    violations: list[str] = Field(default_factory=list)


class Summary(ApiModel):
    system_mode: str | None = None
    quality_status: str | None = None
    readiness_score: float | None = None
    active_pairs: list[str] = Field(default_factory=list)
    closed_orders: int | None = None
    closed_target: int | None = None
    win_rate: float | None = None
    profit_factor: float | None = None
    expectancy: float | None = None
    net_profit: float | None = None
    max_drawdown: float | None = None
    reference_balance: float | None = None
    max_lot: float = 0.01


class EquityPoint(ApiModel):
    index: int
    timestamp: datetime | None = None
    equity: float
    cumulative_net_profit: float
    drawdown_percent: float | None = None
    order_id: str | None = None


class Performance(ApiModel):
    total_orders: int | None = None
    closed_orders: int | None = None
    open_orders: int | None = None
    wins: int | None = None
    losses: int | None = None
    timeouts: int | None = None
    win_rate: float | None = None
    gross_profit: float | None = None
    gross_loss: float | None = None
    net_profit: float | None = None
    profit_factor: float | None = None
    expectancy: float | None = None
    max_drawdown_percent: float | None = None
    reference_balance: float | None = None
    ending_balance: float | None = None
    equity_curve: list[EquityPoint] = Field(default_factory=list)
    by_symbol: dict[str, dict[str, Any]] = Field(default_factory=dict)
    by_strategy: dict[str, dict[str, Any]] = Field(default_factory=dict)


class NormalizedSignal(ApiModel):
    id: str
    timestamp: datetime | None = None
    symbol: str | None = None
    side: str | None = None
    strategy: str | None = None
    score: float | None = None
    adjusted_score: float | None = None
    status: str | None = None
    reason: str | None = None
    price: float | None = None
    sl: float | None = None
    tp: float | None = None
    lot: float | None = None
    source: str
    data_freshness: SourceState = "unavailable"
    raw_guard_status: str | None = None


class NormalizedPaperOrder(ApiModel):
    order_id: str
    signal_id: str | None = None
    symbol: str | None = None
    side: str | None = None
    strategy: str | None = None
    open_time: datetime | None = None
    close_time: datetime | None = None
    open_price: float | None = None
    close_price: float | None = None
    sl: float | None = None
    tp: float | None = None
    lot: float | None = None
    pnl: float | None = None
    r_multiple: float | None = None
    status: str | None = None
    close_reason: str | None = None
    duration_seconds: float | None = None
    source: str | None = None


class Candle(ApiModel):
    timestamp: datetime
    open: float
    high: float
    low: float
    close: float
    volume: float


class MarketSeries(ApiModel):
    symbol: str
    timeframe: str | None = None
    candles: list[Candle] = Field(default_factory=list)
    latest_price: float | None = None
    price_change_percent: float | None = None
    volatility_percent: float | None = None
    source_timestamp: datetime | None = None
    received_at: datetime
    age_seconds: float | None = None
    stale: bool = False
    freshness_threshold_seconds: float = 180
    status: SourceState = "unavailable"
    source_path: str | None = None


class WatchlistItem(ApiModel):
    symbol: str
    asset_type: str
    latest_price: float | None = None
    price_change_percent: float | None = None
    volatility_percent: float | None = None
    market_status: str = "UNAVAILABLE"
    signal_bias: str | None = None
    strategy_score: float | None = None
    guard_status: str = "UNAVAILABLE"
    source_timestamp: datetime | None = None
    received_at: datetime
    age_seconds: float | None = None
    stale: bool = True
    freshness_threshold_seconds: float = 180
    status: SourceState = "unavailable"


class DecisionHealth(ApiModel):
    engine_status: str = "UNAVAILABLE"
    latest_decision_at: datetime | None = None
    current_symbol: str | None = None
    current_strategy: str | None = None
    market_regime: str | None = None
    volatility_percent: float | None = None
    candle_age_seconds: float | None = None
    readiness_score: float | None = None
    readiness_status: str | None = None
    diagnostics: dict[str, Any] = Field(default_factory=dict)
    blockers: list[str] = Field(default_factory=list)
    latest_reason: str | None = None
    source_status: SourceState = "unavailable"


class DecisionReadiness(ApiModel):
    decision_ready: bool = False
    decision_status: Literal["READY", "WAIT", "BLOCKED", "UNAVAILABLE"] = "UNAVAILABLE"
    evaluated_at: datetime
    symbol: str | None = None
    strategy: str | None = None
    score: float | None = None
    minimum_required: float | None = None
    data_freshness_pass: bool = False
    news_guard: str = "UNAVAILABLE"
    spread_guard: str = "UNAVAILABLE"
    session_guard: str = "UNAVAILABLE"
    blockers: list[str] = Field(default_factory=list)
    source: str | None = None
    explanation: str


class NewsEvent(ApiModel):
    id: str
    scheduled_at: datetime
    title: str
    currency: str | None = None
    region: str | None = None
    status: Literal["UPCOMING", "RELEASED", "LIVE_WINDOW", "UNKNOWN"] = "UNKNOWN"
    impact: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL", "UNKNOWN"] = "UNKNOWN"
    actual: str | None = None
    forecast: str | None = None
    previous: str | None = None
    surprise: Literal["ABOVE", "BELOW", "INLINE", "PENDING", "UNKNOWN"] = "UNKNOWN"
    affected_symbols: list[str] = Field(default_factory=list)
    summary: str | None = None
    direction_bias: str | None = None
    source: str
    source_timestamp: datetime | None = None
    received_at: datetime
    age_seconds: float | None = None
    stale: bool = False
    data_status: SourceState = "unavailable"


class PairNewsImpact(ApiModel):
    id: str
    news_id: str
    symbol: str
    pair_status: str
    direction_bias: Literal["BULLISH", "BEARISH", "MIXED", "NEUTRAL", "UNKNOWN"]
    projected_volatility: Literal[
        "NORMAL",
        "ELEVATED",
        "HIGH",
        "EXTREME",
        "UNKNOWN",
    ]
    spread_risk: Literal["NORMAL", "WIDE", "UNSTABLE", "UNKNOWN"]
    impact_score: float | None = None
    decision_score: float | None = None
    minimum_score: float | None = None
    guard_status: Literal["PASS", "CAUTION", "BLOCKED", "UNAVAILABLE"]
    decision: Literal["PAPER_READY", "WAIT", "BLOCKED", "UNAVAILABLE"]
    effect: str
    required_observation: str
    derived: bool = True


class NewsState(ApiModel):
    provider: str | None = None
    source_status: SourceState = "unavailable"
    last_updated: datetime | None = None
    events: list[NewsEvent] = Field(default_factory=list)
    pair_impacts: list[PairNewsImpact] = Field(default_factory=list)
    note: str


class SourceContractStatus(ApiModel):
    source_key: str
    contract_version: str = "1.0"
    declared_schema_version: str | None = None
    status: Literal["COMPLIANT", "LEGACY", "UNAVAILABLE", "INVALID"]
    compliant: bool = False
    missing_fields: list[str] = Field(default_factory=list)
    issues: list[str] = Field(default_factory=list)


class EvidenceGate(ApiModel):
    key: str
    label: str
    status: Literal["PASSED", "BLOCKED", "WAIT", "UNVERIFIED"]
    passed: bool | None = None
    source: str
    reason: str | None = None


class ProjectProgress(ApiModel):
    stage: str | None = None
    status: str = "UNVERIFIED"
    source_status: SourceState = "unavailable"
    gates_passed: int | None = None
    gates_total: int | None = None
    gates: list[EvidenceGate] = Field(default_factory=list)
    milestones_completed: list[str] = Field(default_factory=list)
    blockers: list[str] = Field(default_factory=list)
    observation_start_at: datetime | None = None
    blind_until: datetime | None = None
    observation_window_status: str = "UNVERIFIED"
    expected_complete_sessions: int | None = None
    promotion_eligible: bool | None = None
    promotion_reason: str | None = None
    sources: list[str] = Field(default_factory=list)


class BrokerReadiness(ApiModel):
    candidate_id: str
    display_name: str
    role: str | None = None
    environment: str | None = None
    server: str | None = None
    account_type: str | None = None
    account_currency: str | None = None
    leverage: str | None = None
    symbols_found: dict[str, str] = Field(default_factory=dict)
    discovery: str = "UNVERIFIED"
    regulatory_evidence: str = "UNVERIFIED"
    calendar_review: str = "UNVERIFIED"
    contract_registration: str = "UNVERIFIED"
    shadow_runtime: str = "UNVERIFIED"
    demo_auto_order_eligibility: str = "BLOCKED"
    live_eligibility: str = "BLOCKED"
    promotion_eligible: bool | None = None
    observation_start_at: datetime | None = None
    blind_until: datetime | None = None
    expected_complete_sessions: int | None = None
    source_status: SourceState = "unavailable"
    sources: list[str] = Field(default_factory=list)


class SessionState(ApiModel):
    current_session: str | None = None
    day_type: Literal["WEEKDAY", "WEEKEND"] | None = None
    market_open_status: str = "UNKNOWN"
    active_test_mode: str | None = None
    session_start: datetime | None = None
    progress: dict[str, Any] = Field(default_factory=dict)
    last_activity: datetime | None = None


class GuardState(ApiModel):
    key: str
    label: str
    enabled: bool | None = None
    status: str = "UNAVAILABLE"
    reason: str | None = None
    source: str | None = None


class PairRotation(ApiModel):
    symbol: str
    role: str
    status: str
    reason: str | None = None
    confidence: float | None = None


class StrategyState(ApiModel):
    strategy: str
    status: str
    minimum_score: float | None = None
    quality_score: float | None = None
    reason: str | None = None
    performance: dict[str, Any] = Field(default_factory=dict)


class ActivityItem(ApiModel):
    timestamp: datetime
    category: str
    title: str
    detail: str | None = None
    source: str | None = None


class ExecutionStage(ApiModel):
    index: int
    key: str
    label: str
    state: Literal["COMPLETE", "ACTIVE", "WAITING", "BLOCKED", "UNKNOWN"]
    result: str | None = None
    timestamp: datetime | None = None


class DashboardSnapshot(ApiModel):
    schema_version: Literal["1.2"] = "1.2"
    snapshot_id: str
    version: int
    generated_at: datetime
    source_updated_at: datetime | None = None
    connection: ConnectionInfo
    safety: SafetyState
    summary: Summary
    performance: Performance
    readiness: dict[str, Any] = Field(default_factory=dict)
    market: dict[str, MarketSeries] = Field(default_factory=dict)
    watchlist: list[WatchlistItem] = Field(default_factory=list)
    signals: list[NormalizedSignal] = Field(default_factory=list)
    paper_orders: list[NormalizedPaperOrder] = Field(default_factory=list)
    decision_health: DecisionHealth
    decision_readiness: DecisionReadiness
    session: SessionState
    guards: list[GuardState] = Field(default_factory=list)
    pair_rotation: list[PairRotation] = Field(default_factory=list)
    strategies: list[StrategyState] = Field(default_factory=list)
    execution_cycle: list[ExecutionStage] = Field(default_factory=list)
    decision_state_distribution: dict[str, int] = Field(default_factory=dict)
    scoring: dict[str, Any] = Field(default_factory=dict)
    regime: dict[str, Any] = Field(default_factory=dict)
    analytics: dict[str, Any] = Field(default_factory=dict)
    news: NewsState
    source_contracts: dict[str, SourceContractStatus] = Field(default_factory=dict)
    project_progress: ProjectProgress
    broker_readiness: list[BrokerReadiness] = Field(default_factory=list)
    activity: list[ActivityItem] = Field(default_factory=list)
    sources: dict[str, SourceMeta] = Field(default_factory=dict)
    warnings: list[str] = Field(default_factory=list)
