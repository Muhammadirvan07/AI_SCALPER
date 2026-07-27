export type ApiSourceState = 'fresh' | 'stale' | 'partial' | 'unavailable' | 'invalid'
export type RealtimeTransportState =
  | 'connecting'
  | 'connected'
  | 'reconnecting'
  | 'polling'
  | 'disconnected'

export type DashboardSourceMode =
  | 'REALTIME'
  | 'REST POLLING'
  | 'STALE'
  | 'DISCONNECTED'
  | 'MOCK FALLBACK'

export interface ApiSourceMeta {
  key: string
  path: string | null
  status: ApiSourceState
  source_timestamp: string | null
  received_at: string
  age_seconds: number | null
  stale: boolean
  size_bytes: number | null
  from_last_known_good: boolean
  error: string | null
}

export interface ApiCandle {
  timestamp: string
  open: number
  high: number
  low: number
  close: number
  volume: number
}

export interface ApiMarketSeries {
  symbol: string
  timeframe: string | null
  candles: ApiCandle[]
  latest_price: number | null
  price_change_percent: number | null
  volatility_percent: number | null
  source_timestamp: string | null
  received_at: string
  age_seconds: number | null
  stale: boolean
  freshness_threshold_seconds: number
  status: ApiSourceState
  source_path: string | null
}

export interface ApiSignal {
  id: string
  timestamp: string | null
  symbol: string | null
  side: string | null
  strategy: string | null
  score: number | null
  adjusted_score: number | null
  status: string | null
  reason: string | null
  price: number | null
  sl: number | null
  tp: number | null
  lot: number | null
  source: string
  data_freshness: ApiSourceState
  raw_guard_status: string | null
}

export interface ApiPaperOrder {
  order_id: string
  signal_id: string | null
  symbol: string | null
  side: string | null
  strategy: string | null
  open_time: string | null
  close_time: string | null
  open_price: number | null
  close_price: number | null
  sl: number | null
  tp: number | null
  lot: number | null
  pnl: number | null
  r_multiple: number | null
  status: string | null
  close_reason: string | null
  duration_seconds: number | null
  source: string | null
}

export interface ApiWatchlistItem {
  symbol: string
  asset_type: string
  latest_price: number | null
  price_change_percent: number | null
  volatility_percent: number | null
  market_status: string
  signal_bias: string | null
  strategy_score: number | null
  guard_status: string
  source_timestamp: string | null
  received_at: string
  age_seconds: number | null
  stale: boolean
  freshness_threshold_seconds: number
  status: ApiSourceState
}

export interface ApiGuard {
  key: string
  label: string
  enabled: boolean | null
  status: string
  reason: string | null
  source: string | null
}

export interface ApiPairRotation {
  symbol: string
  role: string
  status: string
  reason: string | null
  confidence: number | null
}

export interface ApiStrategy {
  strategy: string
  status: string
  minimum_score: number | null
  quality_score: number | null
  reason: string | null
  performance: Record<string, unknown>
}

export interface ApiExecutionStage {
  index: number
  key: string
  label: string
  state: 'COMPLETE' | 'ACTIVE' | 'WAITING' | 'BLOCKED' | 'UNKNOWN'
  result: string | null
  timestamp: string | null
}

export interface ApiDecisionReadiness {
  decision_ready: boolean
  decision_status: 'READY' | 'WAIT' | 'BLOCKED' | 'UNAVAILABLE'
  evaluated_at: string
  symbol: string | null
  strategy: string | null
  score: number | null
  minimum_required: number | null
  data_freshness_pass: boolean
  news_guard: string
  spread_guard: string
  session_guard: string
  blockers: string[]
  source: string | null
  explanation: string
}

export interface ApiNewsEvent {
  id: string
  scheduled_at: string
  title: string
  currency: string | null
  region: string | null
  status: 'UPCOMING' | 'RELEASED' | 'LIVE_WINDOW' | 'UNKNOWN'
  impact: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' | 'UNKNOWN'
  actual: string | null
  forecast: string | null
  previous: string | null
  surprise: 'ABOVE' | 'BELOW' | 'INLINE' | 'PENDING' | 'UNKNOWN'
  affected_symbols: string[]
  summary: string | null
  direction_bias: string | null
  source: string
  source_timestamp: string | null
  received_at: string
  age_seconds: number | null
  stale: boolean
  data_status: ApiSourceState
}

export interface ApiPairNewsImpact {
  id: string
  news_id: string
  symbol: string
  pair_status: string
  direction_bias: 'BULLISH' | 'BEARISH' | 'MIXED' | 'NEUTRAL' | 'UNKNOWN'
  projected_volatility: 'NORMAL' | 'ELEVATED' | 'HIGH' | 'EXTREME' | 'UNKNOWN'
  spread_risk: 'NORMAL' | 'WIDE' | 'UNSTABLE' | 'UNKNOWN'
  impact_score: number | null
  decision_score: number | null
  minimum_score: number | null
  guard_status: 'PASS' | 'CAUTION' | 'BLOCKED' | 'UNAVAILABLE'
  decision: 'PAPER_READY' | 'WAIT' | 'BLOCKED' | 'UNAVAILABLE'
  effect: string
  required_observation: string
  derived: boolean
}

export interface ApiSourceContract {
  source_key: string
  contract_version: string
  declared_schema_version: string | null
  status: 'COMPLIANT' | 'LEGACY' | 'UNAVAILABLE' | 'INVALID'
  compliant: boolean
  missing_fields: string[]
  issues: string[]
}

export interface ApiEvidenceGate {
  key: string
  label: string
  status: 'PASSED' | 'BLOCKED' | 'WAIT' | 'UNVERIFIED'
  passed: boolean | null
  source: string
  reason: string | null
}

export interface ApiProjectProgress {
  stage: string | null
  status: string
  source_status: ApiSourceState
  gates_passed: number | null
  gates_total: number | null
  gates: ApiEvidenceGate[]
  milestones_completed: string[]
  blockers: string[]
  observation_start_at: string | null
  blind_until: string | null
  observation_window_status: string
  expected_complete_sessions: number | null
  promotion_eligible: boolean | null
  promotion_reason: string | null
  sources: string[]
}

export interface ApiBrokerReadiness {
  candidate_id: string
  display_name: string
  role: string | null
  environment: string | null
  server: string | null
  account_type: string | null
  account_currency: string | null
  leverage: string | null
  symbols_found: Record<string, string>
  discovery: string
  regulatory_evidence: string
  calendar_review: string
  contract_registration: string
  shadow_runtime: string
  demo_auto_order_eligibility: string
  live_eligibility: string
  promotion_eligible: boolean | null
  observation_start_at: string | null
  blind_until: string | null
  expected_complete_sessions: number | null
  source_status: ApiSourceState
  sources: string[]
}

export interface DashboardApiSnapshot {
  schema_version: '1.2'
  snapshot_id: string
  version: number
  generated_at: string
  source_updated_at: string | null
  connection: {
    status: 'connected' | 'stale' | 'partial' | 'disconnected'
    mode: 'realtime_file_watch'
    latency_ms: number
    stale: boolean
    watcher_running: boolean
    snapshot_version: number
    stale_source_count: number
  }
  safety: {
    live_allowed: false
    live_trading: 'LOCKED'
    display_status: string
    mode: 'DRY_RUN_SIMULATOR' | 'PAPER'
    paper_trading: 'ACTIVE'
    max_lot: 0.01
    safe_to_demo_observe: true
    safe_to_demo_auto_order: false
    demo_auto_order: 'OUT_OF_SCOPE'
    bridge_mode: string | null
    guard_enabled: boolean | null
    order_capability: string | null
    safety_violation: boolean
    violations: string[]
  }
  summary: {
    system_mode: string | null
    quality_status: string | null
    readiness_score: number | null
    active_pairs: string[]
    closed_orders: number | null
    closed_target: number | null
    win_rate: number | null
    profit_factor: number | null
    expectancy: number | null
    net_profit: number | null
    max_drawdown: number | null
    reference_balance: number | null
    max_lot: number
  }
  performance: {
    total_orders: number | null
    closed_orders: number | null
    open_orders: number | null
    wins: number | null
    losses: number | null
    timeouts: number | null
    win_rate: number | null
    gross_profit: number | null
    gross_loss: number | null
    net_profit: number | null
    profit_factor: number | null
    expectancy: number | null
    max_drawdown_percent: number | null
    reference_balance: number | null
    ending_balance: number | null
    equity_curve: Array<{
      index: number
      timestamp: string | null
      equity: number
      cumulative_net_profit: number
      drawdown_percent: number | null
      order_id: string | null
    }>
    by_symbol: Record<string, Record<string, unknown>>
    by_strategy: Record<string, Record<string, unknown>>
  }
  readiness: {
    score?: number | null
    max_score?: number | null
    percent?: number | null
    label?: string | null
    notes?: string[]
    source?: string | null
  }
  market: Record<string, ApiMarketSeries>
  watchlist: ApiWatchlistItem[]
  signals: ApiSignal[]
  paper_orders: ApiPaperOrder[]
  decision_health: {
    engine_status: string
    latest_decision_at: string | null
    current_symbol: string | null
    current_strategy: string | null
    market_regime: string | null
    volatility_percent: number | null
    candle_age_seconds: number | null
    readiness_score: number | null
    readiness_status: string | null
    diagnostics: Record<string, unknown>
    blockers: string[]
    latest_reason: string | null
    source_status: ApiSourceState
  }
  decision_readiness: ApiDecisionReadiness
  session: {
    current_session: string | null
    day_type: 'WEEKDAY' | 'WEEKEND' | null
    market_open_status: string
    active_test_mode: string | null
    session_start: string | null
    progress: Record<string, unknown>
    last_activity: string | null
  }
  guards: ApiGuard[]
  pair_rotation: ApiPairRotation[]
  strategies: ApiStrategy[]
  execution_cycle: ApiExecutionStage[]
  decision_state_distribution: Record<string, number>
  scoring: Record<string, unknown>
  regime: Record<string, unknown>
  analytics: Record<string, unknown>
  news: {
    provider: string | null
    source_status: ApiSourceState
    last_updated: string | null
    events: ApiNewsEvent[]
    pair_impacts: ApiPairNewsImpact[]
    note: string
  }
  source_contracts: Record<string, ApiSourceContract>
  project_progress: ApiProjectProgress
  broker_readiness: ApiBrokerReadiness[]
  activity: Array<{
    timestamp: string
    category: string
    title: string
    detail: string | null
    source: string | null
  }>
  sources: Record<string, ApiSourceMeta>
  warnings: string[]
}

export interface DashboardWebSocketEvent {
  type:
    | 'connection.ready'
    | 'snapshot.full'
    | 'snapshot.updated'
    | 'market.updated'
    | 'signal.created'
    | 'signal.updated'
    | 'paper_order.updated'
    | 'decision_health.updated'
    | 'session.updated'
    | 'news.updated'
    | 'source.stale'
    | 'source.recovered'
    | 'safety.warning'
    | 'heartbeat'
    | 'error'
  version: number
  timestamp: string
  payload: unknown
}

export interface RealtimeConnectionInfo {
  transportState: RealtimeTransportState
  sourceMode: DashboardSourceMode
  lastEventAt: string | null
  lastHeartbeatAt: string | null
  lastSourceUpdateAt: string | null
  latencyMs: number | null
  snapshotVersion: number
  staleSourceCount: number
  socketActive: boolean
  reconnectAttempt: number
}
