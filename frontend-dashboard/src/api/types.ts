export interface ApiMeta {
  source_updated_at: string | null
  server_timestamp: string
  age_seconds: number | null
  stale: boolean
  source_available: boolean
  source: string | null
  request_id: string | null
  data_status: string
  warnings: string[]
}

export interface ApiResponse<T> {
  success: true
  data: T
  meta: ApiMeta
}

export interface ApiErrorResponse {
  success: false
  error: {
    code: string
    message: string
    details?: unknown
  }
  meta?: {
    timestamp?: string
    request_id?: string | null
  }
}

export interface Page<T> {
  items: T[]
  total: number
  limit: number
  offset: number
}

export interface OverviewKpis {
  account_balance: number | null
  equity: number | null
  net_profit: number | null
  win_rate: number | null
  profit_factor: number | null
  expectancy: number | null
  maximum_drawdown: number | null
  maximum_drawdown_percent: number | null
  closed_orders: number | null
  open_positions: number | null
  readiness_score: number | null
}

export interface OverviewStatus {
  current_phase: string | null
  quality_status: string
  active_pair: string | null
  active_strategy: string | null
  market_session: string | null
  market_regime: string | null
  current_mode: string
  live_allowed: boolean
  system_summary: string
  last_update: string | null
}

export interface OverviewData {
  kpis: OverviewKpis
  status: OverviewStatus
}

export interface PerformancePoint {
  index: number
  timestamp: string | null
  balance: number
  equity: number
  cumulative_pnl: number
  period_pnl: number
  drawdown: number
  drawdown_percent: number
  order_id: string | null
}

export interface PerformanceData {
  total_orders: number
  closed_orders: number
  open_orders: number
  wins: number
  losses: number
  breakeven: number
  timeouts: number
  win_rate: number | null
  gross_profit: number
  gross_loss: number
  net_profit: number
  profit_factor: number | null
  average_win: number | null
  average_loss: number | null
  expectancy: number | null
  maximum_drawdown: number
  maximum_drawdown_percent: number
  consecutive_wins: number
  consecutive_losses: number
  starting_balance: number
  ending_balance: number
  curve: PerformancePoint[]
}

export type Timeframe = 'M1' | 'M5' | 'M15' | 'M30' | 'H1' | 'H4' | 'D1'
export type PerformanceRange = '1d' | '7d' | '30d' | '3m' | 'all'

export interface MarketCandle {
  timestamp: string
  open: number
  high: number
  low: number
  close: number
  volume: number
  spread: number | null
}

export interface CandleSeries {
  symbol: string
  requested_timeframe: Timeframe
  actual_timeframe: string
  derived: boolean
  candles: MarketCandle[]
  resolution_warning: string | null
}

export interface MarketQuote {
  symbol: string
  bid: number | null
  ask: number | null
  last: number | null
  spread: number | null
  change: number | null
  change_percent: number | null
  timestamp: string | null
  source_kind: string
}

export interface MarketIndicators {
  symbol: string
  timeframe: string
  ema20: number | null
  ema50: number | null
  atr14: number | null
  adx14: number | null
  volatility: number | null
  trend: string
  market_regime: string
}

export interface MarketStatus {
  symbol: string
  market_status: string
  quote_source: string
  trend: string
  regime: string
  stale: boolean
  last_update: string | null
}

export interface WatchlistItem {
  symbol: string
  bid: number | null
  ask: number | null
  last_price: number | null
  spread: number | null
  change: number | null
  change_percent: number | null
  trend: string
  volatility: number | null
  atr: number | null
  adx: number | null
  strategy: string | null
  strategy_score: number | null
  signal: string | null
  quality_status: string
  blocked: boolean
  last_update: string | null
  stale: boolean
}

export type SignalStatus =
  | 'WAIT'
  | 'APPROVED'
  | 'PAPER_OPEN'
  | 'CLOSED'
  | 'BLOCKED'
  | 'REJECTED'
  | 'EXPIRED'
  | 'SKIPPED'
  | 'UNKNOWN'

export interface TradingSignal {
  signal_id: string
  timestamp: string | null
  symbol: string | null
  side: string | null
  strategy: string | null
  original_score: number | null
  adaptive_score: number | null
  confidence: number | null
  entry: number | null
  stop_loss: number | null
  take_profit: number | null
  risk_reward_ratio: number | null
  calculated_lot: number | null
  risk_percent: number | null
  status: SignalStatus
  reason: string | null
  blocking_reasons: string[]
  quality_guard: string | null
  pair_guard: string | null
  session_guard: string | null
  expiry: string | null
  source: string
  mode: string
}

export interface PaperOrder {
  order_id: string
  signal_id: string | null
  symbol: string | null
  side: string | null
  strategy: string | null
  entry: number | null
  exit: number | null
  stop_loss: number | null
  take_profit: number | null
  lot: number | null
  open_time: string | null
  close_time: string | null
  duration_seconds: number | null
  pnl: number | null
  pnl_percent: number | null
  r_multiple: number | null
  exit_reason: string | null
  result: string | null
  status: string
  mode: string
  source: string | null
}

export interface DiagnosticsData {
  final_decision: string
  selected_strategy: string | null
  strategy_score: number | null
  confidence: number | null
  score_components: Record<string, unknown>
  score_boost: Record<string, unknown>
  missing_components: string[]
  positive_reasons: string[]
  negative_reasons: string[]
  blocking_reasons: string[]
  market_regime: string | null
  volatility_state: string | null
  session_status: string | null
  pair_rotation_status: string | null
  quality_guard_status: string | null
  strategy_guard_status: string | null
  post_loss_cooldown: string | null
  recovery_lane: string | null
  readiness_score: number | null
  current_recommendation: string | null
  source: string
  updated_at: string | null
  economic_calendar: import('../types/economicCalendar').EconomicCalendarDiagnosticContext | null
}

export interface RiskData {
  account_balance: number | null
  base_risk_percent: number | null
  adaptive_risk_percent: number | null
  risk_profile: string
  calculated_lot: number | null
  engine_max_lot: number | null
  backend_safety_max_lot: number
  effective_max_lot: number
  guard_applied: boolean
  stop_distance: number | null
  target_distance: number | null
  risk_reward_ratio: number | null
  daily_drawdown: number | null
  maximum_drawdown: number | null
  consecutive_losses: number
  cooldown_status: string
  recovery_status: string
  live_allowed: boolean
  live_execution_status: string
  risk_guard_status: string
  warnings: string[]
}

export interface QualityData {
  current_phase: string | null
  quality_status: string
  readiness_status: string
  readiness_score: number | null
  closed_samples: number | null
  required_samples: number | null
  progress_percent: number | null
  win_rate_requirement: number | null
  profit_factor_requirement: number | null
  expectancy_requirement: number | null
  drawdown_requirement: number | null
  current_blockers: string[]
  missing_tests: string[]
  recommendations: string[]
  safe_to_observe: boolean
  safe_to_demo_auto_order: boolean
  safe_to_live_trade: boolean
}

export interface SystemStatusData {
  status: string
  mode: string
  live_allowed: boolean
  uptime_seconds: number
  version: string
  environment: string
  ai_scalper_root_available: boolean
  data_directory_available: boolean
  file_watcher_status: string
  websocket_status: string
  last_successful_read: string | null
  error_count: number
  components: Record<string, string>
  ai_advisory: AIAdvisoryStatusData
}

export interface AIAdvisoryStatusData {
  requested: boolean
  effective_mode: 'DISABLED' | 'BLOCKED_EVIDENCE' | 'OPENAI_ADVISORY' | 'FALLBACK_DETERMINISTIC' | 'BLOCKED_CONFIGURATION'
  model: string
  credential_configured: boolean
  deterministic_fallback_enabled: boolean
  news_ready: boolean
  economic_calendar_ready: boolean
  blockers: string[]
  advisory_only: true
  execution_scope: 'PAPER_ONLY'
  live_allowed: false
  order_capability: 'DISABLED'
}

export interface SystemComponent {
  name: string
  status: string
  last_heartbeat: string | null
  last_successful_update: string | null
  latest_error: string | null
  stale: boolean
  source_file: string | null
  connections?: number
}

export interface ActivityEvent {
  id: string
  timestamp: string
  type: string
  severity: 'info' | 'success' | 'warning' | 'error' | 'critical' | string
  component: string
  title: string
  message: string
  metadata: Record<string, unknown>
}

export interface LogEntry {
  id: string
  timestamp: string
  level: string
  component: string
  message: string
}

export type ResourceStatus = 'idle' | 'loading' | 'success' | 'error'

export interface ResourceState<T> {
  data: T | null
  meta: ApiMeta | null
  status: ResourceStatus
  error: import('./client').ApiClientError | null
}
