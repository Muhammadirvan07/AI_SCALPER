export type Tone = 'positive' | 'warning' | 'negative' | 'info' | 'neutral'

export type GuardStatus =
  | 'ENABLED'
  | 'ACTIVE'
  | 'PRIMARY'
  | 'WEEKEND'
  | 'WATCH'
  | 'BLOCKED'
  | 'RESTRICTED'
  | 'LOCKED'
  | 'DISABLED'
  | 'UNAVAILABLE'

export type DataStatus =
  | 'loading'
  | 'success'
  | 'empty'
  | 'stale'
  | 'disconnected'
  | 'partial'
  | 'error'

export interface DashboardSummary {
  projectName: string
  balanceReference: number
  systemMode: string
  executionMode: string
  qualityStatus: string
  readinessScore: number
  activePairs: number
  closedOrders: number
  closedOrdersTarget: number
  winRate: number
  profitFactor: number
  netProfit: number
  maxDrawdown: number
  liveAllowed: false
  maxLot: 0.01
  safeToDemoObserve: true
  safeToDemoAutoOrder: false
  systemVersion: string
  frontendVersion: string
  updatedAt: string
}

export interface KpiMetric {
  id: string
  label: string
  value: string
  numericValue?: number
  icon:
    | 'mode'
    | 'quality'
    | 'readiness'
    | 'pairs'
    | 'orders'
    | 'winRate'
    | 'profitFactor'
    | 'netProfit'
    | 'drawdown'
  badge: string
  tone: Tone
  description: string
  progress?: {
    value: number
    max: number
    variant: 'bar' | 'ring'
  }
}

export interface EquityPoint {
  session: number
  date: string
  equity: number
  cumulativeProfit: number
  drawdown: number
}

export interface TradeDistribution {
  wins: number
  losses: number
  timeouts: number
}

export interface StrategyPerformance {
  name: string
  shortName: string
  trades: number
  winRate: number
  profitFactor: number
  netResult: number
  guardStatus: GuardStatus
}

export interface PairPerformance {
  symbol: string
  netResult: number
  winRate: number
  signalCount: number
  volatility: 'LOW' | 'NORMAL' | 'ELEVATED' | 'HIGH'
  guardStatus: string
}

export interface ReadinessPoint {
  session: string
  score: number
}

export interface WatchlistItem {
  symbol: string
  assetType: 'Forex' | 'Crypto' | 'Metals' | 'Commodity' | 'Other'
  currentPrice: number
  pricePrecision: number
  priceChange: number
  volatility: 'LOW' | 'NORMAL' | 'ELEVATED' | 'HIGH'
  marketStatus: 'OPEN' | 'CLOSED' | 'UNKNOWN'
  signalBias: 'BUY' | 'SELL' | 'WAIT' | 'BLOCKED'
  strategyScore: number
  guardStatus: string
  lastUpdate: string
  freshness: 'FRESH' | 'STALE'
  tradable: boolean
}

export type NewsImpactLevel = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' | 'UNKNOWN'

export type NewsEventStatus = 'UPCOMING' | 'RELEASED' | 'LIVE_WINDOW' | 'UNKNOWN'

export type NewsSurprise = 'ABOVE' | 'BELOW' | 'INLINE' | 'PENDING' | 'UNKNOWN'

export type PaperDecisionReadiness = 'PAPER_READY' | 'WAIT' | 'BLOCKED' | 'UNAVAILABLE'

export interface MarketNewsEvent {
  id: string
  scheduledAt: string
  title: string
  currency: string
  region: string
  status: NewsEventStatus
  impact: NewsImpactLevel
  actual?: string
  forecast?: string
  previous?: string
  surprise: NewsSurprise
  affectedSymbols: string[]
  summary: string
  source: 'MOCK' | 'API'
  freshness: 'FRESH' | 'STALE'
}

export interface PairNewsImpact {
  id: string
  newsId: string
  symbol: string
  pairStatus: string
  directionBias: 'BULLISH' | 'BEARISH' | 'MIXED' | 'NEUTRAL' | 'UNKNOWN'
  projectedVolatility: 'NORMAL' | 'ELEVATED' | 'HIGH' | 'EXTREME' | 'UNKNOWN'
  spreadRisk: 'NORMAL' | 'WIDE' | 'UNSTABLE' | 'UNKNOWN'
  impactScore: number | null
  decisionScore: number | null
  minimumScore: number | null
  guardStatus: 'PASS' | 'CAUTION' | 'BLOCKED' | 'UNAVAILABLE'
  decision: PaperDecisionReadiness
  effect: string
  requiredObservation: string
}

export interface DashboardNewsSource {
  provider: string
  status: 'FRESH' | 'STALE' | 'PARTIAL' | 'UNAVAILABLE' | 'INVALID'
  lastUpdated: string | null
  note: string
}

export interface DashboardDecisionReadiness {
  ready: boolean
  status: 'READY' | 'WAIT' | 'BLOCKED' | 'UNAVAILABLE'
  symbol: string
  strategy: string
  score: number | null
  minimumRequired: number | null
  blockers: string[]
  gates: {
    dataFreshness: boolean
    news: string
    spread: string
    session: string
  }
  explanation: string
}

export interface SafetyControl {
  id: string
  label: string
  value: string
  status: 'safe' | 'caution' | 'protected' | 'unavailable'
  note?: string
}

export interface SystemSafetyStatus {
  liveAllowed: false
  mode: 'DRY_RUN' | 'PAPER_ONLY'
  maxLot: 0.01
  safeToDemoObserve: true
  safeToDemoAutoOrder: false
  controls: SafetyControl[]
}

export interface DecisionHealthItem {
  label: string
  value: string
  tone: Tone
}

export interface DecisionHealth {
  engineStatus: 'HEALTHY' | 'DEGRADED' | 'OFFLINE' | 'STALE'
  healthScore: number
  lastDecisionTime: string
  dataFreshness: 'FRESH' | 'STALE' | 'MISSING'
  latestCandleAge: string
  activeSymbol: string
  activeStrategy: string
  currentSession: string
  volatilityCondition: string
  readinessStatus: string
  missingDiagnostics: string[]
  checks: DecisionHealthItem[]
}

export type SignalStatus =
  | 'PAPER_OPEN'
  | 'PAPER_CLOSED'
  | 'WAIT'
  | 'BLOCKED'
  | 'REJECTED'
  | 'TIMEOUT'

export interface TradingSignal {
  id: string
  time: string
  symbol: string
  side: 'BUY' | 'SELL' | 'WAIT' | 'BLOCKED'
  strategy: string
  score: number
  status: SignalStatus
  reason: string
  dataFreshness: 'FRESH' | 'STALE'
}

export interface ActivityEvent {
  id: string
  time: string
  title: string
  detail: string
  category: 'data' | 'guard' | 'score' | 'paper' | 'system'
  tone: Tone
}

export interface DashboardSnapshot {
  summary: DashboardSummary
  kpis: KpiMetric[]
  equity: EquityPoint[]
  tradeDistribution: TradeDistribution
  strategies: StrategyPerformance[]
  pairs: PairPerformance[]
  readiness: ReadinessPoint[]
  watchlist: WatchlistItem[]
  marketNews: MarketNewsEvent[]
  pairNewsImpacts: PairNewsImpact[]
  newsSource: DashboardNewsSource
  decisionReadiness: DashboardDecisionReadiness
  safety: SystemSafetyStatus
  decisionHealth: DecisionHealth
  signals: TradingSignal[]
  activity: ActivityEvent[]
}

export interface DashboardDataState {
  status: DataStatus
  data: DashboardSnapshot | null
  error: string | null
  lastSuccessfulUpdate: string | null
}
