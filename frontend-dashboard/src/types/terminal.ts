export type DataFreshnessStatus =
  | 'FRESH'
  | 'STALE'
  | 'PARTIAL'
  | 'DISCONNECTED'
  | 'EMPTY'
  | 'ERROR'

export type TerminalPanelState =
  | 'loading'
  | 'connected'
  | 'stale'
  | 'partial'
  | 'disconnected'
  | 'empty'
  | 'error'

export type TerminalTone = 'safe' | 'positive' | 'caution' | 'warning' | 'blocked' | 'neutral'

export interface TerminalSummary {
  product: string
  edition: string
  subtitle: string
  mode: string
  paperTrading: string
  liveAllowed: false
  liveTrading: 'LOCKED'
  maxLot: 0.01
  safeToObserve: true
  safeToAutoOrder: false
  demoAutoOrder: string
  qualityStatus: string
  systemVersion: string
  dataSource: 'REALTIME' | 'REST POLLING' | 'STALE' | 'DISCONNECTED' | 'MOCK FALLBACK'
}

export interface SystemReadiness {
  score: number
  displayScore: number
  previousScore: number
  delta: number
  status: string
  closedOrders: number
  targetOrders: number
  safeStatus: string
  currentRiskProfile: string
  curve: Array<{
    session: string
    score: number
  }>
}

export interface MarketTicker {
  id: string
  symbol: string
  assetType: 'FOREX' | 'CRYPTO' | 'METALS' | 'COMMODITY' | 'OTHER'
  direction: 'UP' | 'DOWN' | 'FLAT'
  price: number
  precision: number
  changePercent: number
  guardStatus: string
  marketStatus: string
  freshness: DataFreshnessStatus
}

export interface MarketCandle {
  id: string
  timestamp: string
  open: number
  high: number
  low: number
  close: number
  volume: number
}

export interface PaperReferenceLevels {
  entry: number | null
  stopLoss: number | null
  takeProfit: number | null
}

export interface MarketInstrument {
  symbol: string
  quote: string
  precision: number
  latestPrice: number | null
  changePercent: number | null
  open: number | null
  high: number | null
  low: number | null
  spread: number | null
  atr: number | null
  volatilityPercent: number | null
  session: string
  signalBias: 'BUY' | 'SELL' | 'WAIT' | 'BLOCKED'
  strategyScore: number | null
  freshness: DataFreshnessStatus
  selectedTimeframe: 'M5' | 'M15' | 'M30' | 'H1'
  referenceLevels: PaperReferenceLevels
  candles: Partial<Record<'M5' | 'M15' | 'M30' | 'H1', MarketCandle[]>>
}

export interface PaperExecutionStage {
  id: string
  index: number
  label:
    | 'Pindai'
    | 'Deteksi'
    | 'Validasi'
    | 'Penilaian'
    | 'Ukuran'
    | 'Fill Paper'
    | 'Pantau'
    | 'Penyelesaian'
    | 'Tinjauan Kualitas'
  state: 'COMPLETE' | 'ACTIVE' | 'WAITING' | 'BLOCKED' | 'SKIPPED' | 'UNKNOWN'
  durationMs: number | null
  result: string
  timestamp: string
}

export interface RegimeProbabilityPoint {
  time: string
  trend: number
  range: number
  chop: number
  panic: number
  marker?: 'FLIP' | 'CROSS' | 'STABLE' | 'REGIME CHANGE'
}

export interface DecisionLogEntry {
  id: string
  timestamp: string
  pair: string
  side: 'BUY' | 'SELL' | 'WAIT' | 'BLOCKED'
  strategy: string
  score: number
  maximumScore: number
  result: 'PAPER_OPEN' | 'PAPER_CLOSED' | 'WAIT' | 'BLOCKED' | 'REJECTED' | 'TIMEOUT'
  guard: string
  latencyMs: number | null
  paperPnl: number | null
  reason: string
  freshness: DataFreshnessStatus
}

export interface DecisionStateDistribution {
  states: Array<{
    state: 'BUY' | 'SELL' | 'WAIT' | 'BLOCKED' | 'TIMEOUT'
    count: number
    percent: number
  }>
  currentState: 'BUY' | 'SELL' | 'WAIT' | 'BLOCKED' | 'TIMEOUT' | 'UNKNOWN'
  paperOpen: number
  paperClosed: number
  confidence: {
    strategy: number
    guard: number
    data: number
    risk: number
  }
}

export interface ReasoningNode {
  id: string
  label: string
  group: 'left' | 'gate' | 'right'
  latencyMs: number
  passRate: number
  rejectionRate: number
  sampleCount: number
  status: 'PASS' | 'ACTIVE' | 'WAIT'
}

export interface SignalRadarMetric {
  metric: string
  key:
    | 'trendStrength'
    | 'momentum'
    | 'volatility'
    | 'meanReversion'
    | 'breakoutPressure'
    | 'liquidity'
    | 'sessionQuality'
    | 'dataFreshness'
  value: number
  minimumBoundary: number
  maximum: 100
  zone: 'PASS' | 'MARGINAL' | 'BLOCKED'
}

export interface ScoreContribution {
  id: string
  component:
    | 'Keselarasan Tren'
    | 'Momentum'
    | 'Volatilitas'
    | 'Kecocokan Rezim'
    | 'Kualitas Sesi'
    | 'Likuiditas'
    | 'Kesegaran Data'
    | 'Konteks Risiko'
    | 'Cooldown Kerugian'
    | 'Kualitas Strategi'
  rawValue: number
  weight: number
  contribution: number
  result: 'PASS' | 'FAIL' | 'NEUTRAL'
  reason: string
}

export interface RegimeTransition {
  from: 'TREND' | 'RANGE' | 'CHOP' | 'PANIC'
  to: 'TREND' | 'RANGE' | 'CHOP' | 'PANIC'
  probability: number
}

export interface SystemGuard {
  id: string
  label: string
  status: 'ENABLED' | 'ONLINE' | 'LOCKED' | 'OUT OF SCOPE' | 'UNAVAILABLE'
  tone: TerminalTone
  detail: string
}

export interface PairRotationStatus {
  id: string
  symbol: string
  role: 'PRIMARY' | 'WEEKEND PRIMARY' | 'BLOCKED' | 'WATCH'
  activity: string
  reason: string
  confidence: number
}

export interface StrategyGuardStatus {
  id: string
  strategy: string
  status: 'ALLOWED' | 'BLOCKED'
  minimumScore: number
  rule: string
  qualityScore: number
}

export interface EquityPoint {
  session: string
  equity: number
  cumulativeNetProfit: number
  drawdownPercent: number
}

export interface PaperPerformance {
  closedOrders: number
  targetOrders: number
  wins: number
  losses: number
  timeouts: number
  winRate: number
  profitFactor: number
  expectancy: number
  netProfit: number
  maxDrawdown: number
  referenceBalance: number
  averageR: number
  bestStrategy: string
  weakestStrategy: string
  bestPair: string
  blockedPair: string
  equityCurve: EquityPoint[]
}

export interface TerminalRuntime {
  currentSession: string
  activePair: string
  marketStatus: string
  dataFreshness: DataFreshnessStatus
  currentStrategy: string
  sampleProgress: string
  connection: 'ONLINE' | 'OFFLINE' | 'RECONNECTING' | 'DEGRADED'
  pollingLatencyMs: number
  lastSyncTime: string
}

export interface TerminalDashboardData {
  summary: TerminalSummary
  runtime: TerminalRuntime
  readiness: SystemReadiness
  tickers: MarketTicker[]
  instruments: MarketInstrument[]
  executionCycle: PaperExecutionStage[]
  regimeHistory: RegimeProbabilityPoint[]
  regimeCurrent: {
    trend: number | null
    range: number | null
    chop: number | null
    panic: number | null
    classification: string
    confidence: number | null
    projectedRegime: string
  }
  decisionLog: DecisionLogEntry[]
  decisionStates: DecisionStateDistribution
  reasoningNodes: ReasoningNode[]
  signalRadar: SignalRadarMetric[]
  signalSetup: {
    strategy: string
    rawScore: number
    adjustedScore: number
    minimumRequired: number
    decision: string
    label: string
  }
  scoreContributions: ScoreContribution[]
  scoringResult: {
    available: boolean
    rawScore: number
    adaptiveBoost: number
    guardPenalty: number
    finalScore: number
    minimumRequired: number
    action: string
    explanation: string
    rollingScores: number[]
  }
  regimeTransitions: RegimeTransition[]
  transitionSummary: {
    mostLikely: string
    entropy: number
    stability: number
    expectedDuration: string
    confidence: number
    forecast: string
  }
  systemGuards: SystemGuard[]
  healthMetrics: Array<{
    label: string
    value: number
    status: TerminalTone
  }>
  pairRotation: PairRotationStatus[]
  strategyGuards: StrategyGuardStatus[]
  performance: PaperPerformance
}

export interface TerminalDashboardState {
  data: TerminalDashboardData | null
  state: TerminalPanelState
  error: string | null
  isPaused: boolean
  lastSuccessfulUpdate: string | null
}
