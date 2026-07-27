import type {
  ActivityEvent,
  DashboardSnapshot,
  GuardStatus,
  KpiMetric,
  PairPerformance,
  StrategyPerformance,
  Tone,
  TradingSignal,
  WatchlistItem,
} from '../types/dashboard'
import type { DashboardApiSnapshot } from '../types/dashboardApi'
import type {
  DataFreshnessStatus,
  DecisionLogEntry,
  MarketInstrument,
  PaperPerformance,
  ReasoningNode,
  RegimeProbabilityPoint,
  RegimeTransition,
  ScoreContribution,
  SignalRadarMetric,
  TerminalDashboardData,
  TerminalPanelState,
  TerminalTone,
} from '../types/terminal'

const numberValue = (value: unknown, fallback = 0) =>
  typeof value === 'number' && Number.isFinite(value) ? value : fallback

const stringValue = (value: unknown, fallback = 'TIDAK TERSEDIA') =>
  typeof value === 'string' && value.trim() ? value : fallback

const recordValue = (value: unknown): Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {}

const arrayValue = (value: unknown): unknown[] =>
  Array.isArray(value) ? value : []

const probabilityPercent = (value: unknown): number => {
  const number = numberValue(value)
  return number > 0 && number <= 1 ? number * 100 : number
}

const scoreComponentLabels: Record<string, ScoreContribution['component']> = {
  trend_alignment: 'Keselarasan Tren',
  momentum: 'Momentum',
  volatility: 'Volatilitas',
  regime_match: 'Kecocokan Rezim',
  session_quality: 'Kualitas Sesi',
  liquidity: 'Likuiditas',
  data_freshness: 'Kesegaran Data',
  risk_context: 'Konteks Risiko',
  loss_cooldown: 'Cooldown Kerugian',
  strategy_quality: 'Kualitas Strategi',
}

const radarKeyMap: Record<string, SignalRadarMetric['key']> = {
  trend_strength: 'trendStrength',
  trendStrength: 'trendStrength',
  momentum: 'momentum',
  volatility: 'volatility',
  mean_reversion: 'meanReversion',
  meanReversion: 'meanReversion',
  breakout_pressure: 'breakoutPressure',
  breakoutPressure: 'breakoutPressure',
  liquidity: 'liquidity',
  session_quality: 'sessionQuality',
  sessionQuality: 'sessionQuality',
  data_freshness: 'dataFreshness',
  dataFreshness: 'dataFreshness',
}

const radarLabels: Record<SignalRadarMetric['key'], string> = {
  trendStrength: 'Kekuatan tren',
  momentum: 'Momentum',
  volatility: 'Volatilitas',
  meanReversion: 'Reversi mean',
  breakoutPressure: 'Tekanan breakout',
  liquidity: 'Likuiditas',
  sessionQuality: 'Kualitas sesi',
  dataFreshness: 'Kesegaran data',
}

const sourceFreshness = (status: string): DataFreshnessStatus => {
  if (status === 'fresh') return 'FRESH'
  if (status === 'stale') return 'STALE'
  if (status === 'partial' || status === 'invalid') return 'PARTIAL'
  return 'DISCONNECTED'
}

export const snapshotPanelState = (
  snapshot: DashboardApiSnapshot | null,
): TerminalPanelState => {
  if (!snapshot) return 'disconnected'
  if (snapshot.connection.status === 'connected') return 'connected'
  if (snapshot.connection.status === 'stale') return 'stale'
  if (snapshot.connection.status === 'partial') return 'partial'
  return 'disconnected'
}

const precisionFor = (symbol: string, price: number | null) => {
  if (symbol.startsWith('BTC')) return 2
  if (symbol.startsWith('XAU') || symbol.startsWith('XAG') || symbol.includes('OIL')) return 2
  if (price !== null && Math.abs(price) >= 1000) return 2
  if (price !== null && Math.abs(price) >= 10) return 3
  return 5
}

const volatilityLabel = (
  value: number | null,
): 'LOW' | 'NORMAL' | 'ELEVATED' | 'HIGH' => {
  if (value === null) return 'NORMAL'
  if (value >= 2) return 'HIGH'
  if (value >= 0.8) return 'ELEVATED'
  if (value < 0.08) return 'LOW'
  return 'NORMAL'
}

const assetType = (
  value: string,
): WatchlistItem['assetType'] => {
  if (value === 'CRYPTO') return 'Crypto'
  if (value === 'METALS') return 'Metals'
  if (value === 'COMMODITY') return 'Commodity'
  if (value === 'FOREX') return 'Forex'
  return 'Other'
}

const signalStatus = (value: string | null): TradingSignal['status'] => {
  const status = (value ?? '').toUpperCase()
  if (status.includes('TIMEOUT')) return 'TIMEOUT'
  if (status.includes('OPEN')) return 'PAPER_OPEN'
  if (status.includes('CLOSED') || status.includes('WIN') || status.includes('LOSS')) {
    return 'PAPER_CLOSED'
  }
  if (status.includes('REJECT')) return 'REJECTED'
  if (status.includes('BLOCK')) return 'BLOCKED'
  return 'WAIT'
}

const signalSide = (
  value: string | null,
): TradingSignal['side'] => {
  const side = (value ?? '').toUpperCase()
  if (side === 'BUY' || side === 'SELL' || side === 'BLOCKED') return side
  return 'WAIT'
}

const toneFor = (value: number | null, inverse = false): Tone => {
  if (value === null) return 'neutral'
  if (inverse) return value > 3 ? 'negative' : value > 1 ? 'warning' : 'positive'
  return value > 0 ? 'positive' : value < 0 ? 'negative' : 'neutral'
}

const strategyRows = (snapshot: DashboardApiSnapshot): StrategyPerformance[] =>
  snapshot.strategies.map((item) => {
    const performance = item.performance
    const trades = numberValue(performance.total ?? performance.closed_orders)
    const wins = numberValue(performance.wins)
    const profit = numberValue(performance.profit_usd ?? performance.net_profit_usd)
    const losses = numberValue(performance.losses)
    const grossLossProxy = losses > 0 ? Math.abs(profit < 0 ? profit : losses) : 0
    const profitFactor = numberValue(
      performance.profit_factor,
      grossLossProxy > 0 ? Math.max(0, profit) / grossLossProxy : 0,
    )
    return {
      name: item.strategy,
      shortName: item.strategy.replaceAll('_', ' '),
      trades,
      winRate: trades > 0 ? (wins / trades) * 100 : 0,
      profitFactor,
      netResult: profit,
      guardStatus: item.status as GuardStatus,
    }
  })

const pairRows = (snapshot: DashboardApiSnapshot): PairPerformance[] =>
  snapshot.pair_rotation.map((pair) => {
    const performance = recordValue(snapshot.performance.by_symbol[pair.symbol])
    const total = numberValue(performance.total)
    const wins = numberValue(performance.wins)
    const market = snapshot.market[pair.symbol]
    return {
      symbol: pair.symbol,
      netResult: numberValue(performance.profit_usd),
      winRate: total > 0 ? (wins / total) * 100 : 0,
      signalCount: snapshot.signals.filter((signal) => signal.symbol === pair.symbol).length,
      volatility: volatilityLabel(market?.volatility_percent ?? null),
      guardStatus: pair.status,
    }
  })

const watchlistRows = (snapshot: DashboardApiSnapshot): WatchlistItem[] =>
  snapshot.watchlist.map((item) => ({
    symbol: item.symbol,
    assetType: assetType(item.asset_type),
    currentPrice: item.latest_price ?? 0,
    pricePrecision: precisionFor(item.symbol, item.latest_price),
    priceChange: item.price_change_percent ?? 0,
    volatility: volatilityLabel(item.volatility_percent),
    marketStatus:
      item.market_status === 'DATA_AVAILABLE' || item.market_status === 'OPEN_24_7'
        ? 'OPEN'
        : item.market_status === 'STALE' || item.market_status === 'CLOSED_WEEKEND'
          ? 'CLOSED'
          : 'UNKNOWN',
    signalBias: signalSide(item.signal_bias),
    strategyScore: item.strategy_score ?? 0,
    guardStatus: item.guard_status,
    lastUpdate: item.source_timestamp ?? item.received_at,
    freshness: item.stale ? 'STALE' : 'FRESH',
    tradable: item.guard_status !== 'BLOCKED',
  }))

const legacySignals = (snapshot: DashboardApiSnapshot): TradingSignal[] =>
  snapshot.signals.map((signal) => ({
    id: signal.id,
    time: signal.timestamp ?? snapshot.generated_at,
    symbol: signal.symbol ?? 'TIDAK TERSEDIA',
    side: signalSide(signal.side),
    strategy: signal.strategy ?? 'TIDAK TERSEDIA',
    score: signal.adjusted_score ?? signal.score ?? 0,
    status: signalStatus(signal.status),
    reason: signal.reason ?? 'Alasan tidak tersedia dari sumber.',
    dataFreshness: signal.data_freshness === 'fresh' ? 'FRESH' : 'STALE',
  }))

const activityRows = (snapshot: DashboardApiSnapshot): ActivityEvent[] =>
  snapshot.activity.map((item, index) => ({
    id: `${item.source ?? 'source'}-${index.toString()}`,
    time: item.timestamp,
    title: item.title,
    detail: item.detail ?? 'Tidak ada detail tambahan.',
    category: 'data',
    tone: 'neutral',
  }))

const buildKpis = (snapshot: DashboardApiSnapshot): KpiMetric[] => {
  const summary = snapshot.summary
  const entries: KpiMetric[] = [
    {
      id: 'system-mode',
      label: 'Mode Sistem',
      value: summary.system_mode ?? 'TIDAK TERSEDIA',
      icon: 'mode',
      badge: 'HANYA-BACA',
      tone: 'info',
      description: 'Mode aktual yang dilaporkan sumber proyek.',
    },
    {
      id: 'quality-status',
      label: 'Status Kualitas',
      value: summary.quality_status ?? 'TIDAK TERSEDIA',
      icon: 'quality',
      badge: snapshot.connection.stale ? 'STALE' : 'SUMBER AKTUAL',
      tone: 'warning',
      description: 'Status kualitas dari laporan kualitas paper.',
    },
    {
      id: 'readiness-score',
      label: 'Skor Kesiapan',
      value:
        summary.readiness_score === null
          ? 'TIDAK TERSEDIA'
          : `${summary.readiness_score.toFixed(0)}/100`,
      numericValue: summary.readiness_score ?? undefined,
      icon: 'readiness',
      badge: stringValue(snapshot.readiness.label, 'TIDAK TERSEDIA'),
      tone: 'warning',
      description: 'Skor readiness aktual dari offline dashboard report.',
      progress:
        summary.readiness_score === null
          ? undefined
          : { value: summary.readiness_score, max: 100, variant: 'ring' },
    },
    {
      id: 'active-pairs',
      label: 'Pair Aktif',
      value: String(summary.active_pairs.length),
      numericValue: summary.active_pairs.length,
      icon: 'pairs',
      badge: summary.active_pairs.join(', ') || 'TIDAK ADA',
      tone: 'info',
      description: 'Daftar active_pairs dari sumber aktual.',
    },
    {
      id: 'closed-orders',
      label: 'Order Ditutup',
      value: `${summary.closed_orders ?? 0}/${summary.closed_target ?? 0}`,
      numericValue: summary.closed_orders ?? undefined,
      icon: 'orders',
      badge: 'SAMPEL PAPER',
      tone: 'info',
      description: 'Progress aktual sampel paper.',
      progress:
        summary.closed_orders !== null && summary.closed_target
          ? {
              value: Math.min(summary.closed_orders, summary.closed_target),
              max: summary.closed_target,
              variant: 'bar',
            }
          : undefined,
    },
    {
      id: 'win-rate',
      label: 'Rasio Menang',
      value: summary.win_rate === null ? '—' : `${summary.win_rate.toFixed(2)}%`,
      numericValue: summary.win_rate ?? undefined,
      icon: 'winRate',
      badge: `${snapshot.performance.wins ?? 0}W / ${snapshot.performance.losses ?? 0}L`,
      tone: 'warning',
      description: 'Rasio menang yang dihitung laporan paper.',
    },
    {
      id: 'profit-factor',
      label: 'Faktor Profit',
      value: summary.profit_factor?.toFixed(4) ?? '—',
      numericValue: summary.profit_factor ?? undefined,
      icon: 'profitFactor',
      badge: 'SUMBER AKTUAL',
      tone: toneFor(summary.profit_factor),
      description: 'Faktor profit aktual dari laporan kualitas.',
    },
    {
      id: 'net-profit',
      label: 'Laba Bersih',
      value: summary.net_profit === null ? '—' : `$${summary.net_profit.toFixed(4)}`,
      numericValue: summary.net_profit ?? undefined,
      icon: 'netProfit',
      badge: 'PAPER',
      tone: toneFor(summary.net_profit),
      description: 'P&L paper aktual; bukan saldo broker.',
    },
    {
      id: 'max-drawdown',
      label: 'Drawdown Maks.',
      value: summary.max_drawdown === null ? '—' : `${summary.max_drawdown.toFixed(2)}%`,
      numericValue: summary.max_drawdown ?? undefined,
      icon: 'drawdown',
      badge: 'HISTORIS PAPER',
      tone: toneFor(summary.max_drawdown, true),
      description: 'Drawdown dari kurva ekuitas paper aktual.',
    },
  ]
  return entries
}

export const mapApiSnapshotToDashboard = (
  snapshot: DashboardApiSnapshot,
): DashboardSnapshot => ({
  summary: {
    projectName: 'AI_SCALPER',
    balanceReference: snapshot.summary.reference_balance ?? 0,
    systemMode: snapshot.summary.system_mode ?? 'PAPER',
    executionMode: snapshot.safety.mode,
    qualityStatus: snapshot.summary.quality_status ?? 'TIDAK TERSEDIA',
    readinessScore: snapshot.summary.readiness_score ?? 0,
    activePairs: snapshot.summary.active_pairs.length,
    closedOrders: snapshot.summary.closed_orders ?? 0,
    closedOrdersTarget: snapshot.summary.closed_target ?? 0,
    winRate: snapshot.summary.win_rate ?? 0,
    profitFactor: snapshot.summary.profit_factor ?? 0,
    netProfit: snapshot.summary.net_profit ?? 0,
    maxDrawdown: snapshot.summary.max_drawdown ?? 0,
    liveAllowed: false,
    maxLot: 0.01,
    safeToDemoObserve: true,
    safeToDemoAutoOrder: false,
    systemVersion: '1.0.0',
    frontendVersion: '1.0.0',
    updatedAt: snapshot.generated_at,
  },
  kpis: buildKpis(snapshot),
  equity: snapshot.performance.equity_curve.map((point) => ({
    session: point.index,
    date: point.timestamp ?? `#${point.index.toString()}`,
    equity: point.equity,
    cumulativeProfit: point.cumulative_net_profit,
    drawdown: -(point.drawdown_percent ?? 0),
  })),
  tradeDistribution: {
    wins: snapshot.performance.wins ?? 0,
    losses: snapshot.performance.losses ?? 0,
    timeouts: snapshot.performance.timeouts ?? 0,
  },
  strategies: strategyRows(snapshot),
  pairs: pairRows(snapshot),
  readiness: [],
  watchlist: watchlistRows(snapshot),
  marketNews: snapshot.news.events.map((event) => ({
    id: event.id,
    scheduledAt: event.scheduled_at,
    title: event.title,
    currency: event.currency ?? '—',
    region: event.region ?? 'TIDAK TERSEDIA',
    status: event.status,
    impact: event.impact,
    actual: event.actual ?? undefined,
    forecast: event.forecast ?? undefined,
    previous: event.previous ?? undefined,
    surprise: event.surprise,
    affectedSymbols: event.affected_symbols,
    summary:
      event.summary ??
      'Provider tidak memberikan ringkasan; dashboard tidak membuat interpretasi arah.',
    source: 'API',
    freshness: event.stale ? 'STALE' : 'FRESH',
  })),
  pairNewsImpacts: snapshot.news.pair_impacts.map((impact) => ({
    id: impact.id,
    newsId: impact.news_id,
    symbol: impact.symbol,
    pairStatus: impact.pair_status,
    directionBias: impact.direction_bias,
    projectedVolatility: impact.projected_volatility,
    spreadRisk: impact.spread_risk,
    impactScore: impact.impact_score,
    decisionScore: impact.decision_score,
    minimumScore: impact.minimum_score,
    guardStatus: impact.guard_status,
    decision: impact.decision,
    effect: impact.effect,
    requiredObservation: impact.required_observation,
  })),
  newsSource: {
    provider: snapshot.news.provider ?? 'TIDAK DIKONFIGURASI',
    status:
      snapshot.news.source_status === 'fresh'
        ? 'FRESH'
        : snapshot.news.source_status === 'stale'
          ? 'STALE'
          : snapshot.news.source_status === 'partial'
            ? 'PARTIAL'
            : snapshot.news.source_status === 'invalid'
              ? 'INVALID'
              : 'UNAVAILABLE',
    lastUpdated: snapshot.news.last_updated,
    note: snapshot.news.note,
  },
  decisionReadiness: {
    ready: snapshot.decision_readiness.decision_ready,
    status: snapshot.decision_readiness.decision_status,
    symbol: snapshot.decision_readiness.symbol ?? 'TIDAK TERSEDIA',
    strategy: snapshot.decision_readiness.strategy ?? 'TIDAK TERSEDIA',
    score: snapshot.decision_readiness.score,
    minimumRequired: snapshot.decision_readiness.minimum_required,
    blockers: snapshot.decision_readiness.blockers,
    gates: {
      dataFreshness: snapshot.decision_readiness.data_freshness_pass,
      news: snapshot.decision_readiness.news_guard,
      spread: snapshot.decision_readiness.spread_guard,
      session: snapshot.decision_readiness.session_guard,
    },
    explanation: snapshot.decision_readiness.explanation,
  },
  safety: {
    liveAllowed: false,
    mode: snapshot.safety.mode === 'PAPER' ? 'PAPER_ONLY' : 'DRY_RUN',
    maxLot: 0.01,
    safeToDemoObserve: true,
    safeToDemoAutoOrder: false,
    controls: [
      {
        id: 'live',
        label: 'Trading Live',
        value: snapshot.safety.display_status,
        status: 'protected',
        note: 'Dikunci oleh dashboard safety guard.',
      },
      {
        id: 'paper',
        label: 'Paper Trading',
        value: 'AKTIF',
        status: 'safe',
      },
      {
        id: 'auto-order',
        label: 'Demo Auto Order',
        value: 'DI LUAR CAKUPAN',
        status: 'protected',
      },
      ...snapshot.guards.map((guard) => ({
        id: guard.key,
        label: guard.label,
        value: guard.status,
        status:
          guard.enabled === false
            ? ('caution' as const)
            : guard.enabled === true
              ? ('safe' as const)
              : ('unavailable' as const),
        note: guard.reason ?? undefined,
      })),
    ],
  },
  decisionHealth: {
    engineStatus:
      snapshot.decision_health.engine_status === 'ONLINE'
        ? 'HEALTHY'
        : snapshot.decision_health.engine_status === 'STALE'
          ? 'STALE'
          : 'DEGRADED',
    healthScore: snapshot.decision_health.readiness_score ?? 0,
    lastDecisionTime: snapshot.decision_health.latest_decision_at ?? snapshot.generated_at,
    dataFreshness:
      snapshot.decision_health.source_status === 'fresh'
        ? 'FRESH'
        : snapshot.decision_health.source_status === 'unavailable'
          ? 'MISSING'
          : 'STALE',
    latestCandleAge:
      snapshot.decision_health.candle_age_seconds === null
        ? 'TIDAK TERSEDIA'
        : `${Math.round(snapshot.decision_health.candle_age_seconds)} dtk`,
    activeSymbol: snapshot.decision_health.current_symbol ?? 'TIDAK TERSEDIA',
    activeStrategy: snapshot.decision_health.current_strategy ?? 'TIDAK TERSEDIA',
    currentSession: snapshot.session.current_session ?? 'TIDAK TERSEDIA',
    volatilityCondition:
      snapshot.decision_health.volatility_percent === null
        ? 'TIDAK TERSEDIA'
        : `${snapshot.decision_health.volatility_percent.toFixed(5)}%`,
    readinessStatus: snapshot.decision_health.readiness_status ?? 'TIDAK TERSEDIA',
    missingDiagnostics: snapshot.decision_health.blockers,
    checks: snapshot.guards.map((guard) => ({
      label: guard.label,
      value: guard.status,
      tone: guard.enabled === false ? 'negative' : guard.enabled ? 'positive' : 'neutral',
    })),
  },
  signals: legacySignals(snapshot),
  activity: activityRows(snapshot),
})

const actualDecisionLog = (snapshot: DashboardApiSnapshot): DecisionLogEntry[] => {
  const fromSignals: DecisionLogEntry[] = snapshot.signals.map((signal) => ({
    id: signal.id,
    timestamp: signal.timestamp ?? snapshot.generated_at,
    pair: signal.symbol ?? '—',
    side: signalSide(signal.side),
    strategy: signal.strategy ?? '—',
    score: signal.adjusted_score ?? signal.score ?? 0,
    maximumScore: 5,
    result: signalStatus(signal.status),
    guard: signal.raw_guard_status ?? signal.status ?? 'TIDAK TERSEDIA',
    latencyMs: null,
    paperPnl: null,
    reason: signal.reason ?? 'Alasan tidak tersedia dari sumber.',
    freshness: sourceFreshness(signal.data_freshness),
  }))
  const fromOrders: DecisionLogEntry[] = snapshot.paper_orders.slice(0, 30).map((order) => ({
    id: order.order_id,
    timestamp: order.close_time ?? order.open_time ?? snapshot.generated_at,
    pair: order.symbol ?? '—',
    side: signalSide(order.side),
    strategy: order.strategy ?? '—',
    score: 0,
    maximumScore: 5,
    result: order.close_time ? 'PAPER_CLOSED' : 'PAPER_OPEN',
    guard: order.status ?? 'PAPER',
    latencyMs: null,
    paperPnl: order.pnl,
    reason: order.close_reason ?? 'Order paper dari sumber aktual.',
    freshness: snapshot.sources.paper_orders?.status === 'fresh' ? 'FRESH' : 'STALE',
  }))
  return [...fromSignals, ...fromOrders]
    .sort((left, right) => Date.parse(right.timestamp) - Date.parse(left.timestamp))
    .slice(0, 40)
}

const performanceData = (snapshot: DashboardApiSnapshot): PaperPerformance => {
  const strategyEntries = Object.entries(snapshot.performance.by_strategy)
  const pairEntries = Object.entries(snapshot.performance.by_symbol)
  const sortedStrategies = [...strategyEntries].sort(
    (left, right) =>
      numberValue(recordValue(right[1]).profit_usd) -
      numberValue(recordValue(left[1]).profit_usd),
  )
  const sortedPairs = [...pairEntries].sort(
    (left, right) =>
      numberValue(recordValue(right[1]).profit_usd) -
      numberValue(recordValue(left[1]).profit_usd),
  )
  const rValues = snapshot.paper_orders
    .map((order) => order.r_multiple)
    .filter((value): value is number => value !== null)
  return {
    closedOrders: snapshot.performance.closed_orders ?? 0,
    targetOrders: snapshot.summary.closed_target ?? 0,
    wins: snapshot.performance.wins ?? 0,
    losses: snapshot.performance.losses ?? 0,
    timeouts: snapshot.performance.timeouts ?? 0,
    winRate: snapshot.performance.win_rate ?? 0,
    profitFactor: snapshot.performance.profit_factor ?? 0,
    expectancy: snapshot.performance.expectancy ?? 0,
    netProfit: snapshot.performance.net_profit ?? 0,
    maxDrawdown: snapshot.performance.max_drawdown_percent ?? 0,
    referenceBalance: snapshot.performance.reference_balance ?? 0,
    averageR:
      rValues.length > 0
        ? rValues.reduce((total, value) => total + value, 0) / rValues.length
        : 0,
    bestStrategy: sortedStrategies[0]?.[0] ?? 'TIDAK TERSEDIA',
    weakestStrategy: sortedStrategies.at(-1)?.[0] ?? 'TIDAK TERSEDIA',
    bestPair: sortedPairs[0]?.[0] ?? 'TIDAK TERSEDIA',
    blockedPair:
      snapshot.pair_rotation.find((pair) => pair.status === 'BLOCKED')?.symbol ??
      'TIDAK TERSEDIA',
    equityCurve: snapshot.performance.equity_curve.map((point) => ({
      session: point.timestamp ?? `#${point.index.toString()}`,
      equity: point.equity,
      cumulativeNetProfit: point.cumulative_net_profit,
      drawdownPercent: point.drawdown_percent ?? 0,
    })),
  }
}

const mapInstruments = (snapshot: DashboardApiSnapshot): MarketInstrument[] =>
  Object.values(snapshot.market)
    .filter((market) => market.candles.length > 0)
    .map((market) => {
      const timeframe =
        market.timeframe === 'M5' ||
        market.timeframe === 'M15' ||
        market.timeframe === 'M30' ||
        market.timeframe === 'H1'
          ? market.timeframe
          : 'M15'
      const latest = market.candles.at(-1)
      const matchingSignal = snapshot.signals.find(
        (signal) =>
          signal.symbol === market.symbol &&
          (signal.price !== null || signal.sl !== null || signal.tp !== null),
      )
      const trueRanges = market.candles.slice(-14).map((candle, index, values) => {
        const previousClose = values[index - 1]?.close ?? candle.open
        return Math.max(
          candle.high - candle.low,
          Math.abs(candle.high - previousClose),
          Math.abs(candle.low - previousClose),
        )
      })
      return {
        symbol: market.symbol,
        quote: market.symbol.slice(-3),
        precision: precisionFor(market.symbol, market.latest_price),
        latestPrice: market.latest_price,
        changePercent: market.price_change_percent,
        open: latest?.open ?? null,
        high: latest?.high ?? null,
        low: latest?.low ?? null,
        spread: null,
        atr:
          trueRanges.length > 0
            ? trueRanges.reduce((total, value) => total + value, 0) / trueRanges.length
            : null,
        volatilityPercent: market.volatility_percent,
        session: snapshot.session.current_session ?? 'TIDAK TERSEDIA',
        signalBias: signalSide(
          snapshot.signals.find((signal) => signal.symbol === market.symbol)?.side ?? null,
        ),
        strategyScore:
          snapshot.signals.find((signal) => signal.symbol === market.symbol)?.adjusted_score ??
          null,
        freshness: sourceFreshness(market.status),
        selectedTimeframe: timeframe,
        referenceLevels: {
          entry: matchingSignal?.price ?? null,
          stopLoss: matchingSignal?.sl ?? null,
          takeProfit: matchingSignal?.tp ?? null,
        },
        candles: {
          [timeframe]: market.candles.map((candle, index) => ({
            id: `${market.symbol}-${candle.timestamp}-${index.toString()}`,
            ...candle,
          })),
        },
      }
    })

const healthTone = (value: number): TerminalTone =>
  value >= 80 ? 'safe' : value >= 55 ? 'caution' : 'warning'

export const mapApiSnapshotToTerminal = (
  snapshot: DashboardApiSnapshot,
  sourceMode: TerminalDashboardData['summary']['dataSource'],
): TerminalDashboardData => {
  const performance = performanceData(snapshot)
  const decisionLog = actualDecisionLog(snapshot)
  const distributionEntries = Object.entries(snapshot.decision_state_distribution)
  const distributionTotal = distributionEntries.reduce((sum, [, count]) => sum + count, 0)
  const currentState = signalStatus(snapshot.signals[0]?.status ?? null)
  const scoring = snapshot.scoring
  const rawScore = numberValue(scoring.raw_score)
  const finalScore = numberValue(scoring.adjusted_score, rawScore)
  const requiredScore = numberValue(scoring.minimum_required)
  const action = stringValue(scoring.action, 'TIDAK TERSEDIA')
  const sources = Object.values(snapshot.sources)
  const availableSources = sources.filter(
    (source) => source.status !== 'unavailable' && source.status !== 'invalid',
  ).length
  const dataIntegrity = sources.length > 0 ? (availableSources / sources.length) * 100 : 0
  const sampleSufficiency =
    performance.targetOrders > 0
      ? Math.min(100, (performance.closedOrders / performance.targetOrders) * 100)
      : 0
  const regimeProbabilities = recordValue(snapshot.regime.probabilities)
  const regimeHistory: RegimeProbabilityPoint[] = arrayValue(snapshot.regime.history)
    .map(recordValue)
    .filter((item) => typeof (item.time ?? item.timestamp) === 'string')
    .map((item) => ({
      time: stringValue(item.time ?? item.timestamp),
      trend: probabilityPercent(item.trend ?? item.TREND),
      range: probabilityPercent(item.range ?? item.RANGE),
      chop: probabilityPercent(item.chop ?? item.CHOP),
      panic: probabilityPercent(item.panic ?? item.PANIC),
      marker:
        item.marker === 'FLIP' ||
        item.marker === 'CROSS' ||
        item.marker === 'STABLE' ||
        item.marker === 'REGIME CHANGE'
          ? item.marker
          : undefined,
    }))
  const analytics = snapshot.analytics
  const reasoningNodes: ReasoningNode[] = arrayValue(analytics.reasoning_nodes)
    .map(recordValue)
    .filter(
      (item) =>
        typeof item.id === 'string' &&
        typeof item.label === 'string' &&
        typeof item.latency_ms === 'number' &&
        typeof item.pass_rate === 'number' &&
        typeof item.rejection_rate === 'number' &&
        typeof item.sample_count === 'number',
    )
    .map((item) => ({
      id: stringValue(item.id),
      label: stringValue(item.label),
      group:
        item.group === 'left' || item.group === 'gate' || item.group === 'right'
          ? item.group
          : 'left',
      latencyMs: numberValue(item.latency_ms),
      passRate: numberValue(item.pass_rate),
      rejectionRate: numberValue(item.rejection_rate),
      sampleCount: numberValue(item.sample_count),
      status:
        String(item.status).toUpperCase().includes('PASS')
          ? 'PASS'
          : String(item.status).toUpperCase().includes('ACTIVE')
            ? 'ACTIVE'
            : 'WAIT',
    }))
  const signalRadar: SignalRadarMetric[] = arrayValue(analytics.signal_radar)
    .map(recordValue)
    .flatMap((item): SignalRadarMetric[] => {
      const sourceKey = typeof item.key === 'string' ? item.key : ''
      const key = radarKeyMap[sourceKey]
      if (!key || typeof item.value !== 'number') return []
      const value = probabilityPercent(item.value)
      const minimumBoundary = probabilityPercent(item.minimum_boundary)
      return [{
        metric: radarLabels[key],
        key,
        value,
        minimumBoundary,
        maximum: 100,
        zone:
          String(item.status).toUpperCase().includes('BLOCK')
            ? 'BLOCKED'
            : value >= minimumBoundary
              ? 'PASS'
              : 'MARGINAL',
      }]
    })
  const contributionRows: ScoreContribution[] = arrayValue(scoring.contributions)
    .map(recordValue)
    .flatMap((item): ScoreContribution[] => {
      const sourceKey = typeof item.key === 'string' ? item.key : ''
      const component = scoreComponentLabels[sourceKey]
      if (
        !component ||
        typeof item.raw_value !== 'number' ||
        typeof item.contribution !== 'number'
      ) {
        return []
      }
      return [{
        id: sourceKey,
        component,
        rawValue: numberValue(item.raw_value),
        weight: numberValue(item.weight, 1),
        contribution: numberValue(item.contribution),
        result:
          String(item.status).toUpperCase().includes('PASS')
            ? 'PASS'
            : String(item.status).toUpperCase().includes('FAIL')
              ? 'FAIL'
              : 'NEUTRAL',
        reason: stringValue(item.reason, `Komponen aktual: ${sourceKey}`),
      }]
    })
  const validRegimes = new Set(['TREND', 'RANGE', 'CHOP', 'PANIC'])
  const regimeTransitions: RegimeTransition[] = arrayValue(analytics.regime_transitions)
    .map(recordValue)
    .filter(
      (item) =>
        validRegimes.has(String(item.from).toUpperCase()) &&
        validRegimes.has(String(item.to).toUpperCase()) &&
        typeof item.probability === 'number',
    )
    .map((item) => ({
      from: String(item.from).toUpperCase() as RegimeTransition['from'],
      to: String(item.to).toUpperCase() as RegimeTransition['to'],
      probability: numberValue(item.probability),
    }))
  const transitionSummary = recordValue(analytics.transition_summary)

  return {
    summary: {
      product: 'AI_SCALPER',
      edition: 'QUANT',
      subtitle: 'SISTEM INTELIJENSI PAPER ADAPTIF',
      mode: snapshot.safety.mode,
      paperTrading: 'ACTIVE',
      liveAllowed: false,
      liveTrading: 'LOCKED',
      maxLot: 0.01,
      safeToObserve: true,
      safeToAutoOrder: false,
      demoAutoOrder: 'DI LUAR CAKUPAN',
      qualityStatus: snapshot.summary.quality_status ?? 'TIDAK TERSEDIA',
      systemVersion: '1.0.0',
      dataSource: sourceMode,
    },
    runtime: {
      currentSession: snapshot.session.current_session ?? 'TIDAK TERSEDIA',
      activePair:
        snapshot.decision_health.current_symbol ??
        snapshot.summary.active_pairs[0] ??
        'TIDAK TERSEDIA',
      marketStatus: snapshot.session.market_open_status,
      dataFreshness: sourceFreshness(
        snapshot.connection.status === 'connected'
          ? 'fresh'
          : snapshot.connection.status,
      ),
      currentStrategy: snapshot.decision_health.current_strategy ?? 'TIDAK TERSEDIA',
      sampleProgress: `${performance.closedOrders}/${performance.targetOrders}`,
      connection:
        sourceMode === 'DISCONNECTED'
          ? 'OFFLINE'
          : sourceMode === 'REST POLLING'
            ? 'DEGRADED'
            : 'ONLINE',
      pollingLatencyMs: snapshot.connection.latency_ms,
      lastSyncTime: snapshot.generated_at,
    },
    readiness: {
      score: snapshot.summary.readiness_score ?? 0,
      displayScore: snapshot.summary.readiness_score ?? 0,
      previousScore: snapshot.summary.readiness_score ?? 0,
      delta: 0,
      status: snapshot.readiness.label ?? snapshot.summary.quality_status ?? 'TIDAK TERSEDIA',
      closedOrders: performance.closedOrders,
      targetOrders: performance.targetOrders,
      safeStatus: 'AMAN UNTUK DIAMATI',
      currentRiskProfile: 'PAPER / GUARD AKTIF',
      curve: [],
    },
    tickers: snapshot.watchlist.map((item) => ({
      id: item.symbol,
      symbol: item.symbol,
      assetType:
        item.asset_type === 'CRYPTO' ||
        item.asset_type === 'METALS' ||
        item.asset_type === 'COMMODITY' ||
        item.asset_type === 'OTHER'
          ? item.asset_type
          : 'FOREX',
      direction:
        (item.price_change_percent ?? 0) > 0
          ? 'UP'
          : (item.price_change_percent ?? 0) < 0
            ? 'DOWN'
            : 'FLAT',
      price: item.latest_price ?? 0,
      precision: precisionFor(item.symbol, item.latest_price),
      changePercent: item.price_change_percent ?? 0,
      guardStatus: item.guard_status,
      marketStatus: item.market_status,
      freshness: sourceFreshness(item.status),
    })),
    instruments: mapInstruments(snapshot),
    executionCycle: snapshot.execution_cycle.map((stage) => ({
      id: stage.key,
      index: stage.index,
      label: stage.label as TerminalDashboardData['executionCycle'][number]['label'],
      state: stage.state,
      durationMs: null,
      result: stage.result ?? 'TIDAK TERSEDIA',
      timestamp: stage.timestamp ?? snapshot.generated_at,
    })),
    regimeHistory,
    regimeCurrent: {
      trend:
        regimeProbabilities.trend !== undefined || regimeProbabilities.TREND !== undefined
          ? probabilityPercent(regimeProbabilities.trend ?? regimeProbabilities.TREND)
          : null,
      range:
        regimeProbabilities.range !== undefined || regimeProbabilities.RANGE !== undefined
          ? probabilityPercent(regimeProbabilities.range ?? regimeProbabilities.RANGE)
          : null,
      chop:
        regimeProbabilities.chop !== undefined || regimeProbabilities.CHOP !== undefined
          ? probabilityPercent(regimeProbabilities.chop ?? regimeProbabilities.CHOP)
          : null,
      panic:
        regimeProbabilities.panic !== undefined || regimeProbabilities.PANIC !== undefined
          ? probabilityPercent(regimeProbabilities.panic ?? regimeProbabilities.PANIC)
          : null,
      classification: stringValue(snapshot.regime.classification),
      confidence:
        typeof snapshot.regime.confidence === 'number'
          ? numberValue(snapshot.regime.confidence)
          : null,
      projectedRegime: stringValue(snapshot.regime.projected_regime),
    },
    decisionLog,
    decisionStates: {
      states: distributionEntries.map(([state, count]) => ({
        state:
          state.includes('BLOCK') || state.includes('REJECT')
            ? 'BLOCKED'
            : state.includes('TIMEOUT')
              ? 'TIMEOUT'
              : state.includes('BUY')
                ? 'BUY'
                : state.includes('SELL')
                  ? 'SELL'
                  : 'WAIT',
        count,
        percent: distributionTotal > 0 ? (count / distributionTotal) * 100 : 0,
      })),
      currentState:
        currentState === 'PAPER_OPEN'
          ? 'BUY'
          : currentState === 'PAPER_CLOSED'
            ? 'WAIT'
            : currentState === 'REJECTED'
              ? 'BLOCKED'
              : currentState,
      paperOpen: snapshot.paper_orders.filter((order) => !order.close_time).length,
      paperClosed: snapshot.performance.closed_orders ?? 0,
      confidence: {
        strategy: 0,
        guard: snapshot.safety.guard_enabled ? 1 : 0,
        data: dataIntegrity / 100,
        risk: snapshot.safety.safety_violation ? 0 : 1,
      },
    },
    reasoningNodes,
    signalRadar,
    signalSetup: {
      strategy: stringValue(scoring.strategy),
      rawScore,
      adjustedScore: finalScore,
      minimumRequired: requiredScore,
      decision: action,
      label: stringValue(scoring.reason),
    },
    scoreContributions: contributionRows,
    scoringResult: {
      available: scoring.available === true,
      rawScore,
      adaptiveBoost: finalScore - rawScore,
      guardPenalty: 0,
      finalScore,
      minimumRequired: requiredScore,
      action,
      explanation: stringValue(scoring.reason),
      rollingScores:
        scoring.available === true ? [rawScore, finalScore] : [],
    },
    regimeTransitions,
    transitionSummary: {
      mostLikely: stringValue(transitionSummary.most_likely),
      entropy: numberValue(transitionSummary.entropy),
      stability: numberValue(transitionSummary.stability),
      expectedDuration: stringValue(transitionSummary.expected_duration),
      confidence: numberValue(transitionSummary.confidence),
      forecast: stringValue(transitionSummary.forecast),
    },
    systemGuards: snapshot.guards.map((guard) => ({
      id: guard.key,
      label: guard.label,
      status:
        guard.enabled === true
          ? 'ENABLED'
          : guard.enabled === false
            ? 'LOCKED'
            : 'UNAVAILABLE',
      tone: guard.enabled === true ? 'safe' : guard.enabled === false ? 'blocked' : 'neutral',
      detail: guard.reason ?? `Status sumber: ${guard.status}`,
    })),
    healthMetrics: [
      { label: 'Integritas data', value: Math.round(dataIntegrity), status: healthTone(dataIntegrity) },
      {
        label: 'Kualitas keputusan',
        value: snapshot.decision_health.readiness_score ?? 0,
        status: healthTone(snapshot.decision_health.readiness_score ?? 0),
      },
      {
        label: 'Kecukupan sampel',
        value: Math.round(sampleSufficiency),
        status: healthTone(sampleSufficiency),
      },
      {
        label: 'Kontrol risiko',
        value: snapshot.safety.safety_violation ? 0 : 100,
        status: snapshot.safety.safety_violation ? 'blocked' : 'safe',
      },
    ],
    pairRotation: snapshot.pair_rotation.map((pair) => ({
      id: pair.symbol,
      symbol: pair.symbol,
      role:
        pair.status === 'BLOCKED'
          ? 'BLOCKED'
          : pair.role === 'PRIMARY'
            ? 'PRIMARY'
            : 'WATCH',
      activity: pair.status,
      reason: pair.reason ?? 'Alasan tidak tersedia dari sumber.',
      confidence: pair.confidence ?? 0,
    })),
    strategyGuards: snapshot.strategies.map((strategy) => ({
      id: strategy.strategy,
      strategy: strategy.strategy,
      status: strategy.status === 'BLOCKED' ? 'BLOCKED' : 'ALLOWED',
      minimumScore: strategy.minimum_score ?? 0,
      rule: strategy.reason ?? strategy.status,
      qualityScore: strategy.quality_score ?? 0,
    })),
    performance,
  }
}
