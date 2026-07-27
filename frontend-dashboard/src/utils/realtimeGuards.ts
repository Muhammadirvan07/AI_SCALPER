import type {
  DashboardApiSnapshot,
  DashboardWebSocketEvent,
} from '../types/dashboardApi'

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value)

const isFiniteNumber = (value: unknown): value is number =>
  typeof value === 'number' && Number.isFinite(value)

const isNonNegativeInteger = (value: unknown): value is number =>
  isFiniteNumber(value) && Number.isInteger(value) && value >= 0

const isNonEmptyString = (value: unknown): value is string =>
  typeof value === 'string' && value.trim().length > 0

export const isIsoTimestamp = (value: unknown): value is string =>
  isNonEmptyString(value) && Number.isFinite(Date.parse(value))

const isNullableIsoTimestamp = (value: unknown) =>
  value === null || isIsoTimestamp(value)

const isStringArray = (value: unknown): value is string[] =>
  Array.isArray(value) && value.every((item) => typeof item === 'string')

const isRecordArray = (value: unknown): value is Record<string, unknown>[] =>
  Array.isArray(value) && value.every(isRecord)

const recordsHaveStrings = (
  value: unknown,
  requiredFields: readonly string[],
) =>
  isRecordArray(value) &&
  value.every((item) =>
    requiredFields.every((field) => isNonEmptyString(item[field])),
  )

const isMarketRecord = (value: unknown) => {
  if (!isRecord(value)) return false
  return Object.values(value).every((series) => {
    if (!isRecord(series) || !isNonEmptyString(series.symbol)) return false
    if (!Array.isArray(series.candles)) return false
    return series.candles.every(
      (candle) =>
        isRecord(candle) &&
        isIsoTimestamp(candle.timestamp) &&
        isFiniteNumber(candle.open) &&
        isFiniteNumber(candle.high) &&
        isFiniteNumber(candle.low) &&
        isFiniteNumber(candle.close) &&
        isFiniteNumber(candle.volume),
    )
  })
}

const isNewsRecord = (value: unknown) => {
  if (
    !isRecord(value) ||
    !isRecordArray(value.events) ||
    !isRecordArray(value.pair_impacts)
  ) {
    return false
  }
  return (
    value.events.every(
      (event) =>
        isNonEmptyString(event.id) &&
        isIsoTimestamp(event.scheduled_at) &&
        isStringArray(event.affected_symbols),
    ) &&
    value.pair_impacts.every(
      (impact) =>
        isNonEmptyString(impact.id) &&
        isNonEmptyString(impact.news_id) &&
        isNonEmptyString(impact.symbol),
    )
  )
}

export const isDashboardSnapshot = (value: unknown): value is DashboardApiSnapshot => {
  if (!isRecord(value)) return false
  const connection = value.connection
  const safety = value.safety
  const summary = value.summary
  const performance = value.performance
  const decisionHealth = value.decision_health
  const decisionReadiness = value.decision_readiness
  const session = value.session
  const sources = value.sources
  if (
    !isRecord(connection) ||
    !isRecord(safety) ||
    !isRecord(summary) ||
    !isRecord(performance) ||
    !isRecord(decisionHealth) ||
    !isRecord(decisionReadiness) ||
    !isRecord(session) ||
    !isRecord(sources)
  ) {
    return false
  }
  return (
    (value.schema_version === '1.0' || value.schema_version === '1.1') &&
    isNonEmptyString(value.snapshot_id) &&
    isNonNegativeInteger(value.version) &&
    isIsoTimestamp(value.generated_at) &&
    isNullableIsoTimestamp(value.source_updated_at) &&
    ['connected', 'stale', 'partial', 'disconnected'].includes(
      String(connection.status),
    ) &&
    typeof connection.stale === 'boolean' &&
    isFiniteNumber(connection.latency_ms) &&
    isNonNegativeInteger(connection.snapshot_version) &&
    isNonNegativeInteger(connection.stale_source_count) &&
    safety.live_allowed === false &&
    safety.live_trading === 'LOCKED' &&
    safety.paper_trading === 'ACTIVE' &&
    safety.max_lot === 0.01 &&
    safety.safe_to_demo_observe === true &&
    safety.safe_to_demo_auto_order === false &&
    safety.demo_auto_order === 'OUT_OF_SCOPE' &&
    isStringArray(safety.violations) &&
    summary.max_lot === 0.01 &&
    Array.isArray(performance.equity_curve) &&
    isRecord(performance.by_symbol) &&
    isRecord(performance.by_strategy) &&
    isRecord(value.readiness) &&
    isMarketRecord(value.market) &&
    recordsHaveStrings(value.watchlist, [
      'symbol',
      'asset_type',
      'market_status',
      'guard_status',
    ]) &&
    recordsHaveStrings(value.signals, ['id', 'source', 'data_freshness']) &&
    recordsHaveStrings(value.paper_orders, ['order_id']) &&
    isStringArray(decisionHealth.blockers) &&
    isStringArray(decisionReadiness.blockers) &&
    isRecord(session.progress) &&
    recordsHaveStrings(value.guards, ['key', 'label', 'status']) &&
    recordsHaveStrings(value.pair_rotation, ['symbol', 'role', 'status']) &&
    isRecordArray(value.strategies) &&
    value.strategies.every(
      (strategy) =>
        isNonEmptyString(strategy.strategy) &&
        isNonEmptyString(strategy.status) &&
        isRecord(strategy.performance),
    ) &&
    recordsHaveStrings(value.execution_cycle, ['key', 'label', 'state']) &&
    isRecord(value.decision_state_distribution) &&
    isRecord(value.scoring) &&
    isRecord(value.regime) &&
    isRecord(value.analytics) &&
    isNewsRecord(value.news) &&
    isRecord(value.source_contracts) &&
    recordsHaveStrings(value.activity, ['timestamp', 'category', 'title']) &&
    Object.values(sources).every(isRecord) &&
    isStringArray(value.warnings)
  )
}

const eventTypes = new Set([
  'connection.ready',
  'snapshot.full',
  'snapshot.updated',
  'market.updated',
  'signal.created',
  'signal.updated',
  'paper_order.updated',
  'decision_health.updated',
  'session.updated',
  'news.updated',
  'source.stale',
  'source.recovered',
  'safety.warning',
  'heartbeat',
  'error',
])

export const parseWebSocketEvent = (raw: string): DashboardWebSocketEvent | null => {
  try {
    const value: unknown = JSON.parse(raw)
    if (!isRecord(value)) return null
    if (
      typeof value.type !== 'string' ||
      !eventTypes.has(value.type) ||
      !isNonNegativeInteger(value.version) ||
      !isIsoTimestamp(value.timestamp)
    ) {
      return null
    }
    return value as unknown as DashboardWebSocketEvent
  } catch {
    return null
  }
}
