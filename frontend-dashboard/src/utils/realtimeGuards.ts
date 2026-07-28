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

const isNullableString = (value: unknown): value is string | null =>
  value === null || typeof value === 'string'

const isNullableBoolean = (value: unknown): value is boolean | null =>
  value === null || typeof value === 'boolean'

const isNullableNonNegativeInteger = (value: unknown): value is number | null =>
  value === null || isNonNegativeInteger(value)

const isNullableFiniteNumber = (value: unknown): value is number | null =>
  value === null || isFiniteNumber(value)

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

const isSummary = (value: unknown) => {
  if (!isRecord(value)) return false
  return (
    isNullableString(value.system_mode) &&
    isNullableString(value.quality_status) &&
    isNullableFiniteNumber(value.readiness_score) &&
    isStringArray(value.active_pairs) &&
    isNullableNonNegativeInteger(value.closed_orders) &&
    isNullableNonNegativeInteger(value.closed_target) &&
    isNullableFiniteNumber(value.win_rate) &&
    isNullableFiniteNumber(value.profit_factor) &&
    isNullableFiniteNumber(value.expectancy) &&
    isNullableFiniteNumber(value.net_profit) &&
    isNullableFiniteNumber(value.max_drawdown) &&
    isNullableFiniteNumber(value.reference_balance) &&
    value.max_lot === 0.01
  )
}

const isEquityPoint = (value: unknown) =>
  isRecord(value) &&
  isNonNegativeInteger(value.index) &&
  isNullableIsoTimestamp(value.timestamp) &&
  isFiniteNumber(value.equity) &&
  isFiniteNumber(value.cumulative_net_profit) &&
  isNullableFiniteNumber(value.drawdown_percent) &&
  isNullableString(value.order_id)

const recordValuesAreRecords = (value: unknown) =>
  isRecord(value) && Object.values(value).every(isRecord)

const isPerformance = (value: unknown) => {
  if (!isRecord(value)) return false
  const countFields = [
    'total_orders',
    'closed_orders',
    'open_orders',
    'wins',
    'losses',
    'timeouts',
  ] as const
  const metricFields = [
    'win_rate',
    'gross_profit',
    'gross_loss',
    'net_profit',
    'profit_factor',
    'expectancy',
    'max_drawdown_percent',
    'reference_balance',
    'ending_balance',
  ] as const
  return (
    countFields.every((field) => isNullableNonNegativeInteger(value[field])) &&
    metricFields.every((field) => isNullableFiniteNumber(value[field])) &&
    Array.isArray(value.equity_curve) &&
    value.equity_curve.every(isEquityPoint) &&
    recordValuesAreRecords(value.by_symbol) &&
    recordValuesAreRecords(value.by_strategy)
  )
}

const isPaperOrder = (value: unknown) =>
  isRecord(value) &&
  isNonEmptyString(value.order_id) &&
  isNullableIsoTimestamp(value.close_time) &&
  isNullableString(value.status) &&
  isNullableFiniteNumber(value.r_multiple)

const sourceStates = new Set(['fresh', 'stale', 'partial', 'unavailable', 'invalid'])

const isSourceState = (value: unknown) =>
  typeof value === 'string' && sourceStates.has(value)

const isEvidenceGate = (value: unknown) =>
  isRecord(value) &&
  isNonEmptyString(value.key) &&
  isNonEmptyString(value.label) &&
  ['PASSED', 'BLOCKED', 'WAIT', 'UNVERIFIED'].includes(String(value.status)) &&
  isNullableBoolean(value.passed) &&
  isNonEmptyString(value.source) &&
  isNullableString(value.reason)

const isProjectProgress = (value: unknown) =>
  isRecord(value) &&
  isNullableString(value.stage) &&
  isNonEmptyString(value.status) &&
  isSourceState(value.source_status) &&
  isNullableNonNegativeInteger(value.gates_passed) &&
  isNullableNonNegativeInteger(value.gates_total) &&
  Array.isArray(value.gates) &&
  value.gates.every(isEvidenceGate) &&
  isStringArray(value.milestones_completed) &&
  isStringArray(value.blockers) &&
  isNullableIsoTimestamp(value.observation_start_at) &&
  isNullableIsoTimestamp(value.blind_until) &&
  isNonEmptyString(value.observation_window_status) &&
  isNullableNonNegativeInteger(value.expected_complete_sessions) &&
  isNullableBoolean(value.promotion_eligible) &&
  isNullableString(value.promotion_reason) &&
  isStringArray(value.sources)

const isBrokerReadiness = (value: unknown) =>
  isRecord(value) &&
  isNonEmptyString(value.candidate_id) &&
  isNonEmptyString(value.display_name) &&
  isNullableString(value.role) &&
  isNullableString(value.environment) &&
  isNullableString(value.server) &&
  isNullableString(value.account_type) &&
  isNullableString(value.account_currency) &&
  isNullableString(value.leverage) &&
  isRecord(value.symbols_found) &&
  Object.values(value.symbols_found).every((symbol) => typeof symbol === 'string') &&
  isNonEmptyString(value.discovery) &&
  isNonEmptyString(value.regulatory_evidence) &&
  isNonEmptyString(value.calendar_review) &&
  isNonEmptyString(value.contract_registration) &&
  isNonEmptyString(value.shadow_runtime) &&
  isNonEmptyString(value.demo_auto_order_eligibility) &&
  isNonEmptyString(value.live_eligibility) &&
  isNullableBoolean(value.promotion_eligible) &&
  isNullableIsoTimestamp(value.observation_start_at) &&
  isNullableIsoTimestamp(value.blind_until) &&
  isNullableNonNegativeInteger(value.expected_complete_sessions) &&
  isSourceState(value.source_status) &&
  isStringArray(value.sources)

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
    value.schema_version === '1.2' &&
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
    isNullableString(safety.order_capability) &&
    isStringArray(safety.violations) &&
    isSummary(summary) &&
    isPerformance(performance) &&
    isRecord(value.readiness) &&
    isMarketRecord(value.market) &&
    recordsHaveStrings(value.watchlist, [
      'symbol',
      'asset_type',
      'market_status',
      'guard_status',
    ]) &&
    recordsHaveStrings(value.signals, ['id', 'source', 'data_freshness']) &&
    Array.isArray(value.paper_orders) &&
    value.paper_orders.every(isPaperOrder) &&
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
    isProjectProgress(value.project_progress) &&
    Array.isArray(value.broker_readiness) &&
    value.broker_readiness.every(isBrokerReadiness) &&
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
