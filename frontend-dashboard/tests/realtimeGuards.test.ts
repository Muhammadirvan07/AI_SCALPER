import assert from 'node:assert/strict'
import test from 'node:test'
import {
  isDashboardSnapshot,
  parseWebSocketEvent,
} from '../src/utils/realtimeGuards.ts'

const validSnapshot = () => ({
  schema_version: '1.1',
  snapshot_id: 'snapshot-1',
  version: 1,
  generated_at: '2026-07-27T12:00:00.000Z',
  source_updated_at: '2026-07-27T11:59:59.000Z',
  connection: {
    status: 'connected',
    mode: 'realtime_file_watch',
    latency_ms: 4,
    stale: false,
    watcher_running: true,
    snapshot_version: 1,
    stale_source_count: 0,
  },
  safety: {
    live_allowed: false,
    live_trading: 'LOCKED',
    display_status: 'PAPER ONLY',
    mode: 'PAPER',
    paper_trading: 'ACTIVE',
    max_lot: 0.01,
    safe_to_demo_observe: true,
    safe_to_demo_auto_order: false,
    demo_auto_order: 'OUT_OF_SCOPE',
    bridge_mode: null,
    guard_enabled: true,
    safety_violation: false,
    violations: [],
  },
  summary: { max_lot: 0.01 },
  performance: { equity_curve: [], by_symbol: {}, by_strategy: {} },
  readiness: {},
  market: {},
  watchlist: [],
  signals: [],
  paper_orders: [],
  decision_health: { blockers: [] },
  decision_readiness: { blockers: [] },
  session: { progress: {} },
  guards: [],
  pair_rotation: [],
  strategies: [],
  execution_cycle: [],
  decision_state_distribution: {},
  scoring: {},
  regime: {},
  analytics: {},
  news: { events: [], pair_impacts: [] },
  source_contracts: {},
  activity: [],
  sources: {},
  warnings: [],
})

test('guard menerima kontrak minimum yang aman', () => {
  assert.equal(isDashboardSnapshot(validSnapshot()), true)
})

test('guard menolak snapshot yang mengaktifkan demo auto order', () => {
  const candidate = validSnapshot()
  candidate.safety.safe_to_demo_auto_order = true
  assert.equal(isDashboardSnapshot(candidate), false)
})

test('guard menolak struktur wajib yang hilang atau malformed', () => {
  const missingNews = validSnapshot()
  Reflect.deleteProperty(missingNews, 'news')
  assert.equal(isDashboardSnapshot(missingNews), false)

  const malformedStrategy = validSnapshot()
  malformedStrategy.strategies.push({ strategy: 'trend' })
  assert.equal(isDashboardSnapshot(malformedStrategy), false)
})

test('guard menolak timestamp snapshot invalid', () => {
  const candidate = validSnapshot()
  candidate.generated_at = 'kemarin'
  assert.equal(isDashboardSnapshot(candidate), false)
})

test('parser WebSocket menolak versi dan timestamp invalid', () => {
  assert.equal(
    parseWebSocketEvent(JSON.stringify({
      type: 'heartbeat',
      version: 1.5,
      timestamp: '2026-07-27T12:00:00.000Z',
      payload: {},
    })),
    null,
  )
  assert.equal(
    parseWebSocketEvent(JSON.stringify({
      type: 'heartbeat',
      version: 1,
      timestamp: 'invalid',
      payload: {},
    })),
    null,
  )
})
