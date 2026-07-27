import assert from 'node:assert/strict'
import test from 'node:test'
import type { DashboardApiSnapshot } from '../src/types/dashboardApi.ts'
import {
  heartbeatIsExpired,
  shouldAcceptSnapshot,
  sourceModeFor,
} from '../src/utils/realtimePolicy.ts'

const snapshot = (
  version: number,
  sourceUpdatedAt = '2026-07-27T12:00:00.000Z',
): DashboardApiSnapshot =>
  ({
    version,
    source_updated_at: sourceUpdatedAt,
    connection: { stale: false },
  }) as DashboardApiSnapshot

test('snapshot admission hanya menerima versi yang meningkat', () => {
  const current = snapshot(7)
  assert.equal(shouldAcceptSnapshot(null, current), true)
  assert.equal(shouldAcceptSnapshot(current, snapshot(8)), true)
  assert.equal(shouldAcceptSnapshot(current, snapshot(7)), false)
  assert.equal(shouldAcceptSnapshot(current, snapshot(6)), false)
})

test('watchdog heartbeat memakai heartbeat, bukan event lain', () => {
  const nowMs = Date.parse('2026-07-27T12:01:00.000Z')
  assert.equal(
    heartbeatIsExpired({
      transport: 'connected',
      lastHeartbeatAt: '2026-07-27T12:00:20.000Z',
      connectedAtMs: nowMs - 1_000,
      nowMs,
    }),
    true,
  )
})

test('watchdog memberi grace period sejak koneksi dibuat', () => {
  const nowMs = Date.parse('2026-07-27T12:01:00.000Z')
  assert.equal(
    heartbeatIsExpired({
      transport: 'connected',
      lastHeartbeatAt: null,
      connectedAtMs: nowMs - 10_000,
      nowMs,
    }),
    false,
  )
  assert.equal(
    heartbeatIsExpired({
      transport: 'connected',
      lastHeartbeatAt: null,
      connectedAtMs: nowMs - 40_000,
      nowMs,
    }),
    true,
  )
})

test('timestamp heartbeat terlalu jauh di masa depan ditolak', () => {
  const nowMs = Date.parse('2026-07-27T12:01:00.000Z')
  assert.equal(
    heartbeatIsExpired({
      transport: 'connected',
      lastHeartbeatAt: '2026-07-27T12:03:00.000Z',
      connectedAtMs: nowMs,
      nowMs,
    }),
    true,
  )
})

test('mode sumber fail-closed untuk waktu sumber invalid dan stale', () => {
  const nowMs = Date.parse('2026-07-27T12:01:00.000Z')
  const common = {
    transport: 'connected' as const,
    mockFallback: false,
    heartbeatExpired: false,
    nowMs,
    staleAfterMs: 180_000,
  }
  assert.equal(sourceModeFor({ ...common, snapshot: snapshot(1, 'invalid') }), 'STALE')
  assert.equal(
    sourceModeFor({ ...common, snapshot: snapshot(1, '2026-07-27T11:55:00.000Z') }),
    'STALE',
  )
  assert.equal(
    sourceModeFor({ ...common, snapshot: snapshot(1, '2026-07-27T12:00:00.000Z') }),
    'REALTIME',
  )
})
