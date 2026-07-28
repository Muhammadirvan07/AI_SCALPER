import assert from 'node:assert/strict'
import test from 'node:test'
import type { DashboardApiSnapshot } from '../src/types/dashboardApi.ts'
import {
  buildOperationalActivity,
  deriveNetR,
  deriveRecommendedAction,
  deriveSampleStatus,
  operationalTone,
} from '../src/utils/landingViewModel.ts'

const snapshot = () => ({
  version: 9,
  generated_at: '2026-07-27T12:00:00.000Z',
  source_updated_at: '2026-07-27T11:59:59.000Z',
  connection: { status: 'connected', stale_source_count: 0 },
  safety: { safety_violation: false, violations: [] },
  summary: { closed_target: 50 },
  performance: { closed_orders: 2 },
  paper_orders: [
    { status: 'PAPER_WIN', close_time: '2026-07-27T11:00:00Z', r_multiple: 1.25 },
    { status: 'PAPER_LOSS', close_time: '2026-07-27T11:30:00Z', r_multiple: -0.5 },
  ],
  project_progress: {
    observation_window_status: 'BLIND_OBSERVATION_ACTIVE',
    blind_until: '2099-09-21T15:00:00.000Z',
    blockers: ['WINDOWS_HARDENING_REQUIRED'],
    promotion_eligible: false,
    promotion_reason: 'Gate eksternal belum lulus.',
  },
  source_contracts: {},
  activity: [],
}) as unknown as DashboardApiSnapshot

test('net R hanya dihitung bila setiap order tertutup memiliki evidence R', () => {
  const complete = snapshot()
  assert.equal(deriveNetR(complete).value, 0.75)

  const incomplete = snapshot()
  incomplete.paper_orders[1].r_multiple = null
  assert.equal(deriveNetR(incomplete).value, null)
})

test('sample status tidak memberi kesan siap ketika target belum tercapai', () => {
  assert.equal(deriveSampleStatus(snapshot()), 'SAMPEL BELUM CUKUP · 2/50')
  assert.equal(deriveSampleStatus(null), 'TIDAK TERVERIFIKASI')
})

test('sample status fail-closed ketika metrik wajib hilang atau invalid', () => {
  const missingClosed = snapshot()
  Reflect.deleteProperty(missingClosed.performance, 'closed_orders')
  assert.equal(deriveSampleStatus(missingClosed), 'TIDAK TERVERIFIKASI')
  assert.equal(deriveNetR(missingClosed).expectedCount, null)

  const invalidClosed = snapshot()
  invalidClosed.performance.closed_orders = Number.NaN
  assert.equal(deriveSampleStatus(invalidClosed), 'TIDAK TERVERIFIKASI')
})

test('target total tidak menyamarkan clean sample gate yang masih diblokir', () => {
  const candidate = snapshot()
  candidate.summary.closed_target = 2
  candidate.project_progress.blockers = ['clean_sample_target_met']
  assert.equal(
    deriveSampleStatus(candidate),
    'TOTAL CLOSED 2/2 · CLEAN SAMPLE BELUM LULUS',
  )
})

test('langkah berikutnya fail-closed saat snapshot tidak tersedia', () => {
  const action = deriveRecommendedAction(null, 'DISCONNECTED')
  assert.equal(action.tone, 'blocked')
  assert.match(action.title, /Pulihkan jalur observasi/)
})

test('observation window aktif lebih diprioritaskan daripada promosi', () => {
  const action = deriveRecommendedAction(snapshot(), 'REALTIME')
  assert.equal(action.tone, 'warning')
  assert.match(action.title, /observation window/i)
})

test('status verified-ineligible tidak pernah diberi tone sehat', () => {
  assert.equal(operationalTone('VERIFIED_INELIGIBLE_CURRENT_JAPAN'), 'blocked')
})

test('status negatif majemuk tidak mewarisi tone dari substring positif', () => {
  assert.equal(operationalTone('DEMO_AUTO_ORDER_NOT_READY'), 'blocked')
  assert.equal(operationalTone('INACTIVE'), 'blocked')
  assert.equal(operationalTone('READY'), 'safe')
  assert.equal(operationalTone('ACTIVE'), 'safe')
})

test('timeline hanya dibuat dari timestamp dan evidence aktual', () => {
  const items = buildOperationalActivity(snapshot(), {
    transportState: 'connected',
    sourceMode: 'REALTIME',
    lastEventAt: '2026-07-27T12:00:01.000Z',
    lastHeartbeatAt: '2026-07-27T12:00:00.000Z',
    lastSourceUpdateAt: '2026-07-27T11:59:59.000Z',
    latencyMs: 2,
    snapshotVersion: 9,
    staleSourceCount: 0,
    socketActive: true,
    reconnectAttempt: 0,
  })
  assert.equal(items.some((item) => item.title.includes('Snapshot v9')), true)
  assert.equal(items.some((item) => item.title.includes('Heartbeat')), true)
})
