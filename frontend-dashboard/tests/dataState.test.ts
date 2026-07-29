import assert from 'node:assert/strict'
import test from 'node:test'
import { dataMode, panelStateFor } from '../src/utils/apiDisplay.ts'
import type { ApiMeta } from '../src/api/types.ts'

const connection = {
  state: 'CONNECTED' as const,
  reconnectAttempt: 0,
  lastHeartbeatAt: null,
  lastEventAt: null,
  lastSuccessfulUpdate: null,
  subscribedChannels: [],
  retryAt: null,
  error: null,
}
const meta: ApiMeta = { source_updated_at: null, server_timestamp: '2026-07-29T00:00:00Z', age_seconds: null, stale: false, source_available: true, source: null, request_id: null, data_status: 'live', warnings: [] }

test('stale backend tidak pernah dilabeli LIVE', () => {
  assert.equal(dataMode({ ...meta, stale: true }, connection), 'STALE')
  assert.equal(dataMode(meta, { ...connection, state: 'RECONNECTING' }), 'DELAYED')
  assert.equal(dataMode(meta, { ...connection, state: 'OFFLINE' }), 'OFFLINE')
  assert.equal(dataMode({ ...meta, source_available: false }, connection), 'UNAVAILABLE')
})

test('resource dengan data lama tetap membedakan partial dan stale', () => {
  assert.equal(panelStateFor({ data: { value: 1 }, meta: { ...meta, stale: true }, status: 'success', error: null }), 'stale')
  assert.equal(panelStateFor({ data: null, meta: null, status: 'loading', error: null }), 'loading')
})
