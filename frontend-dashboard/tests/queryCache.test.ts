import assert from 'node:assert/strict'
import test from 'node:test'
import { QueryCache } from '../src/api/cache.ts'

const response = {
  success: true as const,
  data: { value: 1 },
  meta: {
    source_updated_at: null,
    server_timestamp: '2026-07-29T00:00:00Z',
    age_seconds: null,
    stale: false,
    source_available: true,
    source: 'test',
    request_id: null,
    data_status: 'live',
    warnings: [],
  },
}

test('query cache mengembalikan clone dan mendukung invalidasi domain', () => {
  const cache = new QueryCache()
  cache.set('market:EURUSD', response, 10_000)
  const first = cache.get<{ value: number }>('market:EURUSD')
  assert.equal(first?.data.value, 1)
  if (first) first.data.value = 99
  assert.equal(cache.get<{ value: number }>('market:EURUSD')?.data.value, 1)
  cache.invalidate('market')
  assert.equal(cache.get('market:EURUSD'), null)
})
