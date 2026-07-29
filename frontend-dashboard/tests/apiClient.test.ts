import assert from 'node:assert/strict'
import test from 'node:test'
import { ApiClient, ApiClientError } from '../src/api/client.ts'
import { hasRequiredKeys } from '../src/api/guards.ts'

const meta = {
  source_updated_at: null,
  server_timestamp: '2026-07-29T00:00:00Z',
  age_seconds: null,
  stale: true,
  source_available: true,
  source: 'test.json',
  request_id: 'request-1',
  data_status: 'stale',
  warnings: [],
}

const response = (body: unknown, status = 200) => new Response(JSON.stringify(body), {
  status,
  headers: { 'content-type': 'application/json', 'x-request-id': 'header-request' },
})

test('API client menerima success response, null field, dan stale metadata', async () => {
  const fetcher = (async () => response({ success: true, data: { equity: null }, meta })) as typeof fetch
  const client = new ApiClient('http://test/api/v1', 50, 0, fetcher)
  const result = await client.get('/overview', { validate: (value): value is { equity: null } => hasRequiredKeys(value, ['equity']) })
  assert.equal(result.data.equity, null)
  assert.equal(result.meta.stale, true)
})

test('API client memanggil native fetch dengan receiver global yang valid', async () => {
  const receiverAwareFetcher = function (this: typeof globalThis) {
    assert.equal(this, globalThis)
    return Promise.resolve(response({ success: true, data: { status: 'healthy' }, meta }))
  } as typeof fetch
  const client = new ApiClient('http://test/api/v1', 50, 0, receiverAwareFetcher)
  const result = await client.get('/health', {
    validate: (value): value is { status: string } => hasRequiredKeys(value, ['status']),
  })
  assert.equal(result.data.status, 'healthy')
})

test('API client hanya mengirim GET tanpa request body', async () => {
  let observed: RequestInit | undefined
  const fetcher = (async (_input: RequestInfo | URL, init?: RequestInit) => {
    observed = init
    return response({ success: true, data: { status: 'healthy' }, meta })
  }) as typeof fetch
  const client = new ApiClient('http://test/api/v1', 50, 0, fetcher)
  await client.get('/health', { validate: (value): value is object => typeof value === 'object' && value !== null })
  assert.equal(observed?.method, 'GET')
  assert.equal(observed?.body, undefined)
  assert.equal('post' in client, false)
})

test('API client membedakan HTTP 503 unavailable', async () => {
  const fetcher = (async () => response({ success: false, error: { code: 'DATA_SOURCE_UNAVAILABLE', message: 'Unavailable' }, meta: { timestamp: meta.server_timestamp } }, 503)) as typeof fetch
  const client = new ApiClient('http://test/api/v1', 50, 0, fetcher)
  await assert.rejects(
    () => client.get('/overview', { validate: (value): value is object => typeof value === 'object' && value !== null }),
    (error: unknown) => error instanceof ApiClientError && error.kind === 'unavailable',
  )
})

test('API client menolak response malformed', async () => {
  const fetcher = (async () => response({ success: true, data: {}, meta: { stale: false } })) as typeof fetch
  const client = new ApiClient('http://test/api/v1', 50, 0, fetcher)
  await assert.rejects(
    () => client.get('/overview', { validate: (value): value is object => typeof value === 'object' && value !== null }),
    (error: unknown) => error instanceof ApiClientError && error.kind === 'invalid-response',
  )
})

test('API client menormalisasi network error dan timeout', async () => {
  const networkClient = new ApiClient('http://test/api/v1', 50, 0, (async () => { throw new TypeError('offline') }) as typeof fetch)
  await assert.rejects(
    () => networkClient.get('/overview', { validate: (value): value is object => typeof value === 'object' && value !== null }),
    (error: unknown) => error instanceof ApiClientError && error.kind === 'network',
  )

  const timeoutFetcher = ((_input: RequestInfo | URL, init?: RequestInit) => new Promise<Response>((_resolve, reject) => {
    init?.signal?.addEventListener('abort', () => reject(new DOMException('aborted', 'AbortError')), { once: true })
  })) as typeof fetch
  const timeoutClient = new ApiClient('http://test/api/v1', 5, 0, timeoutFetcher)
  await assert.rejects(
    () => timeoutClient.get('/overview', { validate: (value): value is object => typeof value === 'object' && value !== null }),
    (error: unknown) => error instanceof ApiClientError && error.kind === 'timeout',
  )
})
