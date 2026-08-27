import assert from 'node:assert/strict'
import test from 'node:test'
import {
  LOOPBACK_API_ORIGINS,
  LOOPBACK_WS_ORIGINS,
  validateLoopbackServiceUrl,
} from '../src/config/loopbackOrigins'

test('loopback service URLs accept only the origins permitted by dashboard CSP', () => {
  assert.equal(
    validateLoopbackServiceUrl('VITE_API_BASE_URL', 'http://127.0.0.1:8000/api/v1/'),
    'http://127.0.0.1:8000/api/v1',
  )
  assert.equal(
    validateLoopbackServiceUrl('VITE_WS_URL', 'ws://localhost:8000/api/v1/ws'),
    'ws://localhost:8000/api/v1/ws',
  )
  assert.deepEqual(LOOPBACK_API_ORIGINS, ['http://127.0.0.1:8000', 'http://localhost:8000'])
  assert.deepEqual(LOOPBACK_WS_ORIGINS, ['ws://127.0.0.1:8000', 'ws://localhost:8000'])
})

test('loopback service URLs fail closed for remote, credentialed, and unexpected ports', () => {
  assert.throws(
    () => validateLoopbackServiceUrl('VITE_API_BASE_URL', 'https://api.example.com/api/v1'),
    /harus memakai service loopback/,
  )
  assert.throws(
    () => validateLoopbackServiceUrl('VITE_API_BASE_URL', 'http://user:secret@localhost:8000/api/v1'),
    /harus memakai service loopback/,
  )
  assert.throws(
    () => validateLoopbackServiceUrl('VITE_WS_URL', 'ws://127.0.0.1:9000/api/v1/ws'),
    /harus memakai service loopback/,
  )
  assert.throws(
    () => validateLoopbackServiceUrl('VITE_WS_URL', 'not-a-url'),
    /bukan URL yang valid/,
  )
})
