import assert from 'node:assert/strict'
import test from 'node:test'
import { SharedWebSocketClient } from '../src/realtime/websocketClient.ts'
import { parseRealtimeEvent, type ConnectionSnapshot, type RealtimeEvent } from '../src/realtime/websocketTypes.ts'

class FakeSocket {
  readyState = 0
  onopen: (() => void) | null = null
  onmessage: ((event: { data: unknown }) => void) | null = null
  onerror: (() => void) | null = null
  onclose: (() => void) | null = null
  sent: string[] = []
  send(data: string) { this.sent.push(data) }
  open() { this.readyState = 1; this.onopen?.() }
  message(data: unknown) { this.onmessage?.({ data }) }
  close() { this.readyState = 3; this.onclose?.() }
}

const event = (sequence: number, type = 'connection.heartbeat') => JSON.stringify({
  type,
  channel: 'connection',
  timestamp: `2026-07-29T00:00:0${sequence}Z`,
  sequence,
  data: {},
})

test('parser WebSocket menolak event invalid', () => {
  assert.equal(parseRealtimeEvent('{invalid'), null)
  assert.equal(parseRealtimeEvent(JSON.stringify({ type: 'unknown', sequence: 1 })), null)
})

test('shared client connect, subscribe, unsubscribe, heartbeat, dedupe, dan cleanup', () => {
  const sockets: FakeSocket[] = []
  const received: RealtimeEvent[] = []
  const states: ConnectionSnapshot[] = []
  const client = new SharedWebSocketClient({
    url: 'ws://test/ws',
    createSocket: () => { const socket = new FakeSocket(); sockets.push(socket); return socket },
    onEvent: (item) => received.push(item),
    onConnectionChange: (state) => states.push(state),
    pingIntervalMs: 60_000,
  })
  client.start()
  sockets[0]?.open()
  client.setMarketSymbol('EURUSD')
  client.setMarketSymbol('EURUSD')
  client.unsubscribe(['activity'])
  sockets[0]?.message(event(1))
  sockets[0]?.message(event(1))
  sockets[0]?.message('{bad')

  const messages = sockets[0]?.sent.map((item) => JSON.parse(item) as { action: string; channels: string[] }) ?? []
  assert.equal(states.some((state) => state.state === 'CONNECTED'), true)
  assert.equal(messages.some((item) => item.action === 'subscribe' && item.channels.includes('market:EURUSD')), true)
  assert.equal(messages.some((item) => item.action === 'subscribe' && item.channels.includes('news:symbol:EURUSD')), true)
  assert.equal(messages.some((item) => item.action === 'subscribe' && item.channels.includes('news:breaking')), true)
  assert.equal(messages.filter((item) => item.channels.includes('market:EURUSD')).length, 1)
  assert.equal(messages.some((item) => item.action === 'unsubscribe' && item.channels.includes('activity')), true)
  assert.equal(received.length, 1)
  assert.equal(states.at(-1)?.error, 'Event WebSocket invalid diabaikan.')
  client.stop()
  assert.equal(sockets[0]?.readyState, 3)
})

test('parser menerima event News Intelligence dan menolak sequence invalid', () => {
  const news = parseRealtimeEvent(JSON.stringify({ type: 'news.article.created', channel: 'news', timestamp: '2026-07-29T00:00:00Z', sequence: 11, data: { article_id: 'one' } }))
  assert.equal(news?.type, 'news.article.created')
  assert.equal(parseRealtimeEvent(JSON.stringify({ type: 'news.article.created', channel: 'news', timestamp: 'bad', sequence: -1, data: {} })), null)
})

test('shared client reconnect memakai backoff dan connection baru', async () => {
  const sockets: FakeSocket[] = []
  const client = new SharedWebSocketClient({
    url: 'ws://test/ws',
    createSocket: () => { const socket = new FakeSocket(); sockets.push(socket); return socket },
    onEvent: () => undefined,
    onConnectionChange: () => undefined,
    maximumReconnectDelayMs: 1,
    pingIntervalMs: 60_000,
  })
  client.start()
  sockets[0]?.open()
  sockets[0]?.close()
  await new Promise((resolve) => setTimeout(resolve, 5))
  assert.equal(sockets.length, 2)
  client.stop()
})
