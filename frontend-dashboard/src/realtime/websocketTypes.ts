import { isNumber, isRecord, isString } from '../api/guards'

export type WebSocketConnectionState =
  | 'CONNECTING'
  | 'CONNECTED'
  | 'RECONNECTING'
  | 'DELAYED'
  | 'OFFLINE'
  | 'ERROR'

export type RealtimeEventType =
  | 'overview.updated'
  | 'kpi.updated'
  | 'market.quote.updated'
  | 'market.candle.updated'
  | 'signal.created'
  | 'signal.updated'
  | 'order.opened'
  | 'order.updated'
  | 'order.closed'
  | 'quality.updated'
  | 'risk.updated'
  | 'system.updated'
  | 'news.article.created'
  | 'news.article.updated'
  | 'news.breaking.created'
  | 'news.sentiment.updated'
  | 'news.symbol.sentiment.updated'
  | 'news.provider.status.updated'
  | 'news.cache.loaded'
  | 'news.freshness.updated'
  | 'news.provider.rate_limited'
  | 'news.provider.recovered'
  | 'news.provider.failed'
  | 'calendar.event.created'
  | 'calendar.event.updated'
  | 'calendar.event.countdown'
  | 'calendar.event.awaiting-release'
  | 'calendar.event.released'
  | 'calendar.event.revised'
  | 'calendar.event.rescheduled'
  | 'calendar.event.cancelled'
  | 'calendar.schedule.changed'
  | 'calendar.guard-preview.updated'
  | 'calendar.source.status.updated'
  | 'calendar.sync.completed'
  | 'calendar.sync.failed'
  | 'connection.ready'
  | 'connection.heartbeat'
  | 'connection.pong'
  | 'subscription.updated'
  | 'error'

export interface RealtimeEvent {
  type: RealtimeEventType
  channel: string
  timestamp: string
  sequence: number
  data: unknown
}

export interface ConnectionSnapshot {
  state: WebSocketConnectionState
  reconnectAttempt: number
  lastHeartbeatAt: string | null
  lastEventAt: string | null
  lastSuccessfulUpdate: string | null
  subscribedChannels: string[]
  retryAt: string | null
  error: string | null
}

const eventTypes = new Set<RealtimeEventType>([
  'overview.updated',
  'kpi.updated',
  'market.quote.updated',
  'market.candle.updated',
  'signal.created',
  'signal.updated',
  'order.opened',
  'order.updated',
  'order.closed',
  'quality.updated',
  'risk.updated',
  'system.updated',
  'news.article.created',
  'news.article.updated',
  'news.breaking.created',
  'news.sentiment.updated',
  'news.symbol.sentiment.updated',
  'news.provider.status.updated',
  'news.cache.loaded',
  'news.freshness.updated',
  'news.provider.rate_limited',
  'news.provider.recovered',
  'news.provider.failed',
  'calendar.event.created',
  'calendar.event.updated',
  'calendar.event.countdown',
  'calendar.event.awaiting-release',
  'calendar.event.released',
  'calendar.event.revised',
  'calendar.event.rescheduled',
  'calendar.event.cancelled',
  'calendar.schedule.changed',
  'calendar.guard-preview.updated',
  'calendar.source.status.updated',
  'calendar.sync.completed',
  'calendar.sync.failed',
  'connection.ready',
  'connection.heartbeat',
  'connection.pong',
  'subscription.updated',
  'error',
])

export const parseRealtimeEvent = (raw: unknown): RealtimeEvent | null => {
  let value: unknown = raw
  if (typeof raw === 'string') {
    try {
      value = JSON.parse(raw) as unknown
    } catch {
      return null
    }
  }
  if (!isRecord(value)) return null
  if (!isString(value.type) || !eventTypes.has(value.type as RealtimeEventType)) return null
  if (!isString(value.channel) || !isString(value.timestamp) || !isNumber(value.sequence)) return null
  if (!Number.isInteger(value.sequence) || value.sequence < 0 || Number.isNaN(Date.parse(value.timestamp))) return null
  return value as unknown as RealtimeEvent
}
