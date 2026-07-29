import type { RealtimeEventType } from './websocketTypes'

export type DashboardQueryKey =
  | 'overview'
  | 'performance'
  | 'market'
  | 'watchlist'
  | 'signals'
  | 'orders'
  | 'diagnostics'
  | 'risk'
  | 'quality'
  | 'system'
  | 'activity'
  | 'news'
  | 'newsSentiment'
  | 'newsTimeline'
  | 'economicCalendar'
  | 'economicCalendarSources'
  | 'economicCalendarStatus'
  | 'economicCalendarHealth'
  | 'economicCalendarGuard'
  | 'economicCalendarDiagnostic'
  | 'symbolNews'

export const queriesForEvent: Record<RealtimeEventType, DashboardQueryKey[]> = {
  'overview.updated': ['overview', 'diagnostics'],
  'kpi.updated': ['overview', 'performance', 'orders'],
  'market.quote.updated': ['market', 'watchlist'],
  'market.candle.updated': ['market', 'watchlist'],
  'signal.created': ['signals', 'diagnostics', 'activity'],
  'signal.updated': ['signals', 'diagnostics', 'activity'],
  'order.opened': ['orders', 'performance', 'overview', 'activity'],
  'order.updated': ['orders', 'performance', 'overview', 'activity'],
  'order.closed': ['orders', 'performance', 'overview', 'activity'],
  'quality.updated': ['quality', 'overview'],
  'risk.updated': ['risk'],
  'system.updated': ['system', 'activity'],
  'news.article.created': ['news', 'symbolNews'],
  'news.article.updated': ['news', 'symbolNews'],
  'news.breaking.created': ['news', 'symbolNews'],
  'news.sentiment.updated': ['newsSentiment', 'newsTimeline'],
  'news.symbol.sentiment.updated': ['newsSentiment', 'newsTimeline', 'symbolNews'],
  'news.provider.status.updated': ['news'],
  'news.cache.loaded': ['news'],
  'news.freshness.updated': ['news'],
  'news.provider.rate_limited': ['news'],
  'news.provider.recovered': ['news'],
  'news.provider.failed': ['news'],
  'calendar.event.created': ['economicCalendar'],
  'calendar.event.updated': ['economicCalendar'],
  'calendar.event.countdown': ['economicCalendar'],
  'calendar.event.awaiting-release': ['economicCalendar'],
  'calendar.event.released': ['economicCalendar'],
  'calendar.event.revised': ['economicCalendar'],
  'calendar.event.rescheduled': ['economicCalendar'],
  'calendar.event.cancelled': ['economicCalendar'],
  'calendar.schedule.changed': ['economicCalendar'],
  'calendar.guard-preview.updated': ['economicCalendarGuard', 'economicCalendarDiagnostic'],
  'calendar.source.status.updated': ['economicCalendarSources', 'economicCalendarHealth'],
  'calendar.sync.completed': ['economicCalendar', 'economicCalendarSources', 'economicCalendarStatus', 'economicCalendarHealth'],
  'calendar.sync.failed': ['economicCalendarStatus', 'economicCalendarHealth'],
  'connection.ready': [],
  'connection.heartbeat': [],
  'connection.pong': [],
  'subscription.updated': [],
  error: [],
}
