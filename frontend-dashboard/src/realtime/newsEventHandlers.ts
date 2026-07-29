import type { RealtimeEvent } from './websocketTypes'

export const isNewsRealtimeEvent = (event: RealtimeEvent) => event.type.startsWith('news.')

export const newsResourceKeysForEvent = (event: RealtimeEvent) => {
  if (event.type === 'news.sentiment.updated' || event.type === 'news.symbol.sentiment.updated') return ['newsSentiment', 'symbolNews'] as const
  if (event.type === 'news.provider.status.updated' || event.type === 'news.provider.rate_limited' || event.type === 'news.provider.recovered' || event.type === 'news.provider.failed') return ['newsProviders', 'newsStatus'] as const
  return ['news', 'recentNews', 'breakingNews', 'symbolNews'] as const
}
