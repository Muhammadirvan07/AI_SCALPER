import type {
  NewsArticle,
  NewsPage,
  NewsProviderStatus,
  NewsSentimentAggregate,
  NewsSentimentTimeline,
  NewsStatus,
  SymbolNewsSummary,
} from '../types/news'
import { apiClient } from './client'
import { endpoints } from './endpoints'
import { hasRequiredKeys, isBoolean, isNumber, isPageData, isRecord, isString } from './guards'

export const isNewsArticleData = (value: unknown): value is NewsArticle =>
  hasRequiredKeys(value, ['id', 'provider', 'title', 'url', 'sentiment', 'impact', 'symbols', 'stale']) &&
  isString(value.id) && isString(value.title) && isString(value.url) && isRecord(value.sentiment) &&
  Array.isArray(value.symbols) && isBoolean(value.stale)

export const isNewsPageData = (value: unknown): value is NewsPage =>
  isPageData(value) && value.items.every(isNewsArticleData)

export const isNewsSentimentData = (value: unknown): value is NewsSentimentAggregate =>
  hasRequiredKeys(value, ['scope', 'range', 'article_count', 'bullish_count', 'bearish_count', 'neutral_count', 'trend']) &&
  isString(value.scope) && isNumber(value.article_count)

const isTimeline = (value: unknown): value is NewsSentimentTimeline =>
  hasRequiredKeys(value, ['range', 'items', 'aggregate']) && isString(value.range) && Array.isArray(value.items) &&
  value.items.every((item) => hasRequiredKeys(item, ['timestamp', 'score', 'article_count'])) && isNewsSentimentData(value.aggregate)

const isProviders = (value: unknown): value is NewsProviderStatus[] =>
  Array.isArray(value) && value.every((item) => hasRequiredKeys(item, ['name', 'enabled', 'configured', 'healthy', 'status', 'article_count']))

const isNewsStatus = (value: unknown): value is NewsStatus =>
  hasRequiredKeys(value, ['enabled', 'state', 'article_count', 'analyzer', 'scheduler_running', 'live_allowed', 'effective_max_lot']) &&
  isBoolean(value.enabled) && isString(value.state) && isNumber(value.article_count)

const isSymbolSummary = (value: unknown): value is SymbolNewsSummary =>
  hasRequiredKeys(value, ['symbol', 'latest', 'sentiment', 'upcoming_events']) && isString(value.symbol) &&
  Array.isArray(value.latest) && value.latest.every(isNewsArticleData) && isNewsSentimentData(value.sentiment) && Array.isArray(value.upcoming_events)

export const getLatestNews = (limit = 60, signal?: AbortSignal) =>
  apiClient.get(`${endpoints.newsLatest}?limit=${limit}&offset=0&freshness=live&fallback=none`, { signal, validate: isNewsPageData })

export const getRecentNews = (limit = 60, signal?: AbortSignal) =>
  apiClient.get(`${endpoints.news}?limit=${limit}&offset=0&freshness=recent&fallback=none`, { signal, validate: isNewsPageData })

export const getBreakingNews = (limit = 20, signal?: AbortSignal) =>
  apiClient.get(`${endpoints.newsBreaking}?limit=${limit}&offset=0`, { signal, validate: isNewsPageData })

export const getNewsSentiment = (range = '24h', symbol?: string | null, signal?: AbortSignal) => {
  const params = new URLSearchParams({ range })
  if (symbol) params.set('symbol', symbol)
  return apiClient.get(`${endpoints.newsSentiment}?${params}`, { signal, validate: isNewsSentimentData })
}

export const getNewsSentimentTimeline = (range = '24h', symbol?: string | null, signal?: AbortSignal) => {
  const params = new URLSearchParams({ range })
  if (symbol) params.set('symbol', symbol)
  return apiClient.get(`${endpoints.newsSentimentTimeline}?${params}`, { signal, validate: isTimeline })
}

export const getNewsProviders = (signal?: AbortSignal) =>
  apiClient.get(endpoints.newsProviders, { signal, validate: isProviders })

export const getNewsStatus = (signal?: AbortSignal) =>
  apiClient.get(endpoints.newsStatus, { signal, validate: isNewsStatus })

export const getSymbolNewsSummary = (symbol: string, signal?: AbortSignal) =>
  apiClient.get(endpoints.newsSymbolSummary(symbol), { signal, validate: isSymbolSummary })
