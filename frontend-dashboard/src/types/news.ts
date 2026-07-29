import type { Page } from '../api/types'
import type { EconomicCalendarEvent } from './economicCalendar'

export type NewsSentimentLabel = 'VERY_BEARISH' | 'BEARISH' | 'NEUTRAL' | 'BULLISH' | 'VERY_BULLISH' | 'UNKNOWN'
export type NewsImpact = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' | 'UNKNOWN'
export type NewsFreshnessStatus = 'REALTIME' | 'RECENT' | 'HISTORICAL' | 'UNKNOWN'
export type NewsCategory = 'CENTRAL_BANK' | 'INTEREST_RATE' | 'INFLATION' | 'EMPLOYMENT' | 'GDP' | 'FOREX' | 'COMMODITIES' | 'GOLD' | 'SILVER' | 'CRYPTO' | 'EQUITIES' | 'GEOPOLITICS' | 'REGULATION' | 'ENERGY' | 'MARKET_ANALYSIS' | 'GENERAL'

export interface NewsSentimentResult {
  label: NewsSentimentLabel
  score: number | null
  confidence: number | null
  analyzer: string
  positive_probability: number | null
  neutral_probability: number | null
  negative_probability: number | null
  matched_terms: string[]
}

export interface NewsProviderSentiment {
  provider: string
  raw_label: string | null
  raw_score: number | null
  normalized_score: number | null
  normalized_confidence: number | null
}

export interface NewsRelevance {
  symbol: string
  relevance_score: number
  matched_terms: string[]
  breakdown: Record<string, number>
}

export interface NewsArticle {
  id: string
  provider: string
  source: string | null
  source_domain: string | null
  title: string
  summary: string | null
  url: string
  image_url: string | null
  author: string | null
  published_at: string | null
  fetched_at: string
  language: string
  category: NewsCategory
  symbols: string[]
  currencies: string[]
  countries: string[]
  topics: string[]
  sentiment: NewsSentimentResult
  provider_sentiment: NewsProviderSentiment | null
  sentiment_score: number | null
  sentiment_confidence: number | null
  impact: NewsImpact
  impact_score: number | null
  impact_breakdown: Record<string, number>
  relevance_score: number
  relevance: NewsRelevance[]
  is_breaking: boolean
  is_duplicate: boolean
  duplicate_group_id: string | null
  canonical_article_id: string | null
  age_hours: number | null
  freshness_status: NewsFreshnessStatus
  is_realtime: boolean
  is_recent: boolean
  is_historical: boolean
  stale: boolean
  stale_reason: string | null
  raw_provider_id: string | null
}

export interface NewsPage extends Page<NewsArticle> {
  requested_freshness: 'live' | 'recent' | 'historical' | 'all'
  effective_freshness: 'live' | 'recent' | 'historical' | 'all'
  fallback_applied: boolean
  warning: string | null
  realtime_article_count: number
  recent_article_count: number
  historical_article_count: number
  unknown_article_count: number
  oldest_article_at: string | null
  latest_article_at: string | null
  freshness_threshold_hours: Record<string, number>
}

export interface NewsSentimentAggregate {
  scope: string
  range: string
  article_count: number
  bullish_count: number
  bearish_count: number
  neutral_count: number
  weighted_sentiment_score: number | null
  average_impact_score: number | null
  high_impact_count: number
  latest_article_at: string | null
  trend: 'IMPROVING' | 'WEAKENING' | 'STABLE' | 'MIXED' | 'INSUFFICIENT_DATA' | string
  confidence: number | null
}

export interface NewsSentimentTimeline {
  range: string
  items: Array<{ timestamp: string; score: number; article_count: number }>
  aggregate: NewsSentimentAggregate
}

export interface NewsProviderStatus {
  name: string
  enabled: boolean
  configured: boolean
  healthy: boolean
  status: string
  capabilities: string[]
  capability_details: Record<string, boolean | null>
  priority: number | null
  last_fetch_at: string | null
  last_success_at: string | null
  last_error: string | null
  article_count: number
  raw_count: number
  canonical_count: number
  latency_ms: number | null
  rate_limited: boolean
  quota_status: 'AVAILABLE' | 'LOW' | 'EXHAUSTED' | 'UNKNOWN' | 'NOT_APPLICABLE'
  failure_count: number
  cooldown_until: string | null
  circuit_state: 'CLOSED' | 'OPEN' | 'HALF_OPEN'
  authentication_failed: boolean
  entitlement_error: boolean
  last_status_code: number | null
  requests_sent: number
  requests_skipped_from_cache: number
  rate_limit_count: number
  last_retry_after_seconds: number | null
  last_known_good_available: boolean
  feed_count: number
  healthy_feed_count: number
  failed_feed_count: number
  raw_article_count: number
  canonical_article_count: number
  realtime_article_count: number
  recent_article_count: number
  stale: boolean
}

export interface NewsStatus {
  enabled: boolean
  state: string
  provider_mode: string[]
  provider_count: number
  configured_provider_count: number
  article_count: number
  raw_article_count: number
  canonical_article_count: number
  realtime_article_count: number
  recent_article_count: number
  historical_article_count: number
  unknown_article_count: number
  calendar_event_count: number
  last_refresh_at: string | null
  last_success_at: string | null
  analyzer: string
  finbert_enabled: boolean
  finbert_available: boolean
  scheduler_running: boolean
  external_requests_enabled: boolean
  engine_integration_enabled: boolean
  live_allowed: boolean
  effective_max_lot: number
  warnings: string[]
  providers_attempted: string[]
  providers_succeeded: string[]
  providers_failed: string[]
  providers_rate_limited: string[]
  providers_unconfigured: string[]
  providers: Record<string, NewsProviderStatus>
  partial: boolean
}

export interface SymbolNewsSummary {
  symbol: string
  latest: NewsArticle[]
  sentiment: NewsSentimentAggregate
  upcoming_events: EconomicCalendarEvent[]
}
