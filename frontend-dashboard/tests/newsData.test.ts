import assert from 'node:assert/strict'
import test from 'node:test'
import { isNewsArticleData, isNewsPageData, isNewsSentimentData } from '../src/api/news.ts'
import { queriesForEvent } from '../src/realtime/eventHandlers.ts'
import { parseRealtimeEvent } from '../src/realtime/websocketTypes.ts'

const article = {
  id: 'rss:one',
  provider: 'rss',
  source: 'Trusted',
  source_domain: 'trusted.example',
  title: 'ECB publishes decision',
  summary: null,
  url: 'https://trusted.example/one',
  image_url: null,
  author: null,
  published_at: null,
  fetched_at: '2026-07-29T00:00:00Z',
  language: 'en',
  category: 'CENTRAL_BANK',
  symbols: ['EURUSD'],
  currencies: ['EUR'],
  countries: [],
  topics: [],
  sentiment: { label: 'NEUTRAL', score: 0, confidence: 0.2, analyzer: 'baseline', positive_probability: 0, neutral_probability: 1, negative_probability: 0, matched_terms: [] },
  sentiment_score: 0,
  impact: 'HIGH',
  impact_score: 0.6,
  relevance_score: 0.8,
  relevance: [],
  is_breaking: false,
  is_duplicate: false,
  duplicate_group_id: null,
  canonical_article_id: null,
  age_hours: 120,
  freshness_status: 'RECENT',
  is_realtime: false,
  is_recent: true,
  is_historical: false,
  stale: true,
  stale_reason: 'Article is outside the realtime news window.',
  raw_provider_id: null,
}

test('news validator menerima field opsional null tanpa mengarang nilai', () => {
  assert.equal(isNewsArticleData(article), true)
  assert.equal(isNewsPageData({ items: [article], total: 1, limit: 50, offset: 0, requested_freshness: 'live', effective_freshness: 'recent', fallback_applied: true }), true)
  assert.equal(isNewsPageData({ items: [{ ...article, url: null }], total: 1, limit: 50, offset: 0 }), false)
})

test('sentiment aggregate mempertahankan insufficient-data dan nilai null', () => {
  assert.equal(isNewsSentimentData({ scope: 'EURUSD', range: '24h', article_count: 0, bullish_count: 0, bearish_count: 0, neutral_count: 0, weighted_sentiment_score: null, average_impact_score: null, high_impact_count: 0, latest_article_at: null, trend: 'INSUFFICIENT_DATA', confidence: null }), true)
})

test('event news valid diarahkan hanya ke resource yang terdampak', () => {
  const parsed = parseRealtimeEvent(JSON.stringify({ type: 'news.sentiment.updated', channel: 'news:sentiment', timestamp: '2026-07-29T00:00:00Z', sequence: 9, data: {} }))
  assert.ok(parsed)
  assert.deepEqual(queriesForEvent['news.sentiment.updated'], ['newsSentiment', 'newsTimeline'])
  assert.deepEqual(queriesForEvent['news.provider.status.updated'], ['news'])
  assert.deepEqual(queriesForEvent['news.provider.rate_limited'], ['news'])
  assert.deepEqual(queriesForEvent['news.provider.failed'], ['news'])
  assert.equal(parseRealtimeEvent(JSON.stringify({ type: 'news.freshness.updated', channel: 'news', timestamp: '2026-07-29T00:00:00Z', sequence: 10, data: {} }))?.type, 'news.freshness.updated')
})
