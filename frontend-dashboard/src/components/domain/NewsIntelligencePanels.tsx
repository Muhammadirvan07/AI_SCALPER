import {
  AlertTriangle,
  ArrowUpRight,
  CalendarClock,
  CheckCircle2,
  Clock3,
  Newspaper,
  RadioTower,
  ServerOff,
  Sparkles,
} from 'lucide-react'
import { useMemo, useState } from 'react'
import { useNews } from '../../hooks/useNews'
import { useNewsSentiment } from '../../hooks/useNewsSentiment'
import { useRealtimeDashboard } from '../../hooks/useRealtimeDashboard'
import type { NewsArticle, NewsImpact, NewsSentimentLabel } from '../../types/news'
import { formatNullableNumber, formatTimestamp, relativeTime } from '../../utils/apiDisplay'
import { formatStatusLabel } from '../../utils/statusHelpers'
import { TechnicalPanel } from '../terminal/common/TechnicalPanel'
import { TerminalStatusBadge } from '../terminal/common/TerminalStatusBadge'
import { FreshnessBadge } from './FreshnessBadge'
import { ResourceStateView } from './ResourceStateView'

const toneForSentiment = (label: NewsSentimentLabel) =>
  label.includes('BULLISH') ? 'safe' : label.includes('BEARISH') ? 'blocked' : 'neutral'

const toneForImpact = (impact: NewsImpact) =>
  impact === 'CRITICAL' || impact === 'HIGH' ? 'blocked' : impact === 'MEDIUM' ? 'caution' : 'neutral'

const providerMessage = (state: string) => {
  if (state === 'provider_unconfigured' || state === 'unconfigured') return 'News provider is not configured. Configure a trusted provider in the backend environment.'
  if (state === 'disabled') return 'News Intelligence dinonaktifkan melalui konfigurasi backend.'
  if (state === 'rate_limited') return 'Provider membatasi request. Data valid terakhir dipertahankan sebagai stale.'
  if (state === 'error') return 'Provider berita tidak dapat dijangkau. Tidak ada headline buatan sebagai fallback.'
  return null
}

function NewsArticleCard({ article }: { article: NewsArticle }) {
  const freshnessTone = article.is_realtime ? 'safe' : article.is_recent ? 'caution' : 'neutral'
  const ageLabel = article.age_hours === null ? 'Age unavailable' : article.age_hours < 24
    ? `Published ${Math.max(1, Math.round(article.age_hours))} hours ago`
    : `Published ${Math.max(1, Math.floor(article.age_hours / 24))} days ago`
  return (
    <article className={`news-card ${article.is_breaking && article.is_realtime ? 'news-card--breaking' : ''} ${article.is_recent ? 'news-card--recent' : ''}`}>
      <div className="news-card__meta">
        <span>Source: {article.source ?? article.source_domain ?? article.provider}</span>
        <time dateTime={article.published_at ?? article.fetched_at} title={formatTimestamp(article.published_at ?? article.fetched_at)}>
          {relativeTime(article.published_at ?? article.fetched_at)}
        </time>
        <TerminalStatusBadge label={article.freshness_status} tone={freshnessTone} compact />
        {article.provider === 'official_rss' || article.provider === 'investing_rss' ? <TerminalStatusBadge label="OFFICIAL" tone="neutral" compact /> : null}
        {article.is_recent ? <TerminalStatusBadge label="3–7 DAYS OLD" tone="caution" compact /> : null}
      </div>
      <h3>{article.title}</h3>
      {article.summary ? <p>{article.summary}</p> : null}
      {!article.is_realtime ? <p className="news-card__freshness-note"><Clock3 aria-hidden="true" />{ageLabel}. {article.stale_reason}</p> : null}
      <div className="news-card__signals">
        <TerminalStatusBadge label={formatStatusLabel(article.sentiment.label)} tone={toneForSentiment(article.sentiment.label)} compact />
        <TerminalStatusBadge label={`${formatStatusLabel(article.impact)} IMPACT`} tone={toneForImpact(article.impact)} compact />
        <span>Relevance {Math.round(article.relevance_score * 100)}%</span>
        {article.symbols.slice(0, 4).map((symbol) => <span key={symbol}>{symbol}</span>)}
      </div>
      <a href={article.url} target="_blank" rel="noreferrer noopener" aria-label={`Baca sumber asli: ${article.title}`}>
        Read original article <ArrowUpRight aria-hidden="true" />
      </a>
    </article>
  )
}

export function NewsProviderPanel() {
  const { status, providers, refresh } = useNews()
  const { connection } = useRealtimeDashboard()
  const state = status.data?.state ?? 'unknown'
  const message = providerMessage(state)
  return (
    <TechnicalPanel
      code="N00"
      title="News Intelligence Runtime"
      subtitle="Configured providers · deterministic analysis · read-only"
      state={status.status === 'loading' ? 'loading' : status.meta?.stale ? 'stale' : status.data ? 'connected' : 'empty'}
      onRetry={() => void refresh()}
      preserveContent
      className="qt-grid-span-12"
      action={<FreshnessBadge meta={status.meta} connection={connection} />}
    >
      <ResourceStateView resource={status} onRetry={() => void refresh()}>
        {(data) => (
          <>
            {message ? <div className="news-provider-notice" role="status"><ServerOff aria-hidden="true" /><div><strong>{formatStatusLabel(data.state)}</strong><p>{message}</p></div></div> : null}
            <div className="news-runtime-strip">
              <span><em>Service</em><strong>{formatStatusLabel(data.state)}</strong></span>
              <span><em>Analyzer</em><strong>{data.analyzer}</strong></span>
              <span><em>Scheduler</em><strong>{data.scheduler_running ? 'RUNNING' : 'OFFLINE'}</strong></span>
              <span><em>Canonical</em><strong>{data.canonical_article_count}</strong></span>
              <span><em>Realtime</em><strong>{data.realtime_article_count}</strong></span>
              <span><em>Recent</em><strong>{data.recent_article_count}</strong></span>
              <span><em>Engine access</em><strong>READ ONLY</strong></span>
              <span><em>Live execution</em><strong>LOCKED</strong></span>
            </div>
            <div className="news-provider-list">
              {(providers.data ?? []).map((provider) => (
                <div key={provider.name}>
                  {provider.healthy ? <CheckCircle2 aria-hidden="true" /> : <AlertTriangle aria-hidden="true" />}
                  <span>
                    <strong>{formatStatusLabel(provider.name)}</strong>
                    <small title={provider.capabilities.join(', ') || 'No confirmed capability'}>
                      {formatStatusLabel(provider.status)} · {provider.raw_count} raw / {provider.canonical_count} canonical · {provider.feed_count ? `${provider.healthy_feed_count}/${provider.feed_count} feeds · ` : ''}{provider.circuit_state} · {provider.quota_status}
                    </small>
                  </span>
                  <TerminalStatusBadge
                    label={provider.healthy ? 'CONNECTED' : provider.rate_limited ? 'RATE LIMITED' : provider.status === 'disabled' ? 'DISABLED' : provider.configured ? formatStatusLabel(provider.status) : 'UNCONFIGURED'}
                    tone={provider.healthy ? 'safe' : provider.rate_limited ? 'caution' : 'neutral'}
                    compact
                  />
                </div>
              ))}
            </div>
          </>
        )}
      </ResourceStateView>
    </TechnicalPanel>
  )
}

export function LatestNewsPanel() {
  const { latest, breaking, status, refresh } = useNews()
  const { resources, activeSymbol, setActiveSymbol } = useRealtimeDashboard()
  const [category, setCategory] = useState('ALL')
  const [impact, setImpact] = useState('ALL')
  const [sentiment, setSentiment] = useState('ALL')
  const rows = useMemo(() => (latest.data?.items ?? []).filter((article) => article.is_realtime &&
    (category === 'ALL' || article.category === category) &&
    (impact === 'ALL' || article.impact === impact) &&
    (sentiment === 'ALL' || article.sentiment.label === sentiment) &&
    (!activeSymbol || article.symbols.length === 0 || article.symbols.includes(activeSymbol))),
  [activeSymbol, category, impact, latest.data, sentiment])
  const noProvider = providerMessage(status.data?.state ?? '')
  return (
    <TechnicalPanel code="N01" title="Live Financial News" subtitle="Published within 72h · canonical metadata · original-source links" state={latest.status === 'loading' ? 'loading' : rows.length ? 'connected' : 'empty'} onRetry={() => void refresh()} preserveContent className="qt-grid-span-8" action={<TerminalStatusBadge label={`${latest.data?.realtime_article_count ?? 0} REALTIME`} tone={rows.length ? 'safe' : 'neutral'} compact />}>
      <div className="news-filterbar">
        <label><span>Symbol</span><select value={activeSymbol ?? ''} onChange={(event) => setActiveSymbol(event.target.value)} aria-label="Filter symbol berita"><option value="">All symbols</option>{(resources.symbols.data ?? []).map((symbol) => <option key={symbol}>{symbol}</option>)}</select></label>
        <label><span>Category</span><select value={category} onChange={(event) => setCategory(event.target.value)}><option>ALL</option>{['CENTRAL_BANK', 'INTEREST_RATE', 'INFLATION', 'EMPLOYMENT', 'GDP', 'FOREX', 'COMMODITIES', 'GOLD', 'SILVER', 'CRYPTO', 'GEOPOLITICS', 'REGULATION', 'ENERGY', 'MARKET_ANALYSIS', 'GENERAL'].map((item) => <option key={item}>{item}</option>)}</select></label>
        <label><span>Impact</span><select value={impact} onChange={(event) => setImpact(event.target.value)}><option>ALL</option>{['LOW', 'MEDIUM', 'HIGH', 'CRITICAL', 'UNKNOWN'].map((item) => <option key={item}>{item}</option>)}</select></label>
        <label><span>Sentiment</span><select value={sentiment} onChange={(event) => setSentiment(event.target.value)}><option>ALL</option>{['VERY_BEARISH', 'BEARISH', 'NEUTRAL', 'BULLISH', 'VERY_BULLISH', 'UNKNOWN'].map((item) => <option key={item}>{item}</option>)}</select></label>
      </div>
      {(breaking.data?.items.filter((article) => article.is_realtime).length ?? 0) > 0 ? <div className="news-breaking-strip"><RadioTower aria-hidden="true" /><strong>Breaking</strong><span>{breaking.data?.items[0]?.title}</span></div> : null}
      <ResourceStateView resource={latest} onRetry={() => void refresh()} emptyMessage={noProvider ?? 'Provider terhubung tetapi belum mengembalikan artikel.'}>
        {() => rows.length ? <div className="news-list">{rows.map((article) => <NewsArticleCard key={article.id} article={article} />)}</div> : <div className="domain-state" role="status" aria-live="polite"><Newspaper aria-hidden="true" /><strong>{noProvider ? 'Provider belum dikonfigurasi' : 'Belum ada berita realtime'}</strong><p>{noProvider ?? 'Provider aktif, tetapi tidak ada artikel yang diterbitkan dalam 72 jam terakhir.'}</p></div>}
      </ResourceStateView>
    </TechnicalPanel>
  )
}

export function RecentOfficialReleasesPanel() {
  const { recent, status, refresh } = useNews()
  const { activeSymbol } = useRealtimeDashboard()
  const rows = useMemo(
    () => (recent.data?.items ?? []).filter(
      (article) => article.is_recent && (!activeSymbol || article.symbols.length === 0 || article.symbols.includes(activeSymbol)),
    ),
    [activeSymbol, recent.data],
  )
  const noProvider = providerMessage(status.data?.state ?? '')
  return (
    <TechnicalPanel
      code="N01R"
      title="Recent Financial Releases"
      subtitle="Financial releases outside realtime window · 3–7 days old"
      state={recent.status === 'loading' ? 'loading' : rows.length ? 'connected' : 'empty'}
      onRetry={() => void refresh()}
      preserveContent
      className="qt-grid-span-12"
      action={<TerminalStatusBadge label={`${recent.data?.recent_article_count ?? rows.length} RECENT`} tone="caution" compact />}
    >
      <ResourceStateView resource={recent} onRetry={() => void refresh()} emptyMessage={noProvider ?? 'Tidak ada rilis resmi dalam tujuh hari terakhir.'}>
        {() => rows.length
          ? <><div className="news-recent-notice" role="status" aria-live="polite"><Clock3 aria-hidden="true" /><span><strong>Tidak ada berita realtime</strong><small>Menampilkan rilis resmi terbaru dari tujuh hari terakhir. Artikel ini tidak dilabeli live atau breaking.</small></span></div><div className="news-list news-list--recent">{rows.map((article) => <NewsArticleCard key={article.id} article={article} />)}</div></>
          : <div className="domain-state" role="status"><Newspaper aria-hidden="true" /><strong>Belum ada rilis recent</strong><p>{noProvider ?? 'Tidak ada artikel resmi berusia 3–7 hari yang cocok dengan simbol aktif.'}</p></div>}
      </ResourceStateView>
    </TechnicalPanel>
  )
}

export function NewsSentimentPanel() {
  const { resource, timeline, refresh } = useNewsSentiment()
  const { activeSymbol } = useRealtimeDashboard()
  const data = resource.data
  const score = data?.weighted_sentiment_score
  const total = data?.article_count ?? 0
  const percentage = (value: number | undefined) => total ? Math.round((value ?? 0) / total * 100) : 0
  return (
    <TechnicalPanel code="N02" title="Sentiment Overview" subtitle={`${activeSymbol ?? 'All symbols'} · rolling 24h`} state={resource.status === 'loading' ? 'loading' : resource.meta?.stale ? 'stale' : data ? 'connected' : 'empty'} onRetry={() => void refresh()} preserveContent className="qt-grid-span-4" action={<TerminalStatusBadge label={score === null || score === undefined ? 'NO DATA' : formatStatusLabel(data?.trend)} tone={score !== null && score !== undefined && Math.abs(score) >= 0.4 ? (score > 0 ? 'safe' : 'blocked') : 'neutral'} compact />}>
      <ResourceStateView resource={resource} onRetry={() => void refresh()}>
        {(item) => (
          <>
            <div className="news-sentiment-score"><Sparkles aria-hidden="true" /><div><span>Weighted sentiment</span><strong>{formatNullableNumber(item.weighted_sentiment_score, 2)}</strong><small>{item.article_count} canonical articles · confidence {item.confidence === null ? '—' : `${Math.round(item.confidence * 100)}%`}</small></div></div>
            <div className="news-distribution">
              <div><span><em>Bullish</em><strong>{item.bullish_count}</strong></span><i><b style={{ width: `${percentage(item.bullish_count)}%` }} /></i></div>
              <div><span><em>Neutral</em><strong>{item.neutral_count}</strong></span><i><b style={{ width: `${percentage(item.neutral_count)}%` }} /></i></div>
              <div><span><em>Bearish</em><strong>{item.bearish_count}</strong></span><i><b style={{ width: `${percentage(item.bearish_count)}%` }} /></i></div>
            </div>
            <div className="news-sentiment-timeline" aria-label="Sentiment timeline 24 jam">
              {(timeline.data?.items ?? []).map((point) => <span key={point.timestamp} style={{ height: `${Math.max(8, Math.abs(point.score) * 48)}px` }} className={point.score > 0.19 ? 'is-positive' : point.score < -0.19 ? 'is-negative' : 'is-neutral'} title={`${formatTimestamp(point.timestamp)} · ${point.score.toFixed(2)}`} />)}
              {!timeline.data?.items.length ? <small>Timeline belum memiliki sampel.</small> : null}
            </div>
          </>
        )}
      </ResourceStateView>
    </TechnicalPanel>
  )
}

export function SymbolNewsPanel() {
  const { symbol, refresh } = useNews()
  const { activeSymbol } = useRealtimeDashboard()
  const data = symbol.data
  return (
    <TechnicalPanel code="N04" title="Symbol Intelligence" subtitle="Relevant news · next event · freshness" state={symbol.status === 'loading' ? 'loading' : symbol.meta?.stale ? 'stale' : data ? 'connected' : 'empty'} onRetry={() => void refresh()} preserveContent className="qt-grid-span-4" action={<TerminalStatusBadge label={activeSymbol ?? 'NO SYMBOL'} tone="neutral" compact />}>
      <ResourceStateView resource={symbol} onRetry={() => void refresh()} emptyMessage="Pilih symbol untuk memuat intelligence yang relevan.">
        {(item) => (
          <div className="symbol-news-intel">
            <div><Clock3 aria-hidden="true" /><span><em>Relevant articles</em><strong>{item.sentiment.article_count}</strong></span></div>
            <div><Sparkles aria-hidden="true" /><span><em>Aggregate sentiment</em><strong>{formatNullableNumber(item.sentiment.weighted_sentiment_score, 2)}</strong></span></div>
            <div><CalendarClock aria-hidden="true" /><span><em>Nearest high-impact event</em><strong>{item.upcoming_events[0]?.event_name ?? 'None provided'}</strong></span></div>
            <ol>{item.latest.slice(0, 4).map((article) => <li key={article.id}><a href={article.url} target="_blank" rel="noreferrer noopener">{article.title}</a><small>{article.source ?? article.provider} · {relativeTime(article.published_at)}</small></li>)}</ol>
          </div>
        )}
      </ResourceStateView>
    </TechnicalPanel>
  )
}
