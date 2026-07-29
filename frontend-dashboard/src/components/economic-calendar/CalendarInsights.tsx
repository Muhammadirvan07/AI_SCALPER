import { AlertTriangle, CheckCircle2, Clock3, DatabaseZap, RadioTower } from 'lucide-react'
import type { EconomicCalendarEvent, EconomicCalendarSourceStatus } from '../../types/economicCalendar'

const sourceTone = (source: EconomicCalendarSourceStatus) =>
  source.healthy ? 'healthy' : source.status === 'unconfigured' || source.status === 'disabled' ? 'neutral' : 'warning'

export function CalendarInsights({ events, sources, activeSymbol, now, onCurrency, onSymbol }: {
  events: EconomicCalendarEvent[]
  sources: EconomicCalendarSourceStatus[]
  activeSymbol: string | null
  now: number
  onCurrency: (currency: string) => void
  onSymbol: (symbol: string) => void
}) {
  const currencies = [...events.reduce((map, event) => {
    if (event.currency) map.set(event.currency, (map.get(event.currency) ?? 0) + 1)
    return map
  }, new Map<string, number>())].sort((left, right) => right[1] - left[1])
  const symbols = [...events.reduce((map, event) => {
    event.affected_symbols.forEach((symbol) => map.set(symbol, (map.get(symbol) ?? 0) + (event.is_high_impact ? 2 : 1)))
    return map
  }, new Map<string, number>())].sort((left, right) => right[1] - left[1]).slice(0, 7)
  const maxCurrency = Math.max(1, ...currencies.map(([, count]) => count))

  return (
    <aside className="ec-insights">
      <section className="ec-insight-panel">
        <header><span>Currency Impact</span><small>Today</small></header>
        <div className="ec-currency-bars">{currencies.length ? currencies.map(([currency, count]) => <button type="button" key={currency} onClick={() => onCurrency(currency)}><span><strong>{currency}</strong><em>{count} events</em></span><i><b style={{ width: `${count / maxCurrency * 100}%` }} /></i></button>) : <p>No currency impact data.</p>}</div>
      </section>
      <section className="ec-insight-panel">
        <header><span>Symbol Risk</span><small>Weighted</small></header>
        <div className="ec-symbol-risk">{symbols.length ? symbols.map(([symbol, score]) => <button type="button" key={symbol} className={symbol === activeSymbol ? 'is-active' : ''} onClick={() => onSymbol(symbol)}><strong>{symbol}</strong><span>{score} impact points</span><RadioTower aria-hidden="true" /></button>) : <p>No affected active symbols.</p>}</div>
      </section>
      <section className="ec-insight-panel ec-source-health">
        <header><span>Source Health</span><small>{sources.filter((source) => source.healthy).length}/{sources.length} healthy</small></header>
        <div>{sources.length ? sources.map((source) => {
          const tone = sourceTone(source)
          const Icon = tone === 'healthy' ? CheckCircle2 : tone === 'warning' ? AlertTriangle : DatabaseZap
          return <article key={source.name} className={`is-${tone}`}><Icon aria-hidden="true" /><span><strong>{source.display_name}</strong><small>{source.status.replaceAll('_', ' ')} · {source.event_count} events</small></span><time title={source.last_success_at ?? 'No successful sync'}>{source.last_success_at ? new Intl.RelativeTimeFormat('en', { numeric: 'auto' }).format(Math.round((Date.parse(source.last_success_at) - now) / 60_000), 'minute') : '—'}</time></article>
        }) : <p><Clock3 aria-hidden="true" />Source status is not available.</p>}</div>
      </section>
    </aside>
  )
}
