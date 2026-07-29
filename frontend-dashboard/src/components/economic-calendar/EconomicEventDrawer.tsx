import { ExternalLink, History, ShieldCheck, X } from 'lucide-react'
import { useEffect, useRef } from 'react'
import type { EconomicCalendarEvent, EconomicCalendarGuardPreview } from '../../types/economicCalendar'
import { EventStatusBadge, ImpactBadge } from './CalendarPrimitives'
import { formatEventValue } from './calendarViewModel'

const timestamp = (value: string | null, timezone: string) => value
  ? new Intl.DateTimeFormat('en', { dateStyle: 'medium', timeStyle: 'long', timeZone: timezone }).format(new Date(value))
  : '—'

export function EconomicEventDrawer({ event, guard, timezone, onClose }: {
  event: EconomicCalendarEvent | null
  guard: EconomicCalendarGuardPreview | null
  timezone: string
  onClose: () => void
}) {
  const closeRef = useRef<HTMLButtonElement>(null)
  useEffect(() => {
    if (!event) return
    closeRef.current?.focus()
    const listener = (keyboardEvent: KeyboardEvent) => { if (keyboardEvent.key === 'Escape') onClose() }
    document.addEventListener('keydown', listener)
    return () => document.removeEventListener('keydown', listener)
  }, [event, onClose])
  if (!event) return null
  return (
    <div className="ec-drawer-layer" role="presentation" onMouseDown={(mouseEvent) => { if (mouseEvent.target === mouseEvent.currentTarget) onClose() }}>
      <aside className="ec-drawer" role="dialog" aria-modal="true" aria-labelledby="event-drawer-title">
        <header><div><span>Official Event Detail</span><h2 id="event-drawer-title">{event.event_name}</h2></div><button ref={closeRef} type="button" onClick={onClose} aria-label="Close event detail"><X aria-hidden="true" /></button></header>
        <div className="ec-drawer-badges"><ImpactBadge impact={event.impact} /><EventStatusBadge status={event.status} /></div>
        <p className="ec-drawer-description">{event.description ?? 'No additional description was provided by the official source.'}</p>
        <dl className="ec-drawer-values"><div><dt>Actual</dt><dd>{formatEventValue(event.actual, event.unit)}</dd></div><div><dt>Forecast</dt><dd>{formatEventValue(event.forecast, event.unit)}</dd></div><div><dt>Previous</dt><dd>{formatEventValue(event.previous, event.unit)}</dd></div><div><dt>Revised previous</dt><dd>{formatEventValue(event.revised_previous, event.unit)}</dd></div></dl>
        <dl className="ec-drawer-details">
          <div><dt>Country / currency</dt><dd>{event.country ?? '—'} · {event.currency ?? '—'}</dd></div>
          <div><dt>Category</dt><dd>{event.category.replaceAll('_', ' ')}</dd></div>
          <div><dt>Scheduled</dt><dd>{timestamp(event.scheduled_at, timezone)}</dd></div>
          <div><dt>Original schedule</dt><dd>{timestamp(event.original_scheduled_at, timezone)}</dd></div>
          <div><dt>Reference period</dt><dd>{event.reference_period ?? '—'}</dd></div>
          <div><dt>Frequency</dt><dd>{event.frequency ?? '—'}</dd></div>
          <div><dt>Last checked</dt><dd>{timestamp(event.last_checked_at, timezone)}</dd></div>
          <div><dt>Released at</dt><dd>{timestamp(event.released_at, timezone)}</dd></div>
        </dl>
        <section className="ec-drawer-section"><h3><ShieldCheck aria-hidden="true" />Impact classification</h3><strong>{Math.round(event.impact_score * 100)}/100</strong><ul>{event.impact_reasons.map((reason) => <li key={reason}>{reason}</li>)}</ul></section>
        <section className="ec-drawer-section"><h3>Affected symbols</h3><div className="ec-symbol-row">{event.affected_symbols.map((symbol) => <span key={symbol}>{symbol}</span>)}</div></section>
        <section className="ec-drawer-section"><h3>Read-only guard preview</h3><p>{guard?.state.replaceAll('_', ' ') ?? 'INSUFFICIENT DATA'}</p><ul>{guard?.reasons.map((reason) => <li key={reason}>{reason}</li>)}</ul></section>
        <section className="ec-drawer-section"><h3><History aria-hidden="true" />Schedule history</h3>{event.schedule_history.length ? <ol>{event.schedule_history.map((entry) => <li key={`${entry.changed_at}-${entry.scheduled_at}`}><time>{timestamp(entry.changed_at, timezone)}</time><span>{timestamp(entry.previous_scheduled_at, timezone)} → {timestamp(entry.scheduled_at, timezone)}</span><small>{entry.reason}</small></li>)}</ol> : <p>No schedule changes recorded.</p>}</section>
        <footer><span>{event.verified ? 'Verified official source' : 'Source verification pending'}</span>{event.source_url ? <a href={event.source_url} target="_blank" rel="noopener noreferrer">Open official source <ExternalLink aria-hidden="true" /></a> : null}</footer>
      </aside>
    </div>
  )
}
