import { ArrowUpRight, Clock3, Radio, ShieldAlert, ShieldCheck } from 'lucide-react'
import type { EconomicCalendarEvent, EconomicCalendarGuardPreview } from '../../types/economicCalendar'
import { CalendarBadge, EventStatusBadge, ImpactBadge } from './CalendarPrimitives'
import { countdownParts, formatClock, formatDateLabel, formatEventValue } from './calendarViewModel'

export function NextCriticalEvent({ event, guard, now, timezone, onOpen }: {
  event: EconomicCalendarEvent | null
  guard: EconomicCalendarGuardPreview | null
  now: number
  timezone: string
  onOpen: (event: EconomicCalendarEvent) => void
}) {
  if (!event) {
    return <section className="ec-focus-panel" aria-labelledby="next-critical-title"><header><span id="next-critical-title">Next Critical Event</span><CalendarBadge label="NO VERIFIED EVENT" /></header><div className="ec-focus-empty"><ShieldCheck aria-hidden="true" /><strong>No critical release in the loaded window</strong><p>The panel remains read-only and will update after the next official sync.</p></div></section>
  }
  const countdown = countdownParts(event.scheduled_at, now)
  const precision = String(event.metadata.schedule_precision ?? 'DATETIME')
  const released = event.is_released
  return (
    <section className="ec-focus-panel" aria-labelledby="next-critical-title">
      <header><span id="next-critical-title">Next Critical Event</span><ImpactBadge impact={event.impact} /></header>
      <div className="ec-focus-body">
        <div className="ec-focus-title"><span>{event.currency ?? 'GLOBAL'} · {event.country ?? 'Official source'}</span><h2>{event.event_name}</h2><p>{event.description ?? 'Official release schedule. Forecast remains unavailable unless a trusted source supplies it.'}</p></div>
        <div className="ec-countdown" aria-label={released ? `${event.event_name} released` : `Time remaining until ${event.event_name}`}>
          <small>{released ? 'RELEASED' : precision === 'DATETIME' ? 'COUNTDOWN' : 'OFFICIAL DATE'}</small>
          <strong>{released ? 'RELEASED' : precision === 'DATETIME' ? countdown.label : 'TIME TBA'}</strong>
          <span><Clock3 aria-hidden="true" />{formatDateLabel(event.scheduled_at, timezone)} · {precision === 'DATETIME' ? `${formatClock(event.scheduled_at, timezone)} · ${timezone}` : 'TIME TBA'}</span>
        </div>
        <dl className="ec-release-values" aria-live="polite">
          <div><dt>Actual</dt><dd className={event.actual !== null ? 'is-released' : ''}>{formatEventValue(event.actual, event.unit)}</dd></div>
          <div><dt>Forecast</dt><dd>{formatEventValue(event.forecast, event.unit)}</dd></div>
          <div><dt>Previous</dt><dd>{formatEventValue(event.previous, event.unit)}</dd></div>
        </dl>
        <div className="ec-focus-meta">
          <EventStatusBadge status={event.status} />
          <CalendarBadge label={event.verified ? 'VERIFIED SOURCE' : 'UNVERIFIED'} tone={event.verified ? 'positive' : 'warning'} icon={event.verified ? <ShieldCheck aria-hidden="true" /> : <ShieldAlert aria-hidden="true" />} />
          {guard ? <CalendarBadge label={`GUARD PREVIEW · ${guard.state.replaceAll('_', ' ')}`} tone={guard.state === 'NORMAL' ? 'positive' : guard.state === 'BLOCK_PREVIEW' ? 'critical' : 'warning'} icon={<Radio aria-hidden="true" />} /> : null}
        </div>
        <p className="ec-focus-source">
          <ShieldCheck aria-hidden="true" />
          <span><small>OFFICIAL SOURCE</small><strong>{event.source}</strong></span>
        </p>
        <div className="ec-symbol-row">{event.affected_symbols.slice(0, 8).map((symbol) => <span key={symbol}>{symbol}</span>)}</div>
        <button type="button" className="ec-link-button" onClick={() => onOpen(event)}>Inspect official event <ArrowUpRight aria-hidden="true" /></button>
      </div>
    </section>
  )
}
