import { CalendarDays, ChevronRight, Clock3, Rows3 } from 'lucide-react'
import type { EconomicCalendarEvent } from '../../types/economicCalendar'
import { EventStatusBadge, ImpactBadge } from './CalendarPrimitives'
import {
  formatClock, formatDateLabel, formatEventValue, regionForEvent, weekSummary,
  type CalendarViewMode,
} from './calendarViewModel'

function EventLine({ event, timezone, onOpen }: {
  event: EconomicCalendarEvent
  timezone: string
  onOpen: (event: EconomicCalendarEvent) => void
}) {
  return (
    <button type="button" className={`ec-event-line ${event.is_live ? 'is-live' : ''}`} onClick={() => onOpen(event)}>
      <time dateTime={event.scheduled_at}>{String(event.metadata.schedule_precision ?? 'DATETIME') === 'DATE' ? 'TBA' : formatClock(event.scheduled_at, timezone)}</time>
      <span className="ec-currency">{event.currency ?? '—'}</span>
      <ImpactBadge impact={event.impact} />
      <span className="ec-event-name"><strong>{event.event_name}</strong><small>{event.source}</small></span>
      <span className="ec-event-actual">{formatEventValue(event.actual, event.unit)}</span>
      <EventStatusBadge status={event.status} />
      <ChevronRight aria-hidden="true" />
    </button>
  )
}

export function EconomicCalendarViews({ mode, events, allEvents, selectedDate, timezone, onOpen }: {
  mode: CalendarViewMode
  events: EconomicCalendarEvent[]
  allEvents: EconomicCalendarEvent[]
  selectedDate: string
  timezone: string
  onOpen: (event: EconomicCalendarEvent) => void
}) {
  if (mode === 'week') {
    return (
      <div className="ec-week-grid">
        {weekSummary(allEvents, selectedDate, timezone).map((day) => (
          <article key={day.date} className={day.date === selectedDate ? 'is-selected' : ''}>
            <header><span>{day.label}</span><CalendarDays aria-hidden="true" /></header>
            <strong>{day.items.length}</strong><small>official events</small>
            <dl><div><dt>High impact</dt><dd>{day.highImpact}</dd></div><div><dt>Currencies</dt><dd>{day.currencies.slice(0, 4).join(' · ') || '—'}</dd></div></dl>
            <div>{day.items.slice(0, 3).map((event) => <button type="button" key={event.id} onClick={() => onOpen(event)}><time>{formatClock(event.scheduled_at, timezone)}</time><span>{event.event_name}</span></button>)}</div>
          </article>
        ))}
      </div>
    )
  }
  if (mode === 'day') {
    const regions = ['Asia Pacific', 'Europe', 'North America', 'Global']
    return (
      <div className="ec-day-groups">
        {regions.map((region) => {
          const rows = events.filter((event) => regionForEvent(event) === region)
          if (rows.length === 0) return null
          return <section key={region}><header><Rows3 aria-hidden="true" /><span>{region}</span><small>{rows.length} events</small></header>{rows.map((event) => <EventLine key={event.id} event={event} timezone={timezone} onOpen={onOpen} />)}</section>
        })}
      </div>
    )
  }
  const grouped = new Map<string, EconomicCalendarEvent[]>()
  events.forEach((event) => {
    const key = formatDateLabel(event.scheduled_at, timezone)
    grouped.set(key, [...(grouped.get(key) ?? []), event])
  })
  return (
    <div className="ec-timeline">
      {[...grouped.entries()].map(([label, rows]) => (
        <section key={label}>
          <header><CalendarDays aria-hidden="true" /><strong>{label}</strong><span>{rows.length} events</span></header>
          <div>{rows.map((event) => <EventLine key={event.id} event={event} timezone={timezone} onOpen={onOpen} />)}</div>
        </section>
      ))}
      {grouped.size === 0 ? <div className="ec-timeline-empty"><Clock3 aria-hidden="true" /><span>No events match the current date and filters.</span></div> : null}
    </div>
  )
}
