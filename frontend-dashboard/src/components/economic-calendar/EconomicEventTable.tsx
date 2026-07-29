import { ArrowUpDown, ChevronRight } from 'lucide-react'
import type { EconomicCalendarEvent } from '../../types/economicCalendar'
import { EventStatusBadge, ImpactBadge } from './CalendarPrimitives'
import { formatClock, formatEventValue } from './calendarViewModel'

export function EconomicEventTable({ events, timezone, onOpen }: {
  events: EconomicCalendarEvent[]
  timezone: string
  onOpen: (event: EconomicCalendarEvent) => void
}) {
  return (
    <div className="ec-table-wrap" role="region" aria-label="Official economic events" tabIndex={0}>
      <table className="ec-table">
        <thead><tr><th>Time <ArrowUpDown aria-hidden="true" /></th><th>Currency</th><th>Impact</th><th>Event</th><th className="is-number">Actual</th><th className="is-number">Forecast</th><th className="is-number">Previous</th><th>Status</th><th>Affected Symbols</th><th>Source</th><th><span className="sr-only">Details</span></th></tr></thead>
        <tbody>
          {events.map((event) => (
            <tr key={event.id} className={event.is_live ? 'is-live' : ''}>
              <td><time dateTime={event.scheduled_at}>{String(event.metadata.schedule_precision ?? 'DATETIME') === 'DATE' ? 'TBA' : formatClock(event.scheduled_at, timezone)}</time></td>
              <td><span className="ec-currency">{event.currency ?? '—'}</span></td>
              <td><ImpactBadge impact={event.impact} /></td>
              <th scope="row"><button type="button" onClick={() => onOpen(event)}>{event.event_name}<small>{event.category.replaceAll('_', ' ')}</small></button></th>
              <td className={`is-number ${event.actual !== null ? 'is-actual' : ''}`}>{formatEventValue(event.actual, event.unit)}</td>
              <td className="is-number">{formatEventValue(event.forecast, event.unit)}</td>
              <td className="is-number">{formatEventValue(event.previous, event.unit)}</td>
              <td><EventStatusBadge status={event.status} /></td>
              <td><div className="ec-symbols-inline">{event.affected_symbols.slice(0, 3).map((symbol) => <span key={symbol}>{symbol}</span>)}{event.affected_symbols.length > 3 ? <small>+{event.affected_symbols.length - 3}</small> : null}</div></td>
              <td><span className="ec-source-cell">{event.source}<small>{event.verified ? 'Verified' : 'Unverified'}</small></span></td>
              <td><button type="button" className="ec-row-action" aria-label={`Open ${event.event_name}`} onClick={() => onOpen(event)}><ChevronRight aria-hidden="true" /></button></td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
