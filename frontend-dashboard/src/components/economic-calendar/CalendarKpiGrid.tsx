import { Activity, BadgeDollarSign, CircleGauge, Radio, ShieldCheck, Timer } from 'lucide-react'
import type { EconomicCalendarEvent, EconomicCalendarRuntimeStatus } from '../../types/economicCalendar'
import { countdownParts } from './calendarViewModel'

export function CalendarKpiGrid({ runtime, events, nextCritical, now, selectedDateIsToday }: {
  runtime: EconomicCalendarRuntimeStatus | null
  events: EconomicCalendarEvent[]
  nextCritical: EconomicCalendarEvent | null
  now: number
  selectedDateIsToday: boolean
}) {
  const currencies = new Set(events.flatMap((event) => event.currency ? [event.currency] : [])).size
  const countdown = nextCritical
    ? String(nextCritical.metadata.schedule_precision ?? 'DATETIME') === 'DATETIME'
      ? countdownParts(nextCritical.scheduled_at, now).label
      : 'TIME TBA'
    : '—'
  const cards = [
    { label: selectedDateIsToday ? 'Events Today' : 'Events Selected Day', value: events.length, note: 'Official schedule entries', icon: Activity },
    { label: selectedDateIsToday ? 'High Impact Today' : 'High Impact Selected Day', value: events.filter((event) => event.is_high_impact).length, note: 'High + critical', icon: CircleGauge },
    { label: 'Next Critical Event', value: nextCritical?.short_name ?? nextCritical?.event_name ?? '—', note: nextCritical ? countdown : 'No verified event', icon: Timer },
    { label: 'Currencies Affected', value: currencies, note: 'Current date filter', icon: BadgeDollarSign },
    { label: 'Live Releases', value: runtime?.live_count ?? events.filter((event) => event.is_live).length, note: 'Countdown or awaiting actual', icon: Radio },
    { label: 'Sources Healthy', value: runtime ? `${runtime.healthy_source_count}/${runtime.source_count}` : '—', note: runtime?.partial ? 'Partial coverage' : 'Verified providers', icon: ShieldCheck },
  ]
  return (
    <section className="ec-kpi-grid" aria-label="Economic calendar summary">
      {cards.map(({ label, value, note, icon: Icon }) => (
        <article key={label} className="ec-kpi">
          <span><Icon aria-hidden="true" /><em>{label}</em></span>
          <strong title={String(value)}>{value}</strong>
          <small>{note}</small>
        </article>
      ))}
    </section>
  )
}
