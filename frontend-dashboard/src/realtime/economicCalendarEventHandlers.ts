import { isEconomicCalendarEvent } from '../api/economicCalendar'
import type { EconomicCalendarEvent, EconomicCalendarPage } from '../types/economicCalendar'
import type { RealtimeEvent } from './websocketTypes'

export const calendarMutationEvents = new Set([
  'calendar.event.created',
  'calendar.event.updated',
  'calendar.event.countdown',
  'calendar.event.awaiting-release',
  'calendar.event.released',
  'calendar.event.revised',
  'calendar.event.rescheduled',
  'calendar.event.cancelled',
  'calendar.schedule.changed',
])

const upsert = (items: EconomicCalendarEvent[], incoming: EconomicCalendarEvent) => {
  const byId = new Map(items.map((item) => [item.id, item]))
  byId.set(incoming.id, incoming)
  return [...byId.values()].sort((left, right) => Date.parse(left.scheduled_at) - Date.parse(right.scheduled_at))
}

export function mergeEconomicCalendarEvent(
  page: EconomicCalendarPage | null,
  event: RealtimeEvent,
): EconomicCalendarPage | null {
  if (!calendarMutationEvents.has(event.type) || !isEconomicCalendarEvent(event.data)) return page
  const incoming = event.data
  if (!page) {
    return {
      items: [incoming], total: 1, limit: 200, offset: 0,
      counts: {}, next_critical_event: incoming.impact === 'CRITICAL' ? incoming : null,
    }
  }
  const items = upsert(page.items, incoming).slice(0, page.limit)
  const critical = items.find((item) => item.impact === 'CRITICAL' && Date.parse(item.scheduled_at) >= Date.now()) ?? null
  return {
    ...page,
    items,
    total: page.items.some((item) => item.id === incoming.id) ? page.total : page.total + 1,
    next_critical_event: critical,
    counts: {
      ...page.counts,
      critical: items.filter((item) => item.impact === 'CRITICAL').length,
      high: items.filter((item) => item.impact === 'HIGH').length,
      released: items.filter((item) => item.is_released).length,
      live: items.filter((item) => item.is_live).length,
      currencies: new Set(items.flatMap((item) => item.currency ? [item.currency] : [])).size,
    },
  }
}
