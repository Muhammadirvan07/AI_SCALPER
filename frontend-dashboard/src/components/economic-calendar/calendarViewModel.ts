import type { EconomicCalendarEvent, EconomicImpact } from '../../types/economicCalendar'

export type CalendarViewMode = 'timeline' | 'day' | 'week'

export const connectionStatePresentation = (state: string, stale: boolean) => {
  if (state === 'OFFLINE') return { label: 'OFFLINE', tone: 'critical' as const, icon: 'offline' as const }
  if (state === 'RECONNECTING' || state === 'CONNECTING') return { label: 'SYNCING', tone: 'warning' as const, icon: 'syncing' as const }
  if (state === 'DELAYED' || stale) return { label: 'STALE', tone: 'warning' as const, icon: 'stale' as const }
  return { label: 'LIVE', tone: 'positive' as const, icon: 'live' as const }
}

export const impactRank: Record<EconomicImpact, number> = {
  CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, UNKNOWN: 0,
}

export const dateKey = (value: string | number | Date, timezone: string) =>
  new Intl.DateTimeFormat('en-CA', {
    timeZone: timezone,
    year: 'numeric', month: '2-digit', day: '2-digit',
  }).format(new Date(value))

export const formatClock = (value: string, timezone: string) =>
  new Intl.DateTimeFormat('en-GB', {
    timeZone: timezone, hour: '2-digit', minute: '2-digit', hour12: false,
  }).format(new Date(value))

export const formatDateLabel = (value: string, timezone: string) =>
  new Intl.DateTimeFormat('en', {
    timeZone: timezone, weekday: 'short', month: 'short', day: 'numeric',
  }).format(new Date(value))

export const formatEventValue = (value: string | number | null, unit: string | null) => {
  if (value === null || value === '') return '—'
  return `${value}${unit && !String(value).includes(unit) ? unit : ''}`
}

export const countdownParts = (scheduledAt: string, now: number) => {
  const remaining = Math.max(0, Date.parse(scheduledAt) - now)
  const seconds = Math.floor(remaining / 1_000)
  const hours = Math.floor(seconds / 3_600)
  const minutes = Math.floor((seconds % 3_600) / 60)
  const tail = seconds % 60
  return {
    remaining,
    label: [hours, minutes, tail].map((part) => String(part).padStart(2, '0')).join(':'),
  }
}

export const regionForEvent = (event: EconomicCalendarEvent) => {
  if (['JPY', 'AUD', 'NZD'].includes(event.currency ?? '')) return 'Asia Pacific'
  if (['EUR', 'GBP', 'CHF'].includes(event.currency ?? '')) return 'Europe'
  if (['USD', 'CAD'].includes(event.currency ?? '')) return 'North America'
  return 'Global'
}

export interface CalendarUiFilters {
  search: string
  currency: string
  impact: string
  category: string
  status: string
  symbol: string
}

export const filterCalendarEvents = (
  events: EconomicCalendarEvent[],
  selectedDate: string,
  timezone: string,
  filters: CalendarUiFilters,
) => events.filter((event) => {
  if (dateKey(event.scheduled_at, timezone) !== selectedDate) return false
  const haystack = `${event.event_name} ${event.source} ${event.country ?? ''}`.toLowerCase()
  return (!filters.search || haystack.includes(filters.search.toLowerCase())) &&
    (!filters.currency || event.currency === filters.currency) &&
    (!filters.impact || event.impact === filters.impact) &&
    (!filters.category || event.category === filters.category) &&
    (!filters.status || event.status === filters.status) &&
    (!filters.symbol || event.affected_symbols.includes(filters.symbol))
})

export const weekSummary = (events: EconomicCalendarEvent[], startDate: string, timezone: string) => {
  const start = new Date(`${startDate}T00:00:00Z`)
  return Array.from({ length: 7 }, (_, index) => {
    const cursor = new Date(start.getTime() + index * 86_400_000)
    const key = dateKey(cursor, timezone)
    const items = events.filter((event) => dateKey(event.scheduled_at, timezone) === key)
    return {
      date: key,
      label: new Intl.DateTimeFormat('en', { weekday: 'short', month: 'short', day: 'numeric', timeZone: timezone }).format(cursor),
      items,
      highImpact: items.filter((event) => impactRank[event.impact] >= impactRank.HIGH).length,
      currencies: [...new Set(items.flatMap((event) => event.currency ? [event.currency] : []))],
    }
  })
}
