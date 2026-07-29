import { useMemo } from 'react'
import { useRealtimeDashboard } from './useRealtimeDashboard'

export function useEconomicCalendarEvent(eventId: string | null) {
  const page = useRealtimeDashboard().resources.economicCalendar.data
  return useMemo(
    () => eventId ? page?.items.find((event) => event.id === eventId) ?? null : null,
    [eventId, page],
  )
}
