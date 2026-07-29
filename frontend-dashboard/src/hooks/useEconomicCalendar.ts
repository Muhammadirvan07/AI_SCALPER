import { useRealtimeDashboard } from './useRealtimeDashboard'

export function useEconomicCalendar() {
  const { resources, refreshResource, connection } = useRealtimeDashboard()
  return {
    resource: resources.economicCalendar,
    runtime: resources.economicCalendarStatus,
    health: resources.economicCalendarHealth,
    connection,
    refresh: () => Promise.all([
      refreshResource('economicCalendar'),
      refreshResource('economicCalendarStatus'),
      refreshResource('economicCalendarHealth'),
    ]),
  }
}
