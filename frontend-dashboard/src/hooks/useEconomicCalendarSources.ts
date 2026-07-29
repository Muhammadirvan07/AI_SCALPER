import { useRealtimeDashboard } from './useRealtimeDashboard'

export function useEconomicCalendarSources() {
  const { resources, refreshResource } = useRealtimeDashboard()
  return {
    resource: resources.economicCalendarSources,
    refresh: () => refreshResource('economicCalendarSources'),
  }
}
