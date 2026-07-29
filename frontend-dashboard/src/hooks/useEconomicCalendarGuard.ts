import { useRealtimeDashboard } from './useRealtimeDashboard'

export function useEconomicCalendarGuard() {
  const { activeSymbol, resources, refreshResource } = useRealtimeDashboard()
  return {
    symbol: activeSymbol,
    resource: resources.economicCalendarGuard,
    refresh: () => refreshResource('economicCalendarGuard'),
  }
}
