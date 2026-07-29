import { useRealtimeDashboard } from './useRealtimeDashboard'

export function useEconomicCalendarDiagnostic() {
  const { activeSymbol, resources, refreshResource } = useRealtimeDashboard()
  return {
    symbol: activeSymbol,
    resource: resources.economicCalendarDiagnostic,
    refresh: () => refreshResource('economicCalendarDiagnostic'),
  }
}
