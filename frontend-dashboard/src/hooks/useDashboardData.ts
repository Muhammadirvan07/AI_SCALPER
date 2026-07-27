import { useRealtimeDashboard } from './useRealtimeDashboard'

/**
 * Compatibility hook for existing modules. It consumes the shared provider and
 * never creates another REST poller or WebSocket.
 */
export function useDashboardData() {
  const realtime = useRealtimeDashboard()
  return {
    data: realtime.dashboard,
    status: realtime.dataStatus,
    error: realtime.error,
    lastSuccessfulUpdate: realtime.lastSuccessfulUpdate,
    refresh: realtime.refresh,
  }
}
