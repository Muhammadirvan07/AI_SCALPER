import { useRealtimeDashboard } from './useRealtimeDashboard'

export function useConnectionStatus() {
  const { connection } = useRealtimeDashboard()
  return connection
}
