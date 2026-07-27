import { useRealtimeDashboard } from './useRealtimeDashboard'

/**
 * Compatibility hook backed by the centralized realtime provider. No synthetic
 * price, signal, order, or PnL updates are produced here.
 */
export function useTerminalDashboard() {
  const realtime = useRealtimeDashboard()
  return {
    data: realtime.terminal,
    state: realtime.panelState,
    error: realtime.error,
    isPaused: realtime.isPaused,
    lastSuccessfulUpdate: realtime.lastSuccessfulUpdate,
    refresh: realtime.refresh,
    togglePause: realtime.togglePause,
  }
}
