import { createContext } from 'react'
import type { DashboardSnapshot, DataStatus } from '../types/dashboard'
import type {
  DashboardApiSnapshot,
  RealtimeConnectionInfo,
} from '../types/dashboardApi'
import type {
  TerminalDashboardData,
  TerminalPanelState,
} from '../types/terminal'

export interface DashboardRealtimeContextValue {
  apiSnapshot: DashboardApiSnapshot | null
  dashboard: DashboardSnapshot | null
  terminal: TerminalDashboardData | null
  dataStatus: DataStatus
  panelState: TerminalPanelState
  connection: RealtimeConnectionInfo
  error: string | null
  isPaused: boolean
  lastSuccessfulUpdate: string | null
  refresh: () => Promise<void>
  togglePause: () => void
}

export const DashboardRealtimeContext =
  createContext<DashboardRealtimeContextValue | null>(null)
