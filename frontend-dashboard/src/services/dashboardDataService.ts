import { mockDashboardData } from '../data/mockDashboardData'
import { mockTerminalData } from '../data/mockTerminalData'
import { fetchDashboardSnapshot } from './dashboardApiClient'

/**
 * Single data-service abstraction. API replacement or a different transport can
 * be introduced here without changing UI panels.
 */
export const dashboardDataService = {
  getRealtimeSnapshot: (signal?: AbortSignal) => fetchDashboardSnapshot(signal),
  getMockDashboardSnapshot: () => structuredClone(mockDashboardData),
  getMockTerminalSnapshot: () => structuredClone(mockTerminalData),
}
