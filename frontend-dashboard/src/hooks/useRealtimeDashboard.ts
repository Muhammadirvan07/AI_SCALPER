import { useContext } from 'react'
import { DashboardRealtimeContext } from '../context/dashboardRealtimeContext'

export function useRealtimeDashboard() {
  const context = useContext(DashboardRealtimeContext)
  if (!context) {
    throw new Error('useRealtimeDashboard harus digunakan di dalam DashboardRealtimeProvider.')
  }
  return context
}
