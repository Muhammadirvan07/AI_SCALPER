import type { DashboardSnapshot, DataStatus } from '../types/dashboard'

export interface DashboardPageProps {
  data: DashboardSnapshot | null
  staticSnapshot: DashboardSnapshot | null
  status: DataStatus
  error: string | null
  lastSuccessfulUpdate: string | null
  onRefresh: () => void
}
