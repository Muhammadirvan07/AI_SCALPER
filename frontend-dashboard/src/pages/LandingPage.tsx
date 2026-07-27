import { HeroSection } from '../components/dashboard/HeroSection'
import { DataStatusBanner } from '../components/dashboard/DataStatusBanner'
import { Panel } from '../components/ui/Panel'
import { PanelState } from '../components/ui/PanelState'
import type { DashboardSummary, DataStatus } from '../types/dashboard'
import type { DashboardSourceMode } from '../types/dashboardApi'

interface LandingPageProps {
  summary: DashboardSummary | null
  sourceMode: DashboardSourceMode
  status: DataStatus
  error: string | null
  lastSuccessfulUpdate: string | null
  onRefresh: () => void
}

export function LandingPage({
  summary,
  sourceMode,
  status,
  error,
  lastSuccessfulUpdate,
  onRefresh,
}: LandingPageProps) {
  const unavailableState = status === 'loading'
    ? 'loading'
    : status === 'disconnected'
      ? 'disconnected'
      : 'error'
  return (
    <main id="main-content" className="future-landing text-slate-200">
      {summary ? (
        <>
          <div className="page-container pt-6">
            <DataStatusBanner
              status={status}
              error={error}
              lastSuccessfulUpdate={lastSuccessfulUpdate}
              onRefresh={onRefresh}
            />
          </div>
          <HeroSection summary={summary} sourceMode={sourceMode} />
        </>
      ) : (
        <div className="page-container py-16">
          <Panel className="p-4 sm:p-6">
            <PanelState
              state={unavailableState}
              title="Data observasi belum tersedia"
              message="Dashboard tidak menampilkan data simulasi ketika sumber aktual belum terverifikasi. Trading live tetap TERKUNCI (LOCKED)."
              onRetry={status === 'error' ? onRefresh : undefined}
            />
          </Panel>
        </div>
      )}
    </main>
  )
}
