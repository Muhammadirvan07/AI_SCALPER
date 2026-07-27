import { Radar } from 'lucide-react'
import { KpiGrid } from '../components/dashboard/KpiGrid'
import { DashboardPageShell } from '../components/layout/DashboardPageShell'
import { SectionHeader } from '../components/layout/SectionHeader'
import { Panel } from '../components/ui/Panel'
import { PanelState } from '../components/ui/PanelState'
import type { DashboardPageProps } from './pageTypes'

export function OverviewPage({
  data,
  staticSnapshot,
  status,
  error,
  lastSuccessfulUpdate,
  onRefresh,
}: DashboardPageProps) {
  const unavailableState = status === 'loading'
    ? 'loading'
    : status === 'disconnected'
      ? 'disconnected'
      : 'error'

  return (
    <DashboardPageShell
      eyebrow="Pusat kendali"
      title="Ringkasan Sistem"
      description="Snapshot konservatif untuk performa paper, kesiapan, kualitas, dan kontrol risiko."
      icon={Radar}
      status={status}
      error={error}
      lastSuccessfulUpdate={lastSuccessfulUpdate}
      onRefresh={onRefresh}
    >
      <SectionHeader
        id="overview-title"
        eyebrow="Snapshot saat ini"
        title="KPI pemantauan"
        description="Metrik merupakan keluaran pemantauan lingkungan paper dan tidak dapat memicu eksekusi pasar."
        icon={Radar}
      />
      {!data || !staticSnapshot ? (
        <Panel className="p-4 sm:p-6">
          <PanelState
            state={unavailableState}
            onRetry={status === 'error' ? onRefresh : undefined}
          />
        </Panel>
      ) : (
        <KpiGrid metrics={staticSnapshot.kpis} loading={status === 'loading'} />
      )}
    </DashboardPageShell>
  )
}
