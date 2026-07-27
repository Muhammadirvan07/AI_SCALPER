import { BrainCircuit } from 'lucide-react'
import { RecentSignalsTable } from '../components/dashboard/RecentSignalsTable'
import { DashboardPageShell } from '../components/layout/DashboardPageShell'
import { SectionHeader } from '../components/layout/SectionHeader'
import { Panel } from '../components/ui/Panel'
import { PanelErrorBoundary } from '../components/ui/PanelErrorBoundary'
import { PanelState } from '../components/ui/PanelState'
import type { DashboardPageProps } from './pageTypes'

export function SignalsPage({
  data,
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
      eyebrow="Observabilitas keputusan"
      title="Riwayat Sinyal"
      description="Keputusan paper, menunggu, ditolak, diblokir, dan batas waktu yang dapat dicari beserta alasan model."
      icon={BrainCircuit}
      status={status}
      error={error}
      lastSuccessfulUpdate={lastSuccessfulUpdate}
      onRefresh={onRefresh}
    >
      <SectionHeader
        id="signals-section-title"
        eyebrow="Aliran keputusan"
        title="Sinyal pemantauan terbaru"
        description="Setiap catatan bersifat observasi atau simulasi. Tidak ada baris yang dapat membuat atau mengulang order."
        icon={BrainCircuit}
      />
      <PanelErrorBoundary>
        {data ? (
          <RecentSignalsTable signals={data.signals} />
        ) : (
          <Panel className="p-4 sm:p-6">
            <PanelState
              state={unavailableState}
              onRetry={status === 'error' ? onRefresh : undefined}
            />
          </Panel>
        )}
      </PanelErrorBoundary>
    </DashboardPageShell>
  )
}
