import { Activity } from 'lucide-react'
import { Watchlist } from '../components/dashboard/Watchlist'
import { DashboardPageShell } from '../components/layout/DashboardPageShell'
import { SectionHeader } from '../components/layout/SectionHeader'
import { Panel } from '../components/ui/Panel'
import { PanelErrorBoundary } from '../components/ui/PanelErrorBoundary'
import { PanelState } from '../components/ui/PanelState'
import type { DashboardPageProps } from './pageTypes'

export function MarketsPage({
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
      eyebrow="Intelijen pasar"
      title="Pasar Terpantau"
      description="Harga, kesegaran data, bias model, volatilitas, dan guard kelayakan pair dalam mode hanya-baca."
      icon={Activity}
      status={status}
      error={error}
      lastSuccessfulUpdate={lastSuccessfulUpdate}
      onRefresh={onRefresh}
    >
      <SectionHeader
        id="markets-title"
        eyebrow="Daftar pantau"
        title="Observasi pasar"
        description="Cari dan filter instrumen tanpa menyediakan kontrol order atau eksekusi."
        icon={Activity}
      />
      <PanelErrorBoundary>
        {data ? (
          <Watchlist items={data.watchlist} />
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
