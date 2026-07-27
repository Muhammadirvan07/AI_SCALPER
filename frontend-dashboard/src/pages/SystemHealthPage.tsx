import { ShieldCheck } from 'lucide-react'
import { SourceHealthPanel } from '../components/common/SourceHealthPanel'
import { ActivityTimeline } from '../components/dashboard/ActivityTimeline'
import { DecisionHealthPanel } from '../components/dashboard/DecisionHealthPanel'
import { SystemSafetyPanel } from '../components/dashboard/SystemSafetyPanel'
import { DashboardPageShell } from '../components/layout/DashboardPageShell'
import { SectionHeader } from '../components/layout/SectionHeader'
import { Panel } from '../components/ui/Panel'
import { PanelErrorBoundary } from '../components/ui/PanelErrorBoundary'
import { PanelState } from '../components/ui/PanelState'
import type { DashboardPageProps } from './pageTypes'
import { useRealtimeDashboard } from '../hooks/useRealtimeDashboard'

export function SystemHealthPage({
  data,
  staticSnapshot,
  status,
  error,
  lastSuccessfulUpdate,
  onRefresh,
}: DashboardPageProps) {
  const { apiSnapshot } = useRealtimeDashboard()
  const unavailableState = status === 'loading'
    ? 'loading'
    : status === 'disconnected'
      ? 'disconnected'
      : 'error'

  return (
    <DashboardPageShell
      eyebrow="Keselamatan & keandalan"
      title="Kesehatan Sistem"
      description="Penghalang eksekusi, mesin adaptif, diagnostik, dan kualitas data keputusan selalu terlihat."
      icon={ShieldCheck}
      status={status}
      error={error}
      lastSuccessfulUpdate={lastSuccessfulUpdate}
      onRefresh={onRefresh}
    >
      <SectionHeader
        id="health-title"
        eyebrow="Status perlindungan"
        title="Pusat kontrol keselamatan"
        description="Trading live tetap TERKUNCI (LOCKED) sesuai desain, sementara pemantauan paper dan diagnostik adaptif tetap dapat diamati."
        icon={ShieldCheck}
      />
      <div className="grid gap-4">
        <PanelErrorBoundary>
          {staticSnapshot ? (
            <SystemSafetyPanel data={staticSnapshot.safety} />
          ) : (
            <Panel className="p-4 sm:p-6">
              <PanelState
                state={unavailableState}
                onRetry={status === 'error' ? onRefresh : undefined}
              />
            </Panel>
          )}
        </PanelErrorBoundary>
        <PanelErrorBoundary>
          <SourceHealthPanel snapshot={apiSnapshot} />
        </PanelErrorBoundary>
        <div className="grid gap-4 xl:grid-cols-[1.35fr_0.65fr]">
          <PanelErrorBoundary>
            {data ? (
              <DecisionHealthPanel data={data.decisionHealth} />
            ) : (
              <Panel className="p-4 sm:p-6">
                <PanelState
                  state={unavailableState}
                  onRetry={status === 'error' ? onRefresh : undefined}
                />
              </Panel>
            )}
          </PanelErrorBoundary>
          <PanelErrorBoundary>
            {data ? (
              <ActivityTimeline events={data.activity} />
            ) : (
              <Panel className="p-4 sm:p-6">
                <PanelState
                  state={unavailableState}
                  onRetry={status === 'error' ? onRefresh : undefined}
                />
              </Panel>
            )}
          </PanelErrorBoundary>
        </div>
      </div>
    </DashboardPageShell>
  )
}
