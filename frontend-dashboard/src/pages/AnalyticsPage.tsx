import { BarChart3 } from 'lucide-react'
import { EquityChart } from '../components/dashboard/EquityChart'
import { PairPerformanceChart } from '../components/dashboard/PairPerformanceChart'
import { ReadinessTrendChart } from '../components/dashboard/ReadinessTrendChart'
import { StrategyPerformanceChart } from '../components/dashboard/StrategyPerformanceChart'
import { TradeDistributionChart } from '../components/dashboard/TradeDistributionChart'
import { DashboardPageShell } from '../components/layout/DashboardPageShell'
import { SectionHeader } from '../components/layout/SectionHeader'
import { Panel } from '../components/ui/Panel'
import { PanelErrorBoundary } from '../components/ui/PanelErrorBoundary'
import { PanelState } from '../components/ui/PanelState'
import type { DashboardPageProps } from './pageTypes'

export function AnalyticsPage({
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
      eyebrow="Analitik paper"
      title="Performa & Diagnostik"
      description="Ekuitas, hasil evaluasi, kualitas strategi, perilaku pair, dan pergerakan kesiapan pada sampel paper."
      icon={BarChart3}
      status={status}
      error={error}
      lastSuccessfulUpdate={lastSuccessfulUpdate}
      onRefresh={onRefresh}
    >
      <SectionHeader
        id="analytics-title"
        eyebrow="Jendela evaluasi"
        title="Analitik performa paper"
        description="Hasil dibuat tetap realistis serta mencakup kerugian, strategi terbatas, dan kondisi pantauan."
        icon={BarChart3}
      />

      {data ? (
        <div className="grid gap-4 xl:grid-cols-[1.55fr_0.75fr]">
          <PanelErrorBoundary>
            <EquityChart data={data.equity} />
          </PanelErrorBoundary>
          <PanelErrorBoundary>
            <TradeDistributionChart data={data.tradeDistribution} />
          </PanelErrorBoundary>
          <div className="xl:col-span-2">
            <PanelErrorBoundary>
              <StrategyPerformanceChart data={data.strategies} />
            </PanelErrorBoundary>
          </div>
          <PanelErrorBoundary>
            <PairPerformanceChart data={data.pairs} />
          </PanelErrorBoundary>
          <PanelErrorBoundary>
            <ReadinessTrendChart data={data.readiness} />
          </PanelErrorBoundary>
        </div>
      ) : (
        <div className="grid gap-4 lg:grid-cols-2">
          {Array.from({ length: 4 }, (_, index) => (
            <Panel key={`analytics-state-${index.toString()}`} className="p-4 sm:p-6">
              <PanelState
                state={unavailableState}
                onRetry={status === 'error' ? onRefresh : undefined}
              />
            </Panel>
          ))}
        </div>
      )}
    </DashboardPageShell>
  )
}
