import { Newspaper } from 'lucide-react'
import { DashboardPageShell } from '../components/layout/DashboardPageShell'
import { SectionHeader } from '../components/layout/SectionHeader'
import { NewsImpactMatrix } from '../components/news/NewsImpactMatrix'
import { NewsIntelligencePanel } from '../components/news/NewsIntelligencePanel'
import { NewsReadyPairsPanel } from '../components/news/NewsReadyPairsPanel'
import { NewsDecisionReadiness } from '../components/news/NewsDecisionReadiness'
import { Panel } from '../components/ui/Panel'
import { PanelErrorBoundary } from '../components/ui/PanelErrorBoundary'
import { PanelState } from '../components/ui/PanelState'
import type { DashboardNewsSource, DataStatus } from '../types/dashboard'
import type { DashboardPageProps } from './pageTypes'

const resolveNewsStatus = (
  pageStatus: DataStatus,
  sourceStatus: DashboardNewsSource['status'],
): DataStatus => {
  if (pageStatus === 'loading' || pageStatus === 'disconnected') return pageStatus
  if (sourceStatus === 'FRESH') return 'success'
  if (sourceStatus === 'STALE') return 'stale'
  if (sourceStatus === 'PARTIAL') return 'partial'
  if (sourceStatus === 'INVALID') return 'error'
  return 'empty'
}

export function NewsPage({
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
  const newsStatus = data
    ? resolveNewsStatus(status, data.newsSource.status)
    : status
  const newsError = newsStatus === 'error'
    ? data?.newsSource.note ?? error
    : null
  const newsLastUpdate = data?.newsSource.lastUpdated ?? lastSuccessfulUpdate

  return (
    <DashboardPageShell
      eyebrow="Diagnostik berbasis berita"
      title="Intelijen Berita"
      description="Konteks peristiwa ekonomi, selisih terhadap perkiraan, dan efek terjaga pada kandidat trading paper."
      icon={Newspaper}
      status={newsStatus}
      error={newsError}
      lastSuccessfulUpdate={newsLastUpdate}
      onRefresh={onRefresh}
    >
      <SectionHeader
        id="news-page-title"
        eyebrow="Mesin dampak peristiwa"
        title="Dampak berita dan kesiapan keputusan"
        description="Peristiwa hanya ditampilkan jika tersedia dari snapshot API. Dashboard tidak mengarang berita saat backend terhubung; status paper tidak pernah mengizinkan eksekusi live."
        icon={Newspaper}
      />

      {data ? (
        <div className="grid min-w-0 gap-5">
          <PanelErrorBoundary>
            <NewsDecisionReadiness
              readiness={data.decisionReadiness}
              source={data.newsSource}
            />
          </PanelErrorBoundary>
          <div className="grid min-w-0 gap-5 2xl:grid-cols-[minmax(0,1.35fr)_minmax(22rem,0.65fr)]">
            <PanelErrorBoundary>
              <NewsIntelligencePanel
                events={data.marketNews ?? []}
                dataStatus={newsStatus}
                source={data.newsSource}
              />
            </PanelErrorBoundary>
            <PanelErrorBoundary>
              <NewsReadyPairsPanel
                events={data.marketNews ?? []}
                impacts={data.pairNewsImpacts ?? []}
              />
            </PanelErrorBoundary>
          </div>
          <PanelErrorBoundary>
            <NewsImpactMatrix
              events={data.marketNews ?? []}
              impacts={data.pairNewsImpacts ?? []}
            />
          </PanelErrorBoundary>
        </div>
      ) : (
        <Panel className="p-4 sm:p-6">
          <PanelState
            state={unavailableState}
            title="Intelijen berita tidak tersedia"
            message="Data peristiwa pasar tidak dapat dimuat. Trading live tetap TERKUNCI (LOCKED)."
            onRetry={status === 'error' ? onRefresh : undefined}
          />
        </Panel>
      )}
    </DashboardPageShell>
  )
}
