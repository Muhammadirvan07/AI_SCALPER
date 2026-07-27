import { AlertTriangle, LoaderCircle } from 'lucide-react'
import { BrokerReadinessSection } from '../components/landing/BrokerReadinessSection'
import { DocumentationLinksSection } from '../components/landing/DocumentationLinksSection'
import { NextActionSection } from '../components/landing/NextActionSection'
import { OperationalActivitySection } from '../components/landing/OperationalActivitySection'
import { OperationalLandingHero } from '../components/landing/OperationalLandingHero'
import { OperationalStatusSection } from '../components/landing/OperationalStatusSection'
import { PerformanceSummarySection } from '../components/landing/PerformanceSummarySection'
import { ProjectProgressSection } from '../components/landing/ProjectProgressSection'
import { SafetyBoundarySection } from '../components/landing/SafetyBoundarySection'
import { DataStatusBanner } from '../components/dashboard/DataStatusBanner'
import type { DataStatus } from '../types/dashboard'
import type {
  DashboardApiSnapshot,
  RealtimeConnectionInfo,
} from '../types/dashboardApi'

interface LandingPageProps {
  snapshot: DashboardApiSnapshot | null
  connection: RealtimeConnectionInfo
  status: DataStatus
  error: string | null
  lastSuccessfulUpdate: string | null
  onRefresh: () => void
}

export function LandingPage({
  snapshot,
  connection,
  status,
  error,
  lastSuccessfulUpdate,
  onRefresh,
}: LandingPageProps) {
  const mockDevelopment = connection.sourceMode === 'MOCK FALLBACK'
  const pending = !snapshot && status === 'loading'

  return (
    <main id="main-content" className="future-landing ops-landing">
      <OperationalLandingHero snapshot={snapshot} sourceMode={connection.sourceMode} />

      <div className="page-container ops-landing__body">
        <DataStatusBanner
          status={status}
          error={error}
          lastSuccessfulUpdate={lastSuccessfulUpdate}
          onRefresh={onRefresh}
        />

        {!snapshot ? (
          <div
            className={`ops-fail-closed ${pending ? 'is-loading' : 'is-blocked'}`}
            role={pending ? 'status' : 'alert'}
          >
            {pending ? (
              <LoaderCircle aria-hidden="true" className="size-5 motion-safe:animate-spin" />
            ) : (
              <AlertTriangle aria-hidden="true" className="size-5" />
            )}
            <div>
              <strong>
                {pending ? 'Memvalidasi snapshot operasional' : 'Data observasi belum tersedia'}
              </strong>
              <p>
                {mockDevelopment
                  ? 'MOCK DEVELOPMENT — BUKAN DATA AKTUAL. Nilai mock tidak digunakan untuk status operasional landing.'
                  : 'Data tidak diganti dengan mock. Seluruh nilai operasional ditandai tidak terverifikasi dan live order tetap terkunci.'}
              </p>
            </div>
          </div>
        ) : null}

        <div className="ops-landing__priority-grid">
          <OperationalStatusSection snapshot={snapshot} connection={connection} />
          <SafetyBoundarySection snapshot={snapshot} />
        </div>

        <ProjectProgressSection snapshot={snapshot} />
        <BrokerReadinessSection brokers={snapshot?.broker_readiness ?? []} />
        <PerformanceSummarySection snapshot={snapshot} />

        <div className="ops-landing__secondary-grid">
          <OperationalActivitySection snapshot={snapshot} connection={connection} />
          <NextActionSection snapshot={snapshot} sourceMode={connection.sourceMode} />
        </div>

        <DocumentationLinksSection />
      </div>
    </main>
  )
}
