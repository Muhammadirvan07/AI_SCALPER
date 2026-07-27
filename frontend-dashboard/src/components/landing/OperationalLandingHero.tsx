import { ArrowRight, Eye, LockKeyhole, ShieldCheck } from 'lucide-react'
import { Link } from '../../routing/Router'
import type {
  DashboardApiSnapshot,
  DashboardSourceMode,
} from '../../types/dashboardApi'
import {
  deriveOperationalMode,
  operationalLabel,
} from '../../utils/landingViewModel'
import { OperationalStatusTag } from './OperationalStatusTag'
import { OperationalTimestamp } from './OperationalTimestamp'

interface OperationalLandingHeroProps {
  snapshot: DashboardApiSnapshot | null
  sourceMode: DashboardSourceMode
}

const verifiedBoolean = (value: boolean | null | undefined) => {
  if (value === null || value === undefined) return 'TIDAK TERVERIFIKASI'
  return value ? 'YA' : 'TIDAK'
}

export function OperationalLandingHero({
  snapshot,
  sourceMode,
}: OperationalLandingHeroProps) {
  const mode = deriveOperationalMode(snapshot)
  const mockDevelopment = sourceMode === 'MOCK FALLBACK'

  return (
    <section className="ops-hero" aria-labelledby="landing-title">
      <div className="ops-hero__grid" aria-hidden="true" />
      <div className="page-container ops-hero__layout">
        <div className="ops-hero__copy">
          <p className="ops-kicker">
            <Eye aria-hidden="true" className="size-4" />
            Pusat kendali observasi operasional
          </p>
          <div className="ops-hero__badges" aria-label="Batas operasional utama">
            <OperationalStatusTag
              value="LOCKED"
              label="LIVE ORDER TERKUNCI"
              tone="blocked"
            />
            <OperationalStatusTag
              value={snapshot ? sourceMode : 'UNVERIFIED'}
              label={mockDevelopment ? 'MOCK DEVELOPMENT — BUKAN DATA AKTUAL' : undefined}
              tone={mockDevelopment ? 'warning' : undefined}
            />
          </div>
          <h1 id="landing-title">
            AI_<span>SCALPER</span>
          </h1>
          <p className="ops-hero__lead">
            Platform observasi, diagnostik, dan trading paper untuk memantau kualitas
            keputusan AI_SCALPER tanpa memberi kemampuan eksekusi order.
          </p>
          <p className="ops-hero__support">
            Dalam satu pandangan, operator dapat memverifikasi koneksi data, batas
            keselamatan, gate proyek, kesiapan broker, dan evidence performa paper aktual.
          </p>
          <div className="ops-hero__actions">
            <Link to="/overview" className="button-primary">
              Buka Dashboard
              <ArrowRight aria-hidden="true" className="size-4" />
            </Link>
            <Link to="/system-health" className="button-secondary">
              <ShieldCheck aria-hidden="true" className="size-4" />
              Lihat Kesehatan Sistem
            </Link>
          </div>
        </div>

        <aside className="ops-hero__brief" aria-label="Ringkasan operasi saat ini">
          <header>
            <span>STATUS OPERASI AKTUAL</span>
            <LockKeyhole aria-hidden="true" className="size-4 text-red-300" />
          </header>
          <dl>
            <div>
              <dt>Mode teramati</dt>
              <dd data-testid="operational-mode">{operationalLabel(mode)}</dd>
            </div>
            <div>
              <dt>Tahap sistem</dt>
              <dd>{operationalLabel(snapshot?.project_progress.stage)}</dd>
            </div>
            <div>
              <dt>Status keputusan</dt>
              <dd>{operationalLabel(snapshot?.decision_readiness.decision_status)}</dd>
            </div>
            <div>
              <dt>Layak promosi</dt>
              <dd>{verifiedBoolean(snapshot?.project_progress.promotion_eligible)}</dd>
            </div>
            <div>
              <dt>Lot maksimum</dt>
              <dd>{snapshot ? snapshot.safety.max_lot.toFixed(2) : 'TIDAK TERVERIFIKASI'}</dd>
            </div>
          </dl>
          <div className="ops-hero__snapshot">
            <span>Snapshot terakhir tervalidasi</span>
            <OperationalTimestamp value={snapshot?.generated_at} />
          </div>
          <p>
            {snapshot
              ? snapshot.project_progress.promotion_reason ?? 'Alasan promosi belum tersedia pada snapshot.'
              : 'Data operasional tidak diasumsikan. Antarmuka tetap fail-closed hingga snapshot API tervalidasi.'}
          </p>
        </aside>
      </div>
    </section>
  )
}
