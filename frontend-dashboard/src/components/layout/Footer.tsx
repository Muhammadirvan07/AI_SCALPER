import { Database, LockKeyhole, Radar } from 'lucide-react'
import type { DashboardSummary, DataStatus } from '../../types/dashboard'
import { formatDateTime } from '../../utils/formatters'
import { StatusBadge } from '../dashboard/StatusBadge'

interface FooterProps {
  summary: DashboardSummary
  dataStatus: DataStatus
}

export function Footer({ summary, dataStatus }: FooterProps) {
  return (
    <footer className="mt-16 border-t border-white/[0.07] bg-slate-950/60">
      <div className="page-container py-10">
        <div className="grid gap-8 md:grid-cols-[1.2fr_2fr]">
          <div>
            <div className="flex items-center gap-3">
              <span className="grid size-10 place-items-center rounded-xl border border-cyan-300/20 bg-cyan-300/10 text-cyan-200">
                <Radar aria-hidden="true" className="size-5" />
              </span>
              <div>
                <p className="font-semibold tracking-[0.12em] text-white">AI_SCALPER</p>
                <p className="text-xs text-slate-500">Pusat kendali intelijen paper</p>
              </div>
            </div>
            <p className="mt-4 max-w-md text-sm leading-6 text-slate-400">
              Antarmuka pemantauan dan visualisasi untuk intelijen pasar, diagnostik strategi,
              dan kualitas risiko adaptif.
            </p>
          </div>

          <dl className="grid gap-5 text-sm sm:grid-cols-2 lg:grid-cols-4">
            <div>
              <dt className="text-xs tracking-wider text-slate-500 uppercase">Sistem</dt>
              <dd className="mt-1 font-medium text-slate-200">{summary.systemVersion}</dd>
            </div>
            <div>
              <dt className="text-xs tracking-wider text-slate-500 uppercase">Antarmuka</dt>
              <dd className="mt-1 font-medium text-slate-200">{summary.frontendVersion}</dd>
            </div>
            <div>
              <dt className="text-xs tracking-wider text-slate-500 uppercase">Pembaruan terakhir</dt>
              <dd className="mt-1 font-medium text-slate-200">
                {formatDateTime(summary.updatedAt)}
              </dd>
            </div>
            <div>
              <dt className="text-xs tracking-wider text-slate-500 uppercase">Sumber data</dt>
              <dd className="mt-1">
                <StatusBadge
                  label={dataStatus === 'success' ? 'MOCK TERSINKRON' : dataStatus.toUpperCase()}
                  tone={dataStatus === 'success' ? 'positive' : 'warning'}
                />
              </dd>
            </div>
          </dl>
        </div>

        <div className="mt-8 flex flex-col gap-3 border-t border-white/[0.06] pt-6 text-xs text-slate-500 sm:flex-row sm:items-center sm:justify-between">
          <p className="flex items-center gap-2">
            <LockKeyhole aria-hidden="true" className="size-4 text-red-300" />
            Hanya untuk lingkungan trading paper dan riset. Eksekusi trading live tetap TERKUNCI (LOCKED).
          </p>
          <p className="flex items-center gap-2">
            <Database aria-hidden="true" className="size-4" />
            Antarmuka pemantauan hanya-baca
          </p>
        </div>
      </div>
    </footer>
  )
}
