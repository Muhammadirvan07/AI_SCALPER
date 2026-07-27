import { CheckCircle2, CircleSlash2, DatabaseZap, ShieldCheck } from 'lucide-react'
import type {
  DashboardDecisionReadiness,
  DashboardNewsSource,
  Tone,
} from '../../types/dashboard'
import { formatDecisionBlocker, formatGateStatus } from '../../utils/newsMappings'
import { StatusBadge } from '../dashboard/StatusBadge'
import { Panel } from '../ui/Panel'

interface NewsDecisionReadinessProps {
  readiness: DashboardDecisionReadiness
  source: DashboardNewsSource
}

const gateTone = (value: string | boolean): Tone => {
  if (
    value === true ||
    String(value).toUpperCase().startsWith('PASS') ||
    value === 'ALLOWED'
  ) return 'positive'
  if (
    value === false ||
    value.includes('BLOCK') ||
    value.includes('FAIL') ||
    value.includes('REJECT')
  ) {
    return 'negative'
  }
  return 'neutral'
}

export function NewsDecisionReadiness({
  readiness,
  source,
}: NewsDecisionReadinessProps) {
  return (
    <Panel className="overflow-hidden p-0" labelledBy="news-readiness-title">
      <div className="flex flex-col gap-4 border-b border-white/[0.06] p-4 sm:flex-row sm:items-start sm:justify-between sm:p-5">
        <div className="flex min-w-0 items-start gap-3">
          <span className="grid size-10 shrink-0 place-items-center rounded-xl border border-emerald-300/15 bg-emerald-300/[0.05] text-emerald-200">
            <ShieldCheck aria-hidden="true" className="size-5" />
          </span>
          <div className="min-w-0">
            <p className="text-[0.68rem] font-semibold tracking-[0.16em] text-emerald-300 uppercase">
              Kontrak keputusan
            </p>
            <h2 id="news-readiness-title" className="mt-1 text-lg font-semibold text-white">
              Kesiapan keputusan paper
            </h2>
            <p className="mt-1 text-sm leading-6 text-slate-400">
              Status eksplisit dari backend; UI tidak menebak kesiapan dari teks log.
            </p>
          </div>
        </div>
        <StatusBadge
          label={readiness.ready ? 'PAPER READY' : readiness.status}
          tone={readiness.ready ? 'positive' : readiness.status === 'BLOCKED' ? 'negative' : 'warning'}
          pulse={readiness.ready}
        />
      </div>

      <div className="grid gap-4 p-4 sm:p-5 lg:grid-cols-[0.75fr_1.25fr]">
        <div className="min-w-0 rounded-xl border border-white/[0.06] bg-slate-950/30 p-4">
          <div className="flex min-w-0 flex-wrap items-center gap-2 text-xs text-slate-400">
            <DatabaseZap aria-hidden="true" className="size-4 text-cyan-300" />
            <span className="min-w-0 break-words font-mono">{source.provider}</span>
            <StatusBadge
              label={source.status}
              tone={source.status === 'FRESH' ? 'positive' : source.status === 'STALE' ? 'warning' : 'neutral'}
            />
          </div>
          <dl className="mt-4 grid grid-cols-2 gap-3">
            {[
              ['PAIR', readiness.symbol],
              ['STRATEGI', readiness.strategy],
              ['SKOR', readiness.score?.toFixed(2) ?? '—'],
              ['MINIMUM', readiness.minimumRequired?.toFixed(2) ?? '—'],
            ].map(([label, value]) => (
              <div key={label}>
                <dt className="text-[0.62rem] tracking-[0.12em] text-slate-600 uppercase">{label}</dt>
                <dd className="mt-1 font-mono text-sm text-slate-200">{value}</dd>
              </div>
            ))}
          </dl>
        </div>

        <div className="min-w-0">
          <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
            {[
              ['DATA', readiness.gates.dataFreshness ? 'PASS' : 'FAIL'],
              ['BERITA', readiness.gates.news],
              ['SPREAD', readiness.gates.spread],
              ['SESI', readiness.gates.session],
            ].map(([label, value]) => (
              <div key={label} className="rounded-lg border border-white/[0.055] bg-white/[0.02] p-3">
                <span className="block text-[0.6rem] tracking-[0.12em] text-slate-600 uppercase">{label}</span>
                <span className="mt-1.5 flex items-center gap-1.5 font-mono text-xs text-slate-200">
                  {gateTone(value ?? 'UNAVAILABLE') === 'positive' ? (
                    <CheckCircle2 aria-hidden="true" className="size-3.5 text-emerald-300" />
                  ) : (
                    <CircleSlash2 aria-hidden="true" className="size-3.5 text-amber-300" />
                  )}
                  {formatGateStatus(value ?? 'UNAVAILABLE')}
                </span>
              </div>
            ))}
          </div>
          <p className="mt-4 break-words text-sm leading-6 text-slate-400">{readiness.explanation}</p>
          {readiness.blockers.length > 0 ? (
            <ul className="mt-3 flex flex-wrap gap-2" aria-label="Pemblokir keputusan">
              {readiness.blockers.map((blocker) => (
                <li key={blocker}>
                  <StatusBadge
                    label={formatDecisionBlocker(blocker)}
                    tone={gateTone(blocker)}
                  />
                </li>
              ))}
            </ul>
          ) : null}
        </div>
      </div>
    </Panel>
  )
}
