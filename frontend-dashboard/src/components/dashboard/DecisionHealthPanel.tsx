import { BrainCircuit, CheckCircle2, Clock3, DatabaseZap, TriangleAlert } from 'lucide-react'
import type { DecisionHealth, Tone } from '../../types/dashboard'
import { formatTime } from '../../utils/formatters'
import { formatStatusLabel } from '../../utils/statusHelpers'
import { Panel } from '../ui/Panel'
import { StatusBadge } from './StatusBadge'

const toneText: Record<Tone, string> = {
  positive: 'text-emerald-300',
  warning: 'text-amber-200',
  negative: 'text-red-300',
  info: 'text-cyan-200',
  neutral: 'text-slate-300',
}

interface DecisionHealthPanelProps {
  data: DecisionHealth
}

export function DecisionHealthPanel({ data }: DecisionHealthPanelProps) {
  const healthSegments = Array.from({ length: 10 }, (_, index) => index < data.healthScore / 10)

  const details = [
    { label: 'Keputusan terakhir', value: formatTime(data.lastDecisionTime) },
    { label: 'Usia candle terbaru', value: data.latestCandleAge },
    { label: 'Simbol aktif', value: data.activeSymbol },
    { label: 'Strategi aktif', value: data.activeStrategy },
    { label: 'Sesi saat ini', value: data.currentSession },
    { label: 'Kondisi volatilitas', value: data.volatilityCondition },
  ]

  return (
    <Panel className="p-4 sm:p-6">
      <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
        <div>
          <p className="flex items-center gap-2 text-xs font-semibold tracking-[0.16em] text-violet-300 uppercase">
            <BrainCircuit aria-hidden="true" className="size-4" />
            Pipeline keputusan
          </p>
          <h3 id="decision-health-title" className="mt-1 text-xl font-semibold text-white">
            Kesehatan keputusan
          </h3>
          <p className="mt-2 text-sm leading-6 text-slate-400">
            Kualitas input, cakupan guard, kelengkapan diagnostik, dan latensi keputusan.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <StatusBadge label={data.engineStatus} tone="positive" pulse />
          <StatusBadge label={data.readinessStatus} tone="warning" />
        </div>
      </div>

      <div className="mt-6 rounded-2xl border border-white/[0.07] bg-slate-950/35 p-4">
        <div className="flex items-end justify-between">
          <div>
            <p className="text-xs text-slate-500">Skor kesehatan keputusan</p>
            <p className="mt-1 text-3xl font-semibold text-white">
              {data.healthScore}
              <span className="text-sm font-normal text-slate-500"> / 100</span>
            </p>
          </div>
          <div className="flex items-center gap-2 text-xs text-emerald-300">
            <CheckCircle2 aria-hidden="true" className="size-4" />
            Mesin merespons
          </div>
        </div>
        <div
          className="mt-4 grid grid-cols-10 gap-1.5"
          role="img"
          aria-label={`Skor kesehatan keputusan ${data.healthScore} dari 100`}
        >
          {healthSegments.map((active, index) => (
            <span
              key={`health-segment-${index.toString()}`}
              className={`h-2 rounded-full ${
                active
                  ? index < 5
                    ? 'bg-amber-300'
                    : index < 8
                      ? 'bg-cyan-300'
                      : 'bg-emerald-300'
                  : 'bg-slate-800'
              }`}
            />
          ))}
        </div>
      </div>

      <dl className="mt-4 grid gap-2 sm:grid-cols-2 xl:grid-cols-3">
        {details.map((item) => (
          <div key={item.label} className="rounded-xl border border-white/[0.06] bg-slate-950/25 p-3">
            <dt className="text-[0.68rem] text-slate-500">{item.label}</dt>
            <dd className="mt-1 truncate text-xs font-semibold text-slate-200" title={item.value}>
              {item.value}
            </dd>
          </div>
        ))}
      </dl>

      <div className="mt-4 grid gap-2 sm:grid-cols-2">
        {data.checks.map((check) => (
          <div
            key={check.label}
            className="flex items-center justify-between rounded-xl border border-white/[0.06] bg-slate-950/25 px-3 py-2.5"
          >
            <span className="text-xs text-slate-500">{check.label}</span>
            <span className={`text-xs font-semibold ${toneText[check.tone]}`}>{check.value}</span>
          </div>
        ))}
      </div>

      <div className="mt-4 grid gap-2 sm:grid-cols-2">
        <div className="flex items-center gap-3 rounded-xl border border-emerald-400/10 bg-emerald-400/[0.035] p-3">
          <DatabaseZap aria-hidden="true" className="size-4 text-emerald-300" />
          <div>
            <p className="text-[0.68rem] text-slate-500">Kesegaran data</p>
            <p className="text-xs font-semibold text-emerald-200">{formatStatusLabel(data.dataFreshness)}</p>
          </div>
        </div>
        <div className="flex items-center gap-3 rounded-xl border border-amber-400/10 bg-amber-400/[0.035] p-3">
          {data.missingDiagnostics.length ? (
            <TriangleAlert aria-hidden="true" className="size-4 text-amber-200" />
          ) : (
            <Clock3 aria-hidden="true" className="size-4 text-emerald-300" />
          )}
          <div className="min-w-0">
            <p className="text-[0.68rem] text-slate-500">Diagnostik yang belum tersedia</p>
            <p className="truncate text-xs font-semibold text-amber-100">
              {data.missingDiagnostics.length ? data.missingDiagnostics.join(', ') : 'Tidak ada'}
            </p>
          </div>
        </div>
      </div>
    </Panel>
  )
}
