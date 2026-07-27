import {
  ArrowDownRight,
  ArrowRight,
  ArrowUpRight,
  ChevronDown,
  GitCompareArrows,
  ShieldCheck,
} from 'lucide-react'
import { useMemo, useState } from 'react'
import type { MarketNewsEvent, PairNewsImpact, Tone } from '../../types/dashboard'
import {
  formatDirectionBias,
  formatNewsGuard,
  formatProjectedVolatility,
  formatSpreadRisk,
  paperDecisionTone,
} from '../../utils/newsMappings'
import { StatusBadge } from '../dashboard/StatusBadge'
import { Panel } from '../ui/Panel'
import { PanelState } from '../ui/PanelState'

interface NewsImpactMatrixProps {
  events: MarketNewsEvent[]
  impacts: PairNewsImpact[]
}

const IMPACT_PAGE_SIZE = 30

const guardTone: Record<PairNewsImpact['guardStatus'], Tone> = {
  PASS: 'positive',
  CAUTION: 'warning',
  BLOCKED: 'negative',
  UNAVAILABLE: 'neutral',
}

const directionTone: Record<PairNewsImpact['directionBias'], string> = {
  BULLISH: 'text-emerald-300',
  BEARISH: 'text-red-300',
  MIXED: 'text-amber-200',
  NEUTRAL: 'text-slate-400',
  UNKNOWN: 'text-slate-500',
}

function DirectionIcon({ direction }: { direction: PairNewsImpact['directionBias'] }) {
  if (direction === 'BULLISH') return <ArrowUpRight aria-hidden="true" className="size-3.5" />
  if (direction === 'BEARISH') return <ArrowDownRight aria-hidden="true" className="size-3.5" />
  return <ArrowRight aria-hidden="true" className="size-3.5" />
}

export function NewsImpactMatrix({ events, impacts }: NewsImpactMatrixProps) {
  const [visibleCount, setVisibleCount] = useState(IMPACT_PAGE_SIZE)
  const eventsById = useMemo(
    () => new Map(events.map((event) => [event.id, event])),
    [events],
  )
  const visibleImpacts = impacts.slice(0, visibleCount)
  const remainingCount = Math.max(0, impacts.length - visibleImpacts.length)

  return (
    <Panel className="overflow-hidden p-0" labelledBy="news-impact-matrix-title">
      <div className="border-b border-white/[0.06] p-4 sm:p-5">
        <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
          <div className="flex min-w-0 items-start gap-3">
            <span className="grid size-10 shrink-0 place-items-center rounded-xl border border-violet-300/15 bg-violet-300/[0.06] text-violet-200">
              <GitCompareArrows aria-hidden="true" className="size-5" />
            </span>
            <div>
              <p className="text-[0.68rem] font-semibold tracking-[0.16em] text-violet-300 uppercase">
                Interpretasi lintas aset
              </p>
              <h2 id="news-impact-matrix-title" className="mt-1 text-lg font-semibold text-white">
                Matriks keputusan berita ke pair
              </h2>
              <p className="mt-1 text-sm leading-6 text-slate-400">
                Efek arah dievaluasi bersama volatilitas, spread, skor, dan guard.
              </p>
            </div>
          </div>
          <StatusBadge label={`${impacts.length} PEMERIKSAAN PAIR`} tone="neutral" />
        </div>
      </div>

      {impacts.length === 0 ? (
        <div className="p-4 sm:p-5">
          <PanelState
            state="empty"
            compact
            title="Belum ada catatan dampak pair"
            message="Adapter keputusan belum memetakan peristiwa berita ke pair terpantau."
          />
        </div>
      ) : (
        <>
          <div className="hidden overflow-x-auto md:block">
            <table className="w-full min-w-[1080px] border-collapse text-left">
              <caption className="sr-only">
                Efek berita pada pair terpantau, termasuk skor, guard, dan keputusan paper.
              </caption>
              <thead>
                <tr className="border-b border-white/[0.06] bg-slate-950/25 text-[0.64rem] tracking-[0.12em] text-slate-500 uppercase">
                  <th scope="col" className="px-5 py-3 font-semibold">Pair / peristiwa</th>
                  <th scope="col" className="px-4 py-3 font-semibold">Efek</th>
                  <th scope="col" className="px-4 py-3 font-semibold">Volatilitas / spread</th>
                  <th scope="col" className="px-4 py-3 font-semibold">Skor</th>
                  <th scope="col" className="px-4 py-3 font-semibold">Guard</th>
                  <th scope="col" className="px-4 py-3 font-semibold">Keputusan</th>
                  <th scope="col" className="px-5 py-3 font-semibold">Interpretasi</th>
                </tr>
              </thead>
              <tbody>
                {visibleImpacts.map((impact) => {
                  const event = eventsById.get(impact.newsId)
                  return (
                    <tr
                      key={impact.id}
                      className="border-b border-white/[0.045] align-top transition hover:bg-white/[0.02]"
                    >
                      <th scope="row" className="px-5 py-4">
                        <span className="block font-mono text-sm text-slate-100">{impact.symbol}</span>
                        <span className="mt-1 block max-w-56 text-xs font-normal leading-5 text-slate-500">
                          {event?.title ?? impact.newsId}
                        </span>
                      </th>
                      <td className="px-4 py-4">
                        <span
                          className={`inline-flex items-center gap-1 font-mono text-xs font-semibold ${directionTone[impact.directionBias]}`}
                        >
                          <DirectionIcon direction={impact.directionBias} />
                          {formatDirectionBias(impact.directionBias)}
                        </span>
                      </td>
                      <td className="px-4 py-4 font-mono text-xs text-slate-300">
                        <span className="block">{formatProjectedVolatility(impact.projectedVolatility)}</span>
                        <span className="mt-1 block text-slate-500">{formatSpreadRisk(impact.spreadRisk)}</span>
                      </td>
                      <td className="px-4 py-4">
                        <strong className="font-mono text-sm tabular-nums text-slate-100">
                          {impact.decisionScore?.toFixed(1) ?? '—'}
                        </strong>
                        <span className="mt-1 block font-mono text-[0.66rem] text-slate-500">
                          MIN {impact.minimumScore?.toFixed(1) ?? '—'}
                        </span>
                      </td>
                      <td className="px-4 py-4">
                        <StatusBadge label={formatNewsGuard(impact.guardStatus)} tone={guardTone[impact.guardStatus]} />
                      </td>
                      <td className="px-4 py-4">
                        <StatusBadge
                          label={impact.decision}
                          tone={paperDecisionTone[impact.decision]}
                        />
                      </td>
                      <td className="max-w-sm px-5 py-4">
                        <p className="text-xs leading-5 text-slate-400">{impact.effect}</p>
                        <p className="mt-2 text-[0.68rem] leading-5 text-slate-600">
                          {impact.requiredObservation}
                        </p>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>

          <div className="grid gap-3 p-4 md:hidden">
            {visibleImpacts.map((impact) => {
              const event = eventsById.get(impact.newsId)
              return (
                <article
                  key={impact.id}
                  className="rounded-xl border border-white/[0.065] bg-slate-950/30 p-4"
                >
                  <div className="flex flex-wrap items-start justify-between gap-3">
                    <div>
                      <strong className="font-mono text-base text-white">{impact.symbol}</strong>
                      <p className="mt-1 text-xs leading-5 text-slate-500">
                        {event?.title ?? impact.newsId}
                      </p>
                    </div>
                    <StatusBadge
                      label={impact.decision}
                      tone={paperDecisionTone[impact.decision]}
                    />
                  </div>
                  <div className="mt-3 flex flex-wrap items-center gap-2">
                    <span
                      className={`inline-flex items-center gap-1 font-mono text-xs ${directionTone[impact.directionBias]}`}
                    >
                      <DirectionIcon direction={impact.directionBias} />
                      {formatDirectionBias(impact.directionBias)}
                    </span>
                    <StatusBadge label={formatNewsGuard(impact.guardStatus)} tone={guardTone[impact.guardStatus]} />
                  </div>
                  <dl className="mt-4 grid grid-cols-3 gap-2">
                    {[
                      ['VOL', formatProjectedVolatility(impact.projectedVolatility)],
                      ['SPREAD', formatSpreadRisk(impact.spreadRisk)],
                      [
                        'SKOR',
                        `${impact.decisionScore?.toFixed(1) ?? '—'} / ${impact.minimumScore?.toFixed(1) ?? '—'}`,
                      ],
                    ].map(([label, value]) => (
                      <div key={label} className="rounded-lg bg-white/[0.025] p-2">
                        <dt className="text-[0.58rem] tracking-[0.1em] text-slate-600 uppercase">
                          {label}
                        </dt>
                        <dd className="mt-1 font-mono text-[0.68rem] text-slate-300">{value}</dd>
                      </div>
                    ))}
                  </dl>
                  <p className="mt-4 text-xs leading-5 text-slate-400">{impact.effect}</p>
                </article>
              )
            })}
          </div>
          {remainingCount > 0 ? (
            <div className="flex justify-center border-t border-white/[0.055] p-4">
              <button
                type="button"
                className="filter-button inline-flex items-center gap-2"
                onClick={() => setVisibleCount((count) => count + IMPACT_PAGE_SIZE)}
              >
                <ChevronDown aria-hidden="true" className="size-3.5" />
                TAMPILKAN {Math.min(IMPACT_PAGE_SIZE, remainingCount)} DAMPAK LAGI
              </button>
            </div>
          ) : null}
        </>
      )}

      <div className="flex items-center gap-2 border-t border-white/[0.055] px-4 py-3 text-[0.68rem] text-slate-500 sm:px-5">
        <ShieldCheck aria-hidden="true" className="size-3.5 text-cyan-300" />
        Guard pair tetap menjadi otoritas meskipun skor hasil berita telah lolos.
      </div>
    </Panel>
  )
}
