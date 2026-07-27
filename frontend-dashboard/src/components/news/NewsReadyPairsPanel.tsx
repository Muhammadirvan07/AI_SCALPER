import { CheckCircle2, Gauge, LockKeyhole, ShieldCheck } from 'lucide-react'
import { useMemo } from 'react'
import type { MarketNewsEvent, PairNewsImpact } from '../../types/dashboard'
import {
  formatDirectionBias,
  formatProjectedVolatility,
  formatSpreadRisk,
  paperDecisionTone,
} from '../../utils/newsMappings'
import { StatusBadge } from '../dashboard/StatusBadge'
import { Panel } from '../ui/Panel'
import { PanelState } from '../ui/PanelState'

interface NewsReadyPairsPanelProps {
  events: MarketNewsEvent[]
  impacts: PairNewsImpact[]
}

export function NewsReadyPairsPanel({ events, impacts }: NewsReadyPairsPanelProps) {
  const eventsById = useMemo(
    () => new Map(events.map((event) => [event.id, event])),
    [events],
  )
  const readyPairs = impacts.filter(
    (impact) => impact.decision === 'PAPER_READY' && impact.guardStatus === 'PASS',
  )

  return (
    <Panel className="overflow-hidden p-0" labelledBy="paper-ready-title">
      <div className="border-b border-white/[0.06] p-4 sm:p-5">
        <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
          <div>
            <p className="text-[0.68rem] font-semibold tracking-[0.16em] text-emerald-300 uppercase">
              Pair yang lolos keputusan
            </p>
            <h2 id="paper-ready-title" className="mt-1 text-lg font-semibold text-white">
              Efek berita / gate kesiapan paper
            </h2>
            <p className="mt-1 text-sm leading-6 text-slate-400">
              Kandidat ditampilkan setelah hasil berita, ambang skor, dan guard keselamatan selaras.
            </p>
          </div>
          <StatusBadge label={`${readyPairs.length} PAPER SIAP`} tone="positive" />
        </div>

        <div
          className="mt-4 grid gap-3 rounded-xl border border-emerald-300/15 bg-emerald-300/[0.045] p-3 sm:grid-cols-[auto_1fr_auto] sm:items-center"
          role="note"
        >
          <span className="grid size-9 place-items-center rounded-lg border border-emerald-300/15 bg-emerald-300/[0.07] text-emerald-300">
            <ShieldCheck aria-hidden="true" className="size-4.5" />
          </span>
          <div>
            <strong className="block text-xs tracking-[0.1em] text-emerald-200 uppercase">
              Siap hanya berarti evaluasi paper
            </strong>
            <span className="mt-1 block text-xs leading-5 text-slate-400">
              Status ini adalah keluaran diagnostik, bukan izin mengirim order otomatis live atau demo.
            </span>
          </div>
          <span className="inline-flex items-center gap-1.5 font-mono text-[0.68rem] font-semibold text-red-300">
            <LockKeyhole aria-hidden="true" className="size-3.5" />
            LIVE TERKUNCI (LOCKED)
          </span>
        </div>
      </div>

      {readyPairs.length === 0 ? (
        <div className="p-4 sm:p-5">
          <PanelState
            state="empty"
            compact
            title="Belum ada pair yang lolos gate kesiapan paper"
            message="Konteks berita tersedia, tetapi belum ada kandidat yang memenuhi skor dan persyaratan guard."
          />
        </div>
      ) : (
        <div className="grid gap-3 p-4 sm:p-5">
          {readyPairs.map((impact) => {
            const event = eventsById.get(impact.newsId)
            const scoreProgress = Math.min(
              100,
              impact.decisionScore !== null &&
                impact.minimumScore !== null &&
                impact.minimumScore > 0
                ? (impact.decisionScore / impact.minimumScore) * 100
                : 0,
            )

            return (
              <article
                key={impact.id}
                className="rounded-xl border border-emerald-300/15 bg-emerald-300/[0.035] p-4"
                aria-label={`${impact.symbol} kandidat berita siap-paper`}
              >
                <div className="flex flex-wrap items-start justify-between gap-3">
                  <div>
                    <div className="flex flex-wrap items-center gap-2">
                      <strong className="font-mono text-lg tracking-wide text-white">
                        {impact.symbol}
                      </strong>
                      <StatusBadge label={impact.pairStatus} tone="info" />
                    </div>
                    <p className="mt-1 text-xs text-slate-500">
                      Pemicu hasil: {event?.title ?? impact.newsId}
                    </p>
                  </div>
                  <StatusBadge
                    label={impact.decision}
                    tone={paperDecisionTone[impact.decision]}
                    pulse
                  />
                </div>

                <div className="mt-4 grid grid-cols-2 gap-2 sm:grid-cols-4">
                  {[
                    ['EFEK BERITA', formatDirectionBias(impact.directionBias)],
                    ['VOLATILITAS', formatProjectedVolatility(impact.projectedVolatility)],
                    ['RISIKO SPREAD', formatSpreadRisk(impact.spreadRisk)],
                    [
                      'DAMPAK BERITA',
                      impact.impactScore === null ? '—' : `${impact.impactScore}/100`,
                    ],
                  ].map(([label, value]) => (
                    <div
                      key={label}
                      className="rounded-lg border border-white/[0.055] bg-slate-950/35 px-3 py-2.5"
                    >
                      <span className="block text-[0.6rem] tracking-[0.12em] text-slate-600 uppercase">
                        {label}
                      </span>
                      <strong className="mt-1 block font-mono text-xs text-slate-200">
                        {value}
                      </strong>
                    </div>
                  ))}
                </div>

                <div className="mt-4">
                  <div className="flex items-center justify-between gap-3 text-[0.68rem]">
                    <span className="inline-flex items-center gap-1.5 tracking-[0.1em] text-slate-500 uppercase">
                      <Gauge aria-hidden="true" className="size-3.5" />
                      Skor keputusan
                    </span>
                    <strong className="font-mono tabular-nums text-emerald-200">
                      {impact.decisionScore?.toFixed(1) ?? '—'} /{' '}
                      {impact.minimumScore?.toFixed(1) ?? '—'} MIN
                    </strong>
                  </div>
                  <div className="mt-2 h-1.5 overflow-hidden rounded-full bg-slate-800">
                    <span
                      className="block h-full rounded-full bg-emerald-400 motion-safe:animate-progress-in"
                      style={{ width: `${scoreProgress}%` }}
                    />
                  </div>
                </div>

                <p className="mt-4 text-sm leading-6 text-slate-300">{impact.effect}</p>
                <p className="mt-3 flex items-start gap-2 text-xs leading-5 text-emerald-200/75">
                  <CheckCircle2 aria-hidden="true" className="mt-0.5 size-3.5 shrink-0" />
                  {impact.requiredObservation}
                </p>
              </article>
            )
          })}
        </div>
      )}
    </Panel>
  )
}
