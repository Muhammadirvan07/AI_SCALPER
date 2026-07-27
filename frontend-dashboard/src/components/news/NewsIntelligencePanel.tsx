import { CalendarClock, ChevronDown, Database, Newspaper, Radio, ShieldAlert } from 'lucide-react'
import { useMemo, useState } from 'react'
import type {
  DataStatus,
  MarketNewsEvent,
  DashboardNewsSource,
  NewsImpactLevel,
} from '../../types/dashboard'
import { formatTime } from '../../utils/formatters'
import {
  formatNewsEventStatus,
  formatNewsImpact,
  formatNewsSurprise,
  newsEventStatusTone,
  newsImpactTone,
} from '../../utils/newsMappings'
import { StatusBadge } from '../dashboard/StatusBadge'
import { Panel } from '../ui/Panel'
import { PanelState } from '../ui/PanelState'

type NewsFilter = 'ALL' | 'UPCOMING' | 'RELEASED' | 'HIGH IMPACT'

const filters: NewsFilter[] = ['ALL', 'UPCOMING', 'RELEASED', 'HIGH IMPACT']
const filterLabels: Record<NewsFilter, string> = {
  ALL: 'SEMUA',
  UPCOMING: 'AKAN DATANG',
  RELEASED: 'DIRILIS',
  'HIGH IMPACT': 'DAMPAK TINGGI',
}

const isHighImpact = (impact: NewsImpactLevel) => impact === 'HIGH' || impact === 'CRITICAL'
const NEWS_PAGE_SIZE = 12

interface NewsIntelligencePanelProps {
  events: MarketNewsEvent[]
  dataStatus: DataStatus
  source: DashboardNewsSource
}

export function NewsIntelligencePanel({
  events,
  dataStatus,
  source,
}: NewsIntelligencePanelProps) {
  const [filter, setFilter] = useState<NewsFilter>('ALL')
  const [visibleCount, setVisibleCount] = useState(NEWS_PAGE_SIZE)

  const filteredEvents = useMemo(
    () =>
      events.filter((event) => {
        if (filter === 'ALL') return true
        if (filter === 'HIGH IMPACT') return isHighImpact(event.impact)
        return event.status === filter
      }),
    [events, filter],
  )
  const visibleEvents = filteredEvents.slice(0, visibleCount)
  const remainingCount = Math.max(0, filteredEvents.length - visibleEvents.length)

  const usesApi = events.some((event) => event.source === 'API')
  const sourceDisconnected = dataStatus === 'disconnected'
  const sourceLabel = sourceDisconnected
    ? 'KONEKSI TERPUTUS'
    : source.status === 'FRESH'
      ? 'KALENDER AKTUAL'
      : source.status === 'STALE'
        ? 'BERITA KEDALUWARSA'
        : source.status === 'PARTIAL'
          ? 'DATA BERITA PARSIAL'
          : source.status === 'INVALID'
            ? 'SUMBER BERITA INVALID'
            : 'FEED TIDAK TERSEDIA'
  const sourceTone = source.status === 'FRESH'
    ? 'positive'
    : source.status === 'STALE' || source.status === 'PARTIAL'
      ? 'warning'
      : source.status === 'INVALID' || sourceDisconnected
        ? 'negative'
        : 'neutral'

  return (
    <Panel className="overflow-hidden p-0" labelledBy="news-intelligence-title">
      <div className="border-b border-white/[0.06] p-4 sm:p-5">
        <div className="flex flex-col gap-4 xl:flex-row xl:items-start xl:justify-between">
          <div className="flex min-w-0 items-start gap-3">
            <span className="grid size-10 shrink-0 place-items-center rounded-xl border border-cyan-300/15 bg-cyan-300/[0.06] text-cyan-200">
              <Newspaper aria-hidden="true" className="size-5" />
            </span>
            <div>
              <p className="text-[0.68rem] font-semibold tracking-[0.16em] text-cyan-300 uppercase">
                Intelijen berita
              </p>
              <h2 id="news-intelligence-title" className="mt-1 text-lg font-semibold text-white">
                Monitor peristiwa pasar
              </h2>
              <p className="mt-1 max-w-2xl text-sm leading-6 text-slate-400">
                Hasil peristiwa, selisih perkiraan, dan eksposur pair untuk analisis paper.
              </p>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <StatusBadge
              label={
                source.provider === 'MOCK FALLBACK'
                  ? 'FEED BERITA MOCK'
                  : sourceLabel
              }
              tone={source.provider === 'MOCK FALLBACK' ? 'neutral' : sourceTone}
              pulse={!sourceDisconnected && source.status === 'FRESH' && usesApi}
            />
            <StatusBadge label="LIVE TERKUNCI (LOCKED)" tone="negative" />
          </div>
        </div>

        <div
          className="mt-4 flex items-start gap-2.5 rounded-xl border border-amber-300/15 bg-amber-300/[0.055] px-3 py-2.5 text-xs leading-5 text-amber-100/80"
          role="note"
        >
          {usesApi ? (
            <Radio aria-hidden="true" className="mt-0.5 size-4 shrink-0" />
          ) : (
            <Database aria-hidden="true" className="mt-0.5 size-4 shrink-0" />
          )}
          <span>
            {usesApi
              ? 'Snapshot API bersifat informasional dan tidak dapat mengizinkan eksekusi broker.'
              : source.provider === 'MOCK FALLBACK'
                ? 'Data skenario merupakan konten mock lokal—bukan umpan berita ekonomi waktu nyata.'
                : source.note}
          </span>
        </div>

        <div className="mt-4 flex gap-2 overflow-x-auto pb-1" aria-label="Filter peristiwa berita">
          {filters.map((option) => (
            <button
              key={option}
              type="button"
              className={`filter-button ${filter === option ? 'filter-button-active' : ''}`}
              aria-pressed={filter === option}
              onClick={() => {
                setFilter(option)
                setVisibleCount(NEWS_PAGE_SIZE)
              }}
            >
              {filterLabels[option]}
            </button>
          ))}
        </div>
      </div>

      {events.length === 0 || filteredEvents.length === 0 ? (
        <div className="p-4 sm:p-5">
          <PanelState
            state="empty"
            compact
            title={events.length === 0 ? 'Snapshot berita tidak tersedia' : 'Tidak ada peristiwa yang cocok'}
            message={
              events.length === 0
                ? source.note
                : 'Pilih filter berita lain untuk melihat peristiwa yang tersedia.'
            }
          />
        </div>
      ) : (
        <div className="divide-y divide-white/[0.055]">
          {visibleEvents.map((event) => (
            <article
              key={event.id}
              className="grid gap-4 p-4 transition hover:bg-white/[0.018] sm:p-5 xl:grid-cols-[minmax(0,1fr)_minmax(18rem,0.72fr)]"
            >
              <div className="min-w-0">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="font-mono text-[0.7rem] font-semibold tracking-[0.12em] text-cyan-200">
                    {event.currency}
                  </span>
                  <StatusBadge
                    label={formatNewsEventStatus(event.status)}
                    tone={newsEventStatusTone[event.status]}
                  />
                  <StatusBadge
                    label={`DAMPAK ${formatNewsImpact(event.impact)}`}
                    tone={newsImpactTone[event.impact]}
                  />
                  {event.freshness === 'STALE' ? (
                    <StatusBadge label="STALE" tone="warning" />
                  ) : null}
                </div>
                <h3 className="mt-3 text-sm font-semibold text-slate-100">{event.title}</h3>
                <p className="mt-1 text-xs tracking-wide text-slate-500 uppercase">
                  {event.region}
                </p>
                <p className="mt-3 text-sm leading-6 text-slate-400">{event.summary}</p>
                <div className="mt-3 flex flex-wrap items-center gap-2">
                  <span className="inline-flex items-center gap-1.5 font-mono text-xs text-slate-400">
                    <CalendarClock aria-hidden="true" className="size-3.5" />
                    {formatTime(event.scheduledAt)} JST
                  </span>
                  <span className="text-slate-700" aria-hidden="true">/</span>
                  <span className="text-[0.68rem] tracking-[0.1em] text-slate-500 uppercase">
                    Berdampak pada
                  </span>
                  {event.affectedSymbols.map((symbol) => (
                    <span
                      key={symbol}
                      className="rounded-md border border-white/[0.07] bg-slate-950/45 px-2 py-1 font-mono text-[0.68rem] text-slate-300"
                    >
                      {symbol}
                    </span>
                  ))}
                </div>
              </div>

              <div className="grid grid-cols-3 gap-px overflow-hidden rounded-xl border border-white/[0.065] bg-white/[0.065] self-start">
                {[
                  ['AKTUAL', event.actual ?? 'MENUNGGU'],
                  ['PERKIRAAN', event.forecast ?? '—'],
                  ['SEBELUMNYA', event.previous ?? '—'],
                ].map(([label, value]) => (
                  <div key={label} className="min-w-0 bg-[#07101e] px-3 py-3">
                    <span className="block text-[0.62rem] tracking-[0.12em] text-slate-600 uppercase">
                      {label}
                    </span>
                    <strong className="mt-1 block truncate font-mono text-sm tabular-nums text-slate-100">
                      {value}
                    </strong>
                  </div>
                ))}
                <div className="col-span-3 flex items-center justify-between bg-[#07101e] px-3 py-2.5">
                  <span className="text-[0.62rem] tracking-[0.12em] text-slate-600 uppercase">
                    Selisih dari perkiraan
                  </span>
                  <span
                    className={`font-mono text-xs font-semibold ${
                      event.surprise === 'PENDING'
                        ? 'text-slate-400'
                        : event.surprise === 'INLINE'
                          ? 'text-cyan-200'
                          : 'text-amber-200'
                    }`}
                  >
                    {formatNewsSurprise(event.surprise)}
                  </span>
                </div>
              </div>
            </article>
          ))}
          {remainingCount > 0 ? (
            <div className="flex justify-center p-4 sm:p-5">
              <button
                type="button"
                className="filter-button inline-flex items-center gap-2"
                onClick={() => setVisibleCount((count) => count + NEWS_PAGE_SIZE)}
              >
                <ChevronDown aria-hidden="true" className="size-3.5" />
                TAMPILKAN {Math.min(NEWS_PAGE_SIZE, remainingCount)} BERITA LAGI
              </button>
            </div>
          ) : null}
        </div>
      )}

      <div className="flex items-start gap-2 border-t border-white/[0.055] bg-red-400/[0.025] px-4 py-3 text-[0.7rem] leading-5 text-slate-500 sm:px-5">
        <ShieldAlert aria-hidden="true" className="mt-0.5 size-3.5 shrink-0 text-red-300" />
        Analisis berita tidak pernah mengubah live_allowed=false atau melewati guard pair, risiko, sesi, dan strategi.
      </div>
    </Panel>
  )
}
