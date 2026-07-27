import {
  ArrowDown,
  ArrowUp,
  ArrowUpDown,
  ChevronDown,
  Clock3,
  Search,
  SlidersHorizontal,
} from 'lucide-react'
import { useMemo, useState } from 'react'
import type { SignalStatus, TradingSignal } from '../../types/dashboard'
import { formatTime } from '../../utils/formatters'
import { formatStatusLabel } from '../../utils/statusHelpers'
import { Panel } from '../ui/Panel'
import { PanelState } from '../ui/PanelState'
import { StatusBadge } from './StatusBadge'

type SortKey = 'time' | 'symbol' | 'score' | 'status'
type SortDirection = 'asc' | 'desc'

const statusOptions: Array<'ALL' | SignalStatus> = [
  'ALL',
  'PAPER_OPEN',
  'PAPER_CLOSED',
  'WAIT',
  'BLOCKED',
  'REJECTED',
  'TIMEOUT',
]

interface RecentSignalsTableProps {
  signals: TradingSignal[]
}

interface SortIconProps {
  column: SortKey
  activeColumn: SortKey
  direction: SortDirection
}

function SortIcon({ column, activeColumn, direction }: SortIconProps) {
  if (column !== activeColumn) return <ArrowUpDown aria-hidden="true" className="size-3" />
  return direction === 'asc' ? (
    <ArrowUp aria-hidden="true" className="size-3" />
  ) : (
    <ArrowDown aria-hidden="true" className="size-3" />
  )
}

export function RecentSignalsTable({ signals }: RecentSignalsTableProps) {
  const [search, setSearch] = useState('')
  const [statusFilter, setStatusFilter] = useState<'ALL' | SignalStatus>('ALL')
  const [symbolFilter, setSymbolFilter] = useState('ALL')
  const [sortKey, setSortKey] = useState<SortKey>('time')
  const [sortDirection, setSortDirection] = useState<SortDirection>('desc')
  const [visibleCount, setVisibleCount] = useState(6)

  const symbols = useMemo(
    () => ['ALL', ...Array.from(new Set(signals.map((signal) => signal.symbol))).sort()],
    [signals],
  )

  const filteredSignals = useMemo(() => {
    const normalizedSearch = search.trim().toLowerCase()
    const result = signals.filter((signal) => {
      const matchesSearch =
        !normalizedSearch ||
        signal.symbol.toLowerCase().includes(normalizedSearch) ||
        signal.strategy.toLowerCase().includes(normalizedSearch) ||
        signal.reason.toLowerCase().includes(normalizedSearch)
      const matchesStatus = statusFilter === 'ALL' || signal.status === statusFilter
      const matchesSymbol = symbolFilter === 'ALL' || signal.symbol === symbolFilter
      return matchesSearch && matchesStatus && matchesSymbol
    })

    return [...result].sort((first, second) => {
      const firstValue = sortKey === 'time' ? new Date(first.time).getTime() : first[sortKey]
      const secondValue = sortKey === 'time' ? new Date(second.time).getTime() : second[sortKey]
      const comparison =
        firstValue < secondValue ? -1 : firstValue > secondValue ? 1 : 0
      return sortDirection === 'asc' ? comparison : -comparison
    })
  }, [search, signals, sortDirection, sortKey, statusFilter, symbolFilter])

  const visibleSignals = filteredSignals.slice(0, visibleCount)

  const handleSort = (key: SortKey) => {
    if (key === sortKey) {
      setSortDirection((direction) => (direction === 'asc' ? 'desc' : 'asc'))
    } else {
      setSortKey(key)
      setSortDirection(key === 'symbol' ? 'asc' : 'desc')
    }
  }

  return (
    <Panel className="overflow-hidden p-0">
      <div className="border-b border-white/[0.06] p-4 sm:p-6">
        <div className="flex flex-col gap-5 xl:flex-row xl:items-end xl:justify-between">
          <div>
            <p className="text-xs font-semibold tracking-[0.16em] text-cyan-300 uppercase">
              Aliran keputusan
            </p>
            <h3 id="signals-title" className="mt-1 text-lg font-semibold text-white">
              Sinyal terbaru
            </h3>
            <p className="mt-1 text-sm text-slate-400">
              Hanya peristiwa observasi dan paper — tindakan eksekusi tidak tersedia.
            </p>
          </div>
          <div className="flex items-center gap-2 text-xs text-slate-500">
            <SlidersHorizontal aria-hidden="true" className="size-4" />
            {filteredSignals.length} dari {signals.length} catatan
          </div>
        </div>

        <div className="mt-5 grid gap-3 md:grid-cols-[1fr_auto_auto]">
          <label className="relative block">
            <span className="sr-only">Cari sinyal terbaru</span>
            <Search
              aria-hidden="true"
              className="pointer-events-none absolute top-1/2 left-3 size-4 -translate-y-1/2 text-slate-500"
            />
            <input
              type="search"
              className="input-field w-full pl-9"
              placeholder="Cari simbol, strategi, atau alasan…"
              value={search}
              onChange={(event) => {
                setSearch(event.target.value)
                setVisibleCount(6)
              }}
            />
          </label>
          <label>
            <span className="sr-only">Filter sinyal berdasarkan status</span>
            <select
              className="input-field w-full min-w-40"
              value={statusFilter}
              onChange={(event) => {
                setStatusFilter(event.target.value as 'ALL' | SignalStatus)
                setVisibleCount(6)
              }}
            >
              {statusOptions.map((status) => (
                <option key={status} value={status}>
                  {status === 'ALL' ? 'Semua status' : formatStatusLabel(status)}
                </option>
              ))}
            </select>
          </label>
          <label>
            <span className="sr-only">Filter sinyal berdasarkan simbol</span>
            <select
              className="input-field w-full min-w-36"
              value={symbolFilter}
              onChange={(event) => {
                setSymbolFilter(event.target.value)
                setVisibleCount(6)
              }}
            >
              {symbols.map((symbol) => (
                <option key={symbol} value={symbol}>
                  {symbol === 'ALL' ? 'Semua simbol' : symbol}
                </option>
              ))}
            </select>
          </label>
        </div>
      </div>

      {visibleSignals.length === 0 ? (
        <div className="p-4 sm:p-6">
          <PanelState
            state="empty"
            title={signals.length === 0 ? 'Belum ada catatan sinyal' : 'Tidak ada sinyal yang cocok'}
            message={
              signals.length === 0
                ? 'Sumber sinyal belum mengembalikan peristiwa.'
                : 'Hapus atau sesuaikan filter untuk melihat kumpulan hasil lain.'
            }
          />
        </div>
      ) : (
        <>
          <div className="hidden overflow-x-auto md:block">
            <table className="w-full min-w-[1080px] border-collapse text-left">
              <caption className="sr-only">
                Sinyal paper dan observasi terbaru beserta status dan alasan keputusan.
              </caption>
              <thead>
                <tr className="border-b border-white/[0.06] bg-slate-950/25 text-[0.68rem] tracking-[0.12em] text-slate-500 uppercase">
                  {[
                    ['time', 'Waktu'],
                    ['symbol', 'Simbol'],
                  ].map(([key, label]) => (
                    <th key={key} scope="col" className="px-4 py-3 font-semibold first:pl-6">
                      <button
                        type="button"
                        onClick={() => handleSort(key as SortKey)}
                        className="focus-ring flex items-center gap-1 rounded"
                      >
                        {label}
                        <SortIcon
                          column={key as SortKey}
                          activeColumn={sortKey}
                          direction={sortDirection}
                        />
                      </button>
                    </th>
                  ))}
                  <th scope="col" className="px-4 py-3 font-semibold">Sisi</th>
                  <th scope="col" className="px-4 py-3 font-semibold">Strategi</th>
                  <th scope="col" className="px-4 py-3 font-semibold">
                    <button
                      type="button"
                      onClick={() => handleSort('score')}
                      className="focus-ring flex items-center gap-1 rounded"
                    >
                      Skor
                      <SortIcon column="score" activeColumn={sortKey} direction={sortDirection} />
                    </button>
                  </th>
                  <th scope="col" className="px-4 py-3 font-semibold">
                    <button
                      type="button"
                      onClick={() => handleSort('status')}
                      className="focus-ring flex items-center gap-1 rounded"
                    >
                      Status
                      <SortIcon column="status" activeColumn={sortKey} direction={sortDirection} />
                    </button>
                  </th>
                  <th scope="col" className="px-4 py-3 font-semibold">Alasan</th>
                  <th scope="col" className="px-6 py-3 font-semibold">Kesegaran</th>
                </tr>
              </thead>
              <tbody>
                {visibleSignals.map((signal) => (
                  <tr
                    key={signal.id}
                    className="border-b border-white/[0.045] transition hover:bg-white/[0.025]"
                  >
                    <td className="px-6 py-4 text-xs text-slate-400">
                      <span className="flex items-center gap-1.5">
                        <Clock3 aria-hidden="true" className="size-3.5" />
                        {formatTime(signal.time)}
                      </span>
                    </td>
                    <th scope="row" className="px-4 py-4 text-sm font-semibold text-white">
                      {signal.symbol}
                    </th>
                    <td className="px-4 py-4">
                      <StatusBadge label={signal.side} />
                    </td>
                    <td className="px-4 py-4 text-xs font-medium text-slate-300">
                      {signal.strategy}
                    </td>
                    <td className="px-4 py-4">
                      <div className="flex items-center gap-2">
                        <span className="w-6 text-xs font-semibold text-slate-200">
                          {signal.score}
                        </span>
                        <div className="h-1.5 w-12 overflow-hidden rounded-full bg-slate-800">
                          <div
                            className="h-full rounded-full bg-gradient-to-r from-violet-400 to-cyan-300"
                            style={{ width: `${signal.score}%` }}
                          />
                        </div>
                      </div>
                    </td>
                    <td className="px-4 py-4">
                      <StatusBadge label={signal.status} />
                    </td>
                    <td className="max-w-xs px-4 py-4 text-xs leading-5 text-slate-400">
                      {signal.reason}
                    </td>
                    <td className="px-6 py-4">
                      <StatusBadge
                        label={signal.dataFreshness}
                        tone={signal.dataFreshness === 'FRESH' ? 'positive' : 'warning'}
                      />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <div className="grid gap-3 p-4 md:hidden">
            {visibleSignals.map((signal) => (
              <article
                key={signal.id}
                className="rounded-2xl border border-white/[0.07] bg-slate-950/35 p-4"
              >
                <div className="flex items-start justify-between gap-3">
                  <div>
                    <p className="font-semibold text-white">{signal.symbol}</p>
                    <p className="mt-0.5 flex items-center gap-1 text-[0.68rem] text-slate-500">
                      <Clock3 aria-hidden="true" className="size-3" />
                      {formatTime(signal.time)} · {signal.id}
                    </p>
                  </div>
                  <StatusBadge label={signal.status} />
                </div>
                <div className="mt-4 flex flex-wrap gap-2">
                  <StatusBadge label={signal.side} />
                  <span className="rounded-full border border-white/[0.07] px-2.5 py-1 text-[0.68rem] font-medium text-slate-300">
                    {signal.strategy}
                  </span>
                  <span className="rounded-full border border-white/[0.07] px-2.5 py-1 text-[0.68rem] font-medium text-slate-300">
                    Skor {signal.score}
                  </span>
                </div>
                <p className="mt-4 text-sm leading-6 text-slate-400">{signal.reason}</p>
                <div className="mt-4 flex items-center justify-between border-t border-white/[0.06] pt-3">
                  <span className="text-[0.68rem] text-slate-500">Kesegaran data</span>
                  <StatusBadge
                    label={signal.dataFreshness}
                    tone={signal.dataFreshness === 'FRESH' ? 'positive' : 'warning'}
                  />
                </div>
              </article>
            ))}
          </div>

          {visibleCount < filteredSignals.length ? (
            <div className="border-t border-white/[0.06] p-4 text-center">
              <button
                type="button"
                onClick={() => setVisibleCount((count) => count + 6)}
                className="button-secondary mx-auto"
              >
                Tampilkan lebih banyak sinyal
                <ChevronDown aria-hidden="true" className="size-4" />
              </button>
            </div>
          ) : null}
        </>
      )}
    </Panel>
  )
}
