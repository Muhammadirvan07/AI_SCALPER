import {
  AlertTriangle,
  CircleDot,
  Clock3,
  Search,
  ShieldX,
  TrendingDown,
  TrendingUp,
} from 'lucide-react'
import { useMemo, useState } from 'react'
import type { WatchlistItem } from '../../types/dashboard'
import { formatPercent, formatPrice, formatTime } from '../../utils/formatters'
import { formatStatusLabel } from '../../utils/statusHelpers'
import { Panel } from '../ui/Panel'
import { PanelState } from '../ui/PanelState'
import { StatusBadge } from './StatusBadge'

type WatchlistFilter = 'All' | 'Forex' | 'Crypto' | 'Metals' | 'Tradable' | 'Blocked'

const filters: WatchlistFilter[] = ['All', 'Forex', 'Crypto', 'Metals', 'Tradable', 'Blocked']
const filterLabels: Record<WatchlistFilter, string> = {
  All: 'Semua',
  Forex: 'Forex',
  Crypto: 'Kripto',
  Metals: 'Logam',
  Tradable: 'Dapat dipantau',
  Blocked: 'Diblokir',
}
const assetTypeLabels: Record<WatchlistItem['assetType'], string> = {
  Forex: 'Forex',
  Crypto: 'Kripto',
  Metals: 'Logam',
  Commodity: 'Komoditas',
  Other: 'Lainnya',
}

interface WatchlistProps {
  items: WatchlistItem[]
}

export function Watchlist({ items }: WatchlistProps) {
  const [search, setSearch] = useState('')
  const [filter, setFilter] = useState<WatchlistFilter>('All')

  const filteredItems = useMemo(() => {
    const normalizedSearch = search.trim().toLowerCase()
    return items.filter((item) => {
      const matchesSearch =
        !normalizedSearch ||
        item.symbol.toLowerCase().includes(normalizedSearch) ||
        item.assetType.toLowerCase().includes(normalizedSearch)
      const matchesFilter =
        filter === 'All' ||
        item.assetType === filter ||
        (filter === 'Tradable' && item.tradable) ||
        (filter === 'Blocked' && item.guardStatus === 'BLOCKED')
      return matchesSearch && matchesFilter
    })
  }, [filter, items, search])

  return (
    <Panel className="overflow-hidden p-0">
      <div className="border-b border-white/[0.06] p-4 sm:p-6">
        <div className="flex flex-col gap-5 xl:flex-row xl:items-end xl:justify-between">
          <div>
            <p className="text-xs font-semibold tracking-[0.16em] text-cyan-300 uppercase">
              Instrumen terpantau
            </p>
            <h3 id="watchlist-title" className="mt-1 text-lg font-semibold text-white">
              Daftar pantau pasar
            </h3>
            <p className="mt-1 text-sm text-slate-400">
              Harga, bias model, volatilitas, dan guard kelayakan dalam mode hanya-baca.
            </p>
          </div>

          <div className="flex flex-col gap-3 sm:flex-row sm:items-center">
            <label className="relative block">
              <span className="sr-only">Cari daftar pantau pasar</span>
              <Search
                aria-hidden="true"
                className="pointer-events-none absolute top-1/2 left-3 size-4 -translate-y-1/2 text-slate-500"
              />
              <input
                type="search"
                value={search}
                onChange={(event) => setSearch(event.target.value)}
                placeholder="Cari simbol…"
                className="input-field w-full pl-9 sm:w-52"
              />
            </label>
          </div>
        </div>

        <div className="mt-4 flex gap-2 overflow-x-auto pb-1" aria-label="Filter daftar pantau">
          {filters.map((option) => (
            <button
              key={option}
              type="button"
              onClick={() => setFilter(option)}
              aria-pressed={filter === option}
              className={`filter-button ${filter === option ? 'filter-button-active' : ''}`}
            >
              {filterLabels[option]}
            </button>
          ))}
        </div>
      </div>

      {items.length === 0 || filteredItems.length === 0 ? (
        <div className="p-4 sm:p-6">
          <PanelState
            state="empty"
            title={items.length === 0 ? 'Belum ada catatan pasar' : 'Tidak ada instrumen yang cocok'}
            message={
              items.length === 0
                ? 'Sumber daftar pantau tidak mengembalikan instrumen.'
                : 'Sesuaikan pencarian atau filter pasar untuk melihat instrumen.'
            }
          />
        </div>
      ) : (
        <>
          <div className="hidden overflow-x-auto lg:block">
            <table className="w-full min-w-[1080px] border-collapse text-left">
              <caption className="sr-only">
                Daftar pantau pasar yang menampilkan harga, bias sinyal, volatilitas, dan status guard.
              </caption>
              <thead>
                <tr className="border-b border-white/[0.06] bg-slate-950/25 text-[0.68rem] tracking-[0.12em] text-slate-500 uppercase">
                  <th scope="col" className="px-6 py-3 font-semibold">Simbol</th>
                  <th scope="col" className="px-4 py-3 font-semibold">Harga</th>
                  <th scope="col" className="px-4 py-3 font-semibold">Perubahan</th>
                  <th scope="col" className="px-4 py-3 font-semibold">Pasar</th>
                  <th scope="col" className="px-4 py-3 font-semibold">Bias</th>
                  <th scope="col" className="px-4 py-3 font-semibold">Skor</th>
                  <th scope="col" className="px-4 py-3 font-semibold">Volatilitas</th>
                  <th scope="col" className="px-4 py-3 font-semibold">Guard</th>
                  <th scope="col" className="px-6 py-3 font-semibold">Diperbarui</th>
                </tr>
              </thead>
              <tbody>
                {filteredItems.map((item) => (
                  <tr
                    key={item.symbol}
                    className="border-b border-white/[0.045] transition hover:bg-white/[0.025]"
                  >
                    <th scope="row" className="px-6 py-4">
                      <span className="block text-sm font-semibold text-white">{item.symbol}</span>
                      <span className="mt-0.5 block text-[0.68rem] text-slate-500">{assetTypeLabels[item.assetType]}</span>
                    </th>
                    <td className="px-4 py-4 font-mono text-sm text-slate-200">
                      {formatPrice(item.currentPrice, item.pricePrecision)}
                    </td>
                    <td
                      className={`px-4 py-4 text-sm font-semibold ${
                        item.priceChange >= 0 ? 'text-emerald-300' : 'text-red-300'
                      }`}
                    >
                      <span className="flex items-center gap-1">
                        {item.priceChange >= 0 ? (
                          <TrendingUp aria-hidden="true" className="size-3.5" />
                        ) : (
                          <TrendingDown aria-hidden="true" className="size-3.5" />
                        )}
                        {formatPercent(item.priceChange, 2, true)}
                      </span>
                    </td>
                    <td className="px-4 py-4">
                      <span
                        className={`inline-flex items-center gap-2 text-xs font-medium ${
                          item.marketStatus === 'OPEN' ? 'text-emerald-300' : 'text-slate-400'
                        }`}
                      >
                        <CircleDot aria-hidden="true" className="size-3.5" />
                        {formatStatusLabel(item.marketStatus)}
                      </span>
                    </td>
                    <td className="px-4 py-4">
                      <StatusBadge label={item.signalBias} />
                    </td>
                    <td className="px-4 py-4">
                      <span className="text-sm font-semibold text-slate-200">{item.strategyScore}</span>
                      <div className="mt-1 h-1 w-16 overflow-hidden rounded-full bg-slate-800">
                        <div
                          className="h-full rounded-full bg-gradient-to-r from-violet-400 to-cyan-300"
                          style={{ width: `${item.strategyScore}%` }}
                        />
                      </div>
                    </td>
                    <td className="px-4 py-4">
                      <StatusBadge
                        label={item.volatility}
                        tone={
                          item.volatility === 'HIGH'
                            ? 'negative'
                            : item.volatility === 'ELEVATED'
                              ? 'warning'
                              : 'neutral'
                        }
                      />
                    </td>
                    <td className="px-4 py-4">
                      <StatusBadge
                        label={item.guardStatus}
                        tone={
                          item.guardStatus.includes('PRIMARY')
                            ? 'positive'
                            : item.guardStatus === 'BLOCKED'
                              ? 'negative'
                              : 'warning'
                        }
                      />
                    </td>
                    <td className="px-6 py-4">
                      <span
                        className={`flex items-center gap-1.5 text-xs ${
                          item.freshness === 'STALE' ? 'text-amber-200' : 'text-slate-400'
                        }`}
                      >
                        {item.freshness === 'STALE' ? (
                          <AlertTriangle aria-hidden="true" className="size-3.5" />
                        ) : (
                          <Clock3 aria-hidden="true" className="size-3.5" />
                        )}
                        {formatTime(item.lastUpdate)} · {formatStatusLabel(item.freshness)}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <div className="grid gap-3 p-4 sm:grid-cols-2 lg:hidden">
            {filteredItems.map((item) => (
              <article
                key={item.symbol}
                className="rounded-2xl border border-white/[0.07] bg-slate-950/35 p-4"
              >
                <div className="flex items-start justify-between gap-3">
                  <div>
                    <p className="font-semibold text-white">{item.symbol}</p>
                    <p className="text-xs text-slate-500">{assetTypeLabels[item.assetType]}</p>
                  </div>
                  <StatusBadge label={item.signalBias} />
                </div>
                <div className="mt-4 flex items-end justify-between gap-4">
                  <div>
                    <p className="font-mono text-lg font-semibold text-white">
                      {formatPrice(item.currentPrice, item.pricePrecision)}
                    </p>
                    <p
                      className={`mt-1 flex items-center gap-1 text-xs font-semibold ${
                        item.priceChange >= 0 ? 'text-emerald-300' : 'text-red-300'
                      }`}
                    >
                      {item.priceChange >= 0 ? (
                        <TrendingUp aria-hidden="true" className="size-3.5" />
                      ) : (
                        <TrendingDown aria-hidden="true" className="size-3.5" />
                      )}
                      {formatPercent(item.priceChange, 2, true)}
                    </p>
                  </div>
                  <div className="text-right">
                    <p className="text-xs text-slate-500">Skor strategi</p>
                    <p className="font-semibold text-slate-200">{item.strategyScore}/100</p>
                  </div>
                </div>
                <dl className="mt-4 grid grid-cols-2 gap-3 border-t border-white/[0.06] pt-4 text-xs">
                  <div>
                    <dt className="text-slate-500">Pasar</dt>
                    <dd className="mt-1 text-slate-200">{formatStatusLabel(item.marketStatus)}</dd>
                  </div>
                  <div>
                    <dt className="text-slate-500">Volatilitas</dt>
                    <dd className="mt-1 text-slate-200">{formatStatusLabel(item.volatility)}</dd>
                  </div>
                  <div className="col-span-2 flex items-center justify-between">
                    <dt className="text-slate-500">Guard</dt>
                    <dd className="min-w-0 max-w-[70%]">
                      <StatusBadge
                        label={item.guardStatus}
                        className="max-w-full text-center leading-4"
                        tone={
                          item.guardStatus.includes('PRIMARY')
                            ? 'positive'
                            : item.guardStatus === 'BLOCKED'
                              ? 'negative'
                              : 'warning'
                        }
                      />
                    </dd>
                  </div>
                </dl>
                <p
                  className={`mt-3 flex items-center gap-1.5 text-[0.68rem] ${
                    item.freshness === 'STALE' ? 'text-amber-200' : 'text-slate-500'
                  }`}
                >
                  {item.guardStatus === 'BLOCKED' ? (
                    <ShieldX aria-hidden="true" className="size-3.5" />
                  ) : (
                    <Clock3 aria-hidden="true" className="size-3.5" />
                  )}
                  Diperbarui {formatTime(item.lastUpdate)} · {formatStatusLabel(item.freshness)}
                </p>
              </article>
            ))}
          </div>
        </>
      )}
    </Panel>
  )
}
