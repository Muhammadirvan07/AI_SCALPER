import { Search } from 'lucide-react'
import { useDeferredValue, useMemo, useState } from 'react'
import { useRealtimeDashboard } from '../../hooks/useRealtimeDashboard'
import { formatNullableNumber, formatNullablePercent, formatTimestamp } from '../../utils/apiDisplay'
import { formatStatusLabel } from '../../utils/statusHelpers'
import { TechnicalPanel } from '../terminal/common/TechnicalPanel'
import { TerminalStatusBadge } from '../terminal/common/TerminalStatusBadge'
import { ResourceStateView } from './ResourceStateView'

type SortKey = 'symbol' | 'change_percent' | 'volatility' | 'strategy_score'

export function WatchlistPanel({ className = 'qt-grid-span-4' }: { className?: string }) {
  const { resources, activeSymbol, setActiveSymbol, refreshResource } = useRealtimeDashboard()
  const [search, setSearch] = useState('')
  const deferredSearch = useDeferredValue(search.trim().toUpperCase())
  const [sortKey, setSortKey] = useState<SortKey>('symbol')
  const rows = useMemo(() => {
    const items = (resources.watchlist.data ?? []).filter((item) => item.symbol.includes(deferredSearch))
    return [...items].sort((left, right) => {
      if (sortKey === 'symbol') return left.symbol.localeCompare(right.symbol)
      return (right[sortKey] ?? Number.NEGATIVE_INFINITY) - (left[sortKey] ?? Number.NEGATIVE_INFINITY)
    })
  }, [deferredSearch, resources.watchlist.data, sortKey])

  return (
    <TechnicalPanel
      code="M02"
      title="Watchlist"
      subtitle="All backend-discovered instruments"
      state={resources.watchlist.status === 'loading' ? 'loading' : resources.watchlist.meta?.stale ? 'stale' : rows.length ? 'connected' : 'empty'}
      onRetry={() => void refreshResource('watchlist')}
      preserveContent
      className={className}
      action={<TerminalStatusBadge label={`${rows.length} SYMBOLS`} tone="neutral" compact />}
    >
      <div className="watchlist-tools">
        <label><Search aria-hidden="true" /><span className="sr-only">Cari symbol</span><input value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Search pair" /></label>
        <label><span className="sr-only">Urutkan watchlist</span><select value={sortKey} onChange={(event) => setSortKey(event.target.value as SortKey)}><option value="symbol">Symbol</option><option value="change_percent">Change</option><option value="volatility">Volatility</option><option value="strategy_score">Score</option></select></label>
      </div>
      <ResourceStateView resource={resources.watchlist} onRetry={() => void refreshResource('watchlist')}>
        {() => (
          <div className="domain-table-wrap" tabIndex={0} role="region" aria-label="Watchlist aktual">
            <table className="domain-table domain-table--compact">
              <thead><tr><th>Symbol</th><th>Bid</th><th>Ask</th><th>Last</th><th>Spread</th><th>Change</th><th>Trend</th><th>Volatility</th><th>ATR</th><th>ADX</th><th>Strategy</th><th>Score</th><th>Signal</th><th>Quality</th><th>Updated</th></tr></thead>
              <tbody>
                {rows.map((item) => (
                  <tr key={item.symbol} className={item.symbol === activeSymbol ? 'is-active' : ''}>
                    <th scope="row"><button type="button" onClick={() => setActiveSymbol(item.symbol)}>{item.symbol}</button>{item.blocked ? <TerminalStatusBadge label="BLOCKED" tone="blocked" compact /> : null}</th>
                    <td>{formatNullableNumber(item.bid, 5)}</td><td>{formatNullableNumber(item.ask, 5)}</td><td>{formatNullableNumber(item.last_price, item.symbol.includes('JPY') ? 3 : 5)}</td><td>{formatNullableNumber(item.spread, 5)}</td>
                    <td className={(item.change_percent ?? 0) >= 0 ? 'qt-tone--positive' : 'qt-tone--blocked'}>{formatNullablePercent(item.change_percent, 2, true)}</td>
                    <td>{formatStatusLabel(item.trend)}</td><td>{formatNullablePercent(item.volatility, 2)}</td><td>{formatNullableNumber(item.atr, 5)}</td><td>{formatNullableNumber(item.adx, 1)}</td>
                    <td>{item.strategy ?? '—'}</td><td>{formatNullableNumber(item.strategy_score, 1)}</td><td>{item.signal ?? '—'}</td><td><TerminalStatusBadge label={item.quality_status} tone={item.quality_status === 'READY' ? 'safe' : 'caution'} compact /></td>
                    <td title={formatTimestamp(item.last_update)}>{item.stale ? 'STALE' : formatTimestamp(item.last_update, { hour: '2-digit', minute: '2-digit', timeZone: 'Asia/Tokyo' })}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </ResourceStateView>
    </TechnicalPanel>
  )
}
