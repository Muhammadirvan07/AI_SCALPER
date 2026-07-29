import { ChevronLeft, ChevronRight, Search } from 'lucide-react'
import { useDeferredValue, useMemo, useState } from 'react'
import { useRealtimeDashboard } from '../../hooks/useRealtimeDashboard'
import { formatNullableCurrency, formatNullableNumber, formatTimestamp } from '../../utils/apiDisplay'
import { TechnicalPanel } from '../terminal/common/TechnicalPanel'
import { TerminalStatusBadge } from '../terminal/common/TerminalStatusBadge'
import { ResourceStateView } from './ResourceStateView'

type OrderTab = 'ALL' | 'OPEN' | 'CLOSED'
type SortDirection = 'newest' | 'oldest' | 'pnl-high' | 'pnl-low'
const pageSize = 20

export function OrdersPanel({ className = 'qt-grid-span-12' }: { className?: string }) {
  const { resources, refreshResource } = useRealtimeDashboard()
  const [tab, setTab] = useState<OrderTab>('ALL')
  const [search, setSearch] = useState('')
  const [strategy, setStrategy] = useState('ALL')
  const [sort, setSort] = useState<SortDirection>('newest')
  const [page, setPage] = useState(0)
  const deferredSearch = useDeferredValue(search.toUpperCase())
  const strategies = useMemo(() => [...new Set((resources.orders.data?.items ?? []).map((item) => item.strategy).filter((item): item is string => Boolean(item)))].sort(), [resources.orders.data])
  const rows = useMemo(() => {
    const filtered = (resources.orders.data?.items ?? []).filter((order) => {
      if (tab !== 'ALL' && order.status !== tab) return false
      if (strategy !== 'ALL' && order.strategy !== strategy) return false
      return `${order.order_id} ${order.symbol ?? ''} ${order.strategy ?? ''}`.toUpperCase().includes(deferredSearch)
    })
    return filtered.sort((left, right) => {
      if (sort === 'pnl-high') return (right.pnl ?? Number.NEGATIVE_INFINITY) - (left.pnl ?? Number.NEGATIVE_INFINITY)
      if (sort === 'pnl-low') return (left.pnl ?? Number.POSITIVE_INFINITY) - (right.pnl ?? Number.POSITIVE_INFINITY)
      const delta = Date.parse(right.close_time ?? right.open_time ?? '') - Date.parse(left.close_time ?? left.open_time ?? '')
      return sort === 'newest' ? delta : -delta
    })
  }, [deferredSearch, resources.orders.data, sort, strategy, tab])
  const pages = Math.max(1, Math.ceil(rows.length / pageSize))
  const visible = rows.slice(Math.min(page, pages - 1) * pageSize, (Math.min(page, pages - 1) + 1) * pageSize)

  return (
    <TechnicalPanel
      code="O01"
      title="Paper Orders"
      subtitle="Read-only paper ledger · no broker execution path"
      state={resources.orders.status === 'loading' ? 'loading' : resources.orders.meta?.stale ? 'stale' : rows.length ? 'connected' : 'empty'}
      onRetry={() => void refreshResource('orders')}
      preserveContent
      className={className}
      action={<TerminalStatusBadge label="PAPER ONLY" tone="safe" compact />}
    >
      <div className="domain-filterbar domain-filterbar--orders">
        <div className="domain-tabs" role="tablist" aria-label="Status order">{(['ALL', 'OPEN', 'CLOSED'] as const).map((item) => <button key={item} type="button" role="tab" aria-selected={tab === item} className={tab === item ? 'is-active' : ''} onClick={() => { setTab(item); setPage(0) }}>{item}</button>)}</div>
        <label><Search aria-hidden="true" /><span className="sr-only">Cari order</span><input value={search} onChange={(event) => { setSearch(event.target.value); setPage(0) }} placeholder="Search order or symbol" /></label>
        <label><span>Strategy</span><select value={strategy} onChange={(event) => { setStrategy(event.target.value); setPage(0) }}><option value="ALL">All</option>{strategies.map((item) => <option key={item} value={item}>{item}</option>)}</select></label>
        <label><span>Sort</span><select value={sort} onChange={(event) => setSort(event.target.value as SortDirection)}><option value="newest">Newest</option><option value="oldest">Oldest</option><option value="pnl-high">P&amp;L high</option><option value="pnl-low">P&amp;L low</option></select></label>
      </div>
      <ResourceStateView resource={resources.orders} onRetry={() => void refreshResource('orders')}>
        {() => (
          <>
            <div className="domain-table-wrap" tabIndex={0} role="region" aria-label="Paper orders aktual">
              <table className="domain-table">
                <thead><tr><th>Open time</th><th>Close time</th><th>Order ID</th><th>Signal ID</th><th>Symbol</th><th>Side</th><th>Strategy</th><th>Entry</th><th>Exit</th><th>SL</th><th>TP</th><th>Lot</th><th>Duration</th><th>P&amp;L</th><th>P&amp;L %</th><th>R</th><th>Status</th><th>Exit reason</th><th>Mode</th></tr></thead>
                <tbody>{visible.map((order) => (
                  <tr key={order.order_id}>
                    <td title={formatTimestamp(order.open_time)}>{formatTimestamp(order.open_time, { month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit', timeZone: 'Asia/Tokyo' })}</td><td>{formatTimestamp(order.close_time, { month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit', timeZone: 'Asia/Tokyo' })}</td>
                    <td title={order.order_id}>{order.order_id}</td><td title={order.signal_id ?? ''}>{order.signal_id ?? '—'}</td><th scope="row">{order.symbol ?? '—'}</th><td>{order.side ?? '—'}</td><td>{order.strategy ?? '—'}</td>
                    <td>{formatNullableNumber(order.entry, 5)}</td><td>{formatNullableNumber(order.exit, 5)}</td><td>{formatNullableNumber(order.stop_loss, 5)}</td><td>{formatNullableNumber(order.take_profit, 5)}</td><td>{formatNullableNumber(order.lot, 2)}</td><td>{order.duration_seconds === null ? '—' : `${Math.round(order.duration_seconds / 60)}m`}</td>
                    <td className={(order.pnl ?? 0) >= 0 ? 'qt-tone--positive' : 'qt-tone--blocked'}>{formatNullableCurrency(order.pnl, true)}</td><td>{formatNullableNumber(order.pnl_percent, 2)}</td><td>{formatNullableNumber(order.r_multiple, 2)}</td><td><TerminalStatusBadge label={order.status} tone={order.status === 'CLOSED' ? 'safe' : 'caution'} compact /></td><td title={order.exit_reason ?? ''}>{order.exit_reason ?? '—'}</td><td>{order.mode}</td>
                  </tr>
                ))}</tbody>
              </table>
            </div>
            <div className="domain-pagination"><span>{rows.length} orders · page {Math.min(page, pages - 1) + 1}/{pages}</span><div><button type="button" disabled={page <= 0} onClick={() => setPage((value) => Math.max(0, value - 1))} aria-label="Halaman sebelumnya"><ChevronLeft aria-hidden="true" /></button><button type="button" disabled={page >= pages - 1} onClick={() => setPage((value) => Math.min(pages - 1, value + 1))} aria-label="Halaman berikutnya"><ChevronRight aria-hidden="true" /></button></div></div>
          </>
        )}
      </ResourceStateView>
    </TechnicalPanel>
  )
}
