import { ChevronRight, Search } from 'lucide-react'
import { useDeferredValue, useMemo, useState } from 'react'
import type { SignalStatus } from '../../api/types'
import { useRealtimeDashboard } from '../../hooks/useRealtimeDashboard'
import { formatNullableNumber, formatTimestamp } from '../../utils/apiDisplay'
import { TechnicalPanel } from '../terminal/common/TechnicalPanel'
import { TerminalStatusBadge } from '../terminal/common/TerminalStatusBadge'
import { ResourceStateView } from './ResourceStateView'

const statuses: Array<'ALL' | SignalStatus> = ['ALL', 'WAIT', 'APPROVED', 'PAPER_OPEN', 'CLOSED', 'BLOCKED', 'REJECTED', 'EXPIRED', 'SKIPPED', 'UNKNOWN']
const toneForStatus = (status: SignalStatus) => {
  if (status === 'APPROVED' || status === 'PAPER_OPEN' || status === 'CLOSED') return 'safe'
  if (status === 'WAIT' || status === 'EXPIRED' || status === 'SKIPPED') return 'caution'
  if (status === 'BLOCKED' || status === 'REJECTED') return 'blocked'
  return 'neutral'
}

export function SignalsPanel({ className = 'qt-grid-span-12' }: { className?: string }) {
  const { resources, refreshResource } = useRealtimeDashboard()
  const [status, setStatus] = useState<'ALL' | SignalStatus>('ALL')
  const [search, setSearch] = useState('')
  const deferredSearch = useDeferredValue(search.toUpperCase())
  const [expanded, setExpanded] = useState<string | null>(null)
  const rows = useMemo(() => (resources.signals.data?.items ?? []).filter((signal) => {
    if (status !== 'ALL' && signal.status !== status) return false
    const haystack = `${signal.signal_id} ${signal.symbol ?? ''} ${signal.strategy ?? ''} ${signal.reason ?? ''}`.toUpperCase()
    return haystack.includes(deferredSearch)
  }), [deferredSearch, resources.signals.data, status])

  return (
    <TechnicalPanel
      code="S01"
      title="Trading Signals"
      subtitle="Normalized backend decisions · realtime invalidation"
      state={resources.signals.status === 'loading' ? 'loading' : resources.signals.meta?.stale ? 'stale' : rows.length ? 'connected' : 'empty'}
      onRetry={() => void refreshResource('signals')}
      preserveContent
      className={className}
      action={<TerminalStatusBadge label={`${resources.signals.data?.total ?? 0} SIGNALS`} tone="neutral" compact />}
    >
      <div className="domain-filterbar">
        <label><Search aria-hidden="true" /><span className="sr-only">Cari signal</span><input value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Search ID, symbol, strategy" /></label>
        <label><span>Status</span><select value={status} onChange={(event) => setStatus(event.target.value as 'ALL' | SignalStatus)}>{statuses.map((item) => <option key={item} value={item}>{item}</option>)}</select></label>
      </div>
      <ResourceStateView resource={resources.signals} onRetry={() => void refreshResource('signals')}>
        {() => (
          <div className="domain-table-wrap" tabIndex={0} role="region" aria-label="Trading signals aktual">
            <table className="domain-table">
              <thead><tr><th>Time</th><th>ID</th><th>Symbol</th><th>Side</th><th>Strategy</th><th>Original</th><th>Adaptive</th><th>Confidence</th><th>Entry</th><th>SL</th><th>TP</th><th>R:R</th><th>Lot</th><th>Risk</th><th>Status</th><th>Guards</th><th>Mode</th><th>Reason</th></tr></thead>
              <tbody>
                {rows.map((signal) => {
                  const open = expanded === signal.signal_id
                  return (
                    <tr key={signal.signal_id} className={open ? 'is-expanded' : ''}>
                      <td title={formatTimestamp(signal.timestamp)}>{formatTimestamp(signal.timestamp, { month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit', timeZone: 'Asia/Tokyo' })}</td>
                      <td title={signal.signal_id}>{signal.signal_id}</td><th scope="row">{signal.symbol ?? '—'}</th><td>{signal.side ?? '—'}</td><td>{signal.strategy ?? '—'}</td>
                      <td>{formatNullableNumber(signal.original_score, 1)}</td><td>{formatNullableNumber(signal.adaptive_score, 1)}</td><td>{formatNullableNumber(signal.confidence, 2)}</td>
                      <td>{formatNullableNumber(signal.entry, 5)}</td><td>{formatNullableNumber(signal.stop_loss, 5)}</td><td>{formatNullableNumber(signal.take_profit, 5)}</td><td>{formatNullableNumber(signal.risk_reward_ratio, 2)}</td><td>{formatNullableNumber(signal.calculated_lot, 2)}</td><td>{formatNullableNumber(signal.risk_percent, 2)}</td>
                      <td><TerminalStatusBadge label={signal.status} tone={toneForStatus(signal.status)} compact /></td>
                      <td title={`Quality ${signal.quality_guard ?? '—'} · Pair ${signal.pair_guard ?? '—'} · Session ${signal.session_guard ?? '—'}`}>{signal.pair_guard ?? signal.quality_guard ?? '—'}</td>
                      <td>{signal.mode}</td>
                      <td className="domain-reason"><button type="button" aria-expanded={open} onClick={() => setExpanded(open ? null : signal.signal_id)}><span>{signal.reason ?? 'No reason provided by engine'}</span><ChevronRight aria-hidden="true" className={open ? 'rotate-90' : ''} /></button>{open ? <div><strong>Blocking reasons</strong><p>{signal.blocking_reasons.length ? signal.blocking_reasons.join(' · ') : '—'}</p><small>Source {signal.source} · expiry {formatTimestamp(signal.expiry)}</small></div> : null}</td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        )}
      </ResourceStateView>
    </TechnicalPanel>
  )
}
