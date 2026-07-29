import { useMemo } from 'react'
import {
  Area,
  CartesianGrid,
  ComposedChart,
  Legend,
  Line,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'
import type { PerformanceRange } from '../../api/types'
import { useRealtimeDashboard } from '../../hooks/useRealtimeDashboard'
import { formatNullableCurrency, formatNullableNumber, formatNullablePercent, formatTimestamp } from '../../utils/apiDisplay'
import { TechnicalPanel } from '../terminal/common/TechnicalPanel'
import { FreshnessBadge } from './FreshnessBadge'
import { ResourceStateView } from './ResourceStateView'

const ranges: Array<{ value: PerformanceRange; label: string }> = [
  { value: '1d', label: 'Today' },
  { value: '7d', label: '7D' },
  { value: '30d', label: '30D' },
  { value: '3m', label: '3M' },
  { value: 'all', label: 'All' },
]

export function PerformancePanel({ className = 'qt-grid-span-8' }: { className?: string }) {
  const {
    resources,
    connection,
    performanceFilters,
    setPerformanceFilters,
    refreshResource,
  } = useRealtimeDashboard()
  const points = useMemo(() => {
    const seen = new Set<string>()
    return [...(resources.performance.data?.curve ?? [])]
      .filter((point) => {
        if (!point.timestamp || seen.has(point.timestamp)) return false
        seen.add(point.timestamp)
        return true
      })
      .sort((left, right) => Date.parse(left.timestamp ?? '') - Date.parse(right.timestamp ?? ''))
      .map((point) => ({ ...point, label: formatTimestamp(point.timestamp, { month: 'short', day: '2-digit', timeZone: 'Asia/Tokyo' }) }))
  }, [resources.performance.data])

  return (
    <TechnicalPanel
      code="P01"
      title="Performance Overview"
      subtitle="Equity · balance · cumulative P&L · drawdown"
      state={resources.performance.status === 'loading' ? 'loading' : resources.performance.meta?.stale ? 'stale' : points.length ? 'connected' : 'empty'}
      onRetry={() => void refreshResource('performance')}
      preserveContent
      className={className}
      collapsible={false}
      action={(
        <div className="performance-range" aria-label="Filter rentang performa">
          {ranges.map((range) => (
            <button
              key={range.value}
              type="button"
              className={performanceFilters.range === range.value ? 'is-active' : ''}
              aria-pressed={performanceFilters.range === range.value}
              onClick={() => setPerformanceFilters({ ...performanceFilters, range: range.value })}
            >{range.label}</button>
          ))}
        </div>
      )}
    >
      <ResourceStateView resource={resources.performance} onRetry={() => void refreshResource('performance')}>
        {(performance) => (
          <>
            <div className="domain-panel-telemetry">
              <span><em>Ending balance</em><strong>{formatNullableCurrency(performance.ending_balance)}</strong></span>
              <span><em>Net P&amp;L</em><strong className={performance.net_profit >= 0 ? 'qt-tone--positive' : 'qt-tone--blocked'}>{formatNullableCurrency(performance.net_profit, true)}</strong></span>
              <span><em>Max drawdown</em><strong>{formatNullablePercent(performance.maximum_drawdown_percent, 2)}</strong></span>
              <FreshnessBadge meta={resources.performance.meta} connection={connection} />
            </div>
            {points.length > 0 ? (
              <div className="domain-performance-chart" aria-label="Chart performa paper aktual">
                <ResponsiveContainer width="100%" height="100%">
                  <ComposedChart data={points} margin={{ top: 14, right: 8, bottom: 2, left: 0 }}>
                    <defs>
                      <linearGradient id="domain-equity" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="0%" stopColor="#38bdf8" stopOpacity={0.24} />
                        <stop offset="100%" stopColor="#38bdf8" stopOpacity={0} />
                      </linearGradient>
                    </defs>
                    <CartesianGrid stroke="rgba(148,163,184,.12)" vertical={false} />
                    <XAxis dataKey="label" tick={{ fill: '#7c8ca0', fontSize: 10 }} minTickGap={32} />
                    <YAxis yAxisId="balance" tick={{ fill: '#7c8ca0', fontSize: 10 }} domain={['auto', 'auto']} width={48} />
                    <YAxis yAxisId="drawdown" orientation="right" tick={{ fill: '#7c8ca0', fontSize: 10 }} width={42} />
                    <Tooltip
                      contentStyle={{ background: '#0d1726', border: '1px solid rgba(148,163,184,.2)', borderRadius: 10 }}
                      formatter={(value, name) => [formatNullableNumber(typeof value === 'number' ? value : null, 3), String(name)]}
                    />
                    <Legend wrapperStyle={{ fontSize: 11 }} />
                    <Area yAxisId="balance" type="monotone" dataKey="equity" name="Equity" stroke="#38bdf8" fill="url(#domain-equity)" strokeWidth={2} isAnimationActive={false} />
                    <Line yAxisId="balance" type="monotone" dataKey="balance" name="Balance" stroke="#a78bfa" dot={false} strokeWidth={1.25} isAnimationActive={false} />
                    <Line yAxisId="drawdown" type="stepAfter" dataKey="drawdown_percent" name="Drawdown %" stroke="#fb923c" dot={false} strokeDasharray="4 4" isAnimationActive={false} />
                  </ComposedChart>
                </ResponsiveContainer>
              </div>
            ) : <p className="domain-empty-inline">Performance curve belum tersedia; chart nol tidak dibuat.</p>}
          </>
        )}
      </ResourceStateView>
    </TechnicalPanel>
  )
}
