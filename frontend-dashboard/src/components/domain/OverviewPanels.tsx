import {
  Activity,
  BadgeDollarSign,
  ChartNoAxesCombined,
  CircleGauge,
  CirclePercent,
  ClipboardCheck,
  Crosshair,
  Landmark,
  RadioTower,
  Scale,
  ScanLine,
  TrendingDown,
} from 'lucide-react'
import { useRealtimeDashboard } from '../../hooks/useRealtimeDashboard'
import {
  formatNullableCount,
  formatNullableCurrency,
  formatNullableNumber,
  formatNullablePercent,
  formatTimestamp,
  nullReason,
} from '../../utils/apiDisplay'
import { formatStatusLabel } from '../../utils/statusHelpers'
import { FreshnessBadge } from './FreshnessBadge'
import { ResourceStateView } from './ResourceStateView'

type Tone = 'positive' | 'caution' | 'negative' | 'neutral'

export function OverviewHeader() {
  const { resources, connection, refreshResource } = useRealtimeDashboard()
  return (
    <ResourceStateView resource={resources.overview} onRetry={() => void refreshResource('overview')}>
      {(overview) => (
        <section className="domain-command-header">
          <div>
            <span className="domain-eyebrow"><ScanLine aria-hidden="true" /> API v1 · institutional paper intelligence</span>
            <h1>AI_SCALPER Command Center</h1>
            <p>{overview.status.system_summary}</p>
          </div>
          <FreshnessBadge meta={resources.overview.meta} connection={connection} />
          <dl>
            <div><dt>Mode</dt><dd>{formatStatusLabel(overview.status.current_mode)}</dd></div>
            <div><dt>Market</dt><dd>{formatStatusLabel(overview.status.market_session)}</dd></div>
            <div><dt>Active pair</dt><dd>{overview.status.active_pair ?? '—'}</dd></div>
            <div><dt>Strategy</dt><dd>{overview.status.active_strategy ?? '—'}</dd></div>
            <div><dt>Regime</dt><dd>{formatStatusLabel(overview.status.market_regime)}</dd></div>
            <div><dt>Quality</dt><dd>{formatStatusLabel(overview.status.quality_status)}</dd></div>
            <div className="domain-command-header__wide"><dt>Source update</dt><dd title={formatTimestamp(resources.overview.meta?.source_updated_at ?? null)}>{formatTimestamp(overview.status.last_update)}</dd></div>
          </dl>
        </section>
      )}
    </ResourceStateView>
  )
}

export function DomainKpiGrid() {
  const { resources, refreshResource } = useRealtimeDashboard()
  return (
    <ResourceStateView resource={resources.overview} onRetry={() => void refreshResource('overview')}>
      {(overview) => {
        const kpi = overview.kpis
        const metrics = [
          ['Account Balance', formatNullableCurrency(kpi.account_balance), nullReason(kpi.account_balance) ?? 'Paper account', Landmark, 'neutral'],
          ['Equity', formatNullableCurrency(kpi.equity), nullReason(kpi.equity) ?? 'Current paper equity', BadgeDollarSign, 'neutral'],
          ['Net Profit', formatNullableCurrency(kpi.net_profit, true), nullReason(kpi.net_profit) ?? 'Cumulative paper P&L', ChartNoAxesCombined, (kpi.net_profit ?? 0) >= 0 ? 'positive' : 'negative'],
          ['Win Rate', formatNullablePercent(kpi.win_rate), nullReason(kpi.win_rate) ?? 'Closed paper orders', CirclePercent, (kpi.win_rate ?? 0) >= 50 ? 'positive' : 'caution'],
          ['Profit Factor', formatNullableNumber(kpi.profit_factor), nullReason(kpi.profit_factor) ?? 'Gross profit / loss', Scale, (kpi.profit_factor ?? 0) >= 1 ? 'positive' : 'caution'],
          ['Expectancy', formatNullableCurrency(kpi.expectancy, true), nullReason(kpi.expectancy) ?? 'Average per order', Activity, (kpi.expectancy ?? 0) >= 0 ? 'positive' : 'negative'],
          ['Maximum Drawdown', formatNullablePercent(kpi.maximum_drawdown_percent, 2), nullReason(kpi.maximum_drawdown_percent) ?? formatNullableCurrency(kpi.maximum_drawdown), TrendingDown, 'caution'],
          ['Closed Orders', formatNullableCount(kpi.closed_orders), nullReason(kpi.closed_orders) ?? 'Verified paper sample', ClipboardCheck, 'neutral'],
          ['Open Positions', formatNullableCount(kpi.open_positions), nullReason(kpi.open_positions) ?? 'Paper positions only', RadioTower, (kpi.open_positions ?? 0) > 0 ? 'caution' : 'neutral'],
          ['Readiness Score', kpi.readiness_score === null ? '—' : `${kpi.readiness_score.toFixed(0)}/100`, nullReason(kpi.readiness_score) ?? overview.status.quality_status, CircleGauge, (kpi.readiness_score ?? 0) >= 80 ? 'positive' : 'caution'],
        ] as const

        return (
          <section className="domain-kpi-grid" aria-label="Indikator performa aktual">
            {metrics.map(([label, value, detail, Icon, tone]) => (
              <article key={label} className={`domain-kpi domain-kpi--${tone as Tone}`} title={`${label}: ${value}. ${detail}`}>
                <span><em>{label}</em><Icon aria-hidden="true" /></span>
                <strong>{value}</strong>
                <small>{detail}</small>
              </article>
            ))}
          </section>
        )
      }}
    </ResourceStateView>
  )
}

export function CompactOverviewFacts() {
  const { resources } = useRealtimeDashboard()
  const overview = resources.overview.data
  return (
    <div className="domain-facts">
      <span><Crosshair aria-hidden="true" /><em>Pair</em><strong>{overview?.status.active_pair ?? '—'}</strong></span>
      <span><ScanLine aria-hidden="true" /><em>Phase</em><strong>{formatStatusLabel(overview?.status.current_phase)}</strong></span>
      <span><CircleGauge aria-hidden="true" /><em>Readiness</em><strong>{overview?.kpis.readiness_score === null || overview?.kpis.readiness_score === undefined ? '—' : `${overview.kpis.readiness_score}/100`}</strong></span>
    </div>
  )
}
