import {
  Area,
  AreaChart,
  CartesianGrid,
  ReferenceLine,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'
import type { PaperPerformance, TerminalPanelState } from '../../types/terminal'
import { formatCurrency, formatPercent } from '../../utils/formatters'
import { terminalChartColors as chart } from '../../utils/terminalTheme'
import { MetricValue } from './common/MetricValue'
import { StatusDot } from './common/StatusDot'
import { TechnicalPanel } from './common/TechnicalPanel'
import { TerminalStatusBadge } from './common/TerminalStatusBadge'

interface EquityOverviewProps {
  performance: PaperPerformance
  state: TerminalPanelState
  onRetry: () => void
}

export function EquityOverview({
  performance,
  state,
  onRetry,
}: EquityOverviewProps) {
  const currentEquity = performance.referenceBalance + performance.netProfit
  const returnPercent =
    performance.referenceBalance > 0
      ? (performance.netProfit / performance.referenceBalance) * 100
      : 0
  const sampleProgress =
    performance.targetOrders > 0
      ? Math.min(100, (performance.closedOrders / performance.targetOrders) * 100)
      : 0

  return (
    <TechnicalPanel
      code="Q01"
      title="Monitor Ekuitas Paper"
      subtitle="Saldo referensi / P&L paper kumulatif"
      state={state}
      onRetry={onRetry}
      preserveContent
      className="qt-grid-span-5"
      action={<TerminalStatusBadge label={`PAPER ${formatCurrency(performance.netProfit, true)}`} tone="positive" />}
      summary={`Ekuitas paper aktual ${formatCurrency(currentEquity)}, dari referensi ${formatCurrency(performance.referenceBalance)} dan laba bersih kumulatif ${formatCurrency(performance.netProfit, true)}. Drawdown maksimum ${formatPercent(performance.maxDrawdown, 2)}.`}
    >
      <div className="qt-equity-overview">
        <div className="qt-equity-overview__hero">
          <div>
            <span className="qt-micro-label">Ekuitas Paper Saat Ini</span>
            <strong className="qt-equity-overview__number">
              {formatCurrency(currentEquity)}
            </strong>
            <div className="qt-equity-overview__delta">
              <span className="qt-tone--positive">
                {formatCurrency(performance.netProfit, true)}
              </span>
              <span>
                dari referensi {formatCurrency(performance.referenceBalance)}
              </span>
            </div>
          </div>
          <div
            className="qt-equity-overview__ring"
            aria-label={`Progres sampel paper ${sampleProgress.toFixed(0)} persen`}
          >
            <svg viewBox="0 0 100 100" aria-hidden="true">
              <circle cx="50" cy="50" r="42" className="qt-ring__track" />
              <circle
                cx="50"
                cy="50"
                r="42"
                className="qt-ring__value"
                pathLength="100"
                strokeDasharray={`${sampleProgress} ${100 - sampleProgress}`}
              />
            </svg>
            <span>{sampleProgress.toFixed(0)}% SAMPEL</span>
          </div>
        </div>

        <div className="qt-equity-overview__metrics">
          <MetricValue
            label="Saldo referensi"
            value={formatCurrency(performance.referenceBalance)}
            detail="Basis paper"
          />
          <MetricValue
            label="Laba bersih"
            value={formatCurrency(performance.netProfit, true)}
            detail={`Imbal hasil ${formatPercent(returnPercent, 2, true)}`}
            tone="positive"
          />
          <MetricValue
            label="Order ditutup"
            value={`${performance.closedOrders}/${performance.targetOrders}`}
            detail={`${sampleProgress.toFixed(0)}% sampel`}
          />
          <MetricValue
            label="Rasio menang"
            value={formatPercent(performance.winRate)}
            detail={`${performance.wins}W / ${performance.losses}L / ${performance.timeouts}T`}
            tone="caution"
          />
          <MetricValue
            label="Faktor profit"
            value={performance.profitFactor.toFixed(2)}
            detail="Di atas titik impas"
            tone="positive"
          />
          <MetricValue
            label="Drawdown maks."
            value={formatPercent(performance.maxDrawdown, 2)}
            detail="Puncak historis paper"
            tone="warning"
          />
        </div>

        <div className="qt-equity-curve">
          <div className="qt-equity-curve__head">
            <span className="qt-micro-label">Kurva ekuitas</span>
            <span className="qt-micro-label">Referensi {formatCurrency(performance.referenceBalance)} · Khusus paper</span>
          </div>
          <div
            className="qt-equity-curve__chart"
            role="img"
            aria-label={`Kurva ekuitas paper aktual berisi ${performance.equityCurve.length} titik.`}
          >
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart
                data={performance.equityCurve}
                margin={{ top: 8, right: 6, bottom: 0, left: -22 }}
              >
                <CartesianGrid
                  stroke={chart.line}
                  strokeDasharray="2 4"
                  vertical={false}
                />
                <XAxis
                  dataKey="session"
                  tick={{ fill: chart.muted, fontSize: 9 }}
                  tickLine={false}
                  axisLine={false}
                />
                <YAxis
                  domain={['dataMin - 0.1', 'dataMax + 0.1']}
                  tickFormatter={(value: number) => `$${value.toFixed(2)}`}
                  tick={{ fill: chart.muted, fontSize: 9 }}
                  tickLine={false}
                  axisLine={false}
                />
                <ReferenceLine
                  y={performance.referenceBalance}
                  stroke={chart.caution}
                  strokeDasharray="4 3"
                />
                <Tooltip
                  formatter={(value, name) => {
                    if (name === 'equity') return [formatCurrency(Number(value)), 'Ekuitas paper']
                    return [value, name]
                  }}
                  contentStyle={{
                    color: chart.ink,
                    border: `1px solid ${chart.lineStrong}`,
                    borderRadius: 2,
                    background: chart.surfaceRaised,
                    fontFamily: 'ui-monospace',
                    fontSize: 11,
                  }}
                />
                <Area
                  type="monotone"
                  dataKey="equity"
                  stroke={chart.positive}
                  fill={chart.positive}
                  fillOpacity={0.12}
                  strokeWidth={2}
                  dot={{ r: 2, fill: chart.positive }}
                  activeDot={{ r: 4 }}
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="qt-equity-overview__safe">
          <StatusDot tone="safe" label="EKUITAS PAPER · TANPA DANA BROKER" pulse />
          <span>LOT MAKS. 0,01 / LIVE TERKUNCI (LOCKED)</span>
        </div>
      </div>
    </TechnicalPanel>
  )
}
