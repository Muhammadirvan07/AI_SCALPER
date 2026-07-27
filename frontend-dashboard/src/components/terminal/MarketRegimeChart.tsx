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
import type {
  RegimeProbabilityPoint,
  TerminalDashboardData,
  TerminalPanelState,
} from '../../types/terminal'
import { terminalChartColors as chart } from '../../utils/terminalTheme'
import { formatPercent } from '../../utils/formatters'
import { formatStatusLabel } from '../../utils/statusHelpers'
import { MetricValue } from './common/MetricValue'
import { TechnicalPanel } from './common/TechnicalPanel'
import { TerminalStatusBadge } from './common/TerminalStatusBadge'

interface RegimeTooltipProps {
  active?: boolean
  label?: string
  payload?: Array<{
    name?: string
    value?: number
    color?: string
  }>
}

function RegimeTooltip({ active, label, payload }: RegimeTooltipProps) {
  if (!active || !payload?.length) return null
  return (
    <div className="qt-chart-tooltip">
      <strong>{label}</strong>
      {payload.map((entry) => (
        <span key={entry.name}>
          <i style={{ backgroundColor: entry.color }} />
          {entry.name} {formatPercent(entry.value ?? 0, 0)}
        </span>
      ))}
    </div>
  )
}

interface MarketRegimeChartProps {
  history: RegimeProbabilityPoint[]
  current: TerminalDashboardData['regimeCurrent']
  state: TerminalPanelState
  onRetry: () => void
}

export function MarketRegimeChart({
  history,
  current,
  state,
  onRetry,
}: MarketRegimeChartProps) {
  const markers = history.filter((point) => point.marker)
  const hasProbabilities = [current.trend, current.range, current.chop, current.panic].every(
    (value) => value !== null,
  )
  return (
    <TechnicalPanel
      code="Q04"
      title="Probabilitas Rezim Pasar"
      subtitle="Distribusi status Bayesian / transisi historis"
      state={state}
      onRetry={onRetry}
      className="qt-grid-span-8"
      action={<TerminalStatusBadge label={current.classification} tone="warning" />}
      summary={`Klasifikasi rezim aktual adalah ${current.classification}. Probabilitas historis ${hasProbabilities ? 'tersedia' : 'tidak tersedia dari sumber'}.`}
    >
      <div className="qt-regime-summary">
        <MetricValue label="Rezim saat ini" value={formatStatusLabel(current.classification)} tone="warning" />
        <MetricValue label="Proyeksi" value={formatStatusLabel(current.projectedRegime)} />
        <MetricValue label="Keyakinan" value={current.confidence === null ? '—' : current.confidence.toFixed(2)} tone="caution" />
        {hasProbabilities ? (
          <div className="qt-regime-probabilities">
            {[
              ['TREND', current.trend, 'positive'],
              ['RANGE', current.range, 'safe'],
              ['CHOP', current.chop, 'caution'],
              ['PANIC', current.panic, 'blocked'],
            ].map(([label, value, tone]) => (
              <span key={label as string}>
                <i className={`qt-regime-key qt-regime-key--${tone}`} />
                {formatStatusLabel(String(label))} <strong>{value}%</strong>
              </span>
            ))}
          </div>
        ) : (
          <TerminalStatusBadge label="PROBABILITAS TIDAK TERSEDIA" tone="neutral" />
        )}
      </div>
      {history.length > 0 ? (
        <div
          className="qt-regime-chart"
          role="img"
          aria-label="Probabilitas rezim pasar bertumpuk dari sumber aktual."
        >
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={history} margin={{ top: 16, right: 8, bottom: 0, left: -22 }}>
            <CartesianGrid stroke={chart.line} strokeDasharray="2 4" />
            <XAxis dataKey="time" tick={{ fill: chart.muted, fontSize: 9 }} tickLine={false} axisLine={false} />
            <YAxis domain={[0, 100]} tickFormatter={(value: number) => `${value}%`} tick={{ fill: chart.muted, fontSize: 9 }} tickLine={false} axisLine={false} />
            <Tooltip content={<RegimeTooltip />} />
            {markers.map((marker) => (
              <ReferenceLine
                key={`${marker.time}-${marker.marker}`}
                x={marker.time}
                stroke={chart.warning}
                strokeDasharray="3 3"
                label={{
                  value:
                    marker.marker === 'CROSS'
                      ? 'SILANG'
                      : marker.marker === 'FLIP'
                        ? 'BALIK'
                        : marker.marker === 'REGIME CHANGE'
                          ? 'PERUBAHAN REZIM'
                          : 'STABIL',
                  fill: chart.warning,
                  fontSize: 8,
                  position: 'insideTopRight',
                }}
              />
            ))}
            <Area type="monotone" stackId="regime" dataKey="trend" name="TREN" stroke={chart.positive} fill={chart.regimeTrend} fillOpacity={0.82} />
            <Area type="monotone" stackId="regime" dataKey="range" name="RENTANG" stroke={chart.safe} fill={chart.regimeRange} fillOpacity={0.8} />
            <Area type="monotone" stackId="regime" dataKey="chop" name="CHOP" stroke={chart.caution} fill={chart.regimeChop} fillOpacity={0.86} />
            <Area type="monotone" stackId="regime" dataKey="panic" name="PANIK" stroke={chart.blocked} fill={chart.regimePanic} fillOpacity={0.84} />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      ) : (
        <div className="qt-state-notice qt-state-notice--partial" role="status">
          Sumber hanya menyediakan klasifikasi saat ini. Riwayat probabilitas tidak
          direka oleh dashboard.
        </div>
      )}
    </TechnicalPanel>
  )
}
