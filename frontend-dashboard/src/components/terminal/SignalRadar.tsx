import {
  PolarAngleAxis,
  PolarGrid,
  PolarRadiusAxis,
  Radar,
  RadarChart,
  ResponsiveContainer,
  Tooltip,
} from 'recharts'
import type {
  SignalRadarMetric,
  TerminalDashboardData,
  TerminalPanelState,
} from '../../types/terminal'
import { terminalChartColors as chart } from '../../utils/terminalTheme'
import { TechnicalPanel } from './common/TechnicalPanel'
import { TerminalStatusBadge } from './common/TerminalStatusBadge'

interface SignalRadarProps {
  metrics: SignalRadarMetric[]
  setup: TerminalDashboardData['signalSetup']
  state: TerminalPanelState
}

export function SignalRadar({ metrics, setup, state }: SignalRadarProps) {
  return (
    <TechnicalPanel
      code="Q08"
      title="Radar Sinyal"
      subtitle="Vektor bukti delapan sumbu / batas minimum trading"
      state={state}
      className="qt-grid-span-4"
      action={<TerminalStatusBadge label={setup.decision} tone="caution" />}
      summary={`Setup ${setup.strategy} memiliki skor mentah ${setup.rawScore}, skor tersesuaikan ${setup.adjustedScore}, minimum ${setup.minimumRequired}, dan keputusan ${setup.decision}.`}
    >
      <div className="qt-signal-radar">
        <div className="qt-signal-radar__chart" role="img" aria-label="Radar sinyal untuk tren, momentum, volatilitas, mean reversion, tekanan breakout, likuiditas, kualitas sesi, dan kesegaran data.">
          <ResponsiveContainer width="100%" height="100%">
            <RadarChart data={metrics} cx="50%" cy="50%" outerRadius="74%">
              <PolarGrid stroke={chart.lineStrong} />
              <PolarAngleAxis dataKey="metric" tick={{ fill: chart.muted, fontSize: 9 }} />
              <PolarRadiusAxis domain={[0, 100]} tick={false} axisLine={false} />
              <Tooltip
                contentStyle={{ color: chart.ink, border: `1px solid ${chart.lineStrong}`, borderRadius: 2, background: chart.surfaceRaised, fontFamily: 'ui-monospace', fontSize: 10 }}
              />
              <Radar name="Batas minimum" dataKey="minimumBoundary" stroke={chart.warning} fill="transparent" strokeDasharray="4 3" strokeWidth={1.2} />
              <Radar name="Vektor saat ini" dataKey="value" stroke={chart.positive} fill={chart.positive} fillOpacity={0.2} strokeWidth={2} />
            </RadarChart>
          </ResponsiveContainer>
        </div>
        <div className="qt-signal-setup">
          <span className="qt-micro-label">Setup terdeteksi terbaru</span>
          <strong>{setup.strategy}</strong>
          <dl>
            <div><dt>MENTAH</dt><dd>{setup.rawScore}</dd></div>
            <div><dt>PENYES.</dt><dd>{setup.adjustedScore}</dd></div>
            <div><dt>MIN.</dt><dd>{setup.minimumRequired}</dd></div>
          </dl>
          <TerminalStatusBadge label={setup.label} tone="warning" />
        </div>
      </div>
      <div className="qt-radar-legend">
        {metrics.map((metric) => (
          <span key={metric.key}>
            <i className={`qt-radar-zone qt-radar-zone--${metric.zone.toLowerCase()}`} />
            {metric.metric} <strong>{metric.value}</strong>
          </span>
        ))}
      </div>
    </TechnicalPanel>
  )
}
