import type { DecisionStateDistribution, TerminalPanelState } from '../../types/terminal'
import { formatPercent } from '../../utils/formatters'
import { formatStatusLabel } from '../../utils/statusHelpers'
import { terminalChartColors as chart } from '../../utils/terminalTheme'
import { TechnicalPanel } from './common/TechnicalPanel'
import { TerminalStatusBadge } from './common/TerminalStatusBadge'

const stateColors: Record<string, string> = {
  BUY: chart.positive,
  SELL: chart.warning,
  WAIT: chart.caution,
  BLOCKED: chart.blocked,
  TIMEOUT: chart.neutral,
}

const confidenceLabels: Record<string, string> = {
  strategy: 'strategi',
  guard: 'guard',
  data: 'data',
  risk: 'risiko',
}

interface DecisionStateChartProps {
  data: DecisionStateDistribution
  state: TerminalPanelState
}

export function DecisionStateChart({ data, state }: DecisionStateChartProps) {
  const stateSegments = data.states.map((item, index) => ({
    ...item,
    offset: data.states
      .slice(0, index)
      .reduce((total, previous) => total + previous.percent, 0),
  }))

  return (
    <TechnicalPanel
      code="Q06"
      title="Distribusi Status Keputusan"
      subtitle="Kepadatan hasil radial / status saat ini"
      state={state}
      className="qt-grid-span-4"
      action={<TerminalStatusBadge label={`SAAT INI ${data.currentState}`} tone="caution" />}
      summary={`Distribusi dihitung dari ${data.states.reduce((sum, item) => sum + item.count, 0)} keputusan aktual. Status saat ini ${data.currentState}.`}
    >
      <div className="qt-decision-state">
        <div className="qt-decision-state__radial" role="img" aria-label="Distribusi status keputusan radial berlapis">
          <svg viewBox="0 0 240 240" aria-hidden="true">
            <circle cx="120" cy="120" r="92" className="qt-radial-track" />
            {stateSegments.map((item) => {
              return (
                <circle
                  key={item.state}
                  cx="120"
                  cy="120"
                  r="92"
                  pathLength="100"
                  fill="none"
                  stroke={stateColors[item.state]}
                  strokeWidth="17"
                  strokeDasharray={`${Math.max(0.8, item.percent - 0.8)} ${100 - Math.max(0.8, item.percent - 0.8)}`}
                  strokeDashoffset={-item.offset}
                  transform="rotate(-90 120 120)"
                />
              )
            })}
            <circle cx="120" cy="120" r="69" className="qt-radial-track qt-radial-track--inner" />
            <circle
              cx="120"
              cy="120"
              r="69"
              pathLength="100"
              fill="none"
              stroke={chart.safe}
              strokeWidth="6"
              strokeDasharray={`${Math.min(100, (data.paperClosed / 50) * 100)} 100`}
              transform="rotate(-90 120 120)"
            />
            <circle cx="120" cy="120" r="53" fill={chart.surface} stroke={chart.lineStrong} />
            <text x="120" y="108" textAnchor="middle" className="qt-radial-label">STATUS SAAT INI</text>
            <text x="120" y="136" textAnchor="middle" className="qt-radial-value">{formatStatusLabel(data.currentState)}</text>
            <text x="120" y="153" textAnchor="middle" className="qt-radial-small">TANPA PEMICU PAPER</text>
          </svg>
        </div>

        <div className="qt-decision-state__legend">
          {data.states.map((item) => (
            <div key={item.state}>
              <span><i style={{ background: stateColors[item.state] }} />{formatStatusLabel(item.state)}</span>
              <strong>{item.count}</strong>
              <em>{formatPercent(item.percent)}</em>
            </div>
          ))}
          <div className="qt-decision-state__paper">
            <span>PAPER DIBUKA <strong>{data.paperOpen}</strong></span>
            <span>PAPER DITUTUP <strong>{data.paperClosed}</strong></span>
          </div>
        </div>
      </div>

      <div className="qt-confidence-grid">
        {Object.entries(data.confidence).map(([label, value]) => (
          <div key={label}>
            <span className="qt-micro-label">Keyakinan {confidenceLabels[label] ?? label}</span>
            <div><i style={{ width: `${value * 100}%` }} /></div>
            <strong>{value.toFixed(2)}</strong>
          </div>
        ))}
      </div>
    </TechnicalPanel>
  )
}
