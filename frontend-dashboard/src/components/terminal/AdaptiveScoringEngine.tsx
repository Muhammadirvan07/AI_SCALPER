import type {
  ScoreContribution,
  TerminalDashboardData,
  TerminalPanelState,
} from '../../types/terminal'
import { terminalChartColors as chart } from '../../utils/terminalTheme'
import { TechnicalPanel } from './common/TechnicalPanel'
import { TerminalStatusBadge } from './common/TerminalStatusBadge'

interface AdaptiveScoringEngineProps {
  contributions: ScoreContribution[]
  result: TerminalDashboardData['scoringResult']
  state: TerminalPanelState
}

export function AdaptiveScoringEngine({
  contributions,
  result,
  state,
}: AdaptiveScoringEngineProps) {
  const chartWidth = 430
  const chartHeight = 92
  const maxScore = 6
  const points = result.rollingScores
    .map((score, index) => {
      const x = 8 + (index / Math.max(1, result.rollingScores.length - 1)) * (chartWidth - 16)
      const y = chartHeight - 8 - (score / maxScore) * (chartHeight - 16)
      return `${x},${y}`
    })
    .join(' ')
  const thresholdY = chartHeight - 8 - (result.minimumRequired / maxScore) * (chartHeight - 16)

  return (
    <TechnicalPanel
      code="Q09"
      title="Mesin Skoring Adaptif"
      subtitle="Eksplainabilitas berbobot / bukti setelah penyesuaian guard"
      state={state}
      className="qt-grid-span-8"
      action={<TerminalStatusBadge label="AKSI TUNGGU" tone="caution" />}
      summary={`Skor mentah ${result.rawScore}, dorongan adaptif ${result.adaptiveBoost}, penalti guard ${result.guardPenalty}, skor akhir ${result.finalScore}, minimum ${result.minimumRequired}, dan aksi ${result.action}.`}
    >
      <div className="qt-scoring-summary">
        {[
          ['SKOR MENTAH', result.rawScore, 'neutral'],
          ['DORONGAN ADAPTIF', result.adaptiveBoost, 'positive'],
          ['PENALTI GUARD', result.guardPenalty, 'blocked'],
          ['SKOR AKHIR', result.finalScore, 'warning'],
          ['MINIMUM', result.minimumRequired, 'caution'],
        ].map(([label, value, tone]) => (
          <div key={label as string}>
            <span className="qt-micro-label">{label}</span>
            <strong className={`qt-tone--${tone}`}>{Number(value).toFixed(1)}</strong>
          </div>
        ))}
        <div className="qt-scoring-summary__action">
          <span className="qt-micro-label">Aksi</span>
          <strong>{result.action}</strong>
        </div>
      </div>

      <div className="qt-scoring-layout">
        <div className="qt-score-table-wrap">
          <table className="qt-score-table">
            <caption className="sr-only">Komponen kontribusi skoring adaptif</caption>
            <colgroup>
              <col className="qt-score-table__component" />
              <col className="qt-score-table__number" />
              <col className="qt-score-table__number" />
              <col className="qt-score-table__contribution" />
              <col className="qt-score-table__gate" />
            </colgroup>
            <thead>
              <tr><th>Komponen</th><th>Mentah</th><th>Bobot</th><th>Kontribusi</th><th>Gate</th></tr>
            </thead>
            <tbody>
              {contributions.map((item) => (
                <tr key={item.id} title={item.reason}>
                  <th scope="row">
                    <span>{item.component}</span>
                    <small>{item.reason}</small>
                  </th>
                  <td>{item.rawValue.toFixed(2)}</td>
                  <td>{item.weight.toFixed(2)}</td>
                  <td>
                    <div className="qt-contribution-bar">
                      <i style={{ width: `${Math.min(100, item.contribution * 125)}%` }} />
                      <strong>+{item.contribution.toFixed(1)}</strong>
                    </div>
                  </td>
                  <td>
                    <TerminalStatusBadge
                      label={item.result}
                      tone={item.result === 'PASS' ? 'safe' : item.result === 'FAIL' ? 'blocked' : 'neutral'}
                      compact
                    />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <div className="qt-rolling-score">
          <span className="qt-micro-label">Skor penyesuaian bergulir</span>
          <svg viewBox={`0 0 ${chartWidth} ${chartHeight}`} role="img" aria-label="Skor bergulir tetap di bawah ambang minimum lima.">
            {Array.from({ length: 4 }, (_, index) => {
              const y = 8 + (index / 3) * (chartHeight - 16)
              return <line key={index} x1="8" y1={y} x2={chartWidth - 8} y2={y} className="qt-chart-grid-line" />
            })}
            <line x1="8" y1={thresholdY} x2={chartWidth - 8} y2={thresholdY} stroke={chart.warning} strokeDasharray="5 3" />
            <text x={chartWidth - 8} y={thresholdY - 4} textAnchor="end" className="qt-reference-label">MIN {result.minimumRequired.toFixed(1)}</text>
            <polyline points={points} fill="none" stroke={chart.positive} strokeWidth="2" />
            {result.rollingScores.map((score, index) => {
              const x = 8 + (index / Math.max(1, result.rollingScores.length - 1)) * (chartWidth - 16)
              const y = chartHeight - 8 - (score / maxScore) * (chartHeight - 16)
              return <circle key={`${index.toString()}-${score.toString()}`} cx={x} cy={y} r="2.4" fill={chart.surface} stroke={chart.positive} />
            })}
          </svg>
          <div className="qt-explainability">
            <strong>ALASAN MENUNGGU</strong>
            <p>{result.explanation}</p>
          </div>
        </div>
      </div>
    </TechnicalPanel>
  )
}
