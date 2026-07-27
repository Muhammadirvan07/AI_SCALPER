import type { CSSProperties } from 'react'
import type {
  RegimeTransition,
  TerminalDashboardData,
  TerminalPanelState,
} from '../../types/terminal'
import { TechnicalPanel } from './common/TechnicalPanel'
import { TerminalStatusBadge } from './common/TerminalStatusBadge'
import { formatStatusLabel } from '../../utils/statusHelpers'

const regimes = ['TREND', 'RANGE', 'CHOP', 'PANIC'] as const

interface RegimeTransitionMatrixProps {
  transitions: RegimeTransition[]
  summary: TerminalDashboardData['transitionSummary']
  state: TerminalPanelState
}

export function RegimeTransitionMatrix({
  transitions,
  summary,
  state,
}: RegimeTransitionMatrixProps) {
  const getProbability = (from: string, to: string) =>
    transitions.find((entry) => entry.from === from && entry.to === to)?.probability ?? 0

  return (
    <TechnicalPanel
      code="Q10"
      title="Matriks Transisi Rezim"
      subtitle="Probabilitas transisi Markov / proyeksi satu langkah"
      state={state}
      className="qt-grid-span-4"
      action={<TerminalStatusBadge label="PROYEKSI WASPADA" tone="warning" />}
      summary={`Transisi paling mungkin adalah ${summary.mostLikely}, stabilitas ${summary.stability}, durasi perkiraan ${summary.expectedDuration}, dan proyeksi berstatus waspada.`}
    >
      <div className="qt-matrix-wrap">
        <div className="qt-matrix" role="grid" aria-label="Matriks probabilitas transisi rezim">
          <span className="qt-matrix__corner">DARI / KE</span>
          {regimes.map((regime) => <span key={`column-${regime}`} className="qt-matrix__head">{formatStatusLabel(regime)}</span>)}
          {regimes.map((from) => (
            <div key={from} className="qt-matrix__row" role="row">
              <span className="qt-matrix__head" role="rowheader">{formatStatusLabel(from)}</span>
              {regimes.map((to) => {
                const probability = getProbability(from, to)
                return (
                  <span
                    key={`${from}-${to}`}
                    role="gridcell"
                    className="qt-matrix__cell"
                    style={{
                      '--matrix-alpha': Math.max(0.06, probability * 0.42).toString(),
                    } as CSSProperties}
                    title={`${formatStatusLabel(from)} ke ${formatStatusLabel(to)}: ${probability.toFixed(2)}`}
                  >
                    {probability.toFixed(2)}
                  </span>
                )
              })}
            </div>
          ))}
        </div>
      </div>
      <dl className="qt-matrix-stats">
        <div><dt>Paling mungkin</dt><dd>{summary.mostLikely}</dd></div>
        <div><dt>Stabilitas</dt><dd>{summary.stability.toFixed(2)}</dd></div>
        <div><dt>Entropi</dt><dd>{summary.entropy.toFixed(2)}</dd></div>
        <div><dt>Durasi</dt><dd>{summary.expectedDuration}</dd></div>
        <div><dt>Keyakinan</dt><dd>{summary.confidence.toFixed(2)}</dd></div>
      </dl>
    </TechnicalPanel>
  )
}
