import type { PairRotationStatus, TerminalPanelState } from '../../types/terminal'
import { TechnicalPanel } from './common/TechnicalPanel'
import { TerminalStatusBadge } from './common/TerminalStatusBadge'

interface PairRotationPanelProps {
  pairs: PairRotationStatus[]
  state: TerminalPanelState
}

export function PairRotationPanel({ pairs, state }: PairRotationPanelProps) {
  return (
    <TechnicalPanel
      code="Q12"
      title="Rotasi Pair"
      subtitle="Kelayakan pair dinamis / semesta berdasarkan peringkat kualitas"
      state={state}
      className="qt-grid-span-4"
      summary={`${pairs.length} pair ditampilkan dari active_pairs, replay candidates, bridge guard, dan CSV yang ditemukan.`}
    >
      <div
        className="qt-rotation-list"
        tabIndex={0}
        role="region"
        aria-label="Daftar rotasi pair yang dapat digulir"
      >
        {pairs.map((pair) => {
          const tone = pair.role === 'BLOCKED' ? 'blocked' : pair.role === 'WATCH' ? 'warning' : 'safe'
          return (
            <article key={pair.id}>
              <div className="qt-rotation-list__head">
                <strong>{pair.symbol}</strong>
                <TerminalStatusBadge label={pair.role} tone={tone} compact />
              </div>
              <span>{pair.activity}</span>
              <p>{pair.reason}</p>
              <div><i style={{ width: `${pair.confidence * 100}%` }} /><em>{pair.confidence.toFixed(2)} KEYAKINAN</em></div>
            </article>
          )
        })}
      </div>
    </TechnicalPanel>
  )
}
