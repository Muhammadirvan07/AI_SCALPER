import type { StrategyGuardStatus, TerminalPanelState } from '../../types/terminal'
import { TechnicalPanel } from './common/TechnicalPanel'
import { TerminalStatusBadge } from './common/TerminalStatusBadge'

interface StrategyGuardPanelProps {
  strategies: StrategyGuardStatus[]
  state: TerminalPanelState
}

export function StrategyGuardPanel({ strategies, state }: StrategyGuardPanelProps) {
  return (
    <TechnicalPanel
      code="Q13"
      title="Matriks Guard Strategi"
      subtitle="Skor minimum / aturan promosi kualitas"
      state={state}
      className="qt-grid-span-4"
      summary={`${strategies.length} aturan strategi ditampilkan langsung dari paper_quality_rules. Status blokir tidak dapat diubah dari dashboard.`}
    >
      <div className="qt-strategy-matrix">
        <div className="qt-strategy-matrix__head"><span>STRATEGI</span><span>MIN</span><span>KUALITAS</span><span>STATUS</span></div>
        {strategies.map((strategy) => (
          <article key={strategy.id}>
            <div>
              <strong>{strategy.strategy}</strong>
              <small>{strategy.rule}</small>
            </div>
            <span>{strategy.minimumScore}</span>
            <span>{strategy.qualityScore.toFixed(2)}</span>
            <TerminalStatusBadge label={strategy.status} tone={strategy.status === 'ALLOWED' ? 'safe' : 'blocked'} compact />
          </article>
        ))}
      </div>
    </TechnicalPanel>
  )
}
