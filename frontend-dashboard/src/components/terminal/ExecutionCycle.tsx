import type { PaperExecutionStage, TerminalPanelState } from '../../types/terminal'
import { TechnicalPanel } from './common/TechnicalPanel'
import { TerminalStatusBadge } from './common/TerminalStatusBadge'

interface ExecutionCycleProps {
  stages: PaperExecutionStage[]
  state: TerminalPanelState
}

const stageTone = {
  COMPLETE: 'safe',
  ACTIVE: 'caution',
  WAITING: 'neutral',
  BLOCKED: 'blocked',
  SKIPPED: 'neutral',
  UNKNOWN: 'neutral',
} as const

export function ExecutionCycle({ stages, state }: ExecutionCycleProps) {
  return (
    <TechnicalPanel
      code="Q03"
      title="Siklus Eksekusi Paper"
      subtitle="Simulasi bertahap khusus observasi"
      state={state}
      className="qt-grid-span-12"
      action={<TerminalStatusBadge label="TANPA EKSEKUSI LIVE" tone="blocked" />}
      summary={`Siklus paper terdiri dari ${stages.length} tahap yang diturunkan dari keputusan dan order aktual. Tahap yang tidak memiliki bukti sumber ditandai TIDAK DIKETAHUI.`}
    >
      <div className="qt-cycle" role="list" aria-label="Tahapan eksekusi paper">
        {stages.map((stage, index) => (
          <article key={stage.id} role="listitem" className={`qt-cycle__stage qt-cycle__stage--${stage.state.toLowerCase()}`}>
            <div className="qt-cycle__rail">
              <span>{stage.index.toString().padStart(2, '0')}</span>
              {index < stages.length - 1 ? <i aria-hidden="true" /> : null}
            </div>
            <div className="qt-cycle__body">
              <TerminalStatusBadge label={stage.state} tone={stageTone[stage.state]} compact />
              <strong>{stage.label}</strong>
              <dl>
                <div><dt>DURASI</dt><dd>{stage.durationMs === null ? '—' : `${stage.durationMs} ms`}</dd></div>
                <div><dt>HASIL</dt><dd>{stage.result}</dd></div>
                <div><dt>WAKTU</dt><dd>{stage.timestamp}</dd></div>
              </dl>
            </div>
          </article>
        ))}
      </div>
    </TechnicalPanel>
  )
}
