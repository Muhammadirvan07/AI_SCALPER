import { Flag, TimerReset } from 'lucide-react'
import type { DashboardApiSnapshot } from '../../types/dashboardApi'
import { operationalLabel } from '../../utils/landingViewModel'
import { OperationalSection } from './OperationalSection'
import { OperationalStatusTag } from './OperationalStatusTag'
import { OperationalTimestamp } from './OperationalTimestamp'

const gateLabel = (value: string) => value.replaceAll('_', ' ')

export function ProjectProgressSection({
  snapshot,
}: {
  snapshot: DashboardApiSnapshot | null
}) {
  const progress = snapshot?.project_progress
  const passedGates = progress?.gates.filter((gate) => gate.passed === true) ?? []
  const blockedGates = progress?.gates.filter((gate) => gate.passed === false) ?? []

  return (
    <OperationalSection
      id="progres-proyek"
      eyebrow="03 / Evidence gates"
      title="Progres Proyek"
      description="Progres dihitung dari gate yang benar-benar tersedia, bukan persentase dekoratif."
    >
      <div className="ops-progress-summary">
        <div>
          <span>Tahap saat ini</span>
          <strong>{operationalLabel(progress?.stage)}</strong>
        </div>
        <div>
          <span>Gate lulus</span>
          <strong>
            {progress?.gates_passed !== null && progress?.gates_passed !== undefined &&
            progress.gates_total !== null
              ? `${progress.gates_passed} / ${progress.gates_total}`
              : 'TIDAK TERVERIFIKASI'}
          </strong>
        </div>
        <div>
          <span>Kelayakan promosi</span>
          <OperationalStatusTag
            value={progress?.promotion_eligible === true ? 'READY' : progress ? 'BLOCKED' : 'UNVERIFIED'}
            label={progress?.promotion_eligible === true
              ? 'LAYAK DITINJAU'
              : progress?.promotion_eligible === false
                ? 'BELUM DIIZINKAN'
                : 'TIDAK TERVERIFIKASI'}
          />
        </div>
      </div>

      <div className="ops-progress-window">
        <div>
          <TimerReset aria-hidden="true" className="size-4" />
          <span>Observation window</span>
          <span data-testid="observation-status">
            <OperationalStatusTag value={progress?.observation_window_status} />
          </span>
        </div>
        <dl>
          <div>
            <dt>Mulai observasi</dt>
            <dd><OperationalTimestamp value={progress?.observation_start_at} /></dd>
          </div>
          <div>
            <dt>Blind until</dt>
            <dd><OperationalTimestamp value={progress?.blind_until} /></dd>
          </div>
          <div>
            <dt>Target sesi lengkap</dt>
            <dd>{progress?.expected_complete_sessions ?? 'TIDAK TERVERIFIKASI'}</dd>
          </div>
        </dl>
      </div>

      <div className="ops-progress-columns">
        <section aria-labelledby="milestone-title">
          <header>
            <Flag aria-hidden="true" className="size-4" />
            <h3 id="milestone-title">Milestone tervalidasi</h3>
            <span>{passedGates.length}</span>
          </header>
          {passedGates.length ? (
            <ul>
              {passedGates.slice(0, 6).map((gate) => (
                <li key={gate.key}>
                  <OperationalStatusTag value="PASSED" />
                  <span>{gateLabel(gate.label)}</span>
                </li>
              ))}
            </ul>
          ) : (
            <p className="ops-empty-reason">Belum ada milestone yang dapat diverifikasi.</p>
          )}
          {passedGates.length > 6 ? <small>+{passedGates.length - 6} gate lulus lainnya</small> : null}
        </section>

        <section aria-labelledby="blocker-title">
          <header>
            <TimerReset aria-hidden="true" className="size-4" />
            <h3 id="blocker-title">Gate masih diblokir</h3>
            <span>{blockedGates.length}</span>
          </header>
          {blockedGates.length ? (
            <ul>
              {blockedGates.slice(0, 6).map((gate) => (
                <li key={gate.key}>
                  <OperationalStatusTag value="BLOCKED" />
                  <span>{gateLabel(gate.label)}</span>
                </li>
              ))}
            </ul>
          ) : (
            <p className="ops-empty-reason">Gate yang diblokir belum dapat diverifikasi.</p>
          )}
          {blockedGates.length > 6 ? <small>+{blockedGates.length - 6} blocker lainnya</small> : null}
        </section>
      </div>

      <div className="ops-promotion-reason">
        <strong>Alasan promosi belum diizinkan</strong>
        <p>{progress?.promotion_reason ?? 'TIDAK TERVERIFIKASI'}</p>
        <span>Status evidence: {operationalLabel(progress?.source_status)}</span>
      </div>
    </OperationalSection>
  )
}
