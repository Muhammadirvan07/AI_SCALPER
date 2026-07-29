import { BrainCircuit, CircleCheck, CircleX, ShieldAlert } from 'lucide-react'
import { useMemo } from 'react'
import { useRealtimeDashboard } from '../../hooks/useRealtimeDashboard'
import { formatNullableNumber, formatTimestamp } from '../../utils/apiDisplay'
import { formatStatusLabel } from '../../utils/statusHelpers'
import { TechnicalPanel } from '../terminal/common/TechnicalPanel'
import { TerminalStatusBadge } from '../terminal/common/TerminalStatusBadge'
import { ResourceStateView } from './ResourceStateView'

const numberEntries = (value: Record<string, unknown>) =>
  Object.entries(value).filter((entry): entry is [string, number] => typeof entry[1] === 'number' && Number.isFinite(entry[1]))

export function DiagnosticsPanel({ className = 'qt-grid-span-8' }: { className?: string }) {
  const { resources, refreshResource } = useRealtimeDashboard()
  const diagnostic = resources.diagnostics.data
  const scores = useMemo(() => numberEntries(diagnostic?.score_components ?? {}), [diagnostic])
  const scoreMaximum = Math.max(1, ...scores.map(([, value]) => Math.abs(value)))
  return (
    <TechnicalPanel
      code="AI01"
      title="AI Decision Diagnostics"
      subtitle="Backend reasoning only · no generated explanation"
      state={resources.diagnostics.status === 'loading' ? 'loading' : resources.diagnostics.meta?.stale ? 'stale' : diagnostic ? 'connected' : 'empty'}
      onRetry={() => void refreshResource('diagnostics')}
      preserveContent
      className={className}
      action={<TerminalStatusBadge label={diagnostic?.final_decision ?? 'UNKNOWN'} tone={diagnostic?.final_decision === 'WAIT' ? 'caution' : diagnostic?.final_decision === 'BLOCKED' ? 'blocked' : 'neutral'} compact />}
    >
      <ResourceStateView resource={resources.diagnostics} onRetry={() => void refreshResource('diagnostics')}>
        {(data) => (
          <div className="diagnostics-layout">
            <dl className="domain-definition-grid">
              <div><dt>Final decision</dt><dd>{formatStatusLabel(data.final_decision)}</dd></div>
              <div><dt>Selected strategy</dt><dd>{data.selected_strategy ?? '—'}</dd></div>
              <div><dt>Strategy score</dt><dd>{formatNullableNumber(data.strategy_score, 2)}</dd></div>
              <div><dt>Confidence</dt><dd>{formatNullableNumber(data.confidence, 2)}</dd></div>
              <div><dt>Market regime</dt><dd>{formatStatusLabel(data.market_regime)}</dd></div>
              <div><dt>Volatility state</dt><dd>{formatStatusLabel(data.volatility_state)}</dd></div>
              <div><dt>Session status</dt><dd>{formatStatusLabel(data.session_status)}</dd></div>
              <div><dt>Pair rotation</dt><dd>{formatStatusLabel(data.pair_rotation_status)}</dd></div>
              <div><dt>Quality guard</dt><dd>{formatStatusLabel(data.quality_guard_status)}</dd></div>
              <div><dt>Strategy guard</dt><dd>{formatStatusLabel(data.strategy_guard_status)}</dd></div>
              <div><dt>Post-loss cooldown</dt><dd>{formatStatusLabel(data.post_loss_cooldown)}</dd></div>
              <div><dt>Recovery lane</dt><dd>{formatStatusLabel(data.recovery_lane)}</dd></div>
              <div><dt>Readiness</dt><dd>{data.readiness_score === null ? '—' : `${data.readiness_score}/100`}</dd></div>
              <div><dt>Updated</dt><dd>{formatTimestamp(data.updated_at)}</dd></div>
            </dl>
            <div className="diagnostics-scores">
              <strong><BrainCircuit aria-hidden="true" /> Score components</strong>
              {scores.length ? scores.map(([label, value]) => {
                const percent = Math.min(100, Math.abs(value) / scoreMaximum * 100)
                return <div key={label}><span><em>{formatStatusLabel(label)}</em><b>{value.toFixed(2)}</b></span><div role="progressbar" aria-valuemin={0} aria-valuemax={scoreMaximum} aria-valuenow={Math.abs(value)}><i style={{ width: `${percent}%` }} /></div></div>
              }) : <p>Score breakdown tidak disediakan oleh engine.</p>}
            </div>
            <div className="diagnostics-evidence diagnostics-evidence--positive"><strong><CircleCheck aria-hidden="true" /> Positive reasons</strong>{data.positive_reasons.length ? <ul>{data.positive_reasons.map((item) => <li key={item}>{item}</li>)}</ul> : <p>—</p>}</div>
            <div className="diagnostics-evidence"><strong><CircleX aria-hidden="true" /> Negative reasons</strong>{data.negative_reasons.length ? <ul>{data.negative_reasons.map((item) => <li key={item}>{item}</li>)}</ul> : <p>—</p>}</div>
            <div className="diagnostics-evidence diagnostics-evidence--blocked"><strong><ShieldAlert aria-hidden="true" /> Blocking reasons</strong>{data.blocking_reasons.length ? <ul>{data.blocking_reasons.map((item) => <li key={item}>{item}</li>)}</ul> : <p>—</p>}</div>
            <div className="diagnostics-evidence"><strong>Missing components</strong><p>{data.missing_components.length ? data.missing_components.join(' · ') : 'Tidak ada missing component yang dilaporkan.'}</p><strong>Recommendation</strong><p>{data.current_recommendation ?? 'Not provided by engine'}</p></div>
          </div>
        )}
      </ResourceStateView>
    </TechnicalPanel>
  )
}
