import { AlertTriangle, LockKeyhole, ShieldAlert } from 'lucide-react'
import { useRealtimeDashboard } from '../../hooks/useRealtimeDashboard'
import { formatNullableCurrency, formatNullableNumber, formatNullablePercent } from '../../utils/apiDisplay'
import { formatStatusLabel } from '../../utils/statusHelpers'
import { TechnicalPanel } from '../terminal/common/TechnicalPanel'
import { TerminalStatusBadge } from '../terminal/common/TerminalStatusBadge'
import { ResourceStateView } from './ResourceStateView'

export function RiskPanel({ className = 'qt-grid-span-4' }: { className?: string }) {
  const { resources, safetyAnomaly, refreshResource } = useRealtimeDashboard()
  return (
    <TechnicalPanel
      code="R01"
      title="Risk Management"
      subtitle="Engine limits · backend safety cap · effective value"
      state={resources.risk.status === 'loading' ? 'loading' : resources.risk.meta?.stale ? 'stale' : resources.risk.data ? 'connected' : 'empty'}
      onRetry={() => void refreshResource('risk')}
      preserveContent
      className={className}
      action={<TerminalStatusBadge label="LIVE LOCKED" tone="blocked" compact />}
    >
      <ResourceStateView resource={resources.risk} onRetry={() => void refreshResource('risk')}>
        {(risk) => (
          <>
            <div className={`risk-lock ${safetyAnomaly ? 'risk-lock--critical' : ''}`} role={safetyAnomaly ? 'alert' : 'status'}>
              <span><LockKeyhole aria-hidden="true" /></span><div><strong>LIVE EXECUTION LOCKED</strong><small>live_allowed={String(false)} · frontend has no unlock control</small></div>
            </div>
            {risk.guard_applied || (risk.engine_max_lot !== null && risk.engine_max_lot > risk.backend_safety_max_lot) ? (
              <div className="domain-inline-warning"><AlertTriangle aria-hidden="true" /><span><strong>Safety limit applied.</strong> Nilai UI menggunakan effective max lot.</span></div>
            ) : null}
            <dl className="risk-metrics domain-risk-grid">
              <div><dt>Account balance</dt><dd>{formatNullableCurrency(risk.account_balance)}</dd><small>Paper account</small></div>
              <div><dt>Engine max lot</dt><dd>{formatNullableNumber(risk.engine_max_lot, 2)}</dd><small>Reported by engine</small></div>
              <div><dt>Backend safety max</dt><dd>{formatNullableNumber(risk.backend_safety_max_lot, 2)}</dd><small>Fail-closed ceiling</small></div>
              <div className="domain-risk-grid__effective"><dt>Effective max lot</dt><dd>{formatNullableNumber(risk.effective_max_lot, 2)}</dd><small>Value used by UI</small></div>
              <div><dt>Base risk</dt><dd>{formatNullablePercent(risk.base_risk_percent, 2)}</dd><small>Engine optional</small></div>
              <div><dt>Adaptive risk</dt><dd>{formatNullablePercent(risk.adaptive_risk_percent, 2)}</dd><small>Engine optional</small></div>
              <div><dt>Calculated lot</dt><dd>{formatNullableNumber(risk.calculated_lot, 2)}</dd><small>{formatStatusLabel(risk.risk_profile)}</small></div>
              <div><dt>Stop distance</dt><dd>{formatNullableNumber(risk.stop_distance, 6)}</dd><small>Source signal</small></div>
              <div><dt>Target distance</dt><dd>{formatNullableNumber(risk.target_distance, 6)}</dd><small>Source signal</small></div>
              <div><dt>Risk-reward</dt><dd>{risk.risk_reward_ratio === null ? '—' : `1:${risk.risk_reward_ratio.toFixed(2)}`}</dd><small>Entry / SL / TP</small></div>
              <div><dt>Daily drawdown</dt><dd>{formatNullablePercent(risk.daily_drawdown, 2)}</dd><small>Engine optional</small></div>
              <div><dt>Maximum drawdown</dt><dd>{formatNullablePercent(risk.maximum_drawdown, 2)}</dd><small>Historical paper</small></div>
              <div><dt>Consecutive losses</dt><dd>{risk.consecutive_losses}</dd><small>Closed orders</small></div>
              <div><dt>Cooldown</dt><dd>{formatStatusLabel(risk.cooldown_status)}</dd><small>{formatStatusLabel(risk.recovery_status)}</small></div>
            </dl>
            <div className="risk-note"><ShieldAlert aria-hidden="true" /><span>{formatStatusLabel(risk.risk_guard_status)} · guard applied {risk.guard_applied ? 'YES' : 'NO'}</span></div>
          </>
        )}
      </ResourceStateView>
    </TechnicalPanel>
  )
}
