import type {
  SystemGuard,
  TerminalDashboardData,
  TerminalPanelState,
} from '../../types/terminal'
import { TechnicalPanel } from './common/TechnicalPanel'
import { StatusDot } from './common/StatusDot'
import { TerminalStatusBadge } from './common/TerminalStatusBadge'

interface SystemGuardHealthProps {
  guards: SystemGuard[]
  healthMetrics: TerminalDashboardData['healthMetrics']
  data: TerminalDashboardData
  state: TerminalPanelState
  onRetry: () => void
}

export function SystemGuardHealth({
  guards,
  healthMetrics,
  data,
  state,
  onRetry,
}: SystemGuardHealthProps) {
  const safety = [
    ['STATUS KUALITAS', data.summary.qualityStatus, 'warning'],
    ['KESIAPAN', `${data.readiness.score}/100`, 'caution'],
    ['KESIAPAN LIVE', 'BELUM SIAP', 'blocked'],
    ['AMAN DIAMATI', data.summary.safeToObserve ? 'YA' : 'TIDAK', 'safe'],
    ['AMAN AUTO-ORDER', data.summary.safeToAutoOrder ? 'YA' : 'TIDAK', 'blocked'],
  ] as const

  return (
    <TechnicalPanel
      code="Q11"
      title="Kesehatan Guard Sistem"
      subtitle="Batas keselamatan tetap / observabilitas kualitas"
      state={state}
      onRetry={onRetry}
      preserveContent
      className="qt-grid-span-8"
      action={<TerminalStatusBadge label="TRADING LIVE TERKUNCI (LOCKED) · TERLINDUNGI" tone="blocked" />}
      summary={`Terdapat ${guards.length} status guard dari sumber. Status kualitas ${data.summary.qualityStatus}, kesiapan ${data.readiness.score}, live tetap terkunci, aman diamati ${data.summary.safeToObserve ? 'YA' : 'TIDAK'}, dan aman auto-order TIDAK.`}
    >
      <div className="qt-safety-banner">
        <div>
          <StatusDot tone="blocked" label="TRADING LIVE TERKUNCI (LOCKED)" />
          <strong>BATAS PERLINDUNGAN AKTIF</strong>
        </div>
        <p>live_allowed=false · max_lot=0.01 · order otomatis demo=DI LUAR CAKUPAN</p>
      </div>

      <div className="qt-guard-layout">
        <div className="qt-guard-list">
          {guards.map((guard) => (
            <article key={guard.id}>
              <StatusDot tone={guard.tone} label={guard.status} pulse={guard.status === 'ONLINE'} />
              <div>
                <strong>{guard.label}</strong>
                <span>{guard.detail}</span>
              </div>
            </article>
          ))}
        </div>

        <div className="qt-health-bars">
          {healthMetrics.map((metric) => (
            <div key={metric.label}>
              <span><em>{metric.label}</em><strong>{metric.value}%</strong></span>
              <div><i className={`qt-health-bar--${metric.status}`} style={{ width: `${metric.value}%` }} /></div>
            </div>
          ))}
        </div>
      </div>

      <div className="qt-safety-grid">
        {safety.map(([label, value, tone]) => (
          <div key={label}>
            <span>{label}</span>
            <strong className={`qt-tone--${tone}`}>{value}</strong>
          </div>
        ))}
      </div>
    </TechnicalPanel>
  )
}
