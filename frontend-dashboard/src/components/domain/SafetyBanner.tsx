import { AlertOctagon, LockKeyhole, ShieldCheck } from 'lucide-react'
import { useRealtimeDashboard } from '../../hooks/useRealtimeDashboard'
import { formatNullableNumber } from '../../utils/apiDisplay'

export function SafetyBanner() {
  const { resources, safetyAnomaly, safetyMessage } = useRealtimeDashboard()
  const risk = resources.risk.data
  const overview = resources.overview.data
  const mode = resources.system.data?.mode ?? 'DRY_RUN'
  const maximumLot = risk?.effective_max_lot ?? null
  const locked = !safetyAnomaly && risk?.live_allowed !== true && overview?.status.live_allowed !== true

  return (
    <aside data-testid="safety-banner" className={`safety-banner ${locked ? '' : 'safety-banner--critical'}`} role={locked ? 'status' : 'alert'}>
      <span className="safety-banner__icon">
        {locked ? <ShieldCheck aria-hidden="true" /> : <AlertOctagon aria-hidden="true" />}
      </span>
      <div>
        <strong>{locked ? mode : 'SAFETY ANOMALY'}</strong>
        <span><LockKeyhole aria-hidden="true" /> LIVE EXECUTION LOCKED</span>
      </div>
      <p>
        Maximum effective lot: <strong>{formatNullableNumber(maximumLot, 2)}</strong>
        {locked ? ' · Read-only monitoring gateway' : ` · ${safetyMessage ?? 'Fail-closed UI active.'}`}
      </p>
    </aside>
  )
}
