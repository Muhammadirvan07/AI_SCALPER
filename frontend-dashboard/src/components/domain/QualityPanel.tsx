import { CircleCheck, CircleX, ShieldCheck } from 'lucide-react'
import { useRealtimeDashboard } from '../../hooks/useRealtimeDashboard'
import { formatNullableNumber, formatNullablePercent } from '../../utils/apiDisplay'
import { formatStatusLabel } from '../../utils/statusHelpers'
import { TechnicalPanel } from '../terminal/common/TechnicalPanel'
import { TerminalStatusBadge } from '../terminal/common/TerminalStatusBadge'
import { ResourceStateView } from './ResourceStateView'

const clamp = (value: number | null) => Math.max(0, Math.min(100, value ?? 0))

export function QualityPanel({ className = 'qt-grid-span-4' }: { className?: string }) {
  const { resources, refreshResource } = useRealtimeDashboard()
  const quality = resources.quality.data
  const tone = quality?.quality_status === 'READY' ? 'safe' : quality?.quality_status === 'WATCH' ? 'caution' : 'blocked'
  return (
    <TechnicalPanel
      code="Q01"
      title="Quality & Readiness"
      subtitle="Readiness does not grant live permission"
      state={resources.quality.status === 'loading' ? 'loading' : resources.quality.meta?.stale ? 'stale' : quality ? 'connected' : 'empty'}
      onRetry={() => void refreshResource('quality')}
      preserveContent
      className={className}
      action={<TerminalStatusBadge label={quality?.quality_status ?? 'UNKNOWN'} tone={tone} compact />}
    >
      <ResourceStateView resource={resources.quality} onRetry={() => void refreshResource('quality')}>
        {(data) => {
          const score = clamp(data.readiness_score)
          const progress = clamp(data.progress_percent)
          return (
            <>
              <dl className="quality-facts">
                <div><dt>Current phase</dt><dd>{formatStatusLabel(data.current_phase)}</dd></div>
                <div><dt>Quality status</dt><dd>{formatStatusLabel(data.quality_status)}</dd></div>
                <div><dt>Readiness status</dt><dd>{formatStatusLabel(data.readiness_status)}</dd></div>
                <div><dt>Missing tests</dt><dd>{data.missing_tests.length || '—'}</dd></div>
              </dl>
              <div className="quality-progress-list">
                <div><span><em>Readiness score</em><strong>{data.readiness_score === null ? '—' : `${data.readiness_score.toFixed(0)}/100`}</strong></span><div role="progressbar" aria-label="Readiness score" aria-valuemin={0} aria-valuemax={100} aria-valuenow={score}><i style={{ width: `${score}%` }} /></div></div>
                <div><span><em>Closed sample progress</em><strong>{data.closed_samples ?? '—'}/{data.required_samples ?? '—'}</strong></span><div role="progressbar" aria-label="Closed sample progress" aria-valuemin={0} aria-valuemax={100} aria-valuenow={progress}><i style={{ width: `${progress}%` }} /></div></div>
              </div>
              <dl className="domain-requirements">
                <div><dt>Win rate requirement</dt><dd>{formatNullablePercent(data.win_rate_requirement)}</dd></div>
                <div><dt>Profit factor requirement</dt><dd>{formatNullableNumber(data.profit_factor_requirement, 2)}</dd></div>
                <div><dt>Expectancy requirement</dt><dd>{formatNullableNumber(data.expectancy_requirement, 3)}</dd></div>
                <div><dt>Drawdown requirement</dt><dd>{formatNullablePercent(data.drawdown_requirement)}</dd></div>
              </dl>
              <div className="quality-permissions">
                <span className={data.safe_to_observe ? 'is-safe' : 'is-blocked'}>{data.safe_to_observe ? <CircleCheck aria-hidden="true" /> : <CircleX aria-hidden="true" />} Observe</span>
                <span className={data.safe_to_demo_auto_order ? 'is-safe' : 'is-blocked'}>{data.safe_to_demo_auto_order ? <CircleCheck aria-hidden="true" /> : <CircleX aria-hidden="true" />} Demo auto-order</span>
                <span className="is-blocked"><CircleX aria-hidden="true" /> Live trade locked</span>
              </div>
              <div className="quality-blockers"><span>Current blockers</span>{data.current_blockers.length ? <ul>{data.current_blockers.map((item) => <li key={item}>{item}</li>)}</ul> : <p>Tidak ada blocker yang dilaporkan.</p>}</div>
              <div className="quality-next"><span><ShieldCheck aria-hidden="true" /> Next recommended action</span><p>{data.recommendations.length ? data.recommendations.join(' · ') : 'Not provided by engine'}</p></div>
            </>
          )
        }}
      </ResourceStateView>
    </TechnicalPanel>
  )
}
