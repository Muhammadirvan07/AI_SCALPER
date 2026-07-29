import {
  AlertTriangle,
  CalendarClock,
  CheckCircle2,
  CircleDot,
  LockKeyhole,
  RadioTower,
  ShieldCheck,
} from 'lucide-react'
import { useEffect, useMemo, useState } from 'react'
import { useEconomicCalendarClock } from '../../hooks/useEconomicCalendarClock'
import { useEconomicCalendarDiagnostic } from '../../hooks/useEconomicCalendarDiagnostic'
import { measureCalendarFrontendRender } from '../../realtime/economicCalendarPerformance'
import type { CalendarGuardState } from '../../types/economicCalendar'
import { formatTimestamp } from '../../utils/apiDisplay'
import { formatStatusLabel } from '../../utils/statusHelpers'
import { countdownParts, formatEventValue } from '../economic-calendar/calendarViewModel'
import { TechnicalPanel } from '../terminal/common/TechnicalPanel'
import { TerminalStatusBadge } from '../terminal/common/TerminalStatusBadge'
import { ResourceStateView } from './ResourceStateView'

const tone = (status: CalendarGuardState) => {
  if (status === 'CAUTION') return 'caution' as const
  if (status === 'HIGH_RISK' || status === 'BLOCK_PREVIEW') return 'blocked' as const
  if (status === 'POST_RELEASE_VOLATILITY') return 'neutral' as const
  if (status === 'NORMAL') return 'safe' as const
  return 'neutral' as const
}

export function EconomicCalendarDiagnosticPanel({ className = 'qt-grid-span-4' }: { className?: string }) {
  const { symbol, resource, refresh } = useEconomicCalendarDiagnostic()
  const now = useEconomicCalendarClock()
  const [renderLatency, setRenderLatency] = useState<number | null>(null)
  const data = resource.data
  const event = data?.next_event ?? null
  const countdown = useMemo(
    () => event ? countdownParts(event.scheduled_at, now).label : '—',
    [event, now],
  )
  const recentlyReleased = Boolean(
    event?.actual !== null && event?.actual !== undefined &&
    now - Date.parse(event.released_at ?? data?.updated_at ?? '') <= 10_000,
  )

  useEffect(() => {
    if (!event || !['RELEASED', 'REVISED'].includes(event.status)) return
    const frame = globalThis.requestAnimationFrame(() => {
      const metric = measureCalendarFrontendRender(event.id)
      if (metric) setRenderLatency(metric.websocketToRenderMs)
    })
    return () => globalThis.cancelAnimationFrame(frame)
  }, [event])

  return (
    <TechnicalPanel
      code="AI02"
      title="Economic Event Context"
      subtitle={`${symbol ?? 'No active symbol'} · official calendar observation`}
      state={resource.status === 'loading' ? 'loading' : resource.meta?.stale ? 'stale' : data ? 'connected' : 'empty'}
      onRetry={() => void refresh()}
      preserveContent
      className={className}
      action={<TerminalStatusBadge label={data?.status ?? 'UNAVAILABLE'} tone={data ? tone(data.status) : 'neutral'} compact />}
    >
      <ResourceStateView
        resource={resource}
        onRetry={() => void refresh()}
        emptyMessage="Economic context unavailable for the active symbol."
      >
        {(context) => (
          <div className={`calendar-diagnostic calendar-diagnostic--${context.status.toLowerCase()} ${recentlyReleased ? 'is-recently-released' : ''} ${context.next_event?.status === 'AWAITING_RELEASE' ? 'is-awaiting-release' : ''}`}>
            <div className="calendar-diagnostic__safety" aria-label="Calendar diagnostics safety boundary">
              <span><LockKeyhole aria-hidden="true" /> READ-ONLY</span>
              <span><ShieldCheck aria-hidden="true" /> DOES NOT AFFECT EXECUTION</span>
            </div>

            {context.next_event ? (
              <>
                <header className="calendar-diagnostic__hero">
                  <div>
                    <span><CircleDot aria-hidden="true" /> {formatStatusLabel(context.status)}</span>
                    <h3>{context.next_event.event_name}</h3>
                    <p>{context.next_event.currency ?? 'GLOBAL'} · {formatStatusLabel(context.next_event.impact)}</p>
                  </div>
                  <div className="calendar-diagnostic__countdown">
                    <small>{context.next_event.status === 'AWAITING_RELEASE' ? 'ACTUAL PENDING' : ['RELEASED', 'REVISED'].includes(context.next_event.status) ? 'RELEASED' : 'COUNTDOWN'}</small>
                    <strong aria-label={`Countdown ${countdown}`}>{['RELEASED', 'REVISED'].includes(context.next_event.status) ? 'RELEASED' : countdown}</strong>
                  </div>
                </header>

                <div className="calendar-diagnostic__values" aria-live="polite">
                  <div><span>Actual</span><strong>{formatEventValue(context.next_event.actual, context.next_event.unit)}</strong>{context.next_event.actual === null ? <small>Actual pending from official source</small> : null}</div>
                  <div><span>Forecast</span><strong>{formatEventValue(context.next_event.forecast, context.next_event.unit)}</strong></div>
                  <div><span>Previous</span><strong>{formatEventValue(context.next_event.previous, context.next_event.unit)}</strong></div>
                </div>

                <div className="calendar-diagnostic__explanation">
                  <strong><AlertTriangle aria-hidden="true" /> Diagnostic explanation</strong>
                  <ul>{context.reasons.map((reason) => <li key={reason}>{reason}</li>)}</ul>
                </div>

                <dl className="calendar-diagnostic__meta">
                  <div><dt>Exposure</dt><dd>{context.currency_exposure.join(' · ') || '—'}</dd></div>
                  <div><dt>Affected symbols</dt><dd>{context.affected_symbols.join(' · ') || '—'}</dd></div>
                  <div><dt>Source</dt><dd>{context.source ?? '—'}</dd></div>
                  <div><dt>Verification</dt><dd>{context.verified ? <><CheckCircle2 aria-hidden="true" /> Official</> : 'Unverified'}</dd></div>
                  <div><dt>Freshness</dt><dd><RadioTower aria-hidden="true" /> {formatStatusLabel(context.data_freshness)}</dd></div>
                  <div><dt>Updated</dt><dd>{formatTimestamp(context.updated_at)}</dd></div>
                </dl>
                {renderLatency !== null ? <p className="calendar-diagnostic__latency">WebSocket → UI render {renderLatency.toFixed(1)} ms</p> : null}
              </>
            ) : (
              <div className="calendar-diagnostic__empty">
                <CalendarClock aria-hidden="true" />
                <strong>No relevant economic event</strong>
                <p>{context.reasons[0] ?? 'No verified calendar context is available for this symbol.'}</p>
              </div>
            )}
          </div>
        )}
      </ResourceStateView>
    </TechnicalPanel>
  )
}

export function NextEconomicRiskSummary() {
  const { symbol, resource, refresh } = useEconomicCalendarDiagnostic()
  const now = useEconomicCalendarClock()
  const context = resource.data
  const event = context?.next_event
  const countdown = event ? countdownParts(event.scheduled_at, now).label : null
  return (
    <section className="next-economic-risk" aria-label="Next Economic Risk">
      <div><CalendarClock aria-hidden="true" /><span><small>Next Economic Risk</small><strong>{event ? event.event_name : 'Economic context unavailable'}</strong></span></div>
      {event && context ? <p>{event.currency ?? 'GLOBAL'} · {formatStatusLabel(event.impact)} · {event.status === 'AWAITING_RELEASE' ? 'Actual pending' : ['RELEASED', 'REVISED'].includes(event.status) ? 'Released' : `in ${countdown}`}<br /><small>{symbol} diagnostic: {formatStatusLabel(context.status)} · read-only</small></p> : <button type="button" onClick={() => void refresh()}>Retry</button>}
    </section>
  )
}
