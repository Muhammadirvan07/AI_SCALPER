import {
  AlertTriangle, CheckCircle2, CircleDashed, Clock3, DatabaseZap, LoaderCircle,
  RefreshCw, ShieldCheck, WifiOff,
} from 'lucide-react'
import type { ReactNode } from 'react'
import type { EconomicEventStatus, EconomicImpact } from '../../types/economicCalendar'

export function CalendarBadge({ label, tone = 'neutral', icon }: {
  label: string
  tone?: 'critical' | 'warning' | 'positive' | 'accent' | 'neutral'
  icon?: ReactNode
}) {
  return <span className={`ec-badge ec-badge--${tone}`}>{icon}{label}</span>
}

export function ImpactBadge({ impact }: { impact: EconomicImpact }) {
  const tone = impact === 'CRITICAL' ? 'critical' : impact === 'HIGH' ? 'warning' : impact === 'MEDIUM' ? 'accent' : 'neutral'
  return <CalendarBadge label={impact} tone={tone} icon={<span className="ec-impact-dots" aria-hidden="true">{impact === 'CRITICAL' ? '•••' : impact === 'HIGH' ? '••' : '•'}</span>} />
}

export function EventStatusBadge({ status }: { status: EconomicEventStatus }) {
  const released = status === 'RELEASED' || status === 'REVISED'
  const warning = ['COUNTDOWN', 'AWAITING_RELEASE', 'DELAYED', 'RESCHEDULED'].includes(status)
  const critical = status === 'CANCELLED'
  return (
    <CalendarBadge
      label={status.replaceAll('_', ' ')}
      tone={critical ? 'critical' : released ? 'positive' : warning ? 'warning' : 'neutral'}
      icon={released ? <CheckCircle2 aria-hidden="true" /> : warning ? <Clock3 aria-hidden="true" /> : <CircleDashed aria-hidden="true" />}
    />
  )
}

export function CalendarModuleState({
  state,
  title,
  message,
  onRetry,
}: {
  state: 'loading' | 'empty' | 'error' | 'offline' | 'unconfigured'
  title?: string
  message?: string
  onRetry?: () => void
}) {
  const defaults = {
    loading: ['Loading official calendar', 'Synchronizing verified source schedules.', LoaderCircle],
    empty: ['No economic events', 'Tidak ada event ekonomi untuk filter dan tanggal yang dipilih.', DatabaseZap],
    error: ['Calendar unavailable', 'Official calendar data could not be loaded.', AlertTriangle],
    offline: ['Backend offline', 'Cached data remains visible when available; realtime updates are paused.', WifiOff],
    unconfigured: ['No calendar sources configured', 'Belum ada sumber kalender ekonomi yang dikonfigurasi.', ShieldCheck],
  } as const
  const [defaultTitle, defaultMessage, Icon] = defaults[state]
  return (
    <div className={`ec-state ec-state--${state}`} role={state === 'error' ? 'alert' : 'status'}>
      <Icon aria-hidden="true" className={state === 'loading' ? 'ec-spin' : ''} />
      <strong>{title ?? defaultTitle}</strong>
      <p>{message ?? defaultMessage}</p>
      {onRetry && state !== 'loading' ? <button type="button" onClick={onRetry}><RefreshCw aria-hidden="true" />Retry</button> : null}
    </div>
  )
}
