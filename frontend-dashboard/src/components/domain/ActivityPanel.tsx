import { Activity, Ban, CheckCircle2, CircleDot, RefreshCw, TriangleAlert } from 'lucide-react'
import { useRealtimeDashboard } from '../../hooks/useRealtimeDashboard'
import { formatTimestamp } from '../../utils/apiDisplay'
import { TechnicalPanel } from '../terminal/common/TechnicalPanel'
import { TerminalStatusBadge } from '../terminal/common/TerminalStatusBadge'
import { ResourceStateView } from './ResourceStateView'

const activityIcon = (type: string, severity: string) => {
  if (type.includes('blocked')) return { Icon: Ban, tone: 'blocked' }
  if (type.includes('closed') || severity === 'success') return { Icon: CheckCircle2, tone: 'safe' }
  if (type.includes('refreshed')) return { Icon: RefreshCw, tone: 'neutral' }
  if (severity === 'error' || severity === 'critical') return { Icon: TriangleAlert, tone: 'blocked' }
  if (severity === 'warning') return { Icon: Activity, tone: 'caution' }
  return { Icon: CircleDot, tone: 'neutral' }
}

export function ActivityPanel({ className = 'qt-grid-span-4' }: { className?: string }) {
  const { resources, refreshResource } = useRealtimeDashboard()
  return (
    <TechnicalPanel
      code="ACT1"
      title="Recent Activity"
      subtitle="Signals · orders · watcher · commands"
      state={resources.activity.status === 'loading' ? 'loading' : resources.activity.data?.length ? 'connected' : 'empty'}
      onRetry={() => void refreshResource('activity')}
      preserveContent
      className={className}
      action={<TerminalStatusBadge label={`${resources.activity.data?.length ?? 0} EVENTS`} tone="neutral" compact />}
    >
      <ResourceStateView resource={resources.activity} onRetry={() => void refreshResource('activity')} emptyMessage="Backend belum memiliki event activity.">
        {(events) => (
          <ol className="activity-timeline">
            {events.slice(0, 30).map((event) => {
              const { Icon, tone } = activityIcon(event.type, event.severity)
              return <li key={event.id}><span className={`activity-timeline__icon activity-timeline__icon--${tone}`}><Icon aria-hidden="true" /></span><div><strong>{event.title}</strong><p>{event.component} · {event.type}</p><small>{event.message}</small></div><time dateTime={event.timestamp} title={formatTimestamp(event.timestamp)}>{formatTimestamp(event.timestamp, { hour: '2-digit', minute: '2-digit', timeZone: 'Asia/Tokyo' })}</time></li>
            })}
          </ol>
        )}
      </ResourceStateView>
    </TechnicalPanel>
  )
}
