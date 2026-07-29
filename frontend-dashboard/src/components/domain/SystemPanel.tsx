import { AlertTriangle, CheckCircle2, CircleHelp, CircleX, ServerCog } from 'lucide-react'
import { useRealtimeDashboard } from '../../hooks/useRealtimeDashboard'
import { formatTimestamp, relativeTime } from '../../utils/apiDisplay'
import { formatStatusLabel } from '../../utils/statusHelpers'
import { TechnicalPanel } from '../terminal/common/TechnicalPanel'
import { TerminalStatusBadge } from '../terminal/common/TerminalStatusBadge'
import { ResourceStateView } from './ResourceStateView'

const statusPresentation = (status: string) => {
  const normalized = status.toLowerCase()
  if (normalized === 'healthy') return { tone: 'safe' as const, Icon: CheckCircle2 }
  if (normalized === 'warning' || normalized === 'degraded') return { tone: 'caution' as const, Icon: AlertTriangle }
  if (normalized === 'error' || normalized === 'offline') return { tone: 'blocked' as const, Icon: CircleX }
  return { tone: 'neutral' as const, Icon: CircleHelp }
}

export function SystemPanel({ className = 'qt-grid-span-8' }: { className?: string }) {
  const { resources, refreshResource } = useRealtimeDashboard()
  const system = resources.system.data
  const presentation = statusPresentation(system?.status ?? 'unknown')
  return (
    <TechnicalPanel
      code="SYS1"
      title="System Health"
      subtitle="Runtime components · heartbeat · source freshness"
      state={resources.components.status === 'loading' ? 'loading' : resources.components.data ? 'connected' : 'empty'}
      onRetry={() => void Promise.all([refreshResource('system'), refreshResource('components')])}
      preserveContent
      className={className}
      action={<TerminalStatusBadge label={system?.status ?? 'UNKNOWN'} tone={presentation.tone} compact />}
    >
      <ResourceStateView resource={resources.system} onRetry={() => void refreshResource('system')}>
        {(status) => (
          <div className="system-runtime-strip">
            <span><ServerCog aria-hidden="true" /><em>Backend</em><strong>{formatStatusLabel(status.status)}</strong></span>
            <span><em>Mode</em><strong>{formatStatusLabel(status.mode)}</strong></span>
            <span><em>Uptime</em><strong>{Math.floor(status.uptime_seconds / 60)} min</strong></span>
            <span><em>Version</em><strong>{status.version}</strong></span>
            <span><em>Watcher</em><strong>{formatStatusLabel(status.file_watcher_status)}</strong></span>
            <span><em>WebSocket</em><strong>{formatStatusLabel(status.websocket_status)}</strong></span>
            <span><em>Errors</em><strong>{status.error_count}</strong></span>
          </div>
        )}
      </ResourceStateView>
      <ResourceStateView resource={resources.components} onRetry={() => void refreshResource('components')}>
        {(components) => (
          <div className="system-component-grid">
            {components.map((component) => {
              const meta = statusPresentation(component.status)
              const Icon = meta.Icon
              return (
                <article key={component.name} className={`system-component system-component--${meta.tone}`}>
                  <span><Icon aria-hidden="true" /><strong>{formatStatusLabel(component.name)}</strong><TerminalStatusBadge label={component.status} tone={meta.tone} compact /></span>
                  <p>{component.latest_error ?? (component.stale ? 'Source data is stale.' : 'No current error reported.')}</p>
                  <small title={formatTimestamp(component.last_heartbeat)}>Heartbeat {relativeTime(component.last_heartbeat)} · {component.source_file ?? 'runtime'}</small>
                </article>
              )
            })}
          </div>
        )}
      </ResourceStateView>
    </TechnicalPanel>
  )
}
