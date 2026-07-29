import { Bot, ChevronDown, Clock3, Menu, RefreshCw, RotateCw, Wifi, WifiOff } from 'lucide-react'
import { useState } from 'react'
import type { OverviewData } from '../../api/types'
import type { ConnectionSnapshot } from '../../realtime/websocketTypes'
import { formatTimestamp, relativeTime } from '../../utils/apiDisplay'
import { formatStatusLabel } from '../../utils/statusHelpers'
import { defaultPageMeta, pageMetaByPath } from './appNavigation'

const connectionPresentation = (connection: ConnectionSnapshot) => {
  if (connection.state === 'CONNECTING' || connection.state === 'RECONNECTING') return { label: 'Reconnecting', tone: 'reconnecting', Icon: RotateCw, detail: `Attempt ${connection.reconnectAttempt}` }
  if (connection.state === 'OFFLINE' || connection.state === 'ERROR') return { label: connection.state === 'OFFLINE' ? 'Offline' : 'Error', tone: 'offline', Icon: WifiOff, detail: connection.error ?? 'Realtime unavailable' }
  if (connection.state === 'DELAYED') return { label: 'Delayed', tone: 'delayed', Icon: Clock3, detail: 'Heartbeat delayed' }
  return { label: 'Connected', tone: 'live', Icon: Wifi, detail: 'Shared WebSocket connected' }
}

interface AppTopbarProps {
  pathname: string
  overview: OverviewData | null
  connection: ConnectionSnapshot
  onRefresh: () => Promise<void> | void
  onOpenMobileNavigation: () => void
}

export function AppTopbar({ pathname, overview, connection, onRefresh, onOpenMobileNavigation }: AppTopbarProps) {
  const [refreshing, setRefreshing] = useState(false)
  const [profileOpen, setProfileOpen] = useState(false)
  const pageMeta = pageMetaByPath[pathname] ?? defaultPageMeta
  const presentation = connectionPresentation(connection)
  const ConnectionIcon = presentation.Icon
  const lastUpdate = overview?.status.last_update ?? connection.lastSuccessfulUpdate
  const refresh = async () => {
    if (refreshing) return
    setRefreshing(true)
    try { await onRefresh() } finally { setRefreshing(false) }
  }

  return (
    <header className="app-topbar">
      <div className="app-topbar__identity">
        <button type="button" className="app-icon-button app-topbar__menu" onClick={onOpenMobileNavigation} aria-label="Buka navigasi utama" aria-controls="app-sidebar"><Menu aria-hidden="true" /></button>
        <div><strong className="app-topbar__title">{pageMeta.title}</strong><p>{pageMeta.context}</p></div>
      </div>
      <div className="app-topbar__telemetry" aria-label="Status runtime">
        <div className="app-topbar__telemetry-item"><span>Session</span><strong>{formatStatusLabel(overview?.status.market_session)}</strong></div>
        <div className="app-topbar__telemetry-item" title={formatTimestamp(lastUpdate ?? null)}><span>Last update</span><strong>{relativeTime(lastUpdate ?? null)}</strong></div>
        <div data-testid="connection-indicator" className={`app-connection app-connection--${presentation.tone}`} title={`${presentation.detail}. Heartbeat ${formatTimestamp(connection.lastHeartbeatAt)}.`} aria-label={`Koneksi ${presentation.label}. ${presentation.detail}`}>
          <ConnectionIcon aria-hidden="true" className={`size-4 ${presentation.tone === 'reconnecting' ? 'motion-safe:animate-spin' : ''}`} />
          <span><strong>{presentation.label}</strong><small>{connection.state}</small></span>
        </div>
      </div>
      <div className="app-topbar__actions">
        <button type="button" className="app-icon-button" onClick={() => void refresh()} disabled={refreshing} aria-label={refreshing ? 'Sedang memperbarui data' : 'Perbarui semua data API'} title="Refresh REST data"><RefreshCw aria-hidden="true" className={`size-4 ${refreshing ? 'motion-safe:animate-spin' : ''}`} /></button>
        <div className="app-profile">
          <button type="button" className="app-profile__trigger" onClick={() => setProfileOpen((value) => !value)} aria-expanded={profileOpen} aria-haspopup="menu"><span><Bot aria-hidden="true" /></span><span className="app-profile__copy"><strong>Operator</strong><small>Read only</small></span><ChevronDown aria-hidden="true" /></button>
          {profileOpen ? <div className="app-profile__menu" role="menu"><strong>AI_SCALPER Operator</strong><span>Mode {overview?.status.current_mode ?? 'unavailable'}</span><span>{connection.subscribedChannels.length} subscriptions</span><span className="app-profile__locked">Live execution locked</span></div> : null}
        </div>
      </div>
    </header>
  )
}
