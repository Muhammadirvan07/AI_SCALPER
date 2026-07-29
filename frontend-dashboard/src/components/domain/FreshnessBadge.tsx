import { Clock3, DatabaseZap, RadioTower, WifiOff } from 'lucide-react'
import type { ApiMeta } from '../../api/types'
import type { ConnectionSnapshot } from '../../realtime/websocketTypes'
import { dataMode, formatTimestamp, relativeTime } from '../../utils/apiDisplay'

export function FreshnessBadge({ meta, connection }: { meta: ApiMeta | null; connection: ConnectionSnapshot }) {
  const mode = dataMode(meta, connection)
  const Icon = mode === 'LIVE' ? RadioTower : mode === 'OFFLINE' ? WifiOff : mode === 'UNAVAILABLE' ? DatabaseZap : Clock3
  return (
    <span
      className={`domain-freshness domain-freshness--${mode.toLowerCase()}`}
      title={`Source updated: ${formatTimestamp(meta?.source_updated_at ?? null)}. Server: ${formatTimestamp(meta?.server_timestamp ?? null)}.`}
    >
      <Icon aria-hidden="true" className="size-3.5" />
      <strong>{mode}</strong>
      <small>{relativeTime(meta?.source_updated_at ?? null)}</small>
    </span>
  )
}
