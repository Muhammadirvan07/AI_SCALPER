import type { ConnectionSnapshot } from '../../realtime/websocketTypes'

export function ReconnectNotice({ connection }: { connection: ConnectionSnapshot }) {
  if (!['RECONNECTING', 'DELAYED', 'OFFLINE', 'ERROR'].includes(connection.state)) return null
  const message = connection.state === 'RECONNECTING'
    ? `WEBSOCKET RECONNECTING · ATTEMPT ${connection.reconnectAttempt} · LAST VALID DATA REMAINS VISIBLE`
    : connection.state === 'DELAYED'
      ? 'WEBSOCKET DELAYED · HEARTBEAT LATE · STALE DATA IS NOT MARKED LIVE'
      : connection.state === 'OFFLINE'
        ? 'BROWSER OFFLINE · BACKEND DATA UNAVAILABLE · SAFETY REMAINS LOCKED'
        : 'WEBSOCKET ERROR · REST DATA REMAINS AVAILABLE WHEN POSSIBLE'
  return <div className="qt-terminal-alert" role={connection.state === 'ERROR' ? 'alert' : 'status'}>{message}</div>
}
