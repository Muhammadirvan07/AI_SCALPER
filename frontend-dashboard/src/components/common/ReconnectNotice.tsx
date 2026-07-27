import type { RealtimeConnectionInfo } from '../../types/dashboardApi'

export function ReconnectNotice({
  connection,
}: {
  connection: RealtimeConnectionInfo
}) {
  if (connection.transportState !== 'reconnecting') return null
  return (
    <div className="qt-terminal-alert" role="status">
      WEBSOCKET MENYAMBUNG ULANG · PERCOBAAN {connection.reconnectAttempt} · DATA
      TERAKHIR TETAP DITAMPILKAN
    </div>
  )
}
