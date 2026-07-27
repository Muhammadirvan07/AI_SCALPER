import type { RealtimeConnectionInfo } from '../../types/dashboardApi'
import { TerminalStatusBadge } from '../terminal/common/TerminalStatusBadge'

const toneForMode = (mode: RealtimeConnectionInfo['sourceMode']) => {
  if (mode === 'REALTIME') return 'safe'
  if (mode === 'REST POLLING' || mode === 'STALE') return 'warning'
  if (mode === 'MOCK FALLBACK') return 'caution'
  return 'blocked'
}
export function ConnectionStatus({
  connection,
  compact = false,
}: {
  connection: RealtimeConnectionInfo
  compact?: boolean
}) {
  return (
    <div className="qt-connection-status" aria-label={`Sumber data ${connection.sourceMode}`}>
      <TerminalStatusBadge
        label={connection.sourceMode}
        tone={toneForMode(connection.sourceMode)}
        compact={compact}
      />
      {!compact ? (
        <span>
          WS {connection.socketActive ? 'AKTIF' : 'TIDAK AKTIF'} · V
          {connection.snapshotVersion} · STALE {connection.staleSourceCount}
        </span>
      ) : null}
    </div>
  )
}
