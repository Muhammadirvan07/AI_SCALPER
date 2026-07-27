import type {
  DashboardApiSnapshot,
  DashboardSourceMode,
  RealtimeTransportState,
} from '../types/dashboardApi'

export const HEARTBEAT_TIMEOUT_MS = 35_000
export const MAX_FUTURE_CLOCK_SKEW_MS = 60_000

export const timestampMilliseconds = (value: string | null): number | null => {
  if (value === null) return null
  const parsed = Date.parse(value)
  return Number.isFinite(parsed) ? parsed : null
}

export const shouldAcceptSnapshot = (
  current: DashboardApiSnapshot | null,
  incoming: DashboardApiSnapshot,
) => current === null || incoming.version > current.version

export const heartbeatIsExpired = ({
  transport,
  lastHeartbeatAt,
  connectedAtMs,
  nowMs,
  timeoutMs = HEARTBEAT_TIMEOUT_MS,
}: {
  transport: RealtimeTransportState
  lastHeartbeatAt: string | null
  connectedAtMs: number | null
  nowMs: number
  timeoutMs?: number
}) => {
  if (transport !== 'connected') return false
  const heartbeatAtMs = timestampMilliseconds(lastHeartbeatAt)
  if (
    heartbeatAtMs !== null &&
    heartbeatAtMs > nowMs + MAX_FUTURE_CLOCK_SKEW_MS
  ) {
    return true
  }
  const baselineMs = heartbeatAtMs ?? connectedAtMs
  return baselineMs === null || nowMs - baselineMs > timeoutMs
}

export const sourceModeFor = ({
  snapshot,
  transport,
  mockFallback,
  heartbeatExpired,
  nowMs,
  staleAfterMs,
}: {
  snapshot: DashboardApiSnapshot | null
  transport: RealtimeTransportState
  mockFallback: boolean
  heartbeatExpired: boolean
  nowMs: number
  staleAfterMs: number
}): DashboardSourceMode => {
  if (mockFallback) return 'MOCK FALLBACK'
  if (!snapshot) return 'DISCONNECTED'
  const sourceUpdatedAtMs = timestampMilliseconds(snapshot.source_updated_at)
  const sourceInvalid =
    sourceUpdatedAtMs === null ||
    sourceUpdatedAtMs > nowMs + MAX_FUTURE_CLOCK_SKEW_MS
  const sourceAgeMs = sourceUpdatedAtMs === null ? Number.POSITIVE_INFINITY : nowMs - sourceUpdatedAtMs
  if (
    snapshot.connection.stale ||
    sourceInvalid ||
    sourceAgeMs > staleAfterMs ||
    heartbeatExpired
  ) {
    return 'STALE'
  }
  if (transport === 'connected') return 'REALTIME'
  if (
    transport === 'polling' ||
    transport === 'reconnecting' ||
    transport === 'connecting'
  ) {
    return 'REST POLLING'
  }
  return 'DISCONNECTED'
}
