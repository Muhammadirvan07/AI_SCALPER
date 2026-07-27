import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from 'react'
import { dashboardDataConfig } from '../config/dataSources'
import { mockDashboardData } from '../data/mockDashboardData'
import { mockTerminalData } from '../data/mockTerminalData'
import type { DataStatus } from '../types/dashboard'
import { dashboardDataService } from '../services/dashboardDataService'
import { DashboardWebSocketClient } from '../services/dashboardWebSocketClient'
import type {
  DashboardApiSnapshot,
  DashboardSourceMode,
  RealtimeConnectionInfo,
  RealtimeTransportState,
} from '../types/dashboardApi'
import type { TerminalDashboardData, TerminalPanelState } from '../types/terminal'
import { isDashboardSnapshot } from '../utils/realtimeGuards'
import {
  mapApiSnapshotToDashboard,
  mapApiSnapshotToTerminal,
  snapshotPanelState,
} from '../utils/snapshotMapper'
import {
  heartbeatIsExpired,
  shouldAcceptSnapshot,
  sourceModeFor,
} from '../utils/realtimePolicy'
import {
  DashboardRealtimeContext,
  type DashboardRealtimeContextValue,
} from './dashboardRealtimeContext'

const dataStatusFor = (state: TerminalPanelState): DataStatus => {
  if (state === 'connected') return 'success'
  return state
}

export function DashboardRealtimeProvider({ children }: { children: ReactNode }) {
  const [apiSnapshot, setApiSnapshot] = useState<DashboardApiSnapshot | null>(null)
  const [transport, setTransport] = useState<RealtimeTransportState>('connecting')
  const [reconnectAttempt, setReconnectAttempt] = useState(0)
  const [error, setError] = useState<string | null>(null)
  const [mockFallback, setMockFallback] = useState(false)
  const [isPaused, setIsPaused] = useState(false)
  const [lastEventAt, setLastEventAt] = useState<string | null>(null)
  const [lastHeartbeatAt, setLastHeartbeatAt] = useState<string | null>(null)
  const [heartbeatExpired, setHeartbeatExpired] = useState(false)
  const [policyNowMs, setPolicyNowMs] = useState(() => Date.now())
  const pendingSnapshot = useRef<DashboardApiSnapshot | null>(null)
  const latestSnapshot = useRef<DashboardApiSnapshot | null>(null)
  const pausedRef = useRef(false)
  const connectedAtMs = useRef<number | null>(null)

  const admitSnapshot = useCallback((snapshot: DashboardApiSnapshot) => {
    if (!shouldAcceptSnapshot(latestSnapshot.current, snapshot)) return false
    latestSnapshot.current = snapshot
    setMockFallback(false)
    setError(null)
    if (pausedRef.current) pendingSnapshot.current = snapshot
    else setApiSnapshot(snapshot)
    return true
  }, [])

  const refresh = useCallback(async () => {
    try {
      const snapshot = await dashboardDataService.getRealtimeSnapshot()
      admitSnapshot(snapshot)
    } catch (reason) {
      setError(
        reason instanceof Error
          ? reason.message
          : 'Snapshot dashboard tidak dapat dimuat.',
      )
      if (!latestSnapshot.current && dashboardDataConfig.useMockFallback) {
        setMockFallback(true)
      }
    }
  }, [admitSnapshot])

  useEffect(() => {
    const timer = window.setInterval(() => setPolicyNowMs(Date.now()), 10_000)
    return () => window.clearInterval(timer)
  }, [])

  useEffect(() => {
    const controller = new AbortController()
    dashboardDataService.getRealtimeSnapshot(controller.signal)
      .then((snapshot) => {
        admitSnapshot(snapshot)
      })
      .catch((reason: unknown) => {
        if (reason instanceof DOMException && reason.name === 'AbortError') return
        setError(
          reason instanceof Error
            ? reason.message
            : 'Backend dashboard tidak dapat dijangkau.',
        )
        if (dashboardDataConfig.useMockFallback) setMockFallback(true)
      })
    return () => controller.abort()
  }, [admitSnapshot])

  useEffect(() => {
    const client = new DashboardWebSocketClient({
      onStateChange: (state, attempt) => {
        if (state === 'connected') {
          connectedAtMs.current = Date.now()
          setLastHeartbeatAt(null)
          setHeartbeatExpired(false)
        } else {
          connectedAtMs.current = null
          setLastHeartbeatAt(null)
          setHeartbeatExpired(false)
        }
        setTransport(state)
        setReconnectAttempt(attempt)
      },
      onEvent: (event) => {
        setLastEventAt(event.timestamp)
        if (event.type === 'heartbeat') {
          setLastHeartbeatAt(event.timestamp)
          setHeartbeatExpired(false)
          return
        }
        if (
          (event.type === 'snapshot.full' || event.type === 'snapshot.updated') &&
          isDashboardSnapshot(event.payload)
        ) {
          if (event.version !== event.payload.version) {
            setError('Versi event WebSocket tidak cocok dengan payload snapshot.')
            return
          }
          admitSnapshot(event.payload)
        }
      },
    })
    client.start()
    return () => client.stop()
  }, [admitSnapshot])

  useEffect(() => {
    if (transport === 'connected') return
    let active = true
    let controller: AbortController | null = null
    const polling = window.setInterval(() => {
      controller?.abort()
      controller = new AbortController()
      dashboardDataService.getRealtimeSnapshot(controller.signal)
        .then((snapshot) => {
          if (!active) return
          setTransport((current) => (current === 'connected' ? current : 'polling'))
          admitSnapshot(snapshot)
        })
        .catch((reason: unknown) => {
          if (!active || (reason instanceof DOMException && reason.name === 'AbortError')) return
          setError(
            reason instanceof Error
              ? reason.message
              : 'REST polling dashboard gagal.',
          )
        })
    }, dashboardDataConfig.restPollingIntervalMs)
    return () => {
      active = false
      controller?.abort()
      window.clearInterval(polling)
    }
  }, [admitSnapshot, transport])

  useEffect(() => {
    const evaluateHeartbeat = () =>
      setHeartbeatExpired(
        heartbeatIsExpired({
          transport,
          lastHeartbeatAt,
          connectedAtMs: connectedAtMs.current,
          nowMs: Date.now(),
        }),
      )
    evaluateHeartbeat()
    const watchdog = window.setInterval(evaluateHeartbeat, 5_000)
    return () => window.clearInterval(watchdog)
  }, [lastHeartbeatAt, transport])

  const togglePause = useCallback(() => {
    setIsPaused((current) => {
      const next = !current
      pausedRef.current = next
      if (!next && pendingSnapshot.current) {
        setApiSnapshot(pendingSnapshot.current)
        pendingSnapshot.current = null
      }
      return next
    })
  }, [])

  const sourceMode: DashboardSourceMode = sourceModeFor({
    snapshot: apiSnapshot,
    transport,
    mockFallback,
    heartbeatExpired,
    nowMs: policyNowMs,
    staleAfterMs: dashboardDataConfig.staleAfterMs,
  })
  const dashboard = useMemo(
    () =>
      apiSnapshot
        ? mapApiSnapshotToDashboard(apiSnapshot)
        : mockFallback
          ? mockDashboardData
          : null,
    [apiSnapshot, mockFallback],
  )
  const terminal = useMemo<TerminalDashboardData | null>(
    () =>
      apiSnapshot
        ? mapApiSnapshotToTerminal(apiSnapshot, sourceMode)
        : mockFallback
          ? structuredClone(mockTerminalData)
          : null,
    [apiSnapshot, mockFallback, sourceMode],
  )
  const panelState = apiSnapshot
    ? sourceMode === 'STALE'
      ? 'stale'
      : sourceMode === 'DISCONNECTED'
        ? 'disconnected'
        : snapshotPanelState(apiSnapshot)
    : mockFallback
      ? 'partial'
      : error
        ? 'error'
        : transport === 'disconnected'
          ? 'disconnected'
          : 'loading'
  const connection: RealtimeConnectionInfo = useMemo(
    () => ({
      transportState: transport,
      sourceMode,
      lastEventAt,
      lastHeartbeatAt,
      lastSourceUpdateAt: apiSnapshot?.source_updated_at ?? null,
      latencyMs: apiSnapshot?.connection.latency_ms ?? null,
      snapshotVersion: apiSnapshot?.version ?? 0,
      staleSourceCount: apiSnapshot?.connection.stale_source_count ?? 0,
      socketActive: transport === 'connected',
      reconnectAttempt,
    }),
    [
      apiSnapshot,
      lastEventAt,
      lastHeartbeatAt,
      reconnectAttempt,
      sourceMode,
      transport,
    ],
  )
  const dataStatus = mockFallback ? 'partial' : dataStatusFor(panelState)
  const value: DashboardRealtimeContextValue = useMemo(
    () => ({
      apiSnapshot,
      dashboard,
      terminal,
      dataStatus,
      panelState,
      connection,
      error,
      isPaused,
      lastSuccessfulUpdate: apiSnapshot?.generated_at ?? null,
      refresh,
      togglePause,
    }),
    [
      apiSnapshot,
      connection,
      dashboard,
      dataStatus,
      error,
      isPaused,
      panelState,
      refresh,
      terminal,
      togglePause,
    ],
  )

  return (
    <DashboardRealtimeContext.Provider value={value}>
      {children}
    </DashboardRealtimeContext.Provider>
  )
}
