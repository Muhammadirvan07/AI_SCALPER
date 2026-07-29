import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from 'react'
import { getActivity } from '../api/activity'
import { queryCache } from '../api/cache'
import { ApiClientError } from '../api/client'
import {
  getEconomicCalendar,
  getEconomicCalendarDiagnostic,
  getEconomicCalendarGuard,
  getEconomicCalendarHealth,
  getEconomicCalendarSources,
  getEconomicCalendarStatus,
} from '../api/economicCalendar'
import { getDiagnostics } from '../api/diagnostics'
import { getLogs, type LogFilters } from '../api/logs'
import {
  getBreakingNews,
  getLatestNews,
  getNewsProviders,
  getRecentNews,
  getNewsSentiment,
  getNewsSentimentTimeline,
  getNewsStatus,
  getSymbolNewsSummary,
} from '../api/news'
import {
  getMarketCandles,
  getMarketIndicators,
  getMarketQuote,
  getMarketStatus,
  getMarketSymbols,
} from '../api/market'
import { getOrders } from '../api/orders'
import { getOverview } from '../api/overview'
import { getPerformance, type PerformanceFilters } from '../api/performance'
import { getQuality } from '../api/quality'
import { getRisk } from '../api/risk'
import { getSignals } from '../api/signals'
import { getSystemComponents, getSystemStatus } from '../api/system'
import type { ApiResponse, Timeframe } from '../api/types'
import { getWatchlist, isValidMarketSymbol } from '../api/watchlist'
import { queriesForEvent, type DashboardQueryKey } from '../realtime/eventHandlers'
import { calendarMutationEvents, mergeEconomicCalendarEvent } from '../realtime/economicCalendarEventHandlers'
import { markCalendarEventReceived } from '../realtime/economicCalendarPerformance'
import { SharedWebSocketClient } from '../realtime/websocketClient'
import type { ConnectionSnapshot } from '../realtime/websocketTypes'
import {
  DashboardRealtimeContext,
  emptyResource,
  initialResources,
  newestTimestamp,
  type DashboardResourceKey,
  type DashboardResources,
} from './dashboardRealtimeContext'

const staleTimes: Record<DashboardResourceKey, number> = {
  overview: 7_000,
  performance: 120_000,
  symbols: 300_000,
  quote: 3_000,
  candles: 20_000,
  indicators: 20_000,
  marketStatus: 5_000,
  watchlist: 5_000,
  signals: 7_000,
  orders: 7_000,
  diagnostics: 15_000,
  risk: 15_000,
  quality: 45_000,
  system: 15_000,
  components: 15_000,
  activity: 10_000,
  logs: 30_000,
  news: 180_000,
  recentNews: 300_000,
  breakingNews: 60_000,
  newsSentiment: 180_000,
  newsTimeline: 180_000,
  economicCalendar: 600_000,
  economicCalendarSources: 300_000,
  economicCalendarStatus: 30_000,
  economicCalendarHealth: 30_000,
  economicCalendarGuard: 30_000,
  economicCalendarDiagnostic: 15_000,
  newsProviders: 300_000,
  newsStatus: 60_000,
  symbolNews: 120_000,
}

const initialConnection: ConnectionSnapshot = {
  state: 'CONNECTING',
  reconnectAttempt: 0,
  lastHeartbeatAt: null,
  lastEventAt: null,
  lastSuccessfulUpdate: null,
  subscribedChannels: [],
  retryAt: null,
  error: null,
}

const initialKeys: DashboardResourceKey[] = [
  'overview',
  'performance',
  'symbols',
  'watchlist',
  'signals',
  'orders',
  'diagnostics',
  'risk',
  'quality',
  'system',
  'components',
  'activity',
  'logs',
  'news',
  'recentNews',
  'breakingNews',
  'newsSentiment',
  'newsTimeline',
  'economicCalendar',
  'economicCalendarSources',
  'economicCalendarStatus',
  'economicCalendarHealth',
  'newsProviders',
  'newsStatus',
]

const resourceKeysForQuery = (key: DashboardQueryKey): DashboardResourceKey[] => {
  if (key === 'market') return ['quote', 'candles', 'indicators', 'marketStatus']
  if (key === 'system') return ['system', 'components']
  if (key === 'news') return ['news', 'recentNews', 'breakingNews', 'newsProviders', 'newsStatus']
  return [key]
}

export function DashboardRealtimeProvider({ children }: { children: ReactNode }) {
  const [resources, setResources] = useState<DashboardResources>(initialResources)
  const [connection, setConnection] = useState<ConnectionSnapshot>(initialConnection)
  const [activeSymbol, setActiveSymbolState] = useState<string | null>(null)
  const [timeframe, setTimeframe] = useState<Timeframe>('M15')
  const [candleLimit, setCandleLimitState] = useState(200)
  const [performanceFilters, setPerformanceFilters] = useState<PerformanceFilters>({ range: 'all' })
  const websocketRef = useRef<SharedWebSocketClient | null>(null)
  const calendarSymbolRef = useRef<string | null>(null)
  const refreshRef = useRef<(keys: DashboardResourceKey[]) => void>(() => undefined)
  const initialRefreshRef = useRef<(() => void) | null>(null)

  const commit = useCallback((key: DashboardResourceKey, response: ApiResponse<unknown>) => {
    setResources((current) => ({
      ...current,
      [key]: {
        data: response.data,
        meta: response.meta,
        status: 'success',
        error: null,
      },
    }))
  }, [])

  const fail = useCallback((key: DashboardResourceKey, reason: unknown) => {
    const error = reason instanceof ApiClientError
      ? reason
      : new ApiClientError('Data backend tidak dapat dimuat.', 'network')
    if (error.kind === 'aborted') return
    setResources((current) => ({
      ...current,
      [key]: {
        ...current[key],
        status: 'error',
        error,
      },
    }))
  }, [])

  const markLoading = useCallback((key: DashboardResourceKey) => {
    setResources((current) => ({
      ...current,
      [key]: {
        ...current[key],
        status: current[key].data === null ? 'loading' : current[key].status,
        error: null,
      },
    }))
  }, [])

  const load = useCallback(async (
    key: DashboardResourceKey,
    loader: () => Promise<ApiResponse<unknown>>,
    force = false,
  ) => {
    const cacheKey = key === 'performance'
      ? `${key}:${performanceFilters.range}:${performanceFilters.symbol ?? '*'}:${performanceFilters.strategy ?? '*'}`
      : ['quote', 'candles', 'indicators', 'marketStatus', 'economicCalendarGuard', 'economicCalendarDiagnostic', 'symbolNews', 'newsSentiment', 'newsTimeline'].includes(key)
        ? `${key}:${activeSymbol ?? '*'}:${timeframe}:${candleLimit}`
        : key
    if (!force) {
      const cached = queryCache.get<DashboardResources[typeof key]['data']>(cacheKey)
      if (cached) {
        commit(key, cached)
        return
      }
    }
    markLoading(key)
    try {
      const response = await loader()
      queryCache.set(cacheKey, response, staleTimes[key])
      commit(key, response)
    } catch (reason) {
      fail(key, reason)
    }
  }, [activeSymbol, candleLimit, commit, fail, markLoading, performanceFilters, timeframe])

  const refreshResource = useCallback(async (key: DashboardResourceKey, force = true) => {
    if (key === 'overview') return load(key, () => getOverview(), force)
    if (key === 'performance') return load(key, () => getPerformance(performanceFilters), force)
    if (key === 'symbols') return load(key, () => getMarketSymbols(), force)
    if (key === 'watchlist') return load(key, () => getWatchlist(), force)
    if (key === 'signals') return load(key, () => getSignals({ limit: 100, offset: 0 }), force)
    if (key === 'orders') return load(key, () => getOrders({ limit: 100, offset: 0 }), force)
    if (key === 'diagnostics') return load(key, () => getDiagnostics(), force)
    if (key === 'risk') return load(key, () => getRisk(), force)
    if (key === 'quality') return load(key, () => getQuality(), force)
    if (key === 'system') return load(key, () => getSystemStatus(), force)
    if (key === 'components') return load(key, () => getSystemComponents(), force)
    if (key === 'activity') return load(key, () => getActivity(50), force)
    if (key === 'logs') return load(key, () => getLogs({ limit: 100, offset: 0 }), force)
    if (key === 'news') return load(key, () => getLatestNews(60), force)
    if (key === 'recentNews') return load(key, () => getRecentNews(60), force)
    if (key === 'breakingNews') return load(key, () => getBreakingNews(20), force)
    if (key === 'newsSentiment') return load(key, () => getNewsSentiment('24h', activeSymbol), force)
    if (key === 'newsTimeline') return load(key, () => getNewsSentimentTimeline('24h', activeSymbol), force)
    if (key === 'economicCalendar') {
      const now = new Date()
      const start = new Date(now.getTime() - 24 * 60 * 60 * 1000)
      const end = new Date(now.getTime() + 366 * 24 * 60 * 60 * 1000)
      return load(key, () => getEconomicCalendar({ start_time: start.toISOString(), end_time: end.toISOString(), limit: 500, offset: 0 }), force)
    }
    if (key === 'economicCalendarSources') return load(key, () => getEconomicCalendarSources(), force)
    if (key === 'economicCalendarStatus') return load(key, () => getEconomicCalendarStatus(), force)
    if (key === 'economicCalendarHealth') return load(key, () => getEconomicCalendarHealth(), force)
    if (key === 'economicCalendarGuard') {
      if (!activeSymbol) return
      return load(key, () => getEconomicCalendarGuard(activeSymbol), force)
    }
    if (key === 'economicCalendarDiagnostic') {
      if (!activeSymbol) return
      return load(key, () => getEconomicCalendarDiagnostic(activeSymbol), force)
    }
    if (key === 'newsProviders') return load(key, () => getNewsProviders(), force)
    if (key === 'newsStatus') return load(key, () => getNewsStatus(), force)
    if (key === 'symbolNews') {
      if (!activeSymbol) return
      return load(key, () => getSymbolNewsSummary(activeSymbol), force)
    }
    if (!activeSymbol) return
    if (key === 'quote') return load(key, () => getMarketQuote(activeSymbol), force)
    if (key === 'candles') return load(key, () => getMarketCandles(activeSymbol, timeframe, candleLimit), force)
    if (key === 'indicators') return load(key, () => getMarketIndicators(activeSymbol, timeframe), force)
    return load(key, () => getMarketStatus(activeSymbol), force)
  }, [activeSymbol, candleLimit, load, performanceFilters, timeframe])

  const refreshMany = useCallback(async (keys: DashboardResourceKey[], force = true) => {
    await Promise.allSettled([...new Set(keys)].map((key) => refreshResource(key, force)))
  }, [refreshResource])

  useEffect(() => {
    refreshRef.current = (keys) => {
      void refreshMany(keys, true)
    }
  }, [refreshMany])

  const refreshAll = useCallback(async () => {
    queryCache.invalidate()
    const marketKeys: DashboardResourceKey[] = activeSymbol
      ? ['quote', 'candles', 'indicators', 'marketStatus']
      : []
    await refreshMany([...initialKeys, ...marketKeys], true)
  }, [activeSymbol, refreshMany])

  useEffect(() => {
    initialRefreshRef.current = () => {
      void refreshMany(initialKeys, false)
    }
  }, [refreshMany])

  useEffect(() => {
    initialRefreshRef.current?.()
  }, [])

  useEffect(() => {
    const symbols = resources.symbols.data ?? []
    if (activeSymbol || symbols.length === 0) return
    // Wait for overview to settle so its engine-selected active pair wins over
    // the alphabetically first market symbol. Fall back only when overview is
    // genuinely unavailable, not merely slower than the symbols request.
    if (resources.overview.status === 'idle' || resources.overview.status === 'loading') return
    const preferred = resources.overview.data?.status.active_pair
    const selected = preferred && symbols.includes(preferred) ? preferred : symbols[0] ?? null
    const timeout = globalThis.setTimeout(() => setActiveSymbolState(selected), 0)
    return () => globalThis.clearTimeout(timeout)
  }, [activeSymbol, resources.overview.data, resources.overview.status, resources.symbols.data])

  useEffect(() => {
    if (!activeSymbol) return
    websocketRef.current?.setMarketSymbol(activeSymbol)
    queryCache.invalidate('quote')
    queryCache.invalidate('candles')
    queryCache.invalidate('indicators')
    queryCache.invalidate('marketStatus')
    queryCache.invalidate('symbolNews')
    queryCache.invalidate('newsSentiment')
    queryCache.invalidate('newsTimeline')
    queryCache.invalidate('economicCalendarGuard')
    queryCache.invalidate('economicCalendarDiagnostic')
    const symbolChanged = calendarSymbolRef.current !== activeSymbol
    calendarSymbolRef.current = activeSymbol
    const resetTimeout = symbolChanged
      ? globalThis.setTimeout(() => {
        setResources((current) => ({
          ...current,
          economicCalendarGuard: emptyResource(),
          economicCalendarDiagnostic: emptyResource(),
        }))
      }, 0)
      : null
    void refreshMany(['quote', 'candles', 'indicators', 'marketStatus', 'symbolNews', 'newsSentiment', 'newsTimeline', 'economicCalendarGuard', 'economicCalendarDiagnostic'], true)
    return () => {
      if (resetTimeout !== null) globalThis.clearTimeout(resetTimeout)
    }
  }, [activeSymbol, candleLimit, refreshMany, timeframe])

  useEffect(() => {
    const timeout = globalThis.setTimeout(() => {
      queryCache.invalidate('performance')
      void refreshResource('performance', true)
    }, 0)
    return () => globalThis.clearTimeout(timeout)
  }, [performanceFilters, refreshResource])

  useEffect(() => {
    const client = new SharedWebSocketClient({
      onConnectionChange: setConnection,
      onEvent: (event) => {
        if (calendarMutationEvents.has(event.type)) {
          markCalendarEventReceived(event)
          setResources((current) => ({
            ...current,
            economicCalendar: {
              ...current.economicCalendar,
              data: mergeEconomicCalendarEvent(current.economicCalendar.data, event),
              status: 'success',
            },
          }))
          if (event.type !== 'calendar.event.countdown') {
            refreshRef.current(['economicCalendarGuard', 'economicCalendarDiagnostic'])
          }
          return
        }
        const keys = queriesForEvent[event.type].flatMap(resourceKeysForQuery)
        if (keys.length > 0) refreshRef.current(keys)
      },
    })
    websocketRef.current = client
    client.start()
    return () => {
      websocketRef.current = null
      client.stop()
    }
  }, [])

  useEffect(() => {
    const fast = globalThis.setInterval(() => {
      if (document.visibilityState !== 'visible') return
      void refreshMany(['overview', 'quote', 'marketStatus', 'watchlist', 'signals', 'orders', 'activity'], false)
    }, 10_000)
    const medium = globalThis.setInterval(() => {
      if (document.visibilityState !== 'visible') return
      void refreshMany(['diagnostics', 'risk', 'system', 'components', 'candles', 'indicators', 'newsStatus', 'economicCalendarStatus', 'economicCalendarHealth', 'economicCalendarGuard', 'economicCalendarDiagnostic'], false)
    }, 30_000)
    const slow = globalThis.setInterval(() => {
      if (document.visibilityState !== 'visible') return
      void refreshMany(['quality', 'performance', 'news', 'recentNews', 'breakingNews', 'newsSentiment', 'newsTimeline', 'economicCalendar', 'economicCalendarSources', 'newsProviders', 'symbolNews'], false)
    }, 120_000)
    return () => {
      globalThis.clearInterval(fast)
      globalThis.clearInterval(medium)
      globalThis.clearInterval(slow)
    }
  }, [refreshMany])

  const setActiveSymbol = useCallback((symbol: string) => {
    const normalized = symbol.trim().toUpperCase()
    if (!isValidMarketSymbol(normalized) || !resources.symbols.data?.includes(normalized)) return
    setActiveSymbolState(normalized)
  }, [resources.symbols.data])

  const setCandleLimit = useCallback((limit: number) => {
    setCandleLimitState(Math.max(20, Math.min(500, Math.round(limit))))
  }, [])

  const loadLogs = useCallback(async (filters: LogFilters) => {
    markLoading('logs')
    try {
      const response = await getLogs({ ...filters, limit: Math.min(filters.limit ?? 100, 200) })
      commit('logs', response)
    } catch (reason) {
      fail('logs', reason)
    }
  }, [commit, fail, markLoading])

  const safetyState = useMemo(() => {
    const overview = resources.overview.data
    const risk = resources.risk.data
    const quality = resources.quality.data
    const system = resources.system.data
    const violations: string[] = []
    if (overview?.status.live_allowed) violations.push('Overview melaporkan live_allowed=true.')
    if (risk?.live_allowed) violations.push('Risk API melaporkan live_allowed=true.')
    if (system?.live_allowed) violations.push('System API melaporkan live_allowed=true.')
    if (quality?.safe_to_live_trade) violations.push('Quality API melaporkan safe_to_live_trade=true.')
    if (risk && risk.effective_max_lot > 0.01) violations.push('Effective max lot melebihi 0.01.')
    return { anomaly: violations.length > 0, message: violations.join(' ') || null }
  }, [resources.overview.data, resources.quality.data, resources.risk.data, resources.system.data])

  const lastSuccessfulUpdate = useMemo(
    () => newestTimestamp(Object.values(resources).map((resource) => resource.meta)),
    [resources],
  )

  const value = useMemo(() => ({
    resources,
    connection,
    activeSymbol,
    timeframe,
    candleLimit,
    performanceFilters,
    safetyAnomaly: safetyState.anomaly,
    safetyMessage: safetyState.message,
    lastSuccessfulUpdate,
    setActiveSymbol,
    setTimeframe,
    setCandleLimit,
    setPerformanceFilters,
    refreshAll,
    refreshResource: (key: DashboardResourceKey) => refreshResource(key, true),
    loadLogs,
  }), [
    activeSymbol,
    candleLimit,
    connection,
    lastSuccessfulUpdate,
    loadLogs,
    performanceFilters,
    refreshAll,
    refreshResource,
    resources,
    safetyState,
    setActiveSymbol,
    setCandleLimit,
    timeframe,
  ])

  return <DashboardRealtimeContext.Provider value={value}>{children}</DashboardRealtimeContext.Provider>
}
