import { createContext } from 'react'
import type { LogFilters } from '../api/logs'
import type { PerformanceFilters } from '../api/performance'
import type {
  ActivityEvent,
  ApiMeta,
  CandleSeries,
  DiagnosticsData,
  LogEntry,
  MarketIndicators,
  MarketQuote,
  MarketStatus,
  OverviewData,
  Page,
  PaperOrder,
  PerformanceData,
  QualityData,
  ResourceState,
  RiskData,
  SystemComponent,
  SystemStatusData,
  Timeframe,
  TradingSignal,
  WatchlistItem,
} from '../api/types'
import type { ConnectionSnapshot } from '../realtime/websocketTypes'
import type { NewsPage, NewsProviderStatus, NewsSentimentAggregate, NewsSentimentTimeline, NewsStatus, SymbolNewsSummary } from '../types/news'
import type { EconomicCalendarDiagnosticContext, EconomicCalendarGuardPreview, EconomicCalendarHealth, EconomicCalendarPage, EconomicCalendarRuntimeStatus, EconomicCalendarSourceStatus } from '../types/economicCalendar'

export interface DashboardResources {
  overview: ResourceState<OverviewData>
  performance: ResourceState<PerformanceData>
  symbols: ResourceState<string[]>
  quote: ResourceState<MarketQuote>
  candles: ResourceState<CandleSeries>
  indicators: ResourceState<MarketIndicators>
  marketStatus: ResourceState<MarketStatus>
  watchlist: ResourceState<WatchlistItem[]>
  signals: ResourceState<Page<TradingSignal>>
  orders: ResourceState<Page<PaperOrder>>
  diagnostics: ResourceState<DiagnosticsData>
  risk: ResourceState<RiskData>
  quality: ResourceState<QualityData>
  system: ResourceState<SystemStatusData>
  components: ResourceState<SystemComponent[]>
  activity: ResourceState<ActivityEvent[]>
  logs: ResourceState<Page<LogEntry>>
  news: ResourceState<NewsPage>
  recentNews: ResourceState<NewsPage>
  breakingNews: ResourceState<NewsPage>
  newsSentiment: ResourceState<NewsSentimentAggregate>
  newsTimeline: ResourceState<NewsSentimentTimeline>
  economicCalendar: ResourceState<EconomicCalendarPage>
  economicCalendarSources: ResourceState<EconomicCalendarSourceStatus[]>
  economicCalendarStatus: ResourceState<EconomicCalendarRuntimeStatus>
  economicCalendarHealth: ResourceState<EconomicCalendarHealth>
  economicCalendarGuard: ResourceState<EconomicCalendarGuardPreview>
  economicCalendarDiagnostic: ResourceState<EconomicCalendarDiagnosticContext>
  newsProviders: ResourceState<NewsProviderStatus[]>
  newsStatus: ResourceState<NewsStatus>
  symbolNews: ResourceState<SymbolNewsSummary>
}

export type DashboardResourceKey = keyof DashboardResources

export interface DashboardRealtimeContextValue {
  resources: DashboardResources
  connection: ConnectionSnapshot
  activeSymbol: string | null
  timeframe: Timeframe
  candleLimit: number
  performanceFilters: PerformanceFilters
  safetyAnomaly: boolean
  safetyMessage: string | null
  lastSuccessfulUpdate: string | null
  setActiveSymbol: (symbol: string) => void
  setTimeframe: (timeframe: Timeframe) => void
  setCandleLimit: (limit: number) => void
  setPerformanceFilters: (filters: PerformanceFilters) => void
  refreshAll: () => Promise<void>
  refreshResource: (key: DashboardResourceKey) => Promise<void>
  loadLogs: (filters: LogFilters) => Promise<void>
}

export const emptyResource = <T>(): ResourceState<T> => ({
  data: null,
  meta: null,
  status: 'idle',
  error: null,
})

export const initialResources = (): DashboardResources => ({
  overview: emptyResource(),
  performance: emptyResource(),
  symbols: emptyResource(),
  quote: emptyResource(),
  candles: emptyResource(),
  indicators: emptyResource(),
  marketStatus: emptyResource(),
  watchlist: emptyResource(),
  signals: emptyResource(),
  orders: emptyResource(),
  diagnostics: emptyResource(),
  risk: emptyResource(),
  quality: emptyResource(),
  system: emptyResource(),
  components: emptyResource(),
  activity: emptyResource(),
  logs: emptyResource(),
  news: emptyResource(),
  recentNews: emptyResource(),
  breakingNews: emptyResource(),
  newsSentiment: emptyResource(),
  newsTimeline: emptyResource(),
  economicCalendar: emptyResource(),
  economicCalendarSources: emptyResource(),
  economicCalendarStatus: emptyResource(),
  economicCalendarHealth: emptyResource(),
  economicCalendarGuard: emptyResource(),
  economicCalendarDiagnostic: emptyResource(),
  newsProviders: emptyResource(),
  newsStatus: emptyResource(),
  symbolNews: emptyResource(),
})

export const newestTimestamp = (metas: Array<ApiMeta | null>): string | null => {
  const timestamps = metas
    .map((meta) => meta?.server_timestamp ?? null)
    .filter((value): value is string => typeof value === 'string' && !Number.isNaN(Date.parse(value)))
  return timestamps.sort((left, right) => Date.parse(right) - Date.parse(left))[0] ?? null
}

export const DashboardRealtimeContext = createContext<DashboardRealtimeContextValue | null>(null)
