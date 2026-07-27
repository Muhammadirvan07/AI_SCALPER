const positiveFiniteNumber = (value: string | undefined, fallback: number) => {
  const parsed = Number(value)
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback
}

export const dashboardDataConfig = {
  // Alias lama dipertahankan untuk adapter mock development yang tidak lagi dipakai provider realtime.
  mode: 'api' as DashboardDataMode,
  apiBase: '/api/dashboard',
  aiScalperApiBaseUrl:
    import.meta.env.VITE_AI_SCALPER_API_BASE_URL ?? 'http://127.0.0.1:8000',
  apiBaseUrl:
    import.meta.env.VITE_AI_SCALPER_API_BASE_URL ?? 'http://127.0.0.1:8000',
  websocketUrl:
    import.meta.env.VITE_AI_SCALPER_WS_URL ?? 'ws://127.0.0.1:8000/ws/v1/dashboard',
  useMockFallback:
    import.meta.env.DEV &&
    (import.meta.env.VITE_AI_SCALPER_USE_MOCK_FALLBACK ?? 'false').toLowerCase() === 'true',
  staleAfterMs: positiveFiniteNumber(
    import.meta.env.VITE_AI_SCALPER_STALE_AFTER_MS,
    180_000,
  ),
  restPollingIntervalMs: 5_000,
  refreshIntervalMs: 4_000,
  sourceFiles: {
    offlineReport: 'offline_dashboard_report.json',
    signals: 'trade_signals.json',
    mt5Signals: 'mt5_trade_signals.json',
    paperOrders: 'paper_orders.json',
    decisionHealth: 'decision_health_snapshot.json',
    sessionTracker: 'paper_forward_session_tracker.json',
    qualityRules: 'paper_quality_rules.json',
    activePairs: 'active_pairs.json',
    replayCandidates: 'paper_replay_candidates.json',
    marketNews: 'market_news.json',
  },
} as const

export type DashboardDataMode = 'mock' | 'api'
