import { lazy, Suspense } from 'react'
import { ReconnectNotice } from './components/common/ReconnectNotice'
import { SafetyBanner } from './components/domain/SafetyBanner'
import { AppShell } from './components/layout/AppShell'
import { ScrollToTop } from './components/layout/ScrollToTop'
import { Panel } from './components/ui/Panel'
import { PanelErrorBoundary } from './components/ui/PanelErrorBoundary'
import { PanelState } from './components/ui/PanelState'
import { useRealtimeDashboard } from './hooks/useRealtimeDashboard'
import { useLocation } from './routing/routerContext'

const LandingPage = lazy(() =>
  import('./pages/LandingPage').then((module) => ({ default: module.LandingPage })),
)
const QuantTerminalPage = lazy(() =>
  import('./pages/QuantTerminalPage').then((module) => ({ default: module.QuantTerminalPage })),
)
const AnalyticsPage = lazy(() =>
  import('./pages/AnalyticsPage').then((module) => ({ default: module.AnalyticsPage })),
)
const MarketsPage = lazy(() =>
  import('./pages/MarketsPage').then((module) => ({ default: module.MarketsPage })),
)
const NewsPage = lazy(() =>
  import('./pages/NewsPage').then((module) => ({ default: module.NewsPage })),
)
const EconomicCalendarPage = lazy(() =>
  import('./pages/EconomicCalendarPage').then((module) => ({ default: module.EconomicCalendarPage })),
)
const SignalsPage = lazy(() =>
  import('./pages/SignalsPage').then((module) => ({ default: module.SignalsPage })),
)
const SystemHealthPage = lazy(() =>
  import('./pages/SystemHealthPage').then((module) => ({ default: module.SystemHealthPage })),
)
const PaperOrdersPage = lazy(() =>
  import('./pages/PaperOrdersPage').then((module) => ({ default: module.PaperOrdersPage })),
)
const PerformancePage = lazy(() =>
  import('./pages/PerformancePage').then((module) => ({ default: module.PerformancePage })),
)
const StrategyPage = lazy(() =>
  import('./pages/StrategyPage').then((module) => ({ default: module.StrategyPage })),
)
const AIDiagnosticsPage = lazy(() =>
  import('./pages/AIDiagnosticsPage').then((module) => ({ default: module.AIDiagnosticsPage })),
)
const RiskManagementPage = lazy(() =>
  import('./pages/RiskManagementPage').then((module) => ({ default: module.RiskManagementPage })),
)
const SystemLogsPage = lazy(() =>
  import('./pages/SystemLogsPage').then((module) => ({ default: module.SystemLogsPage })),
)
const SettingsPage = lazy(() =>
  import('./pages/SettingsPage').then((module) => ({ default: module.SettingsPage })),
)
const NotFoundPage = lazy(() =>
  import('./pages/NotFoundPage').then((module) => ({ default: module.NotFoundPage })),
)

function RouteLoadingState() {
  return (
    <main id="main-content" className="quant-terminal min-h-[70vh] py-3">
      <div className="qt-container">
      <Panel className="p-4 sm:p-6">
        <PanelState state="loading" />
      </Panel>
      </div>
    </main>
  )
}

function App() {
  const realtime = useRealtimeDashboard()
  const { pathname } = useLocation()
  const routeContent = (() => {
    if (pathname === '/') return <LandingPage />
    if (pathname === '/overview') return <QuantTerminalPage />
    if (pathname === '/analytics') return <AnalyticsPage />
    if (pathname === '/markets') return <MarketsPage />
    if (pathname === '/news') return <NewsPage />
    if (pathname === '/economic-calendar') return <EconomicCalendarPage />
    if (pathname === '/signals') return <SignalsPage />
    if (pathname === '/system-health') return <SystemHealthPage />
    if (pathname === '/paper-orders') return <PaperOrdersPage />
    if (pathname === '/performance') return <PerformancePage />
    if (pathname === '/strategy') return <StrategyPage />
    if (pathname === '/ai-diagnostics') return <AIDiagnosticsPage />
    if (pathname === '/risk-management') return <RiskManagementPage />
    if (pathname === '/system-logs') return <SystemLogsPage />
    if (pathname === '/settings') return <SettingsPage />
    return <NotFoundPage />
  })()

  return (
    <AppShell
      pathname={pathname}
      overview={realtime.resources.overview.data}
      connection={realtime.connection}
      onRefresh={realtime.refreshAll}
    >
      <ScrollToTop />
      <ReconnectNotice connection={realtime.connection} />
      <SafetyBanner />

      <Suspense fallback={<RouteLoadingState />}>
        <PanelErrorBoundary key={pathname}>{routeContent}</PanelErrorBoundary>
      </Suspense>

    </AppShell>
  )
}

export default App
