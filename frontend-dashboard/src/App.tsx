import { lazy, Suspense, useCallback } from 'react'
import { ReconnectNotice } from './components/common/ReconnectNotice'
import { ScrollToTop } from './components/layout/ScrollToTop'
import { QuantHeader } from './components/terminal/QuantHeader'
import { TerminalFooter } from './components/terminal/TerminalFooter'
import { Panel } from './components/ui/Panel'
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
const SignalsPage = lazy(() =>
  import('./pages/SignalsPage').then((module) => ({ default: module.SignalsPage })),
)
const SystemHealthPage = lazy(() =>
  import('./pages/SystemHealthPage').then((module) => ({ default: module.SystemHealthPage })),
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
  const refreshDashboard = realtime.refresh
  const { pathname } = useLocation()
  const data = realtime.dashboard
  const staticSnapshot = realtime.dashboard
  const handleRefresh = useCallback(() => {
    void refreshDashboard()
  }, [refreshDashboard])
  const pageProps = {
    data,
    staticSnapshot,
    status: realtime.dataStatus,
    error: realtime.error,
    lastSuccessfulUpdate: realtime.lastSuccessfulUpdate,
    onRefresh: handleRefresh,
  }
  const routeContent = (() => {
    if (pathname === '/') {
      return (
        <LandingPage
          snapshot={realtime.apiSnapshot}
          connection={realtime.connection}
          status={realtime.dataStatus}
          error={realtime.error}
          lastSuccessfulUpdate={realtime.lastSuccessfulUpdate}
          onRefresh={handleRefresh}
        />
      )
    }
    if (pathname === '/overview') {
      return (
        <QuantTerminalPage
          data={realtime.terminal}
          state={realtime.panelState}
          error={realtime.error}
          isPaused={realtime.isPaused}
          onRetry={handleRefresh}
        />
      )
    }
    if (pathname === '/analytics') return <AnalyticsPage {...pageProps} />
    if (pathname === '/markets') return <MarketsPage {...pageProps} />
    if (pathname === '/news') return <NewsPage {...pageProps} />
    if (pathname === '/signals') return <SignalsPage {...pageProps} />
    if (pathname === '/system-health') return <SystemHealthPage {...pageProps} />
    return <NotFoundPage />
  })()

  return (
    <div className="quant-app overflow-x-hidden">
      <ScrollToTop />
      <QuantHeader
        data={realtime.terminal}
        state={realtime.panelState}
        isPaused={realtime.isPaused}
        onTogglePause={realtime.togglePause}
        connection={realtime.connection}
      />
      <ReconnectNotice connection={realtime.connection} />

      <Suspense fallback={<RouteLoadingState />}>
        {routeContent}
      </Suspense>

      <TerminalFooter data={realtime.terminal} connection={realtime.connection} />
    </div>
  )
}

export default App
