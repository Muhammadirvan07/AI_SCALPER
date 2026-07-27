import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import App from './App'
import { DashboardRealtimeProvider } from './context/DashboardRealtimeProvider'
import { RouterProvider } from './routing/Router'
import { AppErrorBoundary } from './components/ui/AppErrorBoundary'
import './index.css'
import './styles/terminal.css'
import './styles/futuristic.css'

const hashRoute = window.location.hash.replace(/^#\/?/, '')
if (
  ['overview', 'analytics', 'markets', 'news', 'signals', 'system-health'].includes(
    hashRoute,
  )
) {
  window.history.replaceState(null, '', `/${hashRoute}`)
}

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <AppErrorBoundary>
      <RouterProvider>
        <DashboardRealtimeProvider>
          <App />
        </DashboardRealtimeProvider>
      </RouterProvider>
    </AppErrorBoundary>
  </StrictMode>,
)
