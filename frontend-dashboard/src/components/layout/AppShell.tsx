import { useEffect, useState, type ReactNode } from 'react'
import type { OverviewData } from '../../api/types'
import type { ConnectionSnapshot } from '../../realtime/websocketTypes'
import { AppSidebar } from './AppSidebar'
import { AppTopbar } from './AppTopbar'

interface AppShellProps {
  pathname: string
  overview: OverviewData | null
  connection: ConnectionSnapshot
  onRefresh: () => Promise<void> | void
  children: ReactNode
}

export function AppShell({
  pathname,
  overview,
  connection,
  onRefresh,
  children,
}: AppShellProps) {
  const [collapsed, setCollapsed] = useState(false)
  const [mobileOpen, setMobileOpen] = useState(false)

  useEffect(() => {
    if (!mobileOpen) return
    const closeOnEscape = (event: KeyboardEvent) => {
      if (event.key === 'Escape') setMobileOpen(false)
    }
    document.addEventListener('keydown', closeOnEscape)
    return () => document.removeEventListener('keydown', closeOnEscape)
  }, [mobileOpen])

  return (
    <div className={`quant-app app-shell ${collapsed ? 'app-shell--collapsed' : ''}`}>
      <a href="#main-content" className="skip-link">Lewati ke konten utama</a>
      <AppSidebar
        collapsed={collapsed}
        mobileOpen={mobileOpen}
        onToggleCollapsed={() => setCollapsed((value) => !value)}
        onCloseMobile={() => setMobileOpen(false)}
      />
      <div className="app-shell__workspace">
        <AppTopbar
          pathname={pathname}
          overview={overview}
          connection={connection}
          onRefresh={onRefresh}
          onOpenMobileNavigation={() => setMobileOpen(true)}
        />
        <div className="app-shell__content">{children}</div>
      </div>
    </div>
  )
}
