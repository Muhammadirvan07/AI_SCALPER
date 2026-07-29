import { ChevronsLeft, ChevronsRight, LockKeyhole, X } from 'lucide-react'
import { NavLink } from '../../routing/Router'
import { appNavigation } from './appNavigation'

interface AppSidebarProps {
  collapsed: boolean
  mobileOpen: boolean
  onToggleCollapsed: () => void
  onCloseMobile: () => void
}

export function AppSidebar({
  collapsed,
  mobileOpen,
  onToggleCollapsed,
  onCloseMobile,
}: AppSidebarProps) {
  return (
    <>
      <button
        type="button"
        className={`app-sidebar__scrim ${mobileOpen ? 'is-visible' : ''}`}
        aria-label="Tutup navigasi"
        onClick={onCloseMobile}
        tabIndex={mobileOpen ? 0 : -1}
      />
      <aside
        id="app-sidebar"
        className={`app-sidebar ${collapsed ? 'is-collapsed' : ''} ${mobileOpen ? 'is-mobile-open' : ''}`}
        aria-label="Navigasi utama AI_SCALPER"
      >
        <div className="app-sidebar__brand-row">
          <NavLink to="/overview" className="app-sidebar__brand" aria-label="AI_SCALPER Overview" onClick={onCloseMobile}>
            <span className="app-sidebar__brand-mark" aria-hidden="true">AS</span>
            <span className="app-sidebar__brand-copy">
              <strong>AI_SCALPER</strong>
              <small>INTELLIGENCE</small>
            </span>
          </NavLink>
          <button
            type="button"
            className="app-icon-button app-sidebar__mobile-close"
            aria-label="Tutup sidebar"
            onClick={onCloseMobile}
          >
            <X aria-hidden="true" className="size-4" />
          </button>
        </div>

        <nav className="app-sidebar__nav" aria-label="Modul dashboard">
          {appNavigation.map((section) => (
            <div key={section.label} className="app-sidebar__section">
              <p>{section.label}</p>
              <div>
                {section.items.map((item) => {
                  const Icon = item.icon
                  return (
                    <NavLink
                      key={item.to}
                      to={item.to}
                      title={collapsed ? item.label : undefined}
                      className={({ isActive }) =>
                        `app-sidebar__link ${isActive ? 'is-active' : ''}`
                      }
                      onClick={onCloseMobile}
                    >
                      <Icon aria-hidden="true" className="size-[1.1rem]" />
                      <span>{item.label}</span>
                    </NavLink>
                  )
                })}
              </div>
            </div>
          ))}
        </nav>

        <div className="app-sidebar__safety">
          <LockKeyhole aria-hidden="true" className="size-4" />
          <span>
            <strong>LIVE LOCKED</strong>
            <small>Paper environment</small>
          </span>
        </div>

        <button
          type="button"
          className="app-sidebar__collapse"
          onClick={onToggleCollapsed}
          aria-label={collapsed ? 'Perluas sidebar' : 'Ciutkan sidebar'}
          aria-expanded={!collapsed}
        >
          {collapsed ? (
            <ChevronsRight aria-hidden="true" className="size-4" />
          ) : (
            <ChevronsLeft aria-hidden="true" className="size-4" />
          )}
          <span>{collapsed ? 'Buka' : 'Ciutkan sidebar'}</span>
        </button>
      </aside>
    </>
  )
}
