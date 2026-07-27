import { Activity, Menu, Radar, ShieldCheck, Wifi, WifiOff, X } from 'lucide-react'
import { useEffect, useState } from 'react'
import { Link, NavLink } from '../../routing/Router'
import type { DataStatus } from '../../types/dashboard'
import { StatusBadge } from '../dashboard/StatusBadge'

const navigation = [
  { label: 'Ringkasan', to: '/overview' },
  { label: 'Analitik', to: '/analytics' },
  { label: 'Pasar', to: '/markets' },
  { label: 'Berita', to: '/news' },
  { label: 'Sinyal', to: '/signals' },
  { label: 'Kesehatan Sistem', to: '/system-health' },
]

interface NavbarProps {
  dataStatus: DataStatus
}

export function Navbar({ dataStatus }: NavbarProps) {
  const [menuOpen, setMenuOpen] = useState(false)
  const connected = !['disconnected', 'error'].includes(dataStatus)

  useEffect(() => {
    const handleEscape = (event: KeyboardEvent) => {
      if (event.key === 'Escape') setMenuOpen(false)
    }
    document.addEventListener('keydown', handleEscape)
    return () => document.removeEventListener('keydown', handleEscape)
  }, [])

  return (
    <header className="sticky top-0 z-50 border-b border-white/[0.06] bg-[#050b17]/85 backdrop-blur-xl">
      <a href="#main-content" className="skip-link">
        Lewati ke dashboard
      </a>
      <div className="page-container flex h-16 items-center justify-between gap-5">
        <Link to="/" className="focus-ring flex min-w-0 items-center gap-3 rounded-lg">
          <span className="relative grid size-9 shrink-0 place-items-center rounded-xl border border-cyan-300/25 bg-cyan-300/10 text-cyan-200">
            <Radar aria-hidden="true" className="size-5" />
            <span className="absolute inset-0 rounded-xl border border-cyan-300/20 motion-safe:animate-radar-ping" />
          </span>
          <span className="min-w-0">
            <span className="block truncate text-sm font-semibold tracking-[0.12em] text-white">
              AI_SCALPER
            </span>
            <span className="hidden text-[0.65rem] tracking-[0.18em] text-slate-500 uppercase sm:block">
              Konsol intelijen
            </span>
          </span>
        </Link>

        <nav aria-label="Navigasi utama" className="hidden items-center gap-1 xl:flex">
          {navigation.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              className={({ isActive }) => `nav-link ${isActive ? 'nav-link-active' : ''}`}
            >
              {item.label}
            </NavLink>
          ))}
        </nav>

        <div className="ml-auto hidden items-center gap-3 sm:flex">
          <div
            className={`flex items-center gap-2 text-xs font-medium ${
              connected ? 'text-emerald-300' : 'text-red-300'
            }`}
            aria-live="polite"
          >
            {connected ? (
              <Wifi aria-hidden="true" className="size-4" />
            ) : (
              <WifiOff aria-hidden="true" className="size-4" />
            )}
            {dataStatus === 'loading' ? 'Menghubungkan' : connected ? 'Monitor terhubung' : 'Offline'}
          </div>
          <StatusBadge label="KHUSUS PAPER" tone="info" />
          <ShieldCheck aria-label="Kunci keselamatan aktif" className="size-4 text-red-300" />
        </div>

        <button
          type="button"
          className="icon-button xl:hidden"
          aria-label={menuOpen ? 'Tutup menu navigasi' : 'Buka menu navigasi'}
          aria-expanded={menuOpen}
          aria-controls="mobile-navigation"
          onClick={() => setMenuOpen((open) => !open)}
        >
          {menuOpen ? <X aria-hidden="true" /> : <Menu aria-hidden="true" />}
        </button>
      </div>

      <div
        id="mobile-navigation"
        className={`border-t border-white/[0.06] bg-[#07101f]/95 xl:hidden ${
          menuOpen ? 'block' : 'hidden'
        }`}
      >
        <nav aria-label="Navigasi seluler" className="page-container py-3">
          <div className="grid gap-1 sm:grid-cols-3">
            {navigation.map((item) => (
              <NavLink
                key={item.to}
                to={item.to}
                className={({ isActive }) =>
                  `nav-link justify-start ${isActive ? 'nav-link-active' : ''}`
                }
                onClick={() => setMenuOpen(false)}
              >
                <Activity aria-hidden="true" className="size-3.5" />
                {item.label}
              </NavLink>
            ))}
          </div>
          <div className="mt-3 flex items-center justify-between border-t border-white/[0.06] pt-3 sm:hidden">
            <span className={connected ? 'text-xs text-emerald-300' : 'text-xs text-red-300'}>
              {connected ? 'Monitor terhubung' : 'Sumber offline'}
            </span>
            <StatusBadge label="KHUSUS PAPER" tone="info" />
          </div>
        </nav>
      </div>
    </header>
  )
}
