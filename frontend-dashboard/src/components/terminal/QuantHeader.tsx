import { useEffect, useState } from 'react'
import { CalendarDays, Pause, Play, RadioTower, ShieldCheck } from 'lucide-react'
import { Link, NavLink } from '../../routing/Router'
import type { RealtimeConnectionInfo } from '../../types/dashboardApi'
import type { TerminalDashboardData, TerminalPanelState } from '../../types/terminal'
import { formatTime } from '../../utils/formatters'
import { formatStatusLabel } from '../../utils/statusHelpers'
import { MarketTickerStrip } from './MarketTickerStrip'
import { StatusDot } from './common/StatusDot'
import { TerminalStatusBadge } from './common/TerminalStatusBadge'
import { ConnectionStatus } from '../common/ConnectionStatus'

const routes = [
  { label: 'Ringkasan', to: '/overview' },
  { label: 'Analitik', to: '/analytics' },
  { label: 'Pasar', to: '/markets' },
  { label: 'Berita', to: '/news' },
  { label: 'Sinyal', to: '/signals' },
  { label: 'Kesehatan Sistem', to: '/system-health' },
]

const jstClockFormatter = new Intl.DateTimeFormat('id-ID', {
  timeZone: 'Asia/Tokyo',
  hour: '2-digit',
  minute: '2-digit',
  second: '2-digit',
  hour12: false,
})
const jstCalendarFormatter = new Intl.DateTimeFormat('id-ID', {
  timeZone: 'Asia/Tokyo',
  weekday: 'short',
  day: '2-digit',
  month: 'short',
  year: 'numeric',
})

interface QuantHeaderProps {
  data: TerminalDashboardData | null
  state: TerminalPanelState
  isPaused: boolean
  onTogglePause: () => void
  connection: RealtimeConnectionInfo
}

export function QuantHeader({
  data,
  state,
  isPaused,
  onTogglePause,
  connection,
}: QuantHeaderProps) {
  const [localClock, setLocalClock] = useState(() => new Date())
  useEffect(() => {
    const timer = window.setInterval(() => setLocalClock(new Date()), 1_000)
    return () => window.clearInterval(timer)
  }, [])

  const mockMode = connection.sourceMode === 'MOCK FALLBACK'
  const connected =
    data !== null &&
    !mockMode &&
    state !== 'loading' &&
    state !== 'disconnected' &&
    state !== 'error'
  const observedLabel = mockMode
    ? 'DATA MOCK'
    : connected
      ? 'PAPER TERAMATI'
      : 'PAPER TIDAK TERAMATI'
  const jstClock = jstClockFormatter.format(localClock)
  const jstCalendar = jstCalendarFormatter
    .format(localClock)
    .replaceAll('.', '')
    .toUpperCase()

  return (
    <header className="qt-header">
      <a href="#main-content" className="skip-link">
        Lewati ke terminal
      </a>
      <div className="qt-container">
        <div className="qt-header__main">
          <Link to="/" className="qt-header__brand">
            <span className="qt-header__mark" aria-hidden="true">
              AS
            </span>
            <span>
              <strong>AI_SCALPER <em>// QUANT</em></strong>
              <small>
                <span className="qt-header__subtitle-text">
                  {data?.summary.subtitle ?? 'DASHBOARD HANYA-BACA · DATA BELUM TERSEDIA'}
                </span>
                <span className="qt-header__mobile-safety">
                  <span>{observedLabel}</span> · TRADING LIVE TERKUNCI (LOCKED)
                </span>
              </small>
            </span>
          </Link>

          <dl className="qt-header__telemetry">
            <div><dt>SESI</dt><dd>{data?.runtime.currentSession ?? '—'}</dd></div>
            <div><dt>PAIR</dt><dd>{data?.runtime.activePair ?? '—'}</dd></div>
            <div><dt>PASAR</dt><dd>{data ? formatStatusLabel(data.runtime.marketStatus) : '—'}</dd></div>
            <div><dt>KESEGARAN</dt><dd>{data ? formatStatusLabel(data.runtime.dataFreshness) : '—'}</dd></div>
            <div><dt>STRATEGI</dt><dd>{data?.runtime.currentStrategy ?? '—'}</dd></div>
            <div><dt>SAMPEL</dt><dd>{data?.runtime.sampleProgress ?? '—'}</dd></div>
          </dl>

          <div className="qt-header__status">
            <div>
              <StatusDot
                tone={connected ? 'positive' : mockMode ? 'caution' : 'blocked'}
                label={observedLabel}
                pulse={connected && !isPaused}
              />
              <StatusDot
                tone={connected ? 'safe' : 'blocked'}
                label={connected ? 'DATA DARING' : 'DATA LURING'}
              />
              <ConnectionStatus connection={connection} compact />
            </div>
            <div className="qt-header__runtime">
              <span>LAT {data ? `${data.runtime.pollingLatencyMs} MS` : '—'}</span>
              <span>SINKRON {data ? formatTime(data.runtime.lastSyncTime) : '—'}</span>
              <span>
                EVENT {connection.lastEventAt ? formatTime(connection.lastEventAt) : '—'}
              </span>
              <span>
                SUMBER {connection.lastSourceUpdateAt ? formatTime(connection.lastSourceUpdateAt) : '—'}
              </span>
              <span>SNAPSHOT V{connection.snapshotVersion}</span>
              <span>STALE {connection.staleSourceCount}</span>
              <strong>{jstClock} JST</strong>
              <span>{data ? `V${data.summary.systemVersion}` : 'VERSI —'}</span>
            </div>
            <button
              type="button"
              className={`qt-button ${isPaused ? 'qt-button--active' : ''}`}
              onClick={onTogglePause}
              aria-pressed={isPaused}
              title="Hanya menjeda penerapan pembaruan pada UI. Watcher backend dan engine tidak dihentikan."
            >
              {isPaused ? <Play aria-hidden="true" className="size-3.5" /> : <Pause aria-hidden="true" className="size-3.5" />}
              <span className="qt-header__pause-label">
                {isPaused ? 'Lanjutkan tampilan' : 'Jeda pembaruan tampilan'}
              </span>
            </button>
          </div>
        </div>

        <div className="qt-header__nav-row">
          <nav aria-label="Navigasi terminal quant" className="qt-header__nav">
            {routes.map((route) => (
              <NavLink
                key={route.to}
                to={route.to}
                className={({ isActive }) => `qt-header__nav-link ${isActive ? 'is-active' : ''}`}
              >
                {route.label}
              </NavLink>
            ))}
          </nav>
          <div className="qt-header__safety">
            <time
              className="qt-header__calendar"
              dateTime={localClock.toISOString()}
              aria-label={`Tanggal terminal ${jstCalendar}, waktu Jepang`}
              title="Tanggal kalender terminal dalam zona waktu Jepang"
            >
              <CalendarDays aria-hidden="true" className="size-3.5" />
              {jstCalendar}
            </time>
            <TerminalStatusBadge label="MODE PAPER" tone="positive" compact />
            <TerminalStatusBadge label="LIVE TERKUNCI (LOCKED)" tone="blocked" compact />
            <button
              type="button"
              className={`qt-button qt-header__mobile-pause ${isPaused ? 'qt-button--active' : ''}`}
              onClick={onTogglePause}
              aria-pressed={isPaused}
            >
              {isPaused ? <Play aria-hidden="true" className="size-3.5" /> : <Pause aria-hidden="true" className="size-3.5" />}
              {isPaused ? 'Lanjutkan tampilan' : 'Jeda pembaruan tampilan'}
            </button>
            <span className="qt-header__protection">
              <ShieldCheck aria-hidden="true" className="size-3.5" />
              Batas perlindungan
            </span>
          </div>
        </div>
      </div>
      <MarketTickerStrip tickers={data?.tickers ?? []} />
      <div className="qt-header__scan" aria-hidden="true">
        <RadioTower className="size-3" />
      </div>
    </header>
  )
}
