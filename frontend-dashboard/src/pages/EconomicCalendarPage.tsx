import {
  CalendarRange, ChevronLeft, ChevronRight, Clock3, Filter, LoaderCircle, Radio,
  RefreshCw, Search, ShieldCheck, Wifi, WifiOff,
} from 'lucide-react'
import { useMemo, useState } from 'react'
import { CalendarInsights } from '../components/economic-calendar/CalendarInsights'
import { CalendarKpiGrid } from '../components/economic-calendar/CalendarKpiGrid'
import { CalendarBadge, CalendarModuleState } from '../components/economic-calendar/CalendarPrimitives'
import { EconomicCalendarViews } from '../components/economic-calendar/EconomicCalendarViews'
import { EconomicEventDrawer } from '../components/economic-calendar/EconomicEventDrawer'
import { EconomicEventTable } from '../components/economic-calendar/EconomicEventTable'
import { NextCriticalEvent } from '../components/economic-calendar/NextCriticalEvent'
import {
  connectionStatePresentation, dateKey, filterCalendarEvents, impactRank, type CalendarUiFilters, type CalendarViewMode,
} from '../components/economic-calendar/calendarViewModel'
import { useEconomicCalendar } from '../hooks/useEconomicCalendar'
import { useEconomicCalendarClock } from '../hooks/useEconomicCalendarClock'
import { useEconomicCalendarGuard } from '../hooks/useEconomicCalendarGuard'
import { useEconomicCalendarSources } from '../hooks/useEconomicCalendarSources'
import '../styles/economic-calendar.css'
import { useRealtimeDashboard } from '../hooks/useRealtimeDashboard'
import type { EconomicCalendarEvent } from '../types/economicCalendar'

const emptyFilters: CalendarUiFilters = { search: '', currency: '', impact: '', category: '', status: '', symbol: '' }

const absoluteTimestamp = (value: string | null, timezone: string) => value
  ? new Intl.DateTimeFormat('en', { dateStyle: 'medium', timeStyle: 'long', timeZone: timezone }).format(new Date(value))
  : 'Not available'

export function EconomicCalendarPage() {
  const calendar = useEconomicCalendar()
  const sources = useEconomicCalendarSources()
  const guard = useEconomicCalendarGuard()
  const dashboard = useRealtimeDashboard()
  const now = useEconomicCalendarClock()
  const timezone = Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC'
  const [selectedDate, setSelectedDate] = useState(() => dateKey(Date.now(), timezone))
  const [mode, setMode] = useState<CalendarViewMode>('timeline')
  const [filters, setFilters] = useState<CalendarUiFilters>(emptyFilters)
  const [selectedEvent, setSelectedEvent] = useState<EconomicCalendarEvent | null>(null)
  const [refreshing, setRefreshing] = useState(false)
  const [notice, setNotice] = useState<string | null>(null)

  const allEvents = useMemo(() => calendar.resource.data?.items ?? [], [calendar.resource.data])
  const events = useMemo(
    () => filterCalendarEvents(allEvents, selectedDate, timezone, filters),
    [allEvents, filters, selectedDate, timezone],
  )
  const nextCritical = useMemo(() => allEvents
    .filter((event) => event.impact === 'CRITICAL' && event.status !== 'CANCELLED' && Date.parse(event.scheduled_at) >= now)
    .sort((left, right) => Date.parse(left.scheduled_at) - Date.parse(right.scheduled_at))[0] ?? null, [allEvents, now])
  const currencies = [...new Set(allEvents.flatMap((event) => event.currency ? [event.currency] : []))].sort()
  const categories = [...new Set(allEvents.map((event) => event.category))].sort()
  const symbols = [...new Set(allEvents.flatMap((event) => event.affected_symbols))].sort()
  const presentation = connectionStatePresentation(calendar.connection.state, calendar.resource.meta?.stale ?? true)
  const ConnectionIcon = presentation.icon === 'offline' ? WifiOff : presentation.icon === 'syncing' ? LoaderCircle : presentation.icon === 'stale' ? Clock3 : Radio
  const partial = calendar.runtime.data?.partial || calendar.resource.meta?.data_status === 'partial'
  const unavailable = calendar.runtime.data?.state === 'unconfigured' || calendar.health.data?.status === 'unconfigured'

  const shiftDate = (days: number) => {
    const current = new Date(`${selectedDate}T12:00:00Z`)
    current.setUTCDate(current.getUTCDate() + days)
    setSelectedDate(dateKey(current, timezone))
  }
  const refresh = async () => {
    setRefreshing(true)
    setNotice(null)
    try {
      await Promise.all([calendar.refresh(), sources.refresh(), guard.refresh()])
      setNotice('Calendar snapshot reloaded from read-only endpoints. Provider synchronization remains scheduler-owned.')
    } catch (reason) {
      setNotice(reason instanceof Error ? reason.message : 'Calendar sync failed.')
    } finally {
      setRefreshing(false)
    }
  }
  const setFilter = (key: keyof CalendarUiFilters, value: string) => setFilters((current) => ({ ...current, [key]: value }))

  return (
    <main id="main-content" className="quant-terminal ec-page">
      <div className="qt-container">
        <header className="ec-page-header">
          <div><span className="ec-eyebrow"><CalendarRange aria-hidden="true" />Macroeconomic Operations</span><h1>Economic Intelligence</h1><p>Official macroeconomic events and central-bank releases, reconciled into one read-only trading timeline.</p></div>
          <div className="ec-header-status">
            <CalendarBadge label={presentation.label} tone={presentation.tone} icon={<ConnectionIcon aria-hidden="true" />} />
            {partial ? <CalendarBadge label="PARTIAL SOURCES" tone="warning" /> : null}
            <span title={absoluteTimestamp(calendar.runtime.data?.last_success_at ?? null, timezone)}><Clock3 aria-hidden="true" /><em>Last sync</em><strong>{calendar.runtime.data?.last_success_at ? new Intl.RelativeTimeFormat('en', { numeric: 'auto' }).format(Math.round((Date.parse(calendar.runtime.data.last_success_at) - now) / 60_000), 'minute') : '—'}</strong></span>
            <button type="button" onClick={refresh} disabled={refreshing} aria-label="Refresh official economic calendar"><RefreshCw aria-hidden="true" className={refreshing ? 'ec-spin' : ''} />{refreshing ? 'Syncing' : 'Refresh'}</button>
          </div>
          <div className="ec-date-controls">
            <button type="button" onClick={() => shiftDate(-1)} aria-label="Previous day"><ChevronLeft aria-hidden="true" /></button>
            <input type="date" value={selectedDate} onChange={(event) => setSelectedDate(event.target.value)} aria-label="Calendar date" />
            <button type="button" onClick={() => shiftDate(1)} aria-label="Next day"><ChevronRight aria-hidden="true" /></button>
            <button type="button" className="ec-today" onClick={() => setSelectedDate(dateKey(now, timezone))}>Today</button>
            <span><Wifi aria-hidden="true" /><em>Timezone</em><strong>{timezone}</strong></span>
            <span><ShieldCheck aria-hidden="true" /><em>Engine link</em><strong>READ ONLY</strong></span>
          </div>
        </header>
        {notice ? <div className="ec-notice" role="status">{notice}</div> : null}
        {partial ? <div className="ec-source-warning"><Filter aria-hidden="true" /><span><strong>Partial official coverage</strong> Sebagian sumber ekonomi tidak tersedia. Kalender hanya menampilkan data yang berhasil diverifikasi.</span></div> : null}

        <CalendarKpiGrid runtime={calendar.runtime.data} events={events} nextCritical={nextCritical} now={now} selectedDateIsToday={selectedDate === dateKey(now, timezone)} />

        {calendar.resource.status === 'loading' && !calendar.resource.data ? <CalendarModuleState state="loading" /> : null}
        {calendar.resource.status === 'error' && !calendar.resource.data ? <CalendarModuleState state={calendar.connection.state === 'OFFLINE' ? 'offline' : 'error'} onRetry={() => void calendar.refresh()} /> : null}
        {unavailable && !calendar.resource.data?.items.length ? <CalendarModuleState state="unconfigured" /> : null}

        {calendar.resource.data ? <>
          <section className="ec-primary-grid">
            <section className="ec-calendar-panel">
              <header className="ec-section-header"><div><span>Official Schedule</span><h2>Trading timeline</h2></div><div className="ec-view-tabs" role="tablist" aria-label="Calendar view">{(['timeline', 'day', 'week'] as const).map((view) => <button key={view} type="button" role="tab" aria-selected={mode === view} className={mode === view ? 'is-active' : ''} onClick={() => setMode(view)}>{view}</button>)}</div></header>
              <EconomicCalendarViews mode={mode} events={events} allEvents={allEvents} selectedDate={selectedDate} timezone={timezone} onOpen={setSelectedEvent} />
            </section>
            <NextCriticalEvent event={nextCritical} guard={guard.resource.data} now={now} timezone={timezone} onOpen={setSelectedEvent} />
          </section>

          <section className="ec-data-grid">
            <section className="ec-events-panel">
              <header className="ec-section-header"><div><span>Verified Event Ledger</span><h2>{events.length} events · {selectedDate}</h2></div><small>Actual / Forecast / Previous aligned for rapid comparison</small></header>
              <div className="ec-filterbar">
                <label className="ec-search"><Search aria-hidden="true" /><span className="sr-only">Search events</span><input value={filters.search} onChange={(event) => setFilter('search', event.target.value)} placeholder="Search official event…" /></label>
                <label><span>Currency</span><select value={filters.currency} onChange={(event) => setFilter('currency', event.target.value)}><option value="">All currencies</option>{currencies.map((value) => <option key={value}>{value}</option>)}</select></label>
                <label><span>Impact</span><select value={filters.impact} onChange={(event) => setFilter('impact', event.target.value)}><option value="">All impact</option>{Object.keys(impactRank).map((value) => <option key={value}>{value}</option>)}</select></label>
                <label><span>Category</span><select value={filters.category} onChange={(event) => setFilter('category', event.target.value)}><option value="">All categories</option>{categories.map((value) => <option key={value}>{value.replaceAll('_', ' ')}</option>)}</select></label>
                <label><span>Status</span><select value={filters.status} onChange={(event) => setFilter('status', event.target.value)}><option value="">All status</option>{['SCHEDULED', 'COUNTDOWN', 'AWAITING_RELEASE', 'RELEASED', 'REVISED', 'DELAYED', 'RESCHEDULED', 'CANCELLED'].map((value) => <option key={value}>{value}</option>)}</select></label>
                <label><span>Symbol</span><select value={filters.symbol} onChange={(event) => setFilter('symbol', event.target.value)}><option value="">All symbols</option>{symbols.map((value) => <option key={value}>{value}</option>)}</select></label>
                {Object.values(filters).some(Boolean) ? <button type="button" onClick={() => setFilters(emptyFilters)}>Clear filters</button> : null}
              </div>
              {events.length ? <EconomicEventTable events={events} timezone={timezone} onOpen={setSelectedEvent} /> : <CalendarModuleState state="empty" />}
            </section>
            <CalendarInsights events={events} sources={sources.resource.data ?? []} activeSymbol={dashboard.activeSymbol} now={now} onCurrency={(currency) => setFilter('currency', currency)} onSymbol={(symbol) => setFilter('symbol', symbol)} />
          </section>
        </> : null}
      </div>
      <EconomicEventDrawer event={selectedEvent} guard={guard.resource.data} timezone={timezone} onClose={() => setSelectedEvent(null)} />
    </main>
  )
}
