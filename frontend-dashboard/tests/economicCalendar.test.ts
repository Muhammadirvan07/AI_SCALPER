import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import test from 'node:test'
import React, { createElement } from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import { isEconomicCalendarEvent, isEconomicCalendarPage } from '../src/api/economicCalendar'
import { CalendarModuleState } from '../src/components/economic-calendar/CalendarPrimitives'
import { CalendarKpiGrid } from '../src/components/economic-calendar/CalendarKpiGrid'
import { NextCriticalEvent } from '../src/components/economic-calendar/NextCriticalEvent'
import {
  countdownParts, filterCalendarEvents, formatEventValue, weekSummary,
} from '../src/components/economic-calendar/calendarViewModel'
import { mergeEconomicCalendarEvent } from '../src/realtime/economicCalendarEventHandlers'
import type { RealtimeEvent } from '../src/realtime/websocketTypes'
import type { EconomicCalendarEvent, EconomicCalendarPage, EconomicCalendarRuntimeStatus } from '../src/types/economicCalendar'

// The repository test runner transpiles TSX with the classic runtime while
// Vite uses react-jsx in production.
Object.assign(globalThis, { React })

const scheduled = '2026-07-29T12:30:00Z'
const event: EconomicCalendarEvent = {
  id: 'bea:us-gdp', provider: 'bea', source: 'U.S. Bureau of Economic Analysis',
  source_type: 'OFFICIAL', source_url: 'https://www.bea.gov/news/schedule',
  event_name: 'US Gross Domestic Product', short_name: 'US GDP', description: 'Official GDP release.',
  country: 'United States', country_code: 'US', currency: 'USD', category: 'GDP', impact: 'HIGH',
  impact_score: .73, impact_reasons: ['Primary macroeconomic indicator'], scheduled_at: scheduled,
  original_scheduled_at: null, actual: null, actual_raw: null, forecast: null, forecast_source: null,
  forecast_source_type: null, previous: 3, revised_previous: null, revision_source: null, revised_at: null, unit: '%', frequency: 'Quarterly',
  reference_period: 'Q2 2026', status: 'SCHEDULED', affected_symbols: ['EURUSD', 'XAUUSD'],
  symbols: ['EURUSD', 'XAUUSD'], is_high_impact: true, is_live: false, is_released: false,
  is_revised: false, verified: true, verified_at: '2026-07-29T00:00:00Z',
  last_checked_at: '2026-07-29T00:00:00Z', released_at: null, updated_at: '2026-07-29T00:00:00Z',
  stale: false, stale_reason: null, surprise: null, surprise_percent: null, surprise_label: 'NO_FORECAST',
  schedule_history: [], metadata: { schedule_precision: 'DATETIME' },
}

const page: EconomicCalendarPage = {
  items: [event], total: 1, limit: 200, offset: 0, counts: { high: 1 }, next_critical_event: null,
}

test('calendar API validators preserve null forecast and official metadata', () => {
  assert.equal(isEconomicCalendarEvent(event), true)
  assert.equal(isEconomicCalendarPage(page), true)
  assert.equal(event.forecast, null)
  assert.equal(formatEventValue(event.forecast, event.unit), '—')
})

test('countdown uses deterministic timestamp math and never blinks', () => {
  const remaining = countdownParts(scheduled, Date.parse('2026-07-29T11:29:58Z'))
  assert.equal(remaining.label, '01:00:02')
  assert.equal(countdownParts(scheduled, Date.parse('2026-07-29T13:00:00Z')).label, '00:00:00')
})

test('date, currency, impact, symbol, and search filters remain composable', () => {
  const filters = { search: 'gross', currency: 'USD', impact: 'HIGH', category: 'GDP', status: '', symbol: 'EURUSD' }
  const rows = filterCalendarEvents([event], '2026-07-29', 'UTC', filters)
  assert.equal(rows.length, 1)
  assert.equal(filterCalendarEvents([event], '2026-07-29', 'UTC', { ...filters, currency: 'EUR' }).length, 0)
  assert.equal(weekSummary([event], '2026-07-29', 'UTC').reduce((sum, day) => sum + day.items.length, 0), 1)
})

test('WebSocket release merges one event without duplicating the page', () => {
  const released = { ...event, actual: 2.8, is_released: true, is_live: true, status: 'RELEASED' as const }
  const realtime: RealtimeEvent = {
    type: 'calendar.event.released', channel: 'economic-calendar',
    timestamp: '2026-07-29T12:30:05Z', sequence: 81, data: released,
  }
  const merged = mergeEconomicCalendarEvent(page, realtime)
  assert.equal(merged?.items.length, 1)
  assert.equal(merged?.items[0]?.actual, 2.8)
  assert.equal(merged?.items[0]?.forecast, null)
})

test('calendar components expose clear empty/loading states and official attribution', () => {
  const loading = renderToStaticMarkup(createElement(CalendarModuleState, { state: 'loading' }))
  const empty = renderToStaticMarkup(createElement(CalendarModuleState, { state: 'empty' }))
  const focus = renderToStaticMarkup(createElement(NextCriticalEvent, {
    event, guard: null, now: Date.parse('2026-07-29T12:00:00Z'), timezone: 'UTC', onOpen: () => undefined,
  }))
  assert.match(loading, /Loading official calendar/)
  assert.match(empty, /Tidak ada event ekonomi/)
  assert.match(focus, /U\.S\. Bureau of Economic Analysis/)
  assert.match(focus, /00:30:00/)
  assert.doesNotMatch(focus, /Investing\.com|iframe/i)
})

test('daily KPI uses the selected-day event set instead of global cache totals', () => {
  const runtime = {
    enabled: true, state: 'partial', scheduler_running: true, scheduler_mode: 'NORMAL',
    active_interval_seconds: 900, last_sync_at: null, last_success_at: null, next_sync_at: null,
    event_count: 38, today_count: 2, upcoming_count: 34, high_impact_count: 16, live_count: 1,
    source_count: 5, healthy_source_count: 3, partial: true, timezone: 'UTC',
    engine_integration_enabled: false, read_only: true, live_allowed: false,
    effective_max_lot: .01, warnings: [],
  } satisfies EconomicCalendarRuntimeStatus
  const markup = renderToStaticMarkup(createElement(CalendarKpiGrid, {
    runtime, events: [event], nextCritical: null, now: Date.parse('2026-07-29T00:00:00Z'), selectedDateIsToday: true,
  }))
  assert.match(markup, /High Impact Today/)
  assert.match(markup, /<strong title="1">1<\/strong>/)
  assert.doesNotMatch(markup, /<strong title="16">16<\/strong>/)
})

test('native calendar removes iframe runtime and locks CSP frames', () => {
  const app = readFileSync(new URL('../src/pages/EconomicCalendarPage.tsx', import.meta.url), 'utf8')
  const news = readFileSync(new URL('../src/pages/NewsPage.tsx', import.meta.url), 'utf8')
  const vite = readFileSync(new URL('../vite.config.ts', import.meta.url), 'utf8')
  assert.doesNotMatch(app, /iframe|InvestingEconomicCalendarWidget/)
  assert.doesNotMatch(news, /InvestingEconomicCalendarWidget/)
  assert.match(vite, /frame-src 'none'/)
  assert.match(vite, /child-src 'none'/)
  assert.doesNotMatch(vite, /frame-src\s+\*/)
})
