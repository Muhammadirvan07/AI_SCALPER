import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import test from 'node:test'
import React, { createElement } from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import { isEconomicCalendarDiagnostic } from '../src/api/economicCalendar'
import { EconomicCalendarDiagnosticPanel, NextEconomicRiskSummary } from '../src/components/domain/EconomicCalendarDiagnosticPanel'
import { DashboardRealtimeContext, initialResources, type DashboardRealtimeContextValue } from '../src/context/dashboardRealtimeContext'
import { markCalendarEventReceived, measureCalendarFrontendRender } from '../src/realtime/economicCalendarPerformance'
import type { ConnectionSnapshot, RealtimeEvent } from '../src/realtime/websocketTypes'
import type { EconomicCalendarDiagnosticContext } from '../src/types/economicCalendar'

Object.assign(globalThis, { React })

const context: EconomicCalendarDiagnosticContext = {
  symbol: 'EURUSD', status: 'CAUTION', currency_exposure: ['EUR', 'USD'],
  next_event: {
    id: 'bea:gdp-q2-2026', event_name: 'GDP (Advance Estimate), Q2 2026', currency: 'USD',
    impact: 'HIGH', scheduled_at: '2026-07-30T12:30:00Z', actual: null, forecast: null,
    previous: null, unit: '% SAAR', status: 'SCHEDULED', source: 'Bureau of Economic Analysis',
    source_url: 'https://www.bea.gov/news/schedule', verified: true, released_at: null,
  },
  minutes_to_event: 24, minutes_since_event: null, event_impact: 'HIGH', event_status: 'SCHEDULED',
  guard_preview: 'CAUTION', affected_symbols: ['EURUSD', 'XAUUSD'], source: 'Bureau of Economic Analysis',
  verified: true, data_freshness: 'LIVE',
  reasons: ['High-impact USD event is approaching.', 'Preview only; execution gates are not modified.'],
  diagnostic_only: true, execution_guard_enabled: false, affects_execution: false,
  updated_at: '2026-07-30T12:06:00Z',
}

const connection: ConnectionSnapshot = {
  state: 'CONNECTED', reconnectAttempt: 0, lastHeartbeatAt: null, lastEventAt: null,
  lastSuccessfulUpdate: null, subscribedChannels: [], retryAt: null, error: null,
}

function dashboardValue(data: EconomicCalendarDiagnosticContext | null): DashboardRealtimeContextValue {
  const resources = initialResources()
  resources.economicCalendarDiagnostic = {
    data,
    meta: {
      source_updated_at: context.updated_at, server_timestamp: context.updated_at, age_seconds: 0,
      stale: false, source_available: true, source: 'economic_calendar_service', request_id: null,
      data_status: 'live', warnings: [],
    },
    status: data ? 'success' : 'idle', error: null,
  }
  return {
    resources, connection, activeSymbol: 'EURUSD', timeframe: 'M15', candleLimit: 200,
    performanceFilters: { range: 'all' }, safetyAnomaly: false, safetyMessage: null,
    lastSuccessfulUpdate: context.updated_at, setActiveSymbol: () => undefined,
    setTimeframe: () => undefined, setCandleLimit: () => undefined, setPerformanceFilters: () => undefined,
    refreshAll: async () => undefined, refreshResource: async () => undefined,
    loadLogs: async () => undefined,
  }
}

function renderPanel(data: EconomicCalendarDiagnosticContext | null) {
  return renderToStaticMarkup(
    createElement(
      DashboardRealtimeContext.Provider,
      { value: dashboardValue(data) },
      createElement(React.Fragment, null,
        createElement(EconomicCalendarDiagnosticPanel),
        createElement(NextEconomicRiskSummary),
      ),
    ),
  )
}

test('diagnostic schema requires immutable read-only execution flags', () => {
  assert.equal(isEconomicCalendarDiagnostic(context), true)
  assert.equal(isEconomicCalendarDiagnostic({ ...context, affects_execution: true }), false)
  assert.equal(isEconomicCalendarDiagnostic({ ...context, execution_guard_enabled: true }), false)
})

test('calendar diagnostic hierarchy exposes status, event, countdown, source and safety boundary', () => {
  const markup = renderPanel(context)
  assert.match(markup, /Economic Event Context/)
  assert.match(markup, /READ-ONLY/)
  assert.match(markup, /DOES NOT AFFECT EXECUTION/)
  assert.match(markup, /GDP \(Advance Estimate\), Q2 2026/)
  assert.match(markup, /Bureau of Economic Analysis/)
  assert.match(markup, /Actual pending from official source/)
  assert.doesNotMatch(markup, />0(?:\.0+)?\s*% SAAR</)
})

test('all diagnostic preview states remain textual and never become an execution action', () => {
  for (const status of ['CAUTION', 'HIGH_RISK', 'BLOCK_PREVIEW', 'POST_RELEASE_VOLATILITY', 'INSUFFICIENT_DATA'] as const) {
    const markup = renderPanel({ ...context, status, guard_preview: status })
    assert.match(markup, new RegExp(status))
    assert.match(markup, /DOES NOT AFFECT EXECUTION/)
    assert.doesNotMatch(markup, /Enable|Execute trade|BUY|SELL/)
  }
})

test('no-event context renders an honest unavailable summary', () => {
  const empty: EconomicCalendarDiagnosticContext = {
    ...context, status: 'NORMAL', guard_preview: 'NORMAL', next_event: null, event_impact: null,
    event_status: null, minutes_to_event: null, affected_symbols: [], source: null, verified: false,
    data_freshness: 'UNAVAILABLE', reasons: ['No verified calendar events are available.'],
  }
  const markup = renderPanel(empty)
  assert.match(markup, /No relevant economic event/)
  assert.match(markup, /Economic context unavailable/)
})

test('release receipt measures local WebSocket-to-render latency once', () => {
  const event: RealtimeEvent = {
    type: 'calendar.event.released', channel: 'economic-calendar', timestamp: new Date().toISOString(),
    sequence: 91, data: { id: context.next_event?.id, scheduled_at: context.next_event?.scheduled_at },
  }
  markCalendarEventReceived(event)
  const metric = measureCalendarFrontendRender('bea:gdp-q2-2026')
  assert.ok(metric && metric.websocketToRenderMs >= 0)
  assert.equal(measureCalendarFrontendRender('bea:gdp-q2-2026'), null)
})

test('calendar diagnostics CSS is responsive and honors reduced motion', () => {
  const css = readFileSync(new URL('../src/styles/domain-dashboard.css', import.meta.url), 'utf8')
  assert.match(css, /calendar-diagnostic__hero/)
  assert.match(css, /@media \(max-width: 640px\)/)
  assert.match(css, /prefers-reduced-motion: reduce/)
  assert.doesNotMatch(css, /calendar-diagnostic[^}]*overflow-x:\s*(visible|scroll)/)
})
