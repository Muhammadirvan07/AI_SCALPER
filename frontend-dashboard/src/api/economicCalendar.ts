import type {
  EconomicCalendarEvent,
  EconomicCalendarDiagnosticContext,
  EconomicCalendarFilters,
  EconomicCalendarGuardPreview,
  EconomicCalendarHealth,
  EconomicCalendarPage,
  EconomicCalendarRuntimeStatus,
  EconomicCalendarSourceStatus,
  EconomicCalendarMetrics,
} from '../types/economicCalendar'
import { apiClient } from './client'
import { endpoints } from './endpoints'
import { hasRequiredKeys, isBoolean, isNumber, isPageData, isString } from './guards'

export const isEconomicCalendarEvent = (value: unknown): value is EconomicCalendarEvent =>
  hasRequiredKeys(value, [
    'id', 'provider', 'source', 'source_type', 'event_name', 'category', 'impact',
    'impact_score', 'scheduled_at', 'status', 'affected_symbols', 'verified', 'updated_at',
  ]) && isString(value.id) && isString(value.provider) && isString(value.source) &&
  isString(value.event_name) && isString(value.scheduled_at) && isString(value.status) &&
  isNumber(value.impact_score) && Array.isArray(value.affected_symbols) &&
  value.affected_symbols.every(isString) && isBoolean(value.verified)

export const isEconomicCalendarPage = (value: unknown): value is EconomicCalendarPage =>
  isPageData(value) && value.items.every(isEconomicCalendarEvent) &&
  hasRequiredKeys(value, ['counts', 'next_critical_event'])

export const isCalendarSources = (value: unknown): value is EconomicCalendarSourceStatus[] =>
  Array.isArray(value) && value.every((item) => hasRequiredKeys(item, [
    'name', 'display_name', 'enabled', 'configured', 'healthy', 'status', 'event_count', 'stale',
  ]))

const isCalendarRuntime = (value: unknown): value is EconomicCalendarRuntimeStatus =>
  hasRequiredKeys(value, [
    'enabled', 'state', 'scheduler_running', 'scheduler_mode', 'active_interval_seconds',
    'event_count', 'today_count', 'upcoming_count', 'high_impact_count', 'live_count',
    'source_count', 'healthy_source_count', 'partial', 'read_only', 'live_allowed', 'effective_max_lot',
  ]) && isBoolean(value.enabled) && isNumber(value.event_count) && isString(value.state)

const isCalendarHealth = (value: unknown): value is EconomicCalendarHealth =>
  hasRequiredKeys(value, ['status', 'service', 'scheduler', 'cache', 'repository', 'sources', 'stale', 'read_only']) &&
  isString(value.status) && Array.isArray(value.sources)

const isGuard = (value: unknown): value is EconomicCalendarGuardPreview =>
  hasRequiredKeys(value, ['symbol', 'state', 'reasons', 'read_only', 'engine_integration_enabled', 'diagnostic_only', 'execution_guard_enabled', 'affects_execution', 'creates_orders']) &&
  isString(value.symbol) && isString(value.state) && Array.isArray(value.reasons)

export const isEconomicCalendarDiagnostic = (value: unknown): value is EconomicCalendarDiagnosticContext =>
  hasRequiredKeys(value, [
    'symbol', 'status', 'currency_exposure', 'guard_preview', 'affected_symbols', 'data_freshness',
    'reasons', 'diagnostic_only', 'execution_guard_enabled', 'affects_execution', 'updated_at',
  ]) && isString(value.symbol) && isString(value.status) && Array.isArray(value.currency_exposure) &&
  value.currency_exposure.every(isString) && Array.isArray(value.affected_symbols) &&
  value.affected_symbols.every(isString) && Array.isArray(value.reasons) && value.reasons.every(isString) &&
  isBoolean(value.diagnostic_only) && value.diagnostic_only === true &&
  isBoolean(value.execution_guard_enabled) && value.execution_guard_enabled === false &&
  isBoolean(value.affects_execution) && value.affects_execution === false

const isCalendarMetrics = (value: unknown): value is EconomicCalendarMetrics =>
  hasRequiredKeys(value, [
    'economic_calendar_sync_total', 'economic_calendar_sync_failure_total',
    'economic_calendar_release_detected_total', 'economic_calendar_websocket_broadcast_total',
    'economic_calendar_diagnostic_context_total', 'economic_calendar_guard_preview_changes_total',
    'economic_calendar_mutation_block_total', 'audit_record_count', 'diagnostic_only',
    'execution_guard_enabled', 'live_allowed', 'effective_max_lot',
  ]) && isNumber(value.economic_calendar_sync_total) && isNumber(value.effective_max_lot)

const queryString = (filters: EconomicCalendarFilters) => {
  const params = new URLSearchParams()
  Object.entries(filters).forEach(([key, value]) => {
    if (value !== undefined && value !== '') params.set(key, String(value))
  })
  return params.size > 0 ? `?${params}` : ''
}

export const getEconomicCalendar = (filters: EconomicCalendarFilters = {}, signal?: AbortSignal) =>
  apiClient.get(`${endpoints.economicCalendar}${queryString(filters)}`, { signal, validate: isEconomicCalendarPage })

export const getEconomicCalendarToday = (date: string, timezone: string, signal?: AbortSignal) =>
  apiClient.get(`${endpoints.economicCalendarToday}?date=${encodeURIComponent(date)}&timezone=${encodeURIComponent(timezone)}&limit=300`, {
    signal,
    validate: isEconomicCalendarPage,
  })

export const getEconomicCalendarEvent = (eventId: string, signal?: AbortSignal) =>
  apiClient.get(endpoints.economicCalendarEvent(eventId), { signal, validate: isEconomicCalendarEvent })

export const getEconomicCalendarSources = (signal?: AbortSignal) =>
  apiClient.get(endpoints.economicCalendarSources, { signal, validate: isCalendarSources })

export const getEconomicCalendarStatus = (signal?: AbortSignal) =>
  apiClient.get(endpoints.economicCalendarStatus, { signal, validate: isCalendarRuntime })

export const getEconomicCalendarHealth = (signal?: AbortSignal) =>
  apiClient.get(endpoints.economicCalendarHealth, { signal, validate: isCalendarHealth })

export const getEconomicCalendarGuard = (symbol: string, signal?: AbortSignal) =>
  apiClient.get(endpoints.economicCalendarGuard(symbol), { signal, validate: isGuard })

export const getEconomicCalendarDiagnostic = (symbol?: string | null, signal?: AbortSignal) =>
  apiClient.get(symbol ? endpoints.diagnosticsCalendarSymbol(symbol) : endpoints.diagnosticsCalendar, {
    signal,
    validate: isEconomicCalendarDiagnostic,
  })

export const getEconomicCalendarMetrics = (signal?: AbortSignal) =>
  apiClient.get(endpoints.economicCalendarMetrics, { signal, validate: isCalendarMetrics })
