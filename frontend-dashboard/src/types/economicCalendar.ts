import type { Page } from '../api/types'

export type EconomicEventStatus =
  | 'SCHEDULED'
  | 'COUNTDOWN'
  | 'AWAITING_RELEASE'
  | 'RELEASED'
  | 'REVISED'
  | 'DELAYED'
  | 'RESCHEDULED'
  | 'CANCELLED'
  | 'UNKNOWN'

export type EconomicImpact = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN'
export type EconomicSourceType = 'OFFICIAL' | 'MANUAL' | 'LOCAL_FILE' | 'MODEL_ESTIMATE' | 'UNKNOWN'
export type EconomicCategory =
  | 'INTEREST_RATE' | 'CENTRAL_BANK' | 'INFLATION' | 'CPI' | 'PPI'
  | 'EMPLOYMENT' | 'NFP' | 'UNEMPLOYMENT' | 'JOLTS' | 'GDP'
  | 'RETAIL_SALES' | 'PMI' | 'CONSUMER_CONFIDENCE' | 'INDUSTRIAL_PRODUCTION'
  | 'HOUSING' | 'TRADE_BALANCE' | 'ENERGY' | 'INVENTORIES' | 'SPEECH'
  | 'MEETING_MINUTES' | 'FINANCIAL_STABILITY' | 'REGULATION' | 'OTHER'

export type CalendarGuardState =
  | 'NORMAL' | 'CAUTION' | 'HIGH_RISK' | 'BLOCK_PREVIEW'
  | 'POST_RELEASE_VOLATILITY' | 'INSUFFICIENT_DATA'

export interface ScheduleHistoryEntry {
  changed_at: string
  previous_scheduled_at: string
  scheduled_at: string
  reason: string
}

export interface EconomicCalendarEvent {
  id: string
  provider: string
  source: string
  source_type: EconomicSourceType
  source_url: string | null
  event_name: string
  short_name: string | null
  description: string | null
  country: string | null
  country_code: string | null
  currency: string | null
  category: EconomicCategory
  impact: EconomicImpact
  impact_score: number
  impact_reasons: string[]
  scheduled_at: string
  original_scheduled_at: string | null
  actual: string | number | null
  actual_raw: string | number | null
  forecast: string | number | null
  forecast_source: string | null
  forecast_source_type: EconomicSourceType | null
  previous: string | number | null
  revised_previous: string | number | null
  revision_source: string | null
  revised_at: string | null
  unit: string | null
  frequency: string | null
  reference_period: string | null
  status: EconomicEventStatus
  affected_symbols: string[]
  symbols: string[]
  is_high_impact: boolean
  is_live: boolean
  is_released: boolean
  is_revised: boolean
  verified: boolean
  verified_at: string | null
  last_checked_at: string | null
  released_at: string | null
  updated_at: string
  stale: boolean
  stale_reason: string | null
  surprise: number | null
  surprise_percent: number | null
  surprise_label: 'ABOVE_FORECAST' | 'BELOW_FORECAST' | 'INLINE' | 'NO_FORECAST'
  schedule_history: ScheduleHistoryEntry[]
  metadata: Record<string, unknown>
}

export interface EconomicCalendarPage extends Page<EconomicCalendarEvent> {
  counts: Record<string, number>
  next_critical_event: EconomicCalendarEvent | null
}

export interface EconomicCalendarSourceStatus {
  name: string
  display_name: string
  enabled: boolean
  configured: boolean
  healthy: boolean
  status: string
  official_domain: string | null
  capabilities: string[]
  last_fetch_at: string | null
  last_success_at: string | null
  last_error: string | null
  last_status_code: number | null
  latency_ms: number | null
  event_count: number
  failure_count: number
  rate_limited: boolean
  cooldown_until: string | null
  next_retry_at: string | null
  stale: boolean
  last_known_good_available: boolean
  verified_at: string | null
}

export interface EconomicCalendarRuntimeStatus {
  enabled: boolean
  state: string
  scheduler_running: boolean
  scheduler_mode: string
  active_interval_seconds: number
  last_sync_at: string | null
  last_success_at: string | null
  next_sync_at: string | null
  event_count: number
  today_count: number
  upcoming_count: number
  high_impact_count: number
  live_count: number
  source_count: number
  healthy_source_count: number
  partial: boolean
  timezone: string
  engine_integration_enabled: false
  read_only: true
  live_allowed: false
  effective_max_lot: number
  warnings: string[]
}

export interface EconomicCalendarHealth {
  status: string
  service: string
  scheduler: string
  cache: string
  repository: string
  sources: EconomicCalendarSourceStatus[]
  last_success_at: string | null
  stale: boolean
  read_only: true
  live_allowed: false
  effective_max_lot: number
}

export interface EconomicCalendarGuardPreview {
  symbol: string
  state: CalendarGuardState
  event_id: string | null
  event_name: string | null
  event_impact: EconomicImpact | null
  event_scheduled_at: string | null
  minutes_to_event: number | null
  reasons: string[]
  read_only: true
  engine_integration_enabled: false
  diagnostic_only: true
  execution_guard_enabled: false
  affects_execution: false
  creates_orders: false
}

export interface EconomicCalendarDiagnosticEvent {
  id: string
  event_name: string
  currency: string | null
  impact: EconomicImpact
  scheduled_at: string
  actual: string | number | null
  forecast: string | number | null
  previous: string | number | null
  unit: string | null
  status: EconomicEventStatus
  source: string
  source_url: string | null
  verified: boolean
  released_at: string | null
}

export interface EconomicCalendarDiagnosticContext {
  symbol: string
  status: CalendarGuardState
  currency_exposure: string[]
  next_event: EconomicCalendarDiagnosticEvent | null
  minutes_to_event: number | null
  minutes_since_event: number | null
  event_impact: EconomicImpact | null
  event_status: EconomicEventStatus | null
  guard_preview: CalendarGuardState
  affected_symbols: string[]
  source: string | null
  verified: boolean
  data_freshness: string
  reasons: string[]
  diagnostic_only: true
  execution_guard_enabled: false
  affects_execution: false
  updated_at: string
}

export interface EconomicCalendarReleaseLatency {
  event_id: string
  scheduled_at: string
  first_check_at: string | null
  source_published_at: string | null
  backend_updated_at: string | null
  websocket_broadcast_at: string | null
  scheduled_to_first_check_ms: number | null
  scheduled_to_source_publish_ms: number | null
  scheduled_to_backend_update_ms: number | null
  scheduled_to_websocket_broadcast_ms: number | null
  scheduled_to_frontend_render_ms: number | null
}

export interface EconomicCalendarMetrics {
  economic_calendar_sync_total: number
  economic_calendar_sync_failure_total: number
  economic_calendar_release_detected_total: number
  economic_calendar_release_latency_ms: number | null
  economic_calendar_websocket_broadcast_total: number
  economic_calendar_diagnostic_context_total: number
  economic_calendar_guard_preview_changes_total: number
  economic_calendar_mutation_block_total: number
  release_detection_latency_ms: number | null
  websocket_delivery_latency_ms: number | null
  frontend_render_latency_ms: number | null
  latest_release: EconomicCalendarReleaseLatency | null
  audit_record_count: number
  diagnostic_only: true
  execution_guard_enabled: false
  live_allowed: false
  effective_max_lot: number
}

export interface EconomicCalendarFilters {
  start_time?: string
  end_time?: string
  date?: string
  timezone?: string
  currency?: string
  country?: string
  symbol?: string
  category?: EconomicCategory
  impact?: EconomicImpact
  status?: EconomicEventStatus
  source?: string
  released?: boolean
  limit?: number
  offset?: number
  sort?: 'scheduled_at' | '-scheduled_at' | 'impact' | 'updated_at' | '-updated_at'
}
