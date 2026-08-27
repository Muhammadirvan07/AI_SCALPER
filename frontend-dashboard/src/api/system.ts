import { apiClient } from './client'
import { endpoints } from './endpoints'
import { hasRequiredKeys } from './guards'
import type { AIAdvisoryStatusData, SystemComponent, SystemStatusData } from './types'

const isSystemStatus = (value: unknown): value is SystemStatusData =>
  hasRequiredKeys(value, ['status', 'mode', 'live_allowed', 'components', 'ai_advisory'])
const isAiAdvisoryStatus = (value: unknown): value is AIAdvisoryStatusData =>
  hasRequiredKeys(value, [
    'requested',
    'effective_mode',
    'credential_configured',
    'news_ready',
    'economic_calendar_ready',
    'advisory_only',
    'execution_scope',
    'live_allowed',
    'order_capability',
  ])
const isComponents = (value: unknown): value is SystemComponent[] =>
  Array.isArray(value) && value.every((item) => hasRequiredKeys(item, ['name', 'status', 'stale']))

export const getSystemStatus = (signal?: AbortSignal) =>
  apiClient.get(endpoints.systemStatus, { signal, validate: isSystemStatus })

export const getSystemComponents = (signal?: AbortSignal) =>
  apiClient.get(endpoints.systemComponents, { signal, validate: isComponents })

export const getAiAdvisoryStatus = (signal?: AbortSignal) =>
  apiClient.get(endpoints.systemAiAdvisory, { signal, validate: isAiAdvisoryStatus })
