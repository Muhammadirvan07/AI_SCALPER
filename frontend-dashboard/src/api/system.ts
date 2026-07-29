import { apiClient } from './client'
import { endpoints } from './endpoints'
import { hasRequiredKeys } from './guards'
import type { SystemComponent, SystemStatusData } from './types'

const isSystemStatus = (value: unknown): value is SystemStatusData =>
  hasRequiredKeys(value, ['status', 'mode', 'live_allowed', 'components'])
const isComponents = (value: unknown): value is SystemComponent[] =>
  Array.isArray(value) && value.every((item) => hasRequiredKeys(item, ['name', 'status', 'stale']))

export const getSystemStatus = (signal?: AbortSignal) =>
  apiClient.get(endpoints.systemStatus, { signal, validate: isSystemStatus })

export const getSystemComponents = (signal?: AbortSignal) =>
  apiClient.get(endpoints.systemComponents, { signal, validate: isComponents })
