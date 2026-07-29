import { apiClient } from './client'
import { endpoints } from './endpoints'
import { hasRequiredKeys } from './guards'
import type { QualityData } from './types'

const isQuality = (value: unknown): value is QualityData =>
  hasRequiredKeys(value, ['quality_status', 'readiness_status', 'current_blockers', 'safe_to_live_trade']) &&
  Array.isArray(value.current_blockers)

export const getQuality = (signal?: AbortSignal) =>
  apiClient.get(endpoints.quality, { signal, validate: isQuality })
