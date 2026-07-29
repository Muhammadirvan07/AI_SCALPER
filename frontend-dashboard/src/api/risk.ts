import { apiClient } from './client'
import { endpoints } from './endpoints'
import { hasRequiredKeys } from './guards'
import type { RiskData } from './types'

const isRisk = (value: unknown): value is RiskData =>
  hasRequiredKeys(value, ['effective_max_lot', 'backend_safety_max_lot', 'live_allowed', 'live_execution_status'])

export const getRisk = (signal?: AbortSignal) =>
  apiClient.get(endpoints.risk, { signal, validate: isRisk })
