import { apiClient } from './client'
import { endpoints } from './endpoints'
import { hasRequiredKeys } from './guards'
import type { OverviewData } from './types'

const isOverviewData = (value: unknown): value is OverviewData =>
  hasRequiredKeys(value, ['kpis', 'status']) &&
  hasRequiredKeys(value.kpis, ['account_balance', 'equity', 'closed_orders']) &&
  hasRequiredKeys(value.status, ['current_mode', 'live_allowed', 'quality_status'])

export const getOverview = (signal?: AbortSignal) =>
  apiClient.get(endpoints.overview, { signal, validate: isOverviewData })
