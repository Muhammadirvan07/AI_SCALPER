import { apiClient } from './client'
import { endpoints } from './endpoints'
import { hasRequiredKeys } from './guards'
import type { PerformanceData, PerformanceRange } from './types'

const isPerformanceData = (value: unknown): value is PerformanceData =>
  hasRequiredKeys(value, ['total_orders', 'closed_orders', 'net_profit', 'curve']) &&
  Array.isArray(value.curve)

export interface PerformanceFilters {
  range: PerformanceRange
  symbol?: string | null
  strategy?: string | null
}

export const getPerformance = ({ range, symbol, strategy }: PerformanceFilters, signal?: AbortSignal) => {
  const query = new URLSearchParams({ range })
  if (symbol) query.set('symbol', symbol)
  if (strategy) query.set('strategy', strategy)
  return apiClient.get(`${endpoints.performance}?${query}`, { signal, validate: isPerformanceData })
}
