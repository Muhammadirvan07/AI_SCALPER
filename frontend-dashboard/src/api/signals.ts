import { apiClient } from './client'
import { endpoints } from './endpoints'
import { hasRequiredKeys, isPageData } from './guards'
import type { Page, TradingSignal } from './types'

const isSignalsPage = (value: unknown): value is Page<TradingSignal> =>
  isPageData(value) && value.items.every((item) => hasRequiredKeys(item, ['signal_id', 'status', 'source']))

export interface SignalFilters {
  symbol?: string
  side?: string
  strategy?: string
  status?: string
  limit?: number
  offset?: number
}

export const getSignals = (filters: SignalFilters = {}, signal?: AbortSignal) => {
  const query = new URLSearchParams()
  Object.entries(filters).forEach(([key, value]) => {
    if (value !== undefined && value !== '') query.set(key, String(value))
  })
  const suffix = query.size ? `?${query}` : ''
  return apiClient.get(`${endpoints.signals}${suffix}`, { signal, validate: isSignalsPage })
}
