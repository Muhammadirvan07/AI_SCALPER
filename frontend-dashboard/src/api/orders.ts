import { apiClient } from './client'
import { endpoints } from './endpoints'
import { hasRequiredKeys, isPageData } from './guards'
import type { Page, PaperOrder } from './types'

const isOrdersPage = (value: unknown): value is Page<PaperOrder> =>
  isPageData(value) && value.items.every((item) => hasRequiredKeys(item, ['order_id', 'status', 'mode']))

export interface OrderFilters {
  symbol?: string
  status?: string
  side?: string
  strategy?: string
  start_date?: string
  end_date?: string
  limit?: number
  offset?: number
}

export const getOrders = (filters: OrderFilters = {}, signal?: AbortSignal) => {
  const query = new URLSearchParams()
  Object.entries(filters).forEach(([key, value]) => {
    if (value !== undefined && value !== '') query.set(key, String(value))
  })
  const suffix = query.size ? `?${query}` : ''
  return apiClient.get(`${endpoints.orders}${suffix}`, { signal, validate: isOrdersPage })
}
