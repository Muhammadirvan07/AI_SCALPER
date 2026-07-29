import { apiClient } from './client'
import { endpoints } from './endpoints'
import { hasRequiredKeys, isPageData } from './guards'
import type { LogEntry, Page } from './types'

const isLogsPage = (value: unknown): value is Page<LogEntry> =>
  isPageData(value) && value.items.every((item) => hasRequiredKeys(item, ['id', 'timestamp', 'level', 'message']))

export interface LogFilters {
  level?: string
  component?: string
  search?: string
  start_time?: string
  end_time?: string
  limit?: number
  offset?: number
}

export const getLogs = (filters: LogFilters = {}, signal?: AbortSignal) => {
  const query = new URLSearchParams()
  Object.entries(filters).forEach(([key, value]) => {
    if (value !== undefined && value !== '') query.set(key, String(value))
  })
  const suffix = query.size ? `?${query}` : ''
  return apiClient.get(`${endpoints.logs}${suffix}`, { signal, validate: isLogsPage })
}
