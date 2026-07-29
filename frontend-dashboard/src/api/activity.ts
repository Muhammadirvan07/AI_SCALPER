import { apiClient } from './client'
import { endpoints } from './endpoints'
import { hasRequiredKeys } from './guards'
import type { ActivityEvent } from './types'

const isActivity = (value: unknown): value is ActivityEvent[] =>
  Array.isArray(value) && value.every((item) => hasRequiredKeys(item, ['id', 'timestamp', 'type', 'severity']))

export const getActivity = (limit = 50, signal?: AbortSignal) =>
  apiClient.get(`${endpoints.activity}?limit=${limit}`, { signal, validate: isActivity })
