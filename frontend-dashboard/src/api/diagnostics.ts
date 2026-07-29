import { apiClient } from './client'
import { endpoints } from './endpoints'
import { hasRequiredKeys } from './guards'
import type { DiagnosticsData } from './types'

const isDiagnostics = (value: unknown): value is DiagnosticsData =>
  hasRequiredKeys(value, ['final_decision', 'blocking_reasons', 'source']) &&
  Array.isArray(value.blocking_reasons)

export const getDiagnostics = (signal?: AbortSignal) =>
  apiClient.get(endpoints.diagnostics, { signal, validate: isDiagnostics })
