import type { ApiErrorResponse, ApiMeta, ApiResponse } from './types'

export const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value)

export const isString = (value: unknown): value is string => typeof value === 'string'
export const isNullableString = (value: unknown): value is string | null => value === null || isString(value)
export const isNumber = (value: unknown): value is number => typeof value === 'number' && Number.isFinite(value)
export const isNullableNumber = (value: unknown): value is number | null => value === null || isNumber(value)
export const isBoolean = (value: unknown): value is boolean => typeof value === 'boolean'

export const isApiMeta = (value: unknown): value is ApiMeta => {
  if (!isRecord(value)) return false
  return (
    isString(value.server_timestamp) &&
    isBoolean(value.stale) &&
    isBoolean(value.source_available) &&
    isString(value.data_status) &&
    Array.isArray(value.warnings) &&
    value.warnings.every(isString)
  )
}

export const isApiErrorResponse = (value: unknown): value is ApiErrorResponse => {
  if (!isRecord(value) || value.success !== false || !isRecord(value.error)) return false
  return isString(value.error.code) && isString(value.error.message)
}

export const parseApiResponse = <T>(
  value: unknown,
  validateData: (candidate: unknown) => candidate is T,
): ApiResponse<T> | null => {
  if (!isRecord(value) || value.success !== true || !isApiMeta(value.meta)) return null
  if (!validateData(value.data)) return null
  return value as unknown as ApiResponse<T>
}

export const hasRequiredKeys = (value: unknown, keys: string[]): value is Record<string, unknown> =>
  isRecord(value) && keys.every((key) => key in value)

export const isObjectData = (value: unknown): value is Record<string, unknown> => isRecord(value)
export const isArrayData = (value: unknown): value is unknown[] => Array.isArray(value)

export const isPageData = (value: unknown): value is { items: unknown[]; total: number; limit: number; offset: number } =>
  isRecord(value) &&
  Array.isArray(value.items) &&
  isNumber(value.total) &&
  isNumber(value.limit) &&
  isNumber(value.offset)
