import type { ApiResponse } from './types'

interface CacheEntry<T> {
  value: ApiResponse<T>
  expiresAt: number
}

export class QueryCache {
  private readonly entries = new Map<string, CacheEntry<unknown>>()

  get<T>(key: string): ApiResponse<T> | null {
    const entry = this.entries.get(key)
    if (!entry || entry.expiresAt <= Date.now()) return null
    return structuredClone(entry.value) as ApiResponse<T>
  }

  set<T>(key: string, value: ApiResponse<T>, staleTimeMs: number): void {
    this.entries.set(key, {
      value: structuredClone(value) as ApiResponse<unknown>,
      expiresAt: Date.now() + staleTimeMs,
    })
  }

  update<T>(key: string, updater: (current: T | null) => T, staleTimeMs: number): ApiResponse<T> | null {
    const current = this.entries.get(key) as CacheEntry<T> | undefined
    if (!current) return null
    const next = { ...current.value, data: updater(structuredClone(current.value.data)) }
    this.set(key, next, staleTimeMs)
    return structuredClone(next)
  }

  invalidate(prefix?: string): void {
    if (!prefix) {
      this.entries.clear()
      return
    }
    for (const key of this.entries.keys()) {
      if (key === prefix || key.startsWith(`${prefix}:`)) this.entries.delete(key)
    }
  }
}

export const queryCache = new QueryCache()
