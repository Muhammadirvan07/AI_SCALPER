import { apiClient } from './client'
import { endpoints } from './endpoints'
import { hasRequiredKeys } from './guards'
import type { WatchlistItem } from './types'

export const isValidMarketSymbol = (symbol: string) => /^[A-Z0-9._-]{3,20}$/.test(symbol)

const isWatchlist = (value: unknown): value is WatchlistItem[] =>
  Array.isArray(value) && value.every((item) => hasRequiredKeys(item, ['symbol', 'last_price', 'stale']))

export const getWatchlist = async (signal?: AbortSignal) => {
  const response = await apiClient.get(endpoints.watchlist, { signal, validate: isWatchlist })
  return {
    ...response,
    data: response.data.filter((item) => isValidMarketSymbol(item.symbol)),
  }
}
