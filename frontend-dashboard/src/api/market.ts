import { apiClient } from './client'
import { endpoints } from './endpoints'
import { hasRequiredKeys, isString } from './guards'
import type {
  CandleSeries,
  MarketIndicators,
  MarketQuote,
  MarketStatus,
  Timeframe,
} from './types'

const isSymbols = (value: unknown): value is string[] => Array.isArray(value) && value.every(isString)
const isQuote = (value: unknown): value is MarketQuote =>
  hasRequiredKeys(value, ['symbol', 'bid', 'ask', 'last', 'spread', 'source_kind'])
const isCandles = (value: unknown): value is CandleSeries =>
  hasRequiredKeys(value, ['symbol', 'requested_timeframe', 'actual_timeframe', 'candles']) && Array.isArray(value.candles)
const isIndicators = (value: unknown): value is MarketIndicators =>
  hasRequiredKeys(value, ['symbol', 'timeframe', 'trend', 'market_regime'])
const isMarketStatus = (value: unknown): value is MarketStatus =>
  hasRequiredKeys(value, ['symbol', 'market_status', 'stale', 'quote_source'])

export const getMarketSymbols = (signal?: AbortSignal) =>
  apiClient.get(endpoints.marketSymbols, { signal, validate: isSymbols })

export const getMarketQuote = (symbol: string, signal?: AbortSignal) =>
  apiClient.get(endpoints.marketQuote(symbol), { signal, validate: isQuote })

export const getMarketCandles = (
  symbol: string,
  timeframe: Timeframe,
  limit: number,
  signal?: AbortSignal,
) => {
  const query = new URLSearchParams({ timeframe, limit: String(limit) })
  return apiClient.get(`${endpoints.marketCandles(symbol)}?${query}`, { signal, validate: isCandles })
}

export const getMarketIndicators = (symbol: string, timeframe: Timeframe, signal?: AbortSignal) => {
  const query = new URLSearchParams({ timeframe })
  return apiClient.get(`${endpoints.marketIndicators(symbol)}?${query}`, { signal, validate: isIndicators })
}

export const getMarketStatus = (symbol: string, signal?: AbortSignal) =>
  apiClient.get(endpoints.marketStatus(symbol), { signal, validate: isMarketStatus })
