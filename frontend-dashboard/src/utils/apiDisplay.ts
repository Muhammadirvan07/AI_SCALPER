import type { ApiMeta, ResourceState } from '../api/types'
import type { ConnectionSnapshot } from '../realtime/websocketTypes'
import type { TerminalPanelState } from '../types/terminal'

export const unavailable = '—'

export const formatNullableCurrency = (value: number | null, showSign = false) => {
  if (value === null || !Number.isFinite(value)) return unavailable
  const formatted = new Intl.NumberFormat('en-US', {
    style: 'currency',
    currency: 'USD',
    minimumFractionDigits: 2,
    maximumFractionDigits: 2,
  }).format(Math.abs(value))
  if (showSign && value !== 0) return `${value > 0 ? '+' : '-'}${formatted}`
  return value < 0 ? `-${formatted}` : formatted
}

export const formatNullablePercent = (value: number | null, digits = 1, showSign = false) => {
  if (value === null || !Number.isFinite(value)) return unavailable
  return `${showSign && value > 0 ? '+' : ''}${value.toFixed(digits)}%`
}

export const formatNullableNumber = (value: number | null, digits = 2) =>
  value === null || !Number.isFinite(value) ? unavailable : value.toFixed(digits)

export const formatNullableCount = (value: number | null) =>
  value === null || !Number.isFinite(value) ? unavailable : value.toLocaleString('id-ID')

export const formatTimestamp = (value: string | null, options?: Intl.DateTimeFormatOptions) => {
  if (!value || Number.isNaN(Date.parse(value))) return unavailable
  return new Intl.DateTimeFormat('id-ID', options ?? {
    day: '2-digit',
    month: 'short',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
    timeZone: 'Asia/Tokyo',
  }).format(new Date(value))
}

export const relativeTime = (value: string | null) => {
  if (!value || Number.isNaN(Date.parse(value))) return 'Tidak pernah'
  const seconds = Math.max(0, Math.round((Date.now() - Date.parse(value)) / 1000))
  if (seconds < 60) return `${seconds} detik lalu`
  const minutes = Math.floor(seconds / 60)
  if (minutes < 60) return `${minutes} menit lalu`
  const hours = Math.floor(minutes / 60)
  if (hours < 24) return `${hours} jam lalu`
  return `${Math.floor(hours / 24)} hari lalu`
}

export type DataMode = 'LIVE' | 'DELAYED' | 'STALE' | 'OFFLINE' | 'UNAVAILABLE'

export const dataMode = (meta: ApiMeta | null, connection: ConnectionSnapshot): DataMode => {
  if (connection.state === 'OFFLINE' || connection.state === 'ERROR') return 'OFFLINE'
  if (!meta?.source_available) return 'UNAVAILABLE'
  if (meta.stale) return 'STALE'
  if (connection.state === 'RECONNECTING' || connection.state === 'CONNECTING' || connection.state === 'DELAYED') {
    return 'DELAYED'
  }
  return 'LIVE'
}

export const panelStateFor = <T>(resource: ResourceState<T>): TerminalPanelState => {
  if (resource.status === 'loading' || resource.status === 'idle') return 'loading'
  if (resource.status === 'error' && resource.data === null) {
    return resource.error?.kind === 'network' ? 'disconnected' : 'error'
  }
  if (resource.data === null) return 'empty'
  if (resource.meta?.stale) return 'stale'
  if (resource.status === 'error') return 'partial'
  return 'connected'
}

export const nullReason = (value: unknown) =>
  value === null || value === undefined ? 'Not provided by engine' : null
