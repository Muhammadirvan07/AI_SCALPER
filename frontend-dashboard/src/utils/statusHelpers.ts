import type { GuardStatus, SignalStatus, Tone } from '../types/dashboard'

const positiveValues = new Set([
  'ENABLED',
  'ACTIVE',
  'PRIMARY',
  'OPEN',
  'FRESH',
  'BUY',
  'PAPER_OPEN',
  'PAPER_CLOSED',
  'HEALTHY',
])

const warningValues = new Set([
  'WATCH',
  'WAIT',
  'WEEKEND',
  'ELEVATED',
  'STALE',
  'TIMEOUT',
  'DEGRADED',
])

const negativeValues = new Set([
  'LOCKED',
  'DISABLED',
  'BLOCKED',
  'RESTRICTED',
  'REJECTED',
  'HIGH',
  'OFFLINE',
])

export const getStatusTone = (status: string): Tone => {
  if (positiveValues.has(status)) return 'positive'
  if (warningValues.has(status)) return 'warning'
  if (negativeValues.has(status)) return 'negative'
  if (status === 'SELL') return 'negative'
  return 'neutral'
}

export const isProtectedStatus = (status: GuardStatus | SignalStatus | string) =>
  ['LOCKED', 'TERKUNCI', 'DISABLED', 'NONAKTIF', 'BLOCKED', 'DIBLOKIR', 'RESTRICTED', 'DIBATASI']
    .some((token) => status.includes(token))

const statusLabels: Record<string, string> = {
  ACTIVE: 'AKTIF',
  ALLOWED: 'DIIZINKAN',
  BLOCKED: 'DIBLOKIR',
  BUY: 'BELI',
  CAUTION: 'WASPADA',
  CLOSED: 'TUTUP',
  COMPLETE: 'SELESAI',
  CRYPTO: 'KRIPTO',
  DEGRADED: 'MENURUN',
  DELAYED: 'TERTUNDA',
  DISABLED: 'NONAKTIF',
  DISCONNECTED: 'TERPUTUS',
  ELEVATED: 'MENINGKAT',
  ENABLED: 'AKTIF',
  ERROR: 'KESALAHAN',
  FAIL: 'GAGAL',
  FRESH: 'SEGAR',
  HEALTHY: 'SEHAT',
  HIGH: 'TINGGI',
  LOCKED: 'TERKUNCI (LOCKED)',
  LOADING: 'MEMUAT',
  METALS: 'LOGAM',
  OFFLINE: 'LURING',
  ONLINE: 'DARING',
  OPEN: 'BUKA',
  'OUT OF SCOPE': 'DI LUAR CAKUPAN',
  PAPER_CLOSED: 'PAPER DITUTUP',
  PAPER_OPEN: 'PAPER DIBUKA',
  PAPER_READY: 'PAPER SIAP',
  PARTIAL: 'PARSIAL',
  PASS: 'LOLOS',
  PRIMARY: 'UTAMA',
  'PRIMARY / WEEKEND': 'UTAMA / AKHIR PEKAN',
  REJECTED: 'DITOLAK',
  RESTRICTED: 'DIBATASI',
  SELL: 'JUAL',
  SUCCESS: 'BERHASIL',
  SKIPPED: 'DILEWATI',
  STALE: 'KEDALUWARSA',
  TIMEOUT: 'BATAS WAKTU',
  TREND: 'TREN',
  RANGE: 'RENTANG',
  PANIC: 'PANIK',
  WAIT: 'TUNGGU',
  WAITING: 'MENUNGGU',
  WATCH: 'PANTAU (WATCH)',
  WEEKEND: 'AKHIR PEKAN',
  'WEEKEND PRIMARY': 'UTAMA AKHIR PEKAN',
}

export const formatStatusLabel = (status: string) => statusLabels[status] ?? status

export const getFreshnessLabel = (seconds: number) => {
  if (seconds <= 60) return 'SEGAR'
  if (seconds <= 300) return 'TERTUNDA'
  return 'KEDALUWARSA'
}
