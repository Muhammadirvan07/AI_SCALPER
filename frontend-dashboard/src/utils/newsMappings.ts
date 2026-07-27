import type {
  NewsEventStatus,
  NewsImpactLevel,
  PaperDecisionReadiness,
  Tone,
} from '../types/dashboard'

export const newsImpactTone: Record<NewsImpactLevel, Tone> = {
  LOW: 'neutral',
  MEDIUM: 'info',
  HIGH: 'warning',
  CRITICAL: 'negative',
  UNKNOWN: 'neutral',
}

export const paperDecisionTone: Record<PaperDecisionReadiness, Tone> = {
  PAPER_READY: 'positive',
  WAIT: 'warning',
  BLOCKED: 'negative',
  UNAVAILABLE: 'neutral',
}

export const newsEventStatusTone: Record<NewsEventStatus, Tone> = {
  UPCOMING: 'info',
  RELEASED: 'positive',
  LIVE_WINDOW: 'warning',
  UNKNOWN: 'neutral',
}

export const formatNewsEventStatus = (status: NewsEventStatus) =>
  ({
    UPCOMING: 'AKAN DATANG',
    RELEASED: 'DIRILIS',
    LIVE_WINDOW: 'JENDELA HASIL',
    UNKNOWN: 'TIDAK TERSEDIA',
  })[status]

export const formatNewsImpact = (impact: NewsImpactLevel) =>
  ({
    LOW: 'RENDAH',
    MEDIUM: 'SEDANG',
    HIGH: 'TINGGI',
    CRITICAL: 'KRITIS',
    UNKNOWN: 'TIDAK TERSEDIA',
  })[impact]

export const formatNewsSurprise = (
  surprise: 'ABOVE' | 'BELOW' | 'INLINE' | 'PENDING' | 'UNKNOWN',
) =>
  ({
    ABOVE: 'DI ATAS',
    BELOW: 'DI BAWAH',
    INLINE: 'SESUAI',
    PENDING: 'MENUNGGU',
    UNKNOWN: 'TIDAK TERSEDIA',
  })[surprise]

export const formatDirectionBias = (
  direction: 'BULLISH' | 'BEARISH' | 'MIXED' | 'NEUTRAL' | 'UNKNOWN',
) =>
  ({
    BULLISH: 'NAIK',
    BEARISH: 'TURUN',
    MIXED: 'CAMPURAN',
    NEUTRAL: 'NETRAL',
    UNKNOWN: 'TIDAK TERSEDIA',
  })[direction]

export const formatNewsGuard = (
  guard: 'PASS' | 'CAUTION' | 'BLOCKED' | 'UNAVAILABLE',
) =>
  ({
    PASS: 'LOLOS',
    CAUTION: 'WASPADA',
    BLOCKED: 'DIBLOKIR',
    UNAVAILABLE: 'TIDAK TERSEDIA',
  })[guard]

export const formatProjectedVolatility = (
  volatility: 'NORMAL' | 'ELEVATED' | 'HIGH' | 'EXTREME' | 'UNKNOWN',
) =>
  ({
    NORMAL: 'NORMAL',
    ELEVATED: 'MENINGKAT',
    HIGH: 'TINGGI',
    EXTREME: 'EKSTREM',
    UNKNOWN: 'TIDAK TERSEDIA',
  })[volatility]

export const formatSpreadRisk = (
  risk: 'NORMAL' | 'WIDE' | 'UNSTABLE' | 'UNKNOWN',
) =>
  ({
    NORMAL: 'NORMAL',
    WIDE: 'MELEBAR',
    UNSTABLE: 'TIDAK STABIL',
    UNKNOWN: 'TIDAK TERSEDIA',
  })[risk]

export const formatGateStatus = (status: string | boolean) => {
  if (status === true) return 'LOLOS'
  if (status === false) return 'GAGAL'
  const normalized = String(status).trim().toUpperCase()
  if (normalized.startsWith('PASS') || normalized === 'ALLOWED') return 'LOLOS'
  if (normalized.includes('BLOCK')) return 'DIBLOKIR'
  if (normalized.includes('FAIL') || normalized.includes('REJECT')) return 'GAGAL'
  if (normalized === 'CAUTION' || normalized === 'WATCH') return 'WASPADA'
  if (!normalized || normalized === 'UNAVAILABLE' || normalized === 'UNKNOWN') {
    return 'TIDAK TERSEDIA'
  }
  return normalized.replaceAll('_', ' ')
}

const blockerLabels: Record<string, string> = {
  SOURCE_DECISION_WAIT: 'KEPUTUSAN SUMBER: TUNGGU',
  DATA_FRESHNESS_NOT_PASS: 'KESEGARAN DATA BELUM LOLOS',
  SCORE_BELOW_MINIMUM: 'SKOR DI BAWAH MINIMUM',
  SPREAD_GUARD_UNAVAILABLE: 'GUARD SPREAD TIDAK TERSEDIA',
  NEWS_GUARD_BLOCKED: 'DIBLOKIR GUARD BERITA',
  PAIR_GUARD_BLOCKED: 'DIBLOKIR GUARD PAIR',
  STRATEGY_GUARD_BLOCKED: 'DIBLOKIR GUARD STRATEGI',
  SESSION_GUARD_BLOCKED: 'DIBLOKIR GUARD SESI',
}

export const formatDecisionBlocker = (reason: string): string => {
  const normalized = reason.trim().toUpperCase()
  return blockerLabels[normalized] ?? normalized.replaceAll('_', ' ')
}
