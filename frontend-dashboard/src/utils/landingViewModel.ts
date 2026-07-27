import type {
  ApiPaperOrder,
  DashboardApiSnapshot,
  DashboardSourceMode,
  RealtimeConnectionInfo,
} from '../types/dashboardApi'

export type OperationalTone = 'safe' | 'warning' | 'blocked' | 'neutral'

export interface OperationalActivityItem {
  id: string
  timestamp: string
  title: string
  detail: string
  tone: OperationalTone
}

export interface RecommendedAction {
  title: string
  detail: string
  evidence: string
  tone: OperationalTone
}

const blockedTokens = [
  'BLOCK',
  'FAIL',
  'INVALID',
  'INELIGIBLE',
  'DISABLED',
  'DISCONNECTED',
  'LOCKED',
  'VIOLATION',
]
const warningTokens = [
  'WAIT',
  'PENDING',
  'STALE',
  'PARTIAL',
  'WATCH',
  'CAUTION',
  'UNVERIFIED',
  'UNKNOWN',
  'OBSERVATION',
]
const safeTokens = [
  'PASSED',
  'FRESH',
  'CONNECTED',
  'REALTIME',
  'ONLINE',
  'ENABLED',
  'ACTIVE',
  'COMPLIANT',
  'READY',
  'VERIFIED_ELIGIBLE',
]

const containsToken = (value: string, tokens: readonly string[]) =>
  tokens.some((token) => value.includes(token))

export const operationalTone = (value: string | null | undefined): OperationalTone => {
  const normalized = (value ?? '').toUpperCase()
  if (!normalized) return 'neutral'
  if (containsToken(normalized, blockedTokens)) return 'blocked'
  if (containsToken(normalized, warningTokens)) return 'warning'
  if (containsToken(normalized, safeTokens)) return 'safe'
  return 'neutral'
}

const exactStatusLabels: Record<string, string> = {
  ACTIVE: 'AKTIF',
  BLOCKED: 'DIBLOKIR',
  COMPLIANT: 'PATUH',
  CONNECTED: 'TERHUBUNG',
  DISABLED: 'DINONAKTIFKAN',
  DISCONNECTED: 'TERPUTUS',
  FALSE: 'SALAH / NONAKTIF',
  FRESH: 'SEGAR',
  INVALID: 'TIDAK VALID',
  LOCKED: 'TERKUNCI',
  PARTIAL: 'PARSIAL',
  PASSED: 'LULUS',
  READY: 'SIAP',
  STALE: 'KEDALUWARSA',
  TRUE: 'BENAR / AKTIF',
  UNAVAILABLE: 'TIDAK TERSEDIA',
  UNVERIFIED: 'BELUM TERVERIFIKASI',
  WAIT: 'MENUNGGU',
  WAITING: 'MENUNGGU',
}

export const operationalLabel = (value: string | null | undefined) => {
  if (!value) return 'TIDAK TERVERIFIKASI'
  const normalized = value.trim().toUpperCase()
  return exactStatusLabels[normalized] ?? normalized.replaceAll('_', ' ')
}

export const formatDualTime = (value: string | null | undefined) => {
  if (!value || !Number.isFinite(Date.parse(value))) return null
  const date = new Date(value)
  const baseOptions: Intl.DateTimeFormatOptions = {
    day: '2-digit',
    month: 'short',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
  }
  return {
    iso: date.toISOString(),
    jst: new Intl.DateTimeFormat('id-ID', {
      ...baseOptions,
      timeZone: 'Asia/Tokyo',
    }).format(date),
    utc: new Intl.DateTimeFormat('id-ID', {
      ...baseOptions,
      timeZone: 'UTC',
    }).format(date),
  }
}

export const deriveOperationalMode = (snapshot: DashboardApiSnapshot | null) =>
  snapshot?.session.active_test_mode ??
  snapshot?.summary.system_mode ??
  snapshot?.safety.mode ??
  null

const isClosedOrder = (order: ApiPaperOrder) => {
  if (order.close_time) return true
  const status = (order.status ?? '').toUpperCase()
  return ['CLOSED', 'WIN', 'LOSS', 'TIMEOUT', 'SETTLED'].some((token) =>
    status.includes(token),
  )
}

export const deriveNetR = (snapshot: DashboardApiSnapshot | null) => {
  if (!snapshot) return { value: null, sampleCount: 0, expectedCount: null }
  const expectedCount = snapshot.performance.closed_orders
  const closedOrders = snapshot.paper_orders.filter(isClosedOrder)
  const values = closedOrders
    .map((order) => order.r_multiple)
    .filter((value): value is number => value !== null && Number.isFinite(value))
  const complete =
    expectedCount !== null &&
    expectedCount > 0 &&
    closedOrders.length === expectedCount &&
    values.length === expectedCount
  return {
    value: complete ? values.reduce((sum, value) => sum + value, 0) : null,
    sampleCount: values.length,
    expectedCount,
  }
}

export const deriveSampleStatus = (snapshot: DashboardApiSnapshot | null) => {
  if (!snapshot) return 'TIDAK TERVERIFIKASI'
  const closed = snapshot.performance.closed_orders
  const target = snapshot.summary.closed_target
  if (closed === null || target === null || target <= 0) return 'TIDAK TERVERIFIKASI'
  if (closed < target) return `SAMPEL BELUM CUKUP · ${closed}/${target}`
  if (snapshot.project_progress.blockers.some((blocker) =>
    blocker.toUpperCase().includes('CLEAN_SAMPLE'),
  )) {
    return `TOTAL CLOSED ${closed}/${target} · CLEAN SAMPLE BELUM LULUS`
  }
  return `TARGET SAMPEL TERCAPAI · ${closed}/${target}`
}

const formatBlindUntil = (value: string | null) => {
  const formatted = formatDualTime(value)
  return formatted ? `${formatted.jst} JST` : 'tanggal belum terverifikasi'
}

export const deriveRecommendedAction = (
  snapshot: DashboardApiSnapshot | null,
  sourceMode: DashboardSourceMode,
): RecommendedAction => {
  if (!snapshot || sourceMode === 'DISCONNECTED') {
    return {
      title: 'Pulihkan jalur observasi dashboard',
      detail: 'Periksa backend read-only dan koneksi sumber. Jangan mengambil keputusan promosi sampai snapshot tervalidasi kembali.',
      evidence: 'Snapshot aktual tidak tersedia.',
      tone: 'blocked',
    }
  }
  if (sourceMode === 'STALE') {
    return {
      title: 'Pulihkan pembaruan sumber yang kedaluwarsa',
      detail: 'Periksa runtime penghasil sumber dan heartbeat. Pertahankan observasi fail-closed sampai timestamp sumber kembali segar.',
      evidence: `${snapshot.connection.stale_source_count} sumber ditandai kedaluwarsa.`,
      tone: 'warning',
    }
  }
  if (snapshot.safety.safety_violation) {
    return {
      title: 'Tinjau kontradiksi keselamatan sumber',
      detail: 'Dashboard telah memaksa live tetap terkunci. Tinjau evidence sumber tanpa mengubah batas keselamatan melalui dashboard.',
      evidence: snapshot.safety.violations[0] ?? 'Safety violation terdeteksi.',
      tone: 'blocked',
    }
  }
  const progress = snapshot.project_progress
  const blindUntilMs = progress.blind_until ? Date.parse(progress.blind_until) : Number.NaN
  if (
    Number.isFinite(blindUntilMs) &&
    blindUntilMs > Date.now() &&
    ['BLIND_OBSERVATION_ACTIVE', 'WAITING'].includes(progress.observation_window_status)
  ) {
    return {
      title: 'Lanjutkan observation window tanpa promosi',
      detail: 'Jaga runtime observasi tetap aktif dan tinjau hasil hanya setelah blind-until date tercapai.',
      evidence: `Blind until ${formatBlindUntil(progress.blind_until)}.`,
      tone: 'warning',
    }
  }
  const blocker = progress.blockers[0]
  if (blocker) {
    const upper = blocker.toUpperCase()
    const action = upper.includes('WINDOWS')
      ? 'Verifikasi host Windows, MT5, dan scheduled task observasi.'
      : upper.includes('NEWS')
        ? 'Lengkapi evidence penyedia berita produksi dan freshness-nya.'
        : upper.includes('DRILL')
          ? 'Selesaikan drill operasional dan simpan evidence hasilnya.'
          : 'Tinjau evidence gate pertama yang masih diblokir.'
    return {
      title: 'Selesaikan gate operasional berikutnya',
      detail: action,
      evidence: operationalLabel(blocker),
      tone: 'warning',
    }
  }
  return {
    title: 'Pertahankan observasi dan tinjau evidence terbaru',
    detail: 'Tidak ada instruksi aktivasi order dari dashboard ini. Gunakan halaman kesehatan untuk memeriksa sumber dan guard.',
    evidence: progress.promotion_reason ?? 'Eligibility promosi belum terverifikasi.',
    tone: progress.promotion_eligible === true ? 'safe' : 'warning',
  }
}

export const buildOperationalActivity = (
  snapshot: DashboardApiSnapshot | null,
  connection: RealtimeConnectionInfo,
): OperationalActivityItem[] => {
  if (!snapshot) return []
  const items: OperationalActivityItem[] = [
    {
      id: `snapshot-${snapshot.version}`,
      timestamp: snapshot.generated_at,
      title: `Snapshot v${snapshot.version} diterima`,
      detail: `Status sumber ${operationalLabel(snapshot.connection.status)}.`,
      tone: operationalTone(snapshot.connection.status),
    },
  ]
  if (connection.lastHeartbeatAt) {
    items.push({
      id: `heartbeat-${connection.lastHeartbeatAt}`,
      timestamp: connection.lastHeartbeatAt,
      title: 'Heartbeat WebSocket diterima',
      detail: 'Heartbeat dinilai terpisah dari event data umum.',
      tone: connection.socketActive ? 'safe' : 'warning',
    })
  }
  if (snapshot.safety.safety_violation) {
    items.push({
      id: `safety-${snapshot.version}`,
      timestamp: snapshot.generated_at,
      title: 'Safety guard memblokir kontradiksi',
      detail: snapshot.safety.violations[0] ?? 'Kontradiksi keselamatan terdeteksi.',
      tone: 'blocked',
    })
  }
  const compliantContracts = Object.values(snapshot.source_contracts).filter(
    (contract) => contract.compliant,
  ).length
  if (compliantContracts > 0) {
    items.push({
      id: `contracts-${snapshot.version}`,
      timestamp: snapshot.generated_at,
      title: `${compliantContracts} kontrak sumber tervalidasi`,
      detail: 'Jumlah berasal dari source contract snapshot terbaru.',
      tone: 'safe',
    })
  }
  if (snapshot.connection.stale_source_count > 0) {
    items.push({
      id: `stale-${snapshot.version}`,
      timestamp: snapshot.generated_at,
      title: 'Sumber kedaluwarsa terdeteksi',
      detail: `${snapshot.connection.stale_source_count} sumber melewati ambang freshness masing-masing.`,
      tone: 'warning',
    })
  }
  for (const activity of snapshot.activity) {
    items.push({
      id: `${activity.timestamp}-${activity.category}-${activity.source ?? 'system'}`,
      timestamp: activity.timestamp,
      title: activity.title,
      detail: activity.detail ?? `Sumber: ${activity.source ?? 'tidak terverifikasi'}.`,
      tone: operationalTone(activity.category),
    })
  }
  return items
    .filter((item) => Number.isFinite(Date.parse(item.timestamp)))
    .sort((left, right) => Date.parse(right.timestamp) - Date.parse(left.timestamp))
    .slice(0, 7)
}

export const numericMetric = (
  value: Record<string, unknown>,
  keys: readonly string[],
) => {
  for (const key of keys) {
    const candidate = value[key]
    if (typeof candidate === 'number' && Number.isFinite(candidate)) return candidate
  }
  return null
}
