import { LockKeyhole } from 'lucide-react'
import type { RealtimeConnectionInfo } from '../../types/dashboardApi'
import type { TerminalDashboardData } from '../../types/terminal'
import { formatStatusLabel } from '../../utils/statusHelpers'
import { StatusDot } from './common/StatusDot'

interface TerminalFooterProps {
  data: TerminalDashboardData | null
  connection: RealtimeConnectionInfo
}

export function TerminalFooter({ data, connection }: TerminalFooterProps) {
  const mockMode = connection.sourceMode === 'MOCK FALLBACK'
  const observed = data !== null && !mockMode && connection.sourceMode !== 'DISCONNECTED'
  const items = [
    ['AI_SCALPER', observed ? 'TERAMATI' : mockMode ? 'MOCK' : 'TIDAK TERAMATI'],
    ['MODE', mockMode ? 'MOCK DEVELOPMENT' : 'HANYA-BACA'],
    ['LIVE', 'TERKUNCI (LOCKED)'],
    ['KUALITAS', data ? formatStatusLabel(data.summary.qualityStatus) : '—'],
    ['KESIAPAN', data ? data.readiness.score.toString() : '—'],
    ['DITUTUP', data ? `${data.performance.closedOrders}/${data.performance.targetOrders}` : '—'],
    ['UTAMA', data?.runtime.activePair ?? '—'],
    ['WS', connection.socketActive ? 'AKTIF' : 'TIDAK AKTIF'],
    ['DATA', data?.summary.dataSource ?? 'TIDAK TERSEDIA'],
    ['VERSI', data?.summary.systemVersion ?? '—'],
  ]

  return (
    <footer className="qt-footer">
      <div className="qt-footer__track">
        <StatusDot
          tone={observed ? 'safe' : mockMode ? 'caution' : 'blocked'}
          label={observed ? 'SISTEM TERAMATI' : mockMode ? 'DATA MOCK' : 'SISTEM TIDAK TERAMATI'}
          pulse={observed}
        />
        {items.map(([label, value]) => (
          <span key={label} className="qt-footer__item">
            <em>{label}</em> {value}
          </span>
        ))}
      </div>
      <p>
        <LockKeyhole aria-hidden="true" className="size-3.5" />
        Hanya untuk lingkungan trading paper dan riset. Eksekusi trading live tetap TERKUNCI (LOCKED).
      </p>
    </footer>
  )
}
