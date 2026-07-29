import { RefreshCw, ShieldCheck } from 'lucide-react'
import { useState } from 'react'
import { ApiClientError } from '../../api/client'
import { environment } from '../../config/environment'
import { useRealtimeDashboard } from '../../hooks/useRealtimeDashboard'
import { TechnicalPanel } from '../terminal/common/TechnicalPanel'
import { TerminalStatusBadge } from '../terminal/common/TerminalStatusBadge'

export function SafeCommandsPanel({ className = 'qt-grid-span-8' }: { className?: string }) {
  const { refreshAll } = useRealtimeDashboard()
  const [running, setRunning] = useState(false)
  const [notice, setNotice] = useState<{ tone: 'success' | 'error'; message: string } | null>(null)

  const run = async () => {
    if (running) return
    setRunning(true)
    setNotice(null)
    try {
      await refreshAll()
      setNotice({ tone: 'success', message: 'Snapshot dashboard berhasil dimuat ulang melalui endpoint GET read-only.' })
    } catch (reason) {
      const error = reason instanceof ApiClientError ? reason : null
      const message = error?.kind === 'timeout'
        ? 'Refresh melewati batas waktu. Periksa koneksi backend sebelum mencoba lagi.'
        : error?.message ?? 'Snapshot dashboard tidak dapat dimuat ulang.'
      setNotice({ tone: 'error', message })
    } finally {
      setRunning(false)
    }
  }

  return (
    <TechnicalPanel code="SET1" title="Read-only Operations" subtitle="Browser GET-only · no server mutation" className={className} action={<TerminalStatusBadge label="READ ONLY" tone="safe" compact />}>
      <div className="safe-command-grid">
        <button type="button" disabled={running} onClick={() => void run()}>
          <RefreshCw aria-hidden="true" className={running ? 'motion-safe:animate-spin' : ''} />
          <span><strong>Refresh snapshot</strong><small>Muat ulang data REST yang sudah tersedia tanpa memicu fetch atau mutasi server.</small></span>
        </button>
      </div>
      {notice ? <div className={`command-notice command-notice--${notice.tone}`} role={notice.tone === 'error' ? 'alert' : 'status'}>{notice.message}</div> : null}
      <dl className="runtime-config">
        <div><dt>REST API</dt><dd>{environment.apiBaseUrl}</dd></div>
        <div><dt>WebSocket</dt><dd>{environment.websocketUrl}</dd></div>
        <div><dt>Execution boundary</dt><dd><ShieldCheck aria-hidden="true" /> LIVE EXECUTION LOCKED</dd></div>
      </dl>
    </TechnicalPanel>
  )
}
