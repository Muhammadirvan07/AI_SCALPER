import {
  AlertTriangle,
  Database,
  LoaderCircle,
  RefreshCw,
  WifiOff,
} from 'lucide-react'
import type { ReactNode } from 'react'
import type { TerminalPanelState } from '../../../types/terminal'

interface DataStateBoundaryProps {
  state: TerminalPanelState
  children: ReactNode
  onRetry?: () => void
  preserveContent?: boolean
}

const stateCopy = {
  loading: ['MEMUAT DATA', 'Menyinkronkan cuplikan terminal bertipe.'],
  stale: ['DATA KEDALUWARSA', 'Nilai valid terakhir tetap terlihat selama kesegaran dipulihkan.'],
  partial: ['DATA PARSIAL', 'Beberapa bidang diagnostik sementara tidak tersedia.'],
  disconnected: ['DATA SEMENTARA TIDAK TERSEDIA', 'Aliran pasar terputus. Status keselamatan tetap dipertahankan.'],
  empty: ['TIDAK ADA DATA', 'Sumber tidak mengembalikan catatan untuk modul ini.'],
  error: ['DATA SEMENTARA TIDAK TERSEDIA', 'Modul ini tidak dapat memuat cuplikan data terbaru.'],
  connected: ['', ''],
} as const

export function DataStateBoundary({
  state,
  children,
  onRetry,
  preserveContent = false,
}: DataStateBoundaryProps) {
  if (state === 'connected') return <>{children}</>

  const [title, message] = stateCopy[state]
  const isNonBlocking = preserveContent || state === 'stale' || state === 'partial'
  const Icon =
    state === 'loading'
      ? LoaderCircle
      : state === 'disconnected'
        ? WifiOff
        : state === 'empty'
          ? Database
          : AlertTriangle

  if (isNonBlocking) {
    return (
      <>
        <div className={`qt-state-notice qt-state-notice--${state}`} role="status">
          <Icon aria-hidden="true" className="size-3.5" />
          <strong>{title}</strong>
          <span>{message}</span>
        </div>
        {children}
      </>
    )
  }

  return (
    <div className="qt-state-empty" role={state === 'error' ? 'alert' : 'status'}>
      <Icon
        aria-hidden="true"
        className={`size-5 ${state === 'loading' ? 'motion-safe:animate-spin' : ''}`}
      />
      <strong>{title}</strong>
      <span>{message}</span>
      {state === 'error' && onRetry ? (
        <button type="button" className="qt-button qt-button--secondary" onClick={onRetry}>
          <RefreshCw aria-hidden="true" className="size-3.5" />
          Coba lagi
        </button>
      ) : null}
    </div>
  )
}
