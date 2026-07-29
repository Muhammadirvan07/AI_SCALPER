import { AlertTriangle, DatabaseZap, LoaderCircle, RefreshCw, WifiOff } from 'lucide-react'
import type { TerminalPanelState } from '../../types/terminal'

interface PanelStateProps {
  state: Extract<TerminalPanelState, 'loading' | 'empty' | 'disconnected' | 'partial' | 'error'>
  title?: string
  message?: string
  onRetry?: () => void
  compact?: boolean
}

const stateCopy = {
  loading: {
    title: 'Memuat data pemantauan',
    message: 'Menyiapkan cuplikan dashboard aman terbaru.',
    icon: LoaderCircle,
  },
  empty: {
    title: 'Tidak ada data pada panel ini',
    message: 'Sumber terhubung tetapi belum mengembalikan catatan.',
    icon: DatabaseZap,
  },
  disconnected: {
    title: 'Sumber terputus',
    message: 'Aliran data waktu nyata tidak tersedia. Kontrol keselamatan tetap TERKUNCI (LOCKED).',
    icon: WifiOff,
  },
  partial: {
    title: 'Diagnostik parsial',
    message: 'Beberapa bidang tidak tersedia; data pemantauan yang ada tetap ditampilkan.',
    icon: AlertTriangle,
  },
  error: {
    title: 'Data panel tidak tersedia',
    message: 'Panel ini tidak dapat membaca cuplikan data saat ini.',
    icon: AlertTriangle,
  },
}

export function PanelState({
  state,
  title,
  message,
  onRetry,
  compact = false,
}: PanelStateProps) {
  const content = stateCopy[state]
  const Icon = content.icon

  return (
    <div
      className={`flex flex-col items-center justify-center rounded-2xl border border-dashed border-slate-700/70 bg-slate-950/30 px-5 text-center ${
        compact ? 'min-h-32 py-5' : 'min-h-64 py-10'
      }`}
      role={state === 'error' ? 'alert' : 'status'}
    >
      <span className="mb-3 grid size-10 place-items-center rounded-xl border border-slate-700 bg-slate-900 text-slate-400">
        <Icon
          aria-hidden="true"
          className={`size-5 ${state === 'loading' ? 'motion-safe:animate-spin' : ''}`}
        />
      </span>
      <p className="font-semibold text-slate-200">{title ?? content.title}</p>
      <p className="mt-1 max-w-md text-sm leading-6 text-slate-400">{message ?? content.message}</p>
      {onRetry && state !== 'loading' ? (
        <button type="button" onClick={onRetry} className="button-secondary mt-4">
          <RefreshCw aria-hidden="true" className="size-4" />
          Coba ulang cuplikan
        </button>
      ) : null}
    </div>
  )
}
