import { AlertTriangle, DatabaseZap, RefreshCw, WifiOff } from 'lucide-react'
import type { DataStatus } from '../../types/dashboard'
import { formatDateTime } from '../../utils/formatters'

interface DataStatusBannerProps {
  status: DataStatus
  lastSuccessfulUpdate: string | null
  error: string | null
  onRefresh: () => void
}

export function DataStatusBanner({
  status,
  lastSuccessfulUpdate,
  error,
  onRefresh,
}: DataStatusBannerProps) {
  if (status === 'success' || status === 'loading') return null

  const isDisconnected = status === 'disconnected'
  const isError = status === 'error'
  const Icon = isDisconnected ? WifiOff : isError ? AlertTriangle : DatabaseZap

  return (
    <div
      className={`mb-6 flex flex-col gap-4 rounded-2xl border p-4 sm:flex-row sm:items-center sm:justify-between ${
        isError || isDisconnected
          ? 'border-red-400/20 bg-red-400/[0.055]'
          : 'border-amber-400/20 bg-amber-400/[0.055]'
      }`}
      role={isError ? 'alert' : 'status'}
    >
      <div className="flex items-start gap-3">
        <Icon
          aria-hidden="true"
          className={`mt-0.5 size-5 shrink-0 ${
            isError || isDisconnected ? 'text-red-300' : 'text-amber-200'
          }`}
        />
        <div>
          <p className="text-sm font-semibold text-slate-100">
            {status === 'stale'
              ? 'Cuplikan data sudah kedaluwarsa'
              : status === 'partial'
                ? 'Data parsial diterima'
                : status === 'empty'
                  ? 'Sumber terhubung tidak memiliki data'
                  : status === 'disconnected'
                    ? 'Sumber pemantauan terputus'
                    : 'Kesalahan data dashboard'}
          </p>
          <p className="mt-1 text-xs leading-5 text-slate-400">
            {error ??
              (lastSuccessfulUpdate
                ? `Pembaruan berhasil terakhir: ${formatDateTime(lastSuccessfulUpdate)}. Kunci keselamatan tetap aktif.`
                : 'Cuplikan data berhasil belum tersedia. Kunci keselamatan tetap aktif.')}
          </p>
        </div>
      </div>
      <button type="button" onClick={onRefresh} className="button-secondary shrink-0">
        <RefreshCw aria-hidden="true" className="size-4" />
        Perbarui
      </button>
    </div>
  )
}
