import { AlertTriangle, DatabaseZap, LoaderCircle, RefreshCw, WifiOff } from 'lucide-react'
import type { ReactNode } from 'react'
import type { ResourceState } from '../../api/types'
import { panelStateFor } from '../../utils/apiDisplay'

interface ResourceStateViewProps<T> {
  resource: ResourceState<T>
  onRetry: () => void
  children: (data: T) => ReactNode
  emptyMessage?: string
  preserveStale?: boolean
}

export function ResourceStateView<T>({
  resource,
  onRetry,
  children,
  emptyMessage = 'Sumber terhubung tetapi belum mengembalikan data.',
  preserveStale = true,
}: ResourceStateViewProps<T>) {
  const state = panelStateFor(resource)
  const canRender = resource.data !== null && (preserveStale || state === 'connected')
  if (canRender && resource.data !== null) return <>{children(resource.data)}</>

  const copy: Record<typeof state, { title: string; message: string; Icon: typeof AlertTriangle }> = {
    loading: { title: 'Memuat data backend', message: 'Mengambil data awal dari REST API AI_SCALPER.', Icon: LoaderCircle },
    empty: { title: 'Data belum tersedia', message: emptyMessage, Icon: DatabaseZap },
    disconnected: { title: 'Backend unavailable', message: 'Could not connect to AI_SCALPER backend at 127.0.0.1:8000.', Icon: WifiOff },
    stale: { title: 'Data stale', message: 'Nilai valid terakhir dipertahankan dan tidak ditandai sebagai live.', Icon: AlertTriangle },
    partial: { title: 'Data parsial', message: resource.error?.message ?? 'Sebagian data tidak dapat diperbarui.', Icon: AlertTriangle },
    error: { title: 'Data tidak tersedia', message: resource.error?.message ?? 'Respons backend tidak dapat digunakan.', Icon: AlertTriangle },
    connected: { title: 'Data tersedia', message: '', Icon: DatabaseZap },
  }
  const content = copy[state]
  const Icon = content.Icon

  return (
    <div className="domain-state" role={state === 'error' || state === 'disconnected' ? 'alert' : 'status'}>
      <Icon aria-hidden="true" className={state === 'loading' ? 'motion-safe:animate-spin' : ''} />
      <strong>{content.title}</strong>
      <p>{content.message}</p>
      {state !== 'loading' ? (
        <button type="button" className="button-secondary" onClick={onRetry}>
          <RefreshCw aria-hidden="true" className="size-4" /> Coba lagi
        </button>
      ) : null}
    </div>
  )
}
