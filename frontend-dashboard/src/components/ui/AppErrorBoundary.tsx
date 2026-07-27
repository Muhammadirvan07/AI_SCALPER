import { Component, type ErrorInfo, type ReactNode } from 'react'
import { AlertTriangle, LockKeyhole, RefreshCw } from 'lucide-react'

interface AppErrorBoundaryProps {
  children: ReactNode
}

interface AppErrorBoundaryState {
  failed: boolean
}

export class AppErrorBoundary extends Component<
  AppErrorBoundaryProps,
  AppErrorBoundaryState
> {
  state: AppErrorBoundaryState = { failed: false }

  static getDerivedStateFromError(): AppErrorBoundaryState {
    return { failed: true }
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error('Dashboard render boundary activated.', error, info)
  }

  private reload = () => window.location.reload()

  render() {
    if (!this.state.failed) return this.props.children

    return (
      <main className="quant-terminal grid min-h-screen place-items-center p-6">
        <section
          className="w-full max-w-xl rounded-2xl border border-amber-400/30 bg-slate-950/90 p-6 text-slate-200 shadow-2xl"
          role="alert"
          aria-labelledby="app-failure-title"
        >
          <AlertTriangle aria-hidden="true" className="mb-4 size-8 text-amber-300" />
          <h1 id="app-failure-title" className="text-xl font-bold">
            Dashboard tidak dapat ditampilkan
          </h1>
          <p className="mt-3 leading-7 text-slate-400">
            Tampilan dihentikan karena terjadi kesalahan internal. Tidak ada data
            pengganti yang ditampilkan dan trading live tetap TERKUNCI (LOCKED).
          </p>
          <div className="mt-4 flex items-center gap-2 text-sm font-semibold text-rose-300">
            <LockKeyhole aria-hidden="true" className="size-4" />
            Kemampuan order: NONAKTIF
          </div>
          <button type="button" className="button-secondary mt-6" onClick={this.reload}>
            <RefreshCw aria-hidden="true" className="size-4" />
            Muat ulang dashboard
          </button>
        </section>
      </main>
    )
  }
}
