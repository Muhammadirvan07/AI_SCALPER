import { ArrowLeft, Radar } from 'lucide-react'
import { Link } from '../routing/Router'

export function NotFoundPage() {
  return (
    <main id="main-content" className="future-page page-container grid min-h-[70vh] place-items-center py-16">
      <div className="panel future-not-found max-w-xl p-8 text-center sm:p-12">
        <span className="future-icon-frame mx-auto grid size-12 place-items-center text-cyan-200">
          <Radar aria-hidden="true" className="size-6" />
        </span>
        <p className="mt-5 text-xs font-semibold tracking-[0.18em] text-cyan-300 uppercase">
          Route tidak ditemukan
        </p>
        <h1 className="mt-2 text-3xl font-semibold text-white">Halaman tidak tersedia</h1>
        <p className="mt-3 text-sm leading-6 text-slate-400">
          Halaman pemantauan yang diminta tidak tersedia. Kontrol keselamatan tetap tidak berubah.
        </p>
        <Link to="/" className="button-primary mt-7">
          <ArrowLeft aria-hidden="true" className="size-4" />
          Kembali ke beranda
        </Link>
      </div>
    </main>
  )
}
