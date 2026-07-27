import { useEffect } from 'react'
import { useLocation } from '../../routing/routerContext'

const pageTitles: Record<string, string> = {
  '/': 'AI_SCALPER — Pusat Pemantauan Paper',
  '/overview': 'Ringkasan — AI_SCALPER',
  '/analytics': 'Analitik — AI_SCALPER',
  '/markets': 'Pasar — AI_SCALPER',
  '/news': 'Intelijen Berita — AI_SCALPER',
  '/signals': 'Sinyal — AI_SCALPER',
  '/system-health': 'Kesehatan Sistem — AI_SCALPER',
}

export function ScrollToTop() {
  const { pathname } = useLocation()

  useEffect(() => {
    window.scrollTo({ top: 0, behavior: 'instant' })
    document.title = pageTitles[pathname] ?? 'Halaman Tidak Ditemukan — AI_SCALPER'
  }, [pathname])

  return null
}
