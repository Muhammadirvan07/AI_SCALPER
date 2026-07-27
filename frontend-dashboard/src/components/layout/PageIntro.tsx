import { ChevronRight, LockKeyhole, type LucideIcon } from 'lucide-react'
import { Link } from '../../routing/Router'
import { StatusBadge } from '../dashboard/StatusBadge'

interface PageIntroProps {
  eyebrow: string
  title: string
  description: string
  icon: LucideIcon
}

export function PageIntro({ eyebrow, title, description, icon: Icon }: PageIntroProps) {
  return (
    <header className="future-page-intro">
      <div className="future-page-intro__grid" aria-hidden="true" />
      <div className="page-container relative py-8 sm:py-10">
        <div className="future-page-intro__rail" aria-hidden="true">
          <span>AI_SCALPER // OBSERVATION LAYER</span>
          <span>READ ONLY · PAPER ENVIRONMENT</span>
        </div>

        <nav aria-label="Jejak navigasi" className="future-breadcrumb mb-6 flex items-center gap-1.5 text-xs">
          <Link to="/" className="focus-ring rounded transition hover:text-cyan-200">
            Beranda
          </Link>
          <ChevronRight aria-hidden="true" className="size-3.5" />
          <span aria-current="page" className="text-slate-300">
            {title}
          </span>
        </nav>

        <div className="flex flex-col gap-6 lg:flex-row lg:items-end lg:justify-between">
          <div className="min-w-0 max-w-3xl motion-safe:animate-rise-in">
            <p className="future-eyebrow mb-3">
              <span className="future-icon-frame">
                <Icon aria-hidden="true" className="size-3.5" />
              </span>
              {eyebrow}
            </p>
            <h1 className="future-page-title text-3xl font-semibold text-white sm:text-4xl">
              {title}
            </h1>
            <p className="future-page-description mt-3 max-w-2xl break-words text-sm leading-6 sm:text-base">
              {description}
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <StatusBadge label="KHUSUS PAPER" tone="info" />
            <StatusBadge label="LIVE TERKUNCI (LOCKED)" tone="negative" />
          </div>
        </div>

        <p className="future-safety-note mt-7">
          <LockKeyhole aria-hidden="true" className="size-3.5 text-red-300" />
          Antarmuka pemantauan — kontrol eksekusi tidak tersedia.
        </p>
      </div>
    </header>
  )
}
