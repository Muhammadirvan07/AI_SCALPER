import type { LucideIcon } from 'lucide-react'
import type { ReactNode } from 'react'
import type { DataStatus } from '../../types/dashboard'
import { DataStatusBanner } from '../dashboard/DataStatusBanner'
import { PageIntro } from './PageIntro'

interface DashboardPageShellProps {
  eyebrow: string
  title: string
  description: string
  icon: LucideIcon
  status: DataStatus
  error: string | null
  lastSuccessfulUpdate: string | null
  onRefresh: () => void
  children: ReactNode
}

export function DashboardPageShell({
  eyebrow,
  title,
  description,
  icon,
  status,
  error,
  lastSuccessfulUpdate,
  onRefresh,
  children,
}: DashboardPageShellProps) {
  return (
    <main
      id="main-content"
      className="future-page min-h-[calc(100vh-4rem)] text-slate-200"
    >
      <div className="future-page__backdrop" aria-hidden="true">
        <span className="future-page__axis future-page__axis--x" />
        <span className="future-page__axis future-page__axis--y" />
      </div>
      <PageIntro eyebrow={eyebrow} title={title} description={description} icon={icon} />
      <div className="page-container future-page__content py-8 sm:py-10">
        <DataStatusBanner
          status={status}
          lastSuccessfulUpdate={lastSuccessfulUpdate}
          error={error}
          onRefresh={onRefresh}
        />
        {children}
      </div>
    </main>
  )
}
