import type { LucideIcon } from 'lucide-react'
import type { ReactNode } from 'react'

export function DomainPageLayout({ eyebrow, title, description, icon: Icon, children }: {
  eyebrow: string
  title: string
  description: string
  icon: LucideIcon
  children: ReactNode
}) {
  return (
    <main id="main-content" className="quant-terminal terminal-module-page">
      <div className="qt-container">
        <header className="workspace-page-header"><span><Icon aria-hidden="true" />{eyebrow}</span><h1>{title}</h1><p>{description}</p></header>
      </div>
      <div className="qt-container qt-dashboard-grid">{children}</div>
    </main>
  )
}
