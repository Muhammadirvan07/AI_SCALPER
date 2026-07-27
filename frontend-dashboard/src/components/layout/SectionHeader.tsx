import type { LucideIcon } from 'lucide-react'
import type { ReactNode } from 'react'

interface SectionHeaderProps {
  id: string
  eyebrow?: string
  title: string
  description: string
  icon?: LucideIcon
  action?: ReactNode
}

export function SectionHeader({
  id,
  eyebrow,
  title,
  description,
  icon: Icon,
  action,
}: SectionHeaderProps) {
  return (
    <div className="future-section-header mb-5 flex flex-col gap-4 sm:flex-row sm:items-end sm:justify-between">
      <div className="max-w-3xl">
        {eyebrow ? (
          <p className="future-section-header__eyebrow mb-2">
            {Icon ? <Icon aria-hidden="true" className="size-4" /> : null}
            {eyebrow}
          </p>
        ) : null}
        <h2 id={id} className="future-section-header__title text-xl font-semibold text-white sm:text-2xl">
          {title}
        </h2>
        <p className="future-section-header__description mt-2 max-w-2xl text-sm leading-6">
          {description}
        </p>
      </div>
      {action ? <div className="shrink-0">{action}</div> : null}
    </div>
  )
}
