import type { ReactNode } from 'react'

interface OperationalSectionProps {
  id: string
  eyebrow: string
  title: string
  description?: string
  children: ReactNode
  className?: string
}

export function OperationalSection({
  id,
  eyebrow,
  title,
  description,
  children,
  className = '',
}: OperationalSectionProps) {
  const headingId = `${id}-heading`
  return (
    <section id={id} aria-labelledby={headingId} className={`ops-section ${className}`}>
      <header className="ops-section__header">
        <p>{eyebrow}</p>
        <h2 id={headingId}>{title}</h2>
        {description ? <span>{description}</span> : null}
      </header>
      <div className="ops-section__body">{children}</div>
    </section>
  )
}
