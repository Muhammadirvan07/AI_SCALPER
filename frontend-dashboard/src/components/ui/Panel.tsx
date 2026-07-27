import type { ReactNode } from 'react'

interface PanelProps {
  children: ReactNode
  className?: string
  id?: string
  labelledBy?: string
}

export function Panel({ children, className = '', id, labelledBy }: PanelProps) {
  return (
    <section
      id={id}
      aria-labelledby={labelledBy}
      data-surface="module"
      className={`panel ${className}`}
    >
      {children}
    </section>
  )
}
