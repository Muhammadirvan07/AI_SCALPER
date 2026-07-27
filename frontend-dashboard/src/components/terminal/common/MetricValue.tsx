import type { ReactNode } from 'react'
import type { TerminalTone } from '../../../types/terminal'

interface MetricValueProps {
  label: string
  value: ReactNode
  detail?: ReactNode
  tone?: TerminalTone
  size?: 'sm' | 'md' | 'lg' | 'hero'
}

export function MetricValue({
  label,
  value,
  detail,
  tone = 'neutral',
  size = 'md',
}: MetricValueProps) {
  return (
    <div className="qt-metric">
      <span className="qt-micro-label">{label}</span>
      <strong className={`qt-metric__value qt-metric__value--${size} qt-tone--${tone}`}>
        {value}
      </strong>
      {detail ? <span className="qt-metric__detail">{detail}</span> : null}
    </div>
  )
}
