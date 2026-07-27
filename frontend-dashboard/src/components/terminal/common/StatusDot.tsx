import type { TerminalTone } from '../../../types/terminal'
import { formatStatusLabel } from '../../../utils/statusHelpers'

interface StatusDotProps {
  tone: TerminalTone
  label: string
  pulse?: boolean
}

export function StatusDot({ tone, label, pulse = false }: StatusDotProps) {
  const displayLabel = formatStatusLabel(label)

  return (
    <span className="qt-status-dot-wrap">
      <span
        aria-hidden="true"
        className={`qt-status-dot qt-status-dot--${tone} ${pulse ? 'qt-status-dot--pulse' : ''}`}
      />
      <span>{displayLabel}</span>
    </span>
  )
}
