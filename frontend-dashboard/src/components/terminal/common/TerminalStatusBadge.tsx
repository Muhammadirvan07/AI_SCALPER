import { LockKeyhole } from 'lucide-react'
import type { TerminalTone } from '../../../types/terminal'
import { formatStatusLabel } from '../../../utils/statusHelpers'

interface TerminalStatusBadgeProps {
  label: string
  tone?: TerminalTone
  compact?: boolean
}

export function TerminalStatusBadge({
  label,
  tone = 'neutral',
  compact = false,
}: TerminalStatusBadgeProps) {
  const protectedStatus = ['LOCKED', 'BLOCKED', 'OUT OF SCOPE'].some((status) =>
    label.includes(status),
  )
  const displayLabel = formatStatusLabel(label)

  return (
    <span
      className={`qt-badge qt-badge--${tone} ${compact ? 'qt-badge--compact' : ''}`}
      aria-label={`${displayLabel}${protectedStatus ? ', status perlindungan' : ''}`}
    >
      {protectedStatus ? <LockKeyhole aria-hidden="true" className="size-3" /> : null}
      {displayLabel}
    </span>
  )
}
