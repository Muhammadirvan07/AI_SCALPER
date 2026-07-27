import { AlertTriangle, CheckCircle2, CircleDashed, ShieldX } from 'lucide-react'
import {
  operationalLabel,
  operationalTone,
  type OperationalTone,
} from '../../utils/landingViewModel'

interface OperationalStatusTagProps {
  value: string | null | undefined
  label?: string
  tone?: OperationalTone
}

export function OperationalStatusTag({
  value,
  label,
  tone,
}: OperationalStatusTagProps) {
  const resolvedTone = tone ?? operationalTone(value)
  const Icon = resolvedTone === 'safe'
    ? CheckCircle2
    : resolvedTone === 'warning'
      ? AlertTriangle
      : resolvedTone === 'blocked'
        ? ShieldX
        : CircleDashed

  return (
    <span className={`ops-status-tag ops-status-tag--${resolvedTone}`}>
      <Icon aria-hidden="true" className="size-3.5 shrink-0" />
      <span>{label ?? operationalLabel(value)}</span>
    </span>
  )
}
