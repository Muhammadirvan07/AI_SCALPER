import { Circle, LockKeyhole } from 'lucide-react'
import type { Tone } from '../../types/dashboard'
import { formatStatusLabel, getStatusTone, isProtectedStatus } from '../../utils/statusHelpers'

interface StatusBadgeProps {
  label: string
  tone?: Tone
  className?: string
  pulse?: boolean
}

const toneClasses: Record<Tone, string> = {
  positive: 'border-emerald-400/25 bg-emerald-400/10 text-emerald-300',
  warning: 'border-amber-400/25 bg-amber-400/10 text-amber-200',
  negative: 'border-red-400/25 bg-red-400/10 text-red-300',
  info: 'border-cyan-400/25 bg-cyan-400/10 text-cyan-200',
  neutral: 'border-slate-400/20 bg-slate-400/10 text-slate-300',
}

export function StatusBadge({ label, tone, className = '', pulse = false }: StatusBadgeProps) {
  const resolvedTone = tone ?? getStatusTone(label)
  const protectedStatus = isProtectedStatus(label)
  const displayLabel = formatStatusLabel(label)

  return (
    <span
      className={`inline-flex min-h-6 max-w-full items-center gap-1.5 rounded-full border px-2.5 py-1 text-[0.68rem] leading-4 font-semibold tracking-[0.12em] break-words uppercase ${toneClasses[resolvedTone]} ${className}`}
    >
      {protectedStatus ? (
        <LockKeyhole aria-hidden="true" className="size-3 shrink-0" />
      ) : (
        <Circle
          aria-hidden="true"
          className={`size-2 shrink-0 fill-current ${pulse ? 'motion-safe:animate-status-pulse' : ''}`}
        />
      )}
      {displayLabel}
    </span>
  )
}
