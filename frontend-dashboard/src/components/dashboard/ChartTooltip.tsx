import { formatCurrency, formatPercent } from '../../utils/formatters'

interface TooltipEntry {
  color?: string
  dataKey?: string | number
  name?: string | number
  value?: string | number
  payload?: Record<string, unknown>
}

interface ChartTooltipProps {
  active?: boolean
  payload?: TooltipEntry[]
  label?: string | number
  valueType?: 'currency' | 'percent' | 'number'
  labelPrefix?: string
}

export function ChartTooltip({
  active,
  payload,
  label,
  valueType = 'number',
  labelPrefix,
}: ChartTooltipProps) {
  if (!active || !payload?.length) return null

  const formatValue = (value: string | number | undefined) => {
    const numericValue = Number(value ?? 0)
    if (valueType === 'currency') return formatCurrency(numericValue, true)
    if (valueType === 'percent') return formatPercent(numericValue)
    return numericValue.toFixed(2)
  }

  return (
    <div className="min-w-36 rounded-xl border border-white/10 bg-[#07101f]/95 p-3 shadow-2xl backdrop-blur-xl">
      <p className="mb-2 text-[0.68rem] font-semibold tracking-wider text-slate-400 uppercase">
        {labelPrefix ? `${labelPrefix} ` : ''}
        {label}
      </p>
      <div className="space-y-1.5">
        {payload.map((entry) => (
          <div
            key={`${String(entry.dataKey)}-${String(entry.name)}`}
            className="flex items-center justify-between gap-5 text-xs"
          >
            <span className="flex items-center gap-2 text-slate-400">
              <span className="size-1.5 rounded-full" style={{ backgroundColor: entry.color }} />
              {entry.name}
            </span>
            <span className="font-semibold text-slate-100">{formatValue(entry.value)}</span>
          </div>
        ))}
      </div>
    </div>
  )
}
