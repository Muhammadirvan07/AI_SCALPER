import {
  Activity,
  BarChart3,
  Crosshair,
  Gauge,
  Layers3,
  RadioTower,
  Scale,
  ShieldAlert,
  Target,
  type LucideIcon,
} from 'lucide-react'
import type { KpiMetric } from '../../types/dashboard'
import { StatusBadge } from './StatusBadge'

const iconMap: Record<KpiMetric['icon'], LucideIcon> = {
  mode: RadioTower,
  quality: ShieldAlert,
  readiness: Gauge,
  pairs: Crosshair,
  orders: Layers3,
  winRate: Target,
  profitFactor: Scale,
  netProfit: BarChart3,
  drawdown: Activity,
}

const iconTone = {
  positive: 'border-emerald-400/20 bg-emerald-400/10 text-emerald-300',
  warning: 'border-amber-400/20 bg-amber-400/10 text-amber-200',
  negative: 'border-red-400/20 bg-red-400/10 text-red-300',
  info: 'border-cyan-400/20 bg-cyan-400/10 text-cyan-200',
  neutral: 'border-slate-400/20 bg-slate-400/10 text-slate-300',
}

interface KpiCardProps {
  metric: KpiMetric
}

export function KpiCard({ metric }: KpiCardProps) {
  const Icon = iconMap[metric.icon]
  const progressPercentage = metric.progress
    ? Math.min(100, (metric.progress.value / metric.progress.max) * 100)
    : 0

  return (
    <article
      className="group panel panel-hover relative min-h-44 overflow-hidden p-4 sm:p-5"
      title={metric.description}
      aria-label={`${metric.label}: ${metric.value}. ${metric.description}`}
    >
      <div className="absolute -top-16 -right-12 size-28 rounded-full bg-cyan-400/[0.05] blur-2xl transition group-hover:bg-cyan-400/[0.09]" />
      <div className="flex items-start justify-between gap-3">
        <span
          className={`grid size-9 place-items-center rounded-xl border ${iconTone[metric.tone]}`}
        >
          <Icon aria-hidden="true" className="size-4" />
        </span>
        <StatusBadge label={metric.badge} tone={metric.tone} className="max-w-[9rem]" />
      </div>

      <div className="mt-5 flex items-end justify-between gap-3">
        <div>
          <p className="text-xs font-medium tracking-wide text-slate-400">{metric.label}</p>
          <p className="mt-1 text-2xl font-semibold tracking-tight text-white">{metric.value}</p>
        </div>

        {metric.progress?.variant === 'ring' ? (
          <div
            className="progress-ring grid size-12 shrink-0 place-items-center rounded-full"
            style={{ '--progress': `${progressPercentage * 3.6}deg` } as React.CSSProperties}
            role="img"
            aria-label={`${progressPercentage.toFixed(0)} percent complete`}
          >
            <span className="grid size-9 place-items-center rounded-full bg-[#0a1322] text-[0.64rem] font-semibold text-cyan-100">
              {progressPercentage.toFixed(0)}%
            </span>
          </div>
        ) : null}
      </div>

      {metric.progress?.variant === 'bar' ? (
        <div className="mt-4">
          <div className="mb-1.5 flex justify-between text-[0.65rem] text-slate-500">
            <span>Progres sampel</span>
            <span>{progressPercentage.toFixed(0)}%</span>
          </div>
          <div className="h-1.5 overflow-hidden rounded-full bg-slate-800">
            <div
              className="h-full rounded-full bg-gradient-to-r from-cyan-400 to-violet-400 motion-safe:animate-progress-in"
              style={{ width: `${progressPercentage}%` }}
            />
          </div>
        </div>
      ) : (
        <p className="mt-4 line-clamp-2 text-xs leading-5 text-slate-500">{metric.description}</p>
      )}
    </article>
  )
}

export function KpiCardSkeleton() {
  return (
    <div className="panel min-h-44 p-5" aria-hidden="true">
      <div className="motion-safe:animate-pulse">
        <div className="flex justify-between">
          <div className="size-9 rounded-xl bg-slate-800" />
          <div className="h-6 w-20 rounded-full bg-slate-800" />
        </div>
        <div className="mt-6 h-3 w-24 rounded bg-slate-800" />
        <div className="mt-3 h-7 w-28 rounded bg-slate-700/70" />
        <div className="mt-4 h-3 w-full rounded bg-slate-800" />
      </div>
    </div>
  )
}
