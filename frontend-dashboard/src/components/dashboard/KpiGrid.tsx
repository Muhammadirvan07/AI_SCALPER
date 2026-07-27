import type { KpiMetric } from '../../types/dashboard'
import { KpiCard, KpiCardSkeleton } from './KpiCard'

interface KpiGridProps {
  metrics: KpiMetric[]
  loading?: boolean
}

export function KpiGrid({ metrics, loading = false }: KpiGridProps) {
  if (loading) {
    return (
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-5" aria-label="Memuat KPI">
        {Array.from({ length: 9 }, (_, index) => (
          <KpiCardSkeleton key={`kpi-skeleton-${index.toString()}`} />
        ))}
      </div>
    )
  }

  return (
    <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-5">
      {metrics.map((metric) => (
        <KpiCard key={metric.id} metric={metric} />
      ))}
    </div>
  )
}
