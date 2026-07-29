import { ChartNoAxesCombined } from 'lucide-react'
import { DomainPageLayout } from '../components/domain/DomainPageLayout'
import { PerformancePanel } from '../components/domain/PerformancePanel'
import { QualityPanel } from '../components/domain/QualityPanel'

export function PerformancePage() {
  return <DomainPageLayout eyebrow="Paper analytics" title="Performance" description="Kurva performa, P&L, drawdown, dan statistik dihitung backend dari ledger paper aktual." icon={ChartNoAxesCombined}><PerformancePanel /><QualityPanel /></DomainPageLayout>
}
