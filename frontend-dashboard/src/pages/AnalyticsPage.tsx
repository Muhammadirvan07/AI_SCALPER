import { BarChart3 } from 'lucide-react'
import { DomainPageLayout } from '../components/domain/DomainPageLayout'
import { PerformancePanel } from '../components/domain/PerformancePanel'
import { QualityPanel } from '../components/domain/QualityPanel'
import { RiskPanel } from '../components/domain/RiskPanel'

export function AnalyticsPage() {
  return <DomainPageLayout eyebrow="Evaluation window" title="Analytics" description="Analitik performa paper aktual tanpa kurva atau distribusi sintetis." icon={BarChart3}><PerformancePanel /><RiskPanel /><QualityPanel /></DomainPageLayout>
}
