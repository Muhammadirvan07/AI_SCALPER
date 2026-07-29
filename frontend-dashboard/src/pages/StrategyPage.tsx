import { Workflow } from 'lucide-react'
import { DiagnosticsPanel } from '../components/domain/DiagnosticsPanel'
import { DomainPageLayout } from '../components/domain/DomainPageLayout'
import { QualityPanel } from '../components/domain/QualityPanel'

export function StrategyPage() {
  return <DomainPageLayout eyebrow="Decision intelligence" title="Strategy" description="Strategi aktif, score, market regime, guard, dan reasoning yang benar-benar tersedia dari engine." icon={Workflow}><DiagnosticsPanel /><QualityPanel /></DomainPageLayout>
}
