import { ShieldAlert } from 'lucide-react'
import { DomainPageLayout } from '../components/domain/DomainPageLayout'
import { QualityPanel } from '../components/domain/QualityPanel'
import { RiskPanel } from '../components/domain/RiskPanel'

export function RiskManagementPage() {
  return <DomainPageLayout eyebrow="Fail-closed controls" title="Risk Management" description="Engine limit, backend cap, effective lot, drawdown, cooldown, dan recovery status." icon={ShieldAlert}><RiskPanel className="qt-grid-span-8" /><QualityPanel /></DomainPageLayout>
}
