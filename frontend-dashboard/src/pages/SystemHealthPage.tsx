import { ShieldCheck } from 'lucide-react'
import { ActivityPanel } from '../components/domain/ActivityPanel'
import { DomainPageLayout } from '../components/domain/DomainPageLayout'
import { RiskPanel } from '../components/domain/RiskPanel'
import { SystemPanel } from '../components/domain/SystemPanel'

export function SystemHealthPage() {
  return <DomainPageLayout eyebrow="Safety & reliability" title="System Health" description="Status backend dan komponen ditampilkan apa adanya; degraded tidak pernah diubah menjadi healthy." icon={ShieldCheck}><SystemPanel /><RiskPanel /><ActivityPanel className="qt-grid-span-12" /></DomainPageLayout>
}
