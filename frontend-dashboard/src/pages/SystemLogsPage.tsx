import { ScrollText } from 'lucide-react'
import { ActivityPanel } from '../components/domain/ActivityPanel'
import { DomainPageLayout } from '../components/domain/DomainPageLayout'
import { LogsPanel } from '../components/domain/LogsPanel'

export function SystemLogsPage() {
  return <DomainPageLayout eyebrow="Operational evidence" title="System Logs" description="Log backend yang dipaginasi, difilter, dan sudah direduksi dari data sensitif." icon={ScrollText}><LogsPanel /><ActivityPanel className="qt-grid-span-12" /></DomainPageLayout>
}
