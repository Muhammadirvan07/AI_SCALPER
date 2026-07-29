import { ClipboardList } from 'lucide-react'
import { ActivityPanel } from '../components/domain/ActivityPanel'
import { DomainPageLayout } from '../components/domain/DomainPageLayout'
import { OrdersPanel } from '../components/domain/OrdersPanel'

export function PaperOrdersPage() {
  return <DomainPageLayout eyebrow="Paper execution" title="Paper Orders" description="Ledger simulasi read-only dengan filter, sorting, pagination, dan update realtime." icon={ClipboardList}><OrdersPanel /><ActivityPanel className="qt-grid-span-12" /></DomainPageLayout>
}
