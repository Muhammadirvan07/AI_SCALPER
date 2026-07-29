import { Settings } from 'lucide-react'
import { DomainPageLayout } from '../components/domain/DomainPageLayout'
import { SafeCommandsPanel } from '../components/domain/SafeCommandsPanel'
import { SystemPanel } from '../components/domain/SystemPanel'

export function SettingsPage() {
  return <DomainPageLayout eyebrow="Runtime operations" title="Settings" description="Konfigurasi koneksi dan refresh snapshot GET-only. Dashboard tidak mempublikasikan command mutasi." icon={Settings}><SafeCommandsPanel /><SystemPanel className="qt-grid-span-4" /></DomainPageLayout>
}
