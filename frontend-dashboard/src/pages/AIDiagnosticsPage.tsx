import { BrainCircuit } from 'lucide-react'
import { DiagnosticsPanel } from '../components/domain/DiagnosticsPanel'
import { EconomicCalendarDiagnosticPanel } from '../components/domain/EconomicCalendarDiagnosticPanel'
import { DomainPageLayout } from '../components/domain/DomainPageLayout'
import { QualityPanel } from '../components/domain/QualityPanel'

export function AIDiagnosticsPage() {
  return <DomainPageLayout eyebrow="Explainable AI" title="AI Diagnostics" description="Keputusan engine dan konteks kalender read-only, tanpa memodifikasi execution." icon={BrainCircuit}><DiagnosticsPanel /><EconomicCalendarDiagnosticPanel /><QualityPanel /></DomainPageLayout>
}
