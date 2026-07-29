import { ArrowRight, ShieldCheck } from 'lucide-react'
import { ActivityPanel } from '../components/domain/ActivityPanel'
import { NextEconomicRiskSummary } from '../components/domain/EconomicCalendarDiagnosticPanel'
import { DomainKpiGrid, OverviewHeader } from '../components/domain/OverviewPanels'
import { QualityPanel } from '../components/domain/QualityPanel'
import { RiskPanel } from '../components/domain/RiskPanel'

export function LandingPage() {
  return (
    <main id="main-content" className="quant-terminal domain-landing">
      <div className="qt-container qt-command-overview-wrap"><OverviewHeader /><DomainKpiGrid /><NextEconomicRiskSummary /></div>
      <div className="qt-container domain-landing__intro"><div><span><ShieldCheck aria-hidden="true" /> Production API gateway connected</span><h2>Trading intelligence without execution ambiguity.</h2><p>Semua nilai berasal dari endpoint domain backend. Data stale tetap terlihat sebagai stale dan field yang hilang tidak diganti angka buatan.</p></div><a href="/overview" className="button-primary">Open command center <ArrowRight aria-hidden="true" /></a></div>
      <div className="qt-container qt-dashboard-grid"><RiskPanel /><QualityPanel /><ActivityPanel /></div>
    </main>
  )
}
