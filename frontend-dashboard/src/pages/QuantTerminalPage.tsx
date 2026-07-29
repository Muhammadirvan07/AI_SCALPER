import { ActivityPanel } from '../components/domain/ActivityPanel'
import { DiagnosticsPanel } from '../components/domain/DiagnosticsPanel'
import { NextEconomicRiskSummary } from '../components/domain/EconomicCalendarDiagnosticPanel'
import { DomainKpiGrid, OverviewHeader } from '../components/domain/OverviewPanels'
import { MarketPanel } from '../components/domain/MarketPanel'
import { PerformancePanel } from '../components/domain/PerformancePanel'
import { QualityPanel } from '../components/domain/QualityPanel'
import { RiskPanel } from '../components/domain/RiskPanel'

export function QuantTerminalPage() {
  return (
    <main id="main-content" className="quant-terminal">
      <div className="qt-container qt-command-overview-wrap"><OverviewHeader /><DomainKpiGrid /><NextEconomicRiskSummary /></div>
      <div className="qt-container qt-dashboard-grid"><PerformancePanel /><MarketPanel className="qt-grid-span-4" /><DiagnosticsPanel /><RiskPanel /><QualityPanel /><ActivityPanel className="qt-grid-span-12" /></div>
    </main>
  )
}
