import { AdaptiveReasoningLoop } from '../components/terminal/AdaptiveReasoningLoop'
import { AdaptiveScoringEngine } from '../components/terminal/AdaptiveScoringEngine'
import { DecisionLog } from '../components/terminal/DecisionLog'
import { DecisionStateChart } from '../components/terminal/DecisionStateChart'
import { ExecutionCycle } from '../components/terminal/ExecutionCycle'
import { EquityOverview } from '../components/terminal/EquityOverview'
import { MarketCandlestickChart } from '../components/terminal/MarketCandlestickChart'
import { MarketRegimeChart } from '../components/terminal/MarketRegimeChart'
import { PairRotationPanel } from '../components/terminal/PairRotationPanel'
import { PaperPerformancePanel } from '../components/terminal/PaperPerformancePanel'
import { RecentPaperOrders } from '../components/terminal/RecentPaperOrders'
import { RegimeTransitionMatrix } from '../components/terminal/RegimeTransitionMatrix'
import { SignalRadar } from '../components/terminal/SignalRadar'
import { StrategyGuardPanel } from '../components/terminal/StrategyGuardPanel'
import { SystemGuardHealth } from '../components/terminal/SystemGuardHealth'
import { DataStateBoundary } from '../components/terminal/common/DataStateBoundary'
import type {
  TerminalDashboardData,
  TerminalPanelState,
} from '../types/terminal'

interface QuantTerminalPageProps {
  data: TerminalDashboardData | null
  state: TerminalPanelState
  error: string | null
  isPaused: boolean
  onRetry: () => void
}

export function QuantTerminalPage({
  data,
  state,
  error,
  isPaused,
  onRetry,
}: QuantTerminalPageProps) {
  if (!data) {
    return (
      <main id="main-content" className="quant-terminal min-h-[70vh]">
        {error ? (
          <div className="qt-container">
            <div className="qt-terminal-alert" role="alert">
              DATA PASAR TIDAK TERSEDIA · {error} · STATUS KESELAMATAN TETAP TIDAK BERUBAH
            </div>
          </div>
        ) : null}
        <div className="qt-container py-6">
          <DataStateBoundary state={state} onRetry={onRetry}>
            <></>
          </DataStateBoundary>
        </div>
      </main>
    )
  }

  const withData = (available: boolean): TerminalPanelState =>
    available ? state : 'empty'

  return (
    <main id="main-content" className="quant-terminal">
      {error ? (
        <div className="qt-container">
          <div className="qt-terminal-alert" role="alert">
            DATA PASAR MENURUN · {error} · STATUS KESELAMATAN TETAP TIDAK BERUBAH
          </div>
        </div>
      ) : null}

      <div className="qt-container qt-dashboard-grid">
        <EquityOverview
          performance={data.performance}
          state={state}
          onRetry={onRetry}
        />
        <MarketCandlestickChart
          instruments={data.instruments}
          state={state}
          onRetry={onRetry}
        />
        <ExecutionCycle stages={data.executionCycle} state={state} />
        <MarketRegimeChart
          history={data.regimeHistory}
          current={data.regimeCurrent}
          state={withData(data.regimeCurrent.classification !== 'TIDAK TERSEDIA')}
          onRetry={onRetry}
        />
        <DecisionLog entries={data.decisionLog} state={withData(data.decisionLog.length > 0)} isPaused={isPaused} />
        <DecisionStateChart data={data.decisionStates} state={withData(data.decisionStates.states.length > 0)} />
        <AdaptiveReasoningLoop nodes={data.reasoningNodes} state={withData(data.reasoningNodes.length > 0)} isPaused={isPaused} />
        <SignalRadar metrics={data.signalRadar} setup={data.signalSetup} state={withData(data.signalRadar.length > 0)} />
        <AdaptiveScoringEngine
          contributions={data.scoreContributions}
          result={data.scoringResult}
          state={withData(data.scoringResult.available)}
        />
        <RegimeTransitionMatrix
          transitions={data.regimeTransitions}
          summary={data.transitionSummary}
          state={withData(data.regimeTransitions.length > 0)}
        />
        <SystemGuardHealth
          guards={data.systemGuards}
          healthMetrics={data.healthMetrics}
          data={data}
          state={state}
          onRetry={onRetry}
        />
        <PairRotationPanel pairs={data.pairRotation} state={withData(data.pairRotation.length > 0)} />
        <StrategyGuardPanel strategies={data.strategyGuards} state={withData(data.strategyGuards.length > 0)} />
        <PaperPerformancePanel performance={data.performance} state={state} />
        <RecentPaperOrders entries={data.decisionLog} state={state} />
      </div>
    </main>
  )
}
