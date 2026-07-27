import type { PaperPerformance, TerminalPanelState } from '../../types/terminal'
import { formatCurrency, formatPercent } from '../../utils/formatters'
import { MetricValue } from './common/MetricValue'
import { TechnicalPanel } from './common/TechnicalPanel'
import { TerminalStatusBadge } from './common/TerminalStatusBadge'

interface PaperPerformancePanelProps {
  performance: PaperPerformance
  state: TerminalPanelState
}

export function PaperPerformancePanel({ performance, state }: PaperPerformancePanelProps) {
  const outcomes = performance.wins + performance.losses + performance.timeouts
  const outcomePercent = (value: number) => (outcomes > 0 ? (value / outcomes) * 100 : 0)
  return (
    <TechnicalPanel
      code="Q14"
      title="Performa Paper"
      subtitle="Sampel kualitas / referensi saldo rendah yang realistis"
      state={state}
      className="qt-grid-span-4"
      action={<TerminalStatusBadge label="REFERENSI $50" tone="neutral" />}
      summary={`Sampel aktual memiliki ${performance.closedOrders} order ditutup: ${performance.wins} menang, ${performance.losses} kalah, dan ${performance.timeouts} timeout. Rasio menang ${performance.winRate.toFixed(2)} persen dan faktor profit ${performance.profitFactor.toFixed(4)}.`}
    >
      <div className="qt-performance-outcomes">
        <div className="qt-performance-outcomes__bar" aria-label={`${performance.wins} menang, ${performance.losses} kalah, dan ${performance.timeouts} batas waktu`}>
          <i className="wins" style={{ width: `${outcomePercent(performance.wins)}%` }} />
          <i className="losses" style={{ width: `${outcomePercent(performance.losses)}%` }} />
          <i className="timeouts" style={{ width: `${outcomePercent(performance.timeouts)}%` }} />
        </div>
        <div>
          <span>MENANG <strong>{performance.wins}</strong></span>
          <span>KALAH <strong>{performance.losses}</strong></span>
          <span>BATAS WAKTU <strong>{performance.timeouts}</strong></span>
          <span>DITUTUP <strong>{performance.closedOrders}/{performance.targetOrders}</strong></span>
        </div>
      </div>
      <div className="qt-performance-grid">
        <MetricValue label="Rasio menang" value={formatPercent(performance.winRate)} tone="caution" />
        <MetricValue label="Faktor profit" value={performance.profitFactor.toFixed(2)} tone="positive" />
        <MetricValue label="Ekspektansi" value={formatCurrency(performance.expectancy, true)} tone="positive" />
        <MetricValue label="Laba bersih" value={formatCurrency(performance.netProfit, true)} tone="positive" />
        <MetricValue label="Drawdown maks." value={formatPercent(performance.maxDrawdown, 2)} tone="warning" />
        <MetricValue label="R rata-rata" value={`${performance.averageR >= 0 ? '+' : ''}${performance.averageR.toFixed(2)}R`} />
      </div>
      <dl className="qt-performance-ranking">
        <div><dt>Strategi terbaik</dt><dd>{performance.bestStrategy}</dd></div>
        <div><dt>Strategi terlemah</dt><dd>{performance.weakestStrategy}</dd></div>
        <div><dt>Pair terbaik</dt><dd>{performance.bestPair}</dd></div>
        <div><dt>Pair diblokir</dt><dd>{performance.blockedPair}</dd></div>
      </dl>
    </TechnicalPanel>
  )
}
