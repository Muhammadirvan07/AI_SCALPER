import type { ReasoningNode, TerminalPanelState } from '../../types/terminal'
import { terminalChartColors as chart } from '../../utils/terminalTheme'
import { TechnicalPanel } from './common/TechnicalPanel'
import { TerminalStatusBadge } from './common/TerminalStatusBadge'

interface AdaptiveReasoningLoopProps {
  nodes: ReasoningNode[]
  state: TerminalPanelState
  isPaused: boolean
}

const nodePosition: Record<string, [number, number]> = {
  'reason-data': [85, 82],
  'reason-detect': [215, 48],
  'reason-classify': [215, 164],
  'reason-score': [85, 204],
  'gate-quality': [390, 76],
  'gate-risk': [390, 128],
  'gate-session': [390, 180],
  'reason-execute': [635, 50],
  'reason-monitor': [765, 82],
  'reason-evaluate': [765, 204],
  'reason-learn': [635, 236],
}

function ReasoningSvgNode({ node }: { node: ReasoningNode }) {
  const [x, y] = nodePosition[node.id] ?? [0, 0]
  const width = node.group === 'gate' ? 128 : 116
  const tone = node.status === 'PASS' ? chart.safe : node.status === 'ACTIVE' ? chart.caution : chart.neutral
  return (
    <g transform={`translate(${x} ${y})`}>
      <rect x={-width / 2} y="-24" width={width} height="48" rx="3" fill={chart.surface} stroke={tone} />
      <circle cx={-width / 2 + 9} cy="-14" r="3" fill={tone} />
      <text x="0" y="-4" textAnchor="middle" className="qt-loop-node-label">{node.label}</text>
      <text x="0" y="11" textAnchor="middle" className="qt-loop-node-meta">
        {node.latencyMs}MS · {(node.passRate * 100).toFixed(0)}% LOLOS
      </text>
    </g>
  )
}

export function AdaptiveReasoningLoop({ nodes, state, isPaused }: AdaptiveReasoningLoopProps) {
  const totalSamples = nodes.reduce((total, node) => total + node.sampleCount, 0)
  const averageLatency =
    nodes.length > 0
      ? nodes.reduce((total, node) => total + node.latencyMs, 0) / nodes.length
      : null
  const averagePass =
    nodes.length > 0
      ? nodes.reduce((total, node) => total + node.passRate, 0) / nodes.length
      : null
  const averageRejection =
    nodes.length > 0
      ? nodes.reduce((total, node) => total + node.rejectionRate, 0) / nodes.length
      : null
  return (
    <TechnicalPanel
      code="Q07"
      title="Siklus Penalaran Adaptif"
      subtitle="Deteksi berkelanjutan → gate → umpan balik evaluasi paper"
      state={state}
      className="qt-grid-span-8"
      action={
        <TerminalStatusBadge
          label={totalSamples > 0 ? `${totalSamples.toLocaleString('id-ID')} SAMPEL` : 'METRIK TIDAK TERSEDIA'}
          tone={totalSamples > 0 ? 'positive' : 'neutral'}
        />
      }
      summary={`${nodes.length} node penalaran tersedia dari snapshot. Dashboard tidak mengarang metrik node yang tidak disediakan sumber.`}
    >
      <div className="qt-reasoning-loop">
        <svg viewBox="0 0 850 286" role="img" aria-label="Siklus penalaran adaptif dari data melalui gate kualitas dan risiko menuju evaluasi paper dan pembelajaran.">
          <defs>
            <marker id="qtArrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="5" markerHeight="5" orient="auto-start-reverse">
              <path d="M 0 0 L 10 5 L 0 10 z" fill={chart.muted} />
            </marker>
          </defs>
          <path d="M85 82 C85 18, 260 6, 260 82 C260 128, 260 192, 85 204 C20 204, 20 82, 85 82" className={`qt-flow-line ${isPaused ? 'is-paused' : ''}`} markerEnd="url(#qtArrow)" />
          <path d="M275 126 C320 126, 330 128, 326 128" className={`qt-flow-line ${isPaused ? 'is-paused' : ''}`} markerEnd="url(#qtArrow)" />
          <path d="M454 128 C510 128, 545 128, 575 128" className={`qt-flow-line ${isPaused ? 'is-paused' : ''}`} markerEnd="url(#qtArrow)" />
          <path d="M635 50 C828 30, 828 252, 635 236 C570 228, 570 58, 635 50" className={`qt-flow-line ${isPaused ? 'is-paused' : ''}`} markerEnd="url(#qtArrow)" />
          <path d="M635 236 C540 284, 270 284, 85 204" className={`qt-flow-line qt-flow-line--return ${isPaused ? 'is-paused' : ''}`} markerEnd="url(#qtArrow)" />
          <text x="410" y="264" textAnchor="middle" className="qt-loop-return-label">UMPAN BALIK KUALITAS / PEMBELAJARAN SAMPEL / KALIBRASI ULANG GUARD</text>

          {nodes.map((node) => <ReasoningSvgNode key={node.id} node={node} />)}

          <g transform="translate(520 128)">
            <circle r="42" fill={chart.surfaceRaised} stroke={chart.caution} strokeWidth="1.5" />
            <circle r="34" fill="none" stroke={chart.lineStrong} strokeDasharray="2 3" />
            <text x="0" y="-6" textAnchor="middle" className="qt-loop-gate-label">GATE LOLOS</text>
            <text x="0" y="10" textAnchor="middle" className="qt-loop-gate-value">
              {totalSamples > 0 ? totalSamples.toLocaleString('id-ID') : '—'}
            </text>
            <text x="0" y="23" textAnchor="middle" className="qt-loop-node-meta">SAMPEL</text>
          </g>
        </svg>
      </div>
      <div className="qt-loop-stats">
        {[
          ['LATENSI RATA-RATA', averageLatency === null ? '—' : `${averageLatency.toFixed(0)} MS`],
          ['RATA-RATA LOLOS', averagePass === null ? '—' : `${(averagePass * 100).toFixed(0)}%`],
          ['RATA-RATA PENOLAKAN', averageRejection === null ? '—' : `${(averageRejection * 100).toFixed(0)}%`],
          ['SAMPEL NODE', totalSamples > 0 ? totalSamples.toLocaleString('id-ID') : '—'],
        ].map(([label, value]) => (
          <span key={label}><em>{label}</em><strong>{value}</strong></span>
        ))}
      </div>
    </TechnicalPanel>
  )
}
