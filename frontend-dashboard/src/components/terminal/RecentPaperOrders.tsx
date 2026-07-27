import type { DecisionLogEntry, TerminalPanelState } from '../../types/terminal'
import { formatCurrency, formatTime } from '../../utils/formatters'
import { formatStatusLabel } from '../../utils/statusHelpers'
import { TechnicalPanel } from './common/TechnicalPanel'
import { TerminalStatusBadge } from './common/TerminalStatusBadge'

interface RecentPaperOrdersProps {
  entries: DecisionLogEntry[]
  state: TerminalPanelState
}

export function RecentPaperOrders({ entries, state }: RecentPaperOrdersProps) {
  const orders = entries.filter(
    (entry) => entry.result === 'PAPER_OPEN' || entry.result === 'PAPER_CLOSED',
  )
  return (
    <TechnicalPanel
      code="Q15"
      title="Order Paper Terbaru"
      subtitle="Siklus order simulasi / tanpa eksekusi broker"
      state={state}
      className="qt-grid-span-12"
      action={<TerminalStatusBadge label="KHUSUS PAPER" tone="positive" />}
      summary="Catatan order paper terbaru adalah peristiwa simulasi dan tidak dapat dikirim ke broker."
    >
      <div
        className="qt-paper-orders-wrap"
        tabIndex={0}
        role="region"
        aria-label="Tabel order paper terbaru yang dapat digulir"
      >
        <table className="qt-paper-orders">
          <caption className="sr-only">Peristiwa order khusus paper terbaru</caption>
          <colgroup>
            <col className="qt-paper-orders__time" />
            <col className="qt-paper-orders__id" />
            <col className="qt-paper-orders__pair" />
            <col className="qt-paper-orders__side" />
            <col className="qt-paper-orders__strategy" />
            <col className="qt-paper-orders__score" />
            <col className="qt-paper-orders__status" />
            <col className="qt-paper-orders__guard" />
            <col className="qt-paper-orders__latency" />
            <col className="qt-paper-orders__pnl" />
          </colgroup>
          <thead>
            <tr>
              <th>Waktu</th><th>ID</th><th>Pair</th><th>Sisi</th><th>Strategi</th>
              <th>Skor</th><th>Status</th><th>Guard</th><th>Latensi</th><th>P&amp;L Paper</th>
            </tr>
          </thead>
          <tbody>
            {orders.map((order) => (
              <tr key={order.id}>
                <td data-label="Waktu">{formatTime(order.timestamp)}</td>
                <td data-label="ID" title={order.id}>{order.id}</td>
                <th data-label="Pair" scope="row">{order.pair}</th>
                <td data-label="Sisi">{formatStatusLabel(order.side)}</td>
                <td data-label="Strategi" title={order.strategy}>{order.strategy}</td>
                <td data-label="Skor">{order.score}/{order.maximumScore}</td>
                <td data-label="Status"><TerminalStatusBadge label={order.result} tone="safe" compact /></td>
                <td data-label="Guard" title={order.guard}>{order.guard}</td>
                <td data-label="Latensi">{order.latencyMs === null ? '—' : `${order.latencyMs} MS`}</td>
                <td
                  data-label="P&L Paper"
                  className={order.paperPnl === null ? '' : order.paperPnl >= 0 ? 'qt-tone--positive' : 'qt-tone--blocked'}
                >
                  {order.paperPnl === null ? 'BUKA' : formatCurrency(order.paperPnl, true)}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </TechnicalPanel>
  )
}
