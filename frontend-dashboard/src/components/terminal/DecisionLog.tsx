import { ChevronRight } from 'lucide-react'
import { useMemo, useState } from 'react'
import type { DecisionLogEntry, TerminalPanelState } from '../../types/terminal'
import { formatCurrency, formatTime } from '../../utils/formatters'
import { formatStatusLabel } from '../../utils/statusHelpers'
import { TechnicalPanel } from './common/TechnicalPanel'
import { TerminalStatusBadge } from './common/TerminalStatusBadge'

type LogFilter = 'All' | 'Accepted' | 'Wait' | 'Blocked' | 'Closed'

const filters: LogFilter[] = ['All', 'Accepted', 'Wait', 'Blocked', 'Closed']
const filterLabels: Record<LogFilter, string> = {
  All: 'Semua',
  Accepted: 'Diterima',
  Wait: 'Menunggu',
  Blocked: 'Diblokir',
  Closed: 'Ditutup',
}

const resultTone = (result: DecisionLogEntry['result']) => {
  if (result === 'PAPER_OPEN' || result === 'PAPER_CLOSED') return 'safe'
  if (result === 'WAIT' || result === 'TIMEOUT') return 'caution'
  if (result === 'BLOCKED' || result === 'REJECTED') return 'blocked'
  return 'neutral'
}

interface DecisionLogProps {
  entries: DecisionLogEntry[]
  state: TerminalPanelState
  isPaused: boolean
}

export function DecisionLog({ entries, state, isPaused }: DecisionLogProps) {
  const [filter, setFilter] = useState<LogFilter>('All')
  const [selectedId, setSelectedId] = useState<string | null>(null)

  const filtered = useMemo(
    () =>
      entries.filter((entry) => {
        if (filter === 'Accepted') return entry.result === 'PAPER_OPEN'
        if (filter === 'Wait') return entry.result === 'WAIT' || entry.result === 'TIMEOUT'
        if (filter === 'Blocked') return entry.result === 'BLOCKED' || entry.result === 'REJECTED'
        if (filter === 'Closed') return entry.result === 'PAPER_CLOSED'
        return true
      }),
    [entries, filter],
  )

  return (
    <TechnicalPanel
      code="Q05"
      title="Log Keputusan AI_SCALPER"
      subtitle={`${entries.length} peristiwa terbaru · aliran visual ${isPaused ? 'dijeda' : 'aktif'}`}
      state={state}
      className="qt-grid-span-4"
      action={<TerminalStatusBadge label={isPaused ? 'TAMPILAN DIJEDA' : 'TAMBAH OTOMATIS'} tone={isPaused ? 'neutral' : 'positive'} />}
      summary="Log keputusan terbaru mencakup paper dibuka, paper ditutup, menunggu, diblokir, ditolak, dan batas waktu. Tidak ada tindakan log yang dapat mengeksekusi order."
    >
      <div className="qt-log-filters" aria-label="Filter log keputusan">
        {filters.map((item) => (
          <button
            key={item}
            type="button"
            className={`qt-log-filter ${filter === item ? 'is-active' : ''}`}
            aria-pressed={filter === item}
            onClick={() => setFilter(item)}
          >
            {filterLabels[item]}
          </button>
        ))}
      </div>

      <div className="qt-decision-log" role="log" aria-live={isPaused ? 'off' : 'polite'}>
        {filtered.length === 0 ? (
          <p className="qt-decision-log__empty">TIDAK ADA PERISTIWA YANG COCOK</p>
        ) : (
          filtered.map((entry, index) => {
            const open = selectedId === entry.id
            return (
              <article
                key={entry.id}
                className={`qt-log-entry ${index === 0 && !isPaused ? 'qt-log-entry--new' : ''}`}
              >
                <button
                  type="button"
                  className="qt-log-entry__main"
                  aria-expanded={open}
                  onClick={() => setSelectedId(open ? null : entry.id)}
                >
                  <time dateTime={entry.timestamp}>{formatTime(entry.timestamp)}</time>
                  <strong>{entry.pair}</strong>
                  <span className={`qt-tone--${resultTone(entry.result)}`}>{formatStatusLabel(entry.side)}</span>
                  <span>{entry.strategy}</span>
                  <span>{entry.score}/{entry.maximumScore}</span>
                  <TerminalStatusBadge label={entry.result} tone={resultTone(entry.result)} compact />
                  <ChevronRight aria-hidden="true" className={`size-3 transition-transform ${open ? 'rotate-90' : ''}`} />
                </button>
                <div className="qt-log-entry__meta">
                  <span>GUARD {entry.guard}</span>
                  <span>{entry.latencyMs === null ? 'LATENSI —' : `${entry.latencyMs} MS`}</span>
                  {entry.paperPnl !== null ? (
                    <span className={entry.paperPnl >= 0 ? 'qt-tone--positive' : 'qt-tone--blocked'}>
                      PAPER {formatCurrency(entry.paperPnl, true)}
                    </span>
                  ) : null}
                </div>
                {open ? (
                  <div className="qt-log-entry__detail">
                    <p>{entry.reason}</p>
                    <span>DATA {formatStatusLabel(entry.freshness)} · ID {entry.id}</span>
                  </div>
                ) : null}
              </article>
            )
          })
        )}
      </div>
    </TechnicalPanel>
  )
}
