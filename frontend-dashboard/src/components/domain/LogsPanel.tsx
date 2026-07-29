import { ChevronLeft, ChevronRight, Search } from 'lucide-react'
import { useDeferredValue, useState } from 'react'
import { useRealtimeDashboard } from '../../hooks/useRealtimeDashboard'
import { formatTimestamp } from '../../utils/apiDisplay'
import { TechnicalPanel } from '../terminal/common/TechnicalPanel'
import { TerminalStatusBadge } from '../terminal/common/TerminalStatusBadge'
import { ResourceStateView } from './ResourceStateView'

const levels = ['ALL', 'DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'] as const

export function LogsPanel({ className = 'qt-grid-span-12' }: { className?: string }) {
  const { resources, loadLogs, refreshResource } = useRealtimeDashboard()
  const [search, setSearch] = useState('')
  const deferredSearch = useDeferredValue(search)
  const [level, setLevel] = useState<(typeof levels)[number]>('ALL')
  const [component, setComponent] = useState('')
  const [offset, setOffset] = useState(0)
  const limit = 100
  const submit = () => void loadLogs({
    level: level === 'ALL' ? undefined : level,
    component: component || undefined,
    search: deferredSearch || undefined,
    limit,
    offset,
  })

  return (
    <TechnicalPanel
      code="LOG1"
      title="System Logs"
      subtitle="Paginated and redacted by backend"
      state={resources.logs.status === 'loading' ? 'loading' : resources.logs.data ? 'connected' : 'empty'}
      onRetry={() => void refreshResource('logs')}
      preserveContent
      className={className}
      action={<TerminalStatusBadge label={`${resources.logs.data?.items.length ?? 0} ROWS`} tone="neutral" compact />}
    >
      <form className="domain-filterbar" onSubmit={(event) => { event.preventDefault(); setOffset(0); submit() }}>
        <label><Search aria-hidden="true" /><span className="sr-only">Cari log</span><input value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Search message" /></label>
        <label><span>Level</span><select value={level} onChange={(event) => setLevel(event.target.value as (typeof levels)[number])}>{levels.map((item) => <option key={item} value={item}>{item}</option>)}</select></label>
        <label><span>Component</span><input value={component} onChange={(event) => setComponent(event.target.value)} placeholder="decision_engine" /></label>
        <button type="submit" className="button-secondary">Apply filters</button>
      </form>
      <ResourceStateView resource={resources.logs} onRetry={() => void refreshResource('logs')} emptyMessage="Tidak ada baris log yang cocok dengan filter.">
        {(page) => (
          <>
            <div className="domain-log-list" role="log" aria-label="Log backend terbaru">
              {page.items.map((entry) => (
                <article key={entry.id}><time dateTime={entry.timestamp} title={formatTimestamp(entry.timestamp)}>{formatTimestamp(entry.timestamp)}</time><TerminalStatusBadge label={entry.level} tone={entry.level === 'ERROR' || entry.level === 'CRITICAL' ? 'blocked' : entry.level === 'WARNING' ? 'caution' : 'neutral'} compact /><strong>{entry.component}</strong><p>{entry.message}</p></article>
              ))}
            </div>
            <div className="domain-pagination"><span>Offset {page.offset} · max {page.limit}</span><div><button type="button" disabled={offset === 0} onClick={() => { const next = Math.max(0, offset - limit); setOffset(next); void loadLogs({ level: level === 'ALL' ? undefined : level, component: component || undefined, search: deferredSearch || undefined, limit, offset: next }) }} aria-label="Log sebelumnya"><ChevronLeft aria-hidden="true" /></button><button type="button" disabled={page.items.length < limit} onClick={() => { const next = offset + limit; setOffset(next); void loadLogs({ level: level === 'ALL' ? undefined : level, component: component || undefined, search: deferredSearch || undefined, limit, offset: next }) }} aria-label="Log berikutnya"><ChevronRight aria-hidden="true" /></button></div></div>
          </>
        )}
      </ResourceStateView>
    </TechnicalPanel>
  )
}
