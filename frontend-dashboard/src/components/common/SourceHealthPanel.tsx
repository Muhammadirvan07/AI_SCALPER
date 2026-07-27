import type { DashboardApiSnapshot } from '../../types/dashboardApi'
import { TechnicalPanel } from '../terminal/common/TechnicalPanel'
import { DataFreshnessBadge } from './DataFreshnessBadge'

export function SourceHealthPanel({
  snapshot,
}: {
  snapshot: DashboardApiSnapshot | null
}) {
  const sources = snapshot ? Object.values(snapshot.sources) : []
  const compliantCount = snapshot
    ? Object.values(snapshot.source_contracts).filter((contract) => contract.compliant).length
    : 0
  return (
    <TechnicalPanel
      code="SYS-SRC"
      title="Kesehatan Sumber Data"
      subtitle={`File aktual / modification time / last-known-good / kontrak schema ${compliantCount}/${sources.length}`}
      state={snapshot ? (sources.length ? 'connected' : 'empty') : 'disconnected'}
      className="qt-grid-span-12"
    >
      <div className="qt-source-health">
        {sources.map((source) => {
          const contract = snapshot?.source_contracts[source.key]
          return (
          <article key={source.key}>
            <div>
              <strong>{source.key}</strong>
              <DataFreshnessBadge status={source.status} />
            </div>
            <span>{source.path ?? 'FILE TIDAK DITEMUKAN'}</span>
            <small>
              usia {source.age_seconds === null ? '—' : `${Math.round(source.age_seconds)} dtk`}
              {source.from_last_known_good ? ' · LAST-KNOWN-GOOD' : ''}
            </small>
            <small>
              KONTRAK {contract?.status ?? 'TIDAK TERSEDIA'}
              {contract?.missing_fields.length
                ? ` · KURANG: ${contract.missing_fields.join(', ')}`
                : ''}
            </small>
          </article>
          )
        })}
      </div>
    </TechnicalPanel>
  )
}
