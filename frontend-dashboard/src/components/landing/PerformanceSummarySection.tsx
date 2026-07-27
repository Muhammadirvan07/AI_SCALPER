import { BarChart3, Scale } from 'lucide-react'
import type { DashboardApiSnapshot } from '../../types/dashboardApi'
import { formatCurrency, formatPercent } from '../../utils/formatters'
import {
  deriveNetR,
  deriveSampleStatus,
  numericMetric,
} from '../../utils/landingViewModel'
import { OperationalSection } from './OperationalSection'
import { OperationalStatusTag } from './OperationalStatusTag'

const formatNullable = (
  value: number | null | undefined,
  formatter: (number: number) => string,
) => value === null || value === undefined ? 'TIDAK TERVERIFIKASI' : formatter(value)

interface PerformanceRowsProps {
  title: string
  rows: Record<string, Record<string, unknown>>
}

function PerformanceRows({ title, rows }: PerformanceRowsProps) {
  const entries = Object.entries(rows).slice(0, 5)
  return (
    <section className="ops-performance-breakdown" aria-label={title}>
      <h3>{title}</h3>
      {entries.length ? (
        <div className="ops-table-wrap">
          <table>
            <thead>
              <tr>
                <th scope="col">Nama</th>
                <th scope="col">Sampel</th>
                <th scope="col">Win rate</th>
                <th scope="col">Hasil paper</th>
              </tr>
            </thead>
            <tbody>
              {entries.map(([name, metrics]) => {
                const total = numericMetric(metrics, ['total', 'trades', 'closed_orders'])
                const wins = numericMetric(metrics, ['wins'])
                const explicitWinRate = numericMetric(metrics, ['win_rate', 'winrate_percent'])
                const winRate = explicitWinRate ??
                  (total !== null && total > 0 && wins !== null ? (wins / total) * 100 : null)
                const result = numericMetric(metrics, ['net_profit', 'profit_usd', 'net_result'])
                return (
                  <tr key={name}>
                    <th scope="row">{name}</th>
                    <td>{total ?? '—'}</td>
                    <td>{winRate === null ? '—' : formatPercent(winRate)}</td>
                    <td>{result === null ? '—' : formatCurrency(result, true)}</td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      ) : (
        <p className="ops-empty-reason">Breakdown aktual belum tersedia pada snapshot.</p>
      )}
    </section>
  )
}

export function PerformanceSummarySection({
  snapshot,
}: {
  snapshot: DashboardApiSnapshot | null
}) {
  const performance = snapshot?.performance
  const netR = deriveNetR(snapshot)
  const sampleStatus = deriveSampleStatus(snapshot)
  const cleanSampleBlocked = snapshot?.project_progress.blockers.some((blocker) =>
    blocker.toUpperCase().includes('CLEAN_SAMPLE'),
  ) ?? false
  const sampleIncomplete = !snapshot ||
    performance?.closed_orders === null ||
    snapshot.summary.closed_target === null ||
    (performance?.closed_orders ?? 0) < (snapshot?.summary.closed_target ?? Number.POSITIVE_INFINITY) ||
    cleanSampleBlocked

  const metrics = [
    ['Trade ditutup', performance?.closed_orders?.toString() ?? 'TIDAK TERVERIFIKASI'],
    ['Net R', netR.value === null ? 'TIDAK TERVERIFIKASI' : `${netR.value >= 0 ? '+' : ''}${netR.value.toFixed(2)} R`],
    ['Win rate', formatNullable(performance?.win_rate, (value) => formatPercent(value))],
    ['Profit factor', formatNullable(performance?.profit_factor, (value) => value.toFixed(2))],
    ['Drawdown maks.', formatNullable(performance?.max_drawdown_percent, (value) => formatPercent(value, 2))],
    ['Net profit paper', formatNullable(performance?.net_profit, (value) => formatCurrency(value, true))],
  ] as const

  return (
    <OperationalSection
      id="ringkasan-performa"
      eyebrow="05 / Paper evidence"
      title="Ringkasan Performa"
      description="Hanya hasil paper atau shadow yang tersedia dalam snapshot tervalidasi."
    >
      <div className="ops-performance-metrics">
        {metrics.map(([label, value]) => (
          <div key={label}>
            <span>{label}</span>
            <strong>{value}</strong>
          </div>
        ))}
      </div>

      <div className={`ops-sample-notice ${sampleIncomplete ? 'is-warning' : 'is-safe'}`}>
        <Scale aria-hidden="true" className="size-5" />
        <div>
          <strong>{sampleStatus}</strong>
          <p>
            {sampleIncomplete
              ? 'Sampel belum cukup untuk memberi kesan siap live. Kelayakan promosi tetap diblokir atau belum terverifikasi.'
              : 'Target jumlah sampel tercapai; gate lain tetap harus dinilai secara independen.'}
          </p>
        </div>
        <OperationalStatusTag value={sampleIncomplete ? 'WAIT' : 'PASSED'} />
      </div>

      {netR.value === null ? (
        <p className="ops-data-note">
          Net R tidak ditampilkan karena {netR.sampleCount} dari {netR.expectedCount ?? 'jumlah tidak diketahui'}
          {' '}order tertutup memiliki R-multiple lengkap. Dashboard tidak mengestimasi data yang hilang.
        </p>
      ) : null}

      <div className="ops-performance-grid">
        <PerformanceRows title="Performa per pair" rows={performance?.by_symbol ?? {}} />
        <PerformanceRows title="Performa per strategi" rows={performance?.by_strategy ?? {}} />
      </div>
      {!snapshot ? (
        <div className="ops-empty-panel">
          <BarChart3 aria-hidden="true" className="size-5" />
          <strong>Performa aktual belum tersedia</strong>
          <p>Tidak ada chart atau metrik sintetis yang ditampilkan.</p>
        </div>
      ) : null}
    </OperationalSection>
  )
}
