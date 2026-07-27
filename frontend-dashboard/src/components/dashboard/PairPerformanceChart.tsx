import { Bar, BarChart, CartesianGrid, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import type { PairPerformance } from '../../types/dashboard'
import { formatCurrency, formatPercent } from '../../utils/formatters'
import { formatStatusLabel } from '../../utils/statusHelpers'
import { Panel } from '../ui/Panel'
import { PanelState } from '../ui/PanelState'
import { ChartTooltip } from './ChartTooltip'
import { StatusBadge } from './StatusBadge'

interface PairPerformanceChartProps {
  data: PairPerformance[]
}

export function PairPerformanceChart({ data }: PairPerformanceChartProps) {
  return (
    <Panel className="min-w-0 p-4 sm:p-6">
      <p className="text-xs font-semibold tracking-[0.16em] text-violet-300 uppercase">
        Intelijen pair
      </p>
      <h3 id="pair-chart-title" className="mt-1 text-lg font-semibold text-white">
        Performa pair
      </h3>
      <p className="mt-1 text-sm text-slate-400">
        Hasil, kepadatan sinyal, volatilitas, dan status guard per instrumen.
      </p>

      {data.length === 0 ? (
        <div className="mt-5">
          <PanelState state="empty" />
        </div>
      ) : (
        <div className="mt-5 grid gap-5 lg:grid-cols-[0.9fr_1.1fr]">
          <div
            className="h-64"
            role="img"
            aria-labelledby="pair-chart-title"
            aria-label="EURUSD dan BTCUSD positif. GBPUSD negatif dan diblokir. XAUUSD hanya dalam pantauan."
          >
            <ResponsiveContainer width="100%" height="100%">
              <BarChart
                data={data}
                layout="vertical"
                margin={{ top: 4, right: 10, left: 4, bottom: 0 }}
              >
                <CartesianGrid stroke="#1e293b" strokeDasharray="3 6" horizontal={false} />
                <XAxis
                  type="number"
                  tick={{ fill: '#64748b', fontSize: 10 }}
                  tickFormatter={(value: number) => `$${value.toFixed(1)}`}
                  axisLine={false}
                  tickLine={false}
                />
                <YAxis
                  dataKey="symbol"
                  type="category"
                  width={62}
                  tick={{ fill: '#94a3b8', fontSize: 11, fontWeight: 600 }}
                  axisLine={false}
                  tickLine={false}
                />
                <Tooltip content={<ChartTooltip valueType="currency" />} cursor={{ fill: '#ffffff08' }} />
                <Bar dataKey="netResult" name="Hasil bersih" radius={[0, 6, 6, 0]} maxBarSize={26}>
                  {data.map((pair) => (
                    <Cell
                      key={pair.symbol}
                      fill={
                        pair.guardStatus === 'BLOCKED'
                          ? '#fb7185'
                          : pair.netResult >= 0
                            ? '#34d399'
                            : '#fbbf24'
                      }
                    />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>

          <div className="space-y-2">
            {data.map((pair) => (
              <article
                key={pair.symbol}
                className="rounded-xl border border-white/[0.06] bg-slate-950/25 p-3"
              >
                <div className="flex items-center justify-between gap-3">
                  <div>
                    <p className="text-sm font-semibold text-white">{pair.symbol}</p>
                    <p className="mt-0.5 text-[0.68rem] text-slate-500">
                      {pair.signalCount} sinyal · volatilitas {formatStatusLabel(pair.volatility)}
                    </p>
                  </div>
                  <StatusBadge
                    label={pair.guardStatus}
                    tone={
                      pair.guardStatus.includes('PRIMARY')
                        ? 'positive'
                        : pair.guardStatus === 'BLOCKED'
                          ? 'negative'
                          : 'warning'
                    }
                  />
                </div>
                <div className="mt-3 flex items-center justify-between text-xs">
                  <span className="text-slate-500">Rasio menang {formatPercent(pair.winRate)}</span>
                  <span
                    className={
                      pair.netResult >= 0
                        ? 'font-semibold text-emerald-300'
                        : 'font-semibold text-red-300'
                    }
                  >
                    {formatCurrency(pair.netResult, true)}
                  </span>
                </div>
              </article>
            ))}
          </div>
        </div>
      )}
    </Panel>
  )
}
