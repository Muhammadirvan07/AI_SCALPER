import { Bar, BarChart, CartesianGrid, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import type { StrategyPerformance } from '../../types/dashboard'
import { formatCurrency, formatPercent } from '../../utils/formatters'
import { Panel } from '../ui/Panel'
import { PanelState } from '../ui/PanelState'
import { ChartTooltip } from './ChartTooltip'
import { StatusBadge } from './StatusBadge'

interface StrategyPerformanceChartProps {
  data: StrategyPerformance[]
}

export function StrategyPerformanceChart({ data }: StrategyPerformanceChartProps) {
  return (
    <Panel className="min-w-0 p-4 sm:p-6">
      <div>
        <p className="text-xs font-semibold tracking-[0.16em] text-cyan-300 uppercase">
          Diagnostik strategi
        </p>
        <h3 id="strategy-chart-title" className="mt-1 text-lg font-semibold text-white">
          Performa strategi
        </h3>
        <p className="mt-1 text-sm text-slate-400">
          Hasil bersih paper berdasarkan strategi beserta konteks kualitas dan guard.
        </p>
      </div>

      {data.length === 0 ? (
        <div className="mt-5">
          <PanelState state="empty" />
        </div>
      ) : (
        <>
          <div
            className="mt-5 h-64"
            role="img"
            aria-labelledby="strategy-chart-title"
            aria-label="Breakout dan momentum pullback menghasilkan nilai bersih positif. Trend following negatif dan diblokir."
          >
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={data} margin={{ top: 6, right: 8, left: -14, bottom: 0 }}>
                <CartesianGrid stroke="#1e293b" strokeDasharray="3 6" vertical={false} />
                <XAxis
                  dataKey="shortName"
                  tick={{ fill: '#64748b', fontSize: 10 }}
                  axisLine={false}
                  tickLine={false}
                />
                <YAxis
                  tick={{ fill: '#64748b', fontSize: 10 }}
                  tickFormatter={(value: number) => `$${value.toFixed(1)}`}
                  axisLine={false}
                  tickLine={false}
                />
                <Tooltip content={<ChartTooltip valueType="currency" />} cursor={{ fill: '#ffffff08' }} />
                <Bar dataKey="netResult" name="Hasil bersih" radius={[6, 6, 2, 2]} maxBarSize={48}>
                  {data.map((strategy) => (
                    <Cell
                      key={strategy.name}
                      fill={
                        strategy.guardStatus === 'BLOCKED'
                          ? '#fb7185'
                          : strategy.netResult >= 0
                            ? '#22d3ee'
                            : '#fbbf24'
                      }
                      fillOpacity={strategy.guardStatus === 'BLOCKED' ? 0.55 : 0.85}
                    />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>

          <div className="mt-4 grid gap-2 sm:grid-cols-2">
            {data.map((strategy) => (
              <article
                key={strategy.name}
                className={`rounded-xl border p-3 ${
                  strategy.guardStatus === 'BLOCKED'
                    ? 'border-red-400/15 bg-red-400/[0.04]'
                    : 'border-white/[0.06] bg-slate-950/25'
                }`}
              >
                <div className="flex items-center justify-between gap-2">
                  <p className="truncate text-xs font-semibold text-slate-200" title={strategy.name}>
                    {strategy.name}
                  </p>
                  <StatusBadge label={strategy.guardStatus} />
                </div>
                <dl className="mt-3 grid grid-cols-4 gap-2 text-[0.68rem]">
                  <div>
                    <dt className="text-slate-500">Transaksi</dt>
                    <dd className="mt-0.5 font-semibold text-slate-200">{strategy.trades}</dd>
                  </div>
                  <div>
                    <dt className="text-slate-500">Rasio menang</dt>
                    <dd className="mt-0.5 font-semibold text-slate-200">
                      {formatPercent(strategy.winRate)}
                    </dd>
                  </div>
                  <div>
                    <dt className="text-slate-500">PF</dt>
                    <dd className="mt-0.5 font-semibold text-slate-200">
                      {strategy.profitFactor.toFixed(2)}
                    </dd>
                  </div>
                  <div>
                    <dt className="text-slate-500">Bersih</dt>
                    <dd
                      className={`mt-0.5 font-semibold ${
                        strategy.netResult >= 0 ? 'text-emerald-300' : 'text-red-300'
                      }`}
                    >
                      {formatCurrency(strategy.netResult, true)}
                    </dd>
                  </div>
                </dl>
              </article>
            ))}
          </div>
        </>
      )}
    </Panel>
  )
}
