import { useMemo, useState } from 'react'
import {
  Area,
  CartesianGrid,
  ComposedChart,
  Legend,
  Line,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'
import type { EquityPoint } from '../../types/dashboard'
import { formatCurrency } from '../../utils/formatters'
import { Panel } from '../ui/Panel'
import { PanelState } from '../ui/PanelState'
import { ChartTooltip } from './ChartTooltip'

type Range = '7D' | '30D' | 'ALL'

interface EquityChartProps {
  data: EquityPoint[]
  loading?: boolean
}

export function EquityChart({ data, loading = false }: EquityChartProps) {
  const [range, setRange] = useState<Range>('30D')
  const filteredData = useMemo(() => {
    if (range === '7D') return data.slice(-7)
    if (range === '30D') return data.slice(-30)
    return data
  }, [data, range])

  const first = filteredData[0]
  const last = filteredData.at(-1)
  const summary =
    first && last
      ? `Ekuitas bergerak dari ${formatCurrency(first.equity)} menjadi ${formatCurrency(last.equity)} dengan laba kumulatif ${formatCurrency(last.cumulativeProfit, true)}.`
      : 'Data performa ekuitas tidak tersedia.'

  return (
    <Panel className="min-w-0 p-4 sm:p-6">
      <div className="mb-5 flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
        <div>
          <p className="text-xs font-semibold tracking-[0.16em] text-cyan-300 uppercase">
            Performa paper
          </p>
          <h3 id="equity-chart-title" className="mt-1 text-lg font-semibold text-white">
            Performa ekuitas
          </h3>
          <p className="mt-1 text-sm text-slate-400">{summary}</p>
        </div>
        <div
          className="inline-flex w-fit rounded-xl border border-white/[0.07] bg-slate-950/50 p-1"
          aria-label="Rentang tanggal chart ekuitas"
        >
          {(['7D', '30D', 'ALL'] as const).map((option) => (
            <button
              key={option}
              type="button"
              onClick={() => setRange(option)}
              aria-pressed={range === option}
              className={`focus-ring min-h-8 rounded-lg px-3 text-xs font-semibold transition ${
                range === option
                  ? 'bg-cyan-300/15 text-cyan-100'
                  : 'text-slate-500 hover:text-slate-200'
              }`}
            >
              {option === 'ALL' ? 'Semua' : option}
            </button>
          ))}
        </div>
      </div>

      {loading ? (
        <PanelState state="loading" />
      ) : filteredData.length === 0 ? (
        <PanelState state="empty" />
      ) : (
        <div
          className="h-80 w-full"
          role="img"
          aria-labelledby="equity-chart-title"
          aria-describedby="equity-chart-summary"
        >
          <p id="equity-chart-summary" className="sr-only">
            {summary}
          </p>
          <ResponsiveContainer width="100%" height="100%">
            <ComposedChart data={filteredData} margin={{ top: 8, right: 4, left: -16, bottom: 0 }}>
              <defs>
                <linearGradient id="equityFill" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#22d3ee" stopOpacity={0.28} />
                  <stop offset="100%" stopColor="#22d3ee" stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid stroke="#1e293b" strokeDasharray="3 6" vertical={false} />
              <XAxis
                dataKey="date"
                tick={{ fill: '#64748b', fontSize: 11 }}
                axisLine={false}
                tickLine={false}
                minTickGap={32}
              />
              <YAxis
                yAxisId="equity"
                domain={['dataMin - 0.15', 'dataMax + 0.12']}
                tick={{ fill: '#64748b', fontSize: 11 }}
                tickFormatter={(value: number) => `$${value.toFixed(2)}`}
                axisLine={false}
                tickLine={false}
              />
              <YAxis
                yAxisId="performance"
                orientation="right"
                domain={[-0.25, 0.65]}
                hide
              />
              <Tooltip
                cursor={{ stroke: '#334155', strokeDasharray: '4 4' }}
                content={<ChartTooltip valueType="currency" />}
              />
              <Legend
                verticalAlign="top"
                align="right"
                height={34}
                iconType="circle"
                wrapperStyle={{ fontSize: '11px', color: '#94a3b8' }}
              />
              <Area
                yAxisId="equity"
                type="monotone"
                dataKey="equity"
                name="Ekuitas"
                stroke="#22d3ee"
                strokeWidth={2.4}
                fill="url(#equityFill)"
                activeDot={{ r: 4, fill: '#22d3ee', stroke: '#07101f', strokeWidth: 2 }}
              />
              <Line
                yAxisId="performance"
                type="monotone"
                dataKey="cumulativeProfit"
                name="P&L kumulatif"
                stroke="#a78bfa"
                strokeWidth={1.6}
                dot={false}
                strokeDasharray="5 5"
              />
              <Line
                yAxisId="performance"
                type="monotone"
                dataKey="drawdown"
                name="Penurunan"
                stroke="#fb7185"
                strokeWidth={1.2}
                dot={false}
                opacity={0.7}
              />
            </ComposedChart>
          </ResponsiveContainer>
        </div>
      )}
    </Panel>
  )
}
