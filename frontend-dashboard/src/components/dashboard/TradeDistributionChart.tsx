import { Cell, Pie, PieChart, ResponsiveContainer, Tooltip } from 'recharts'
import type { TradeDistribution } from '../../types/dashboard'
import { formatPercent } from '../../utils/formatters'
import { Panel } from '../ui/Panel'
import { ChartTooltip } from './ChartTooltip'

const chartColors = ['#34d399', '#fb7185', '#fbbf24']

interface TradeDistributionChartProps {
  data: TradeDistribution
}

export function TradeDistributionChart({ data }: TradeDistributionChartProps) {
  const chartData = [
    { name: 'Menang', value: data.wins },
    { name: 'Kalah', value: data.losses },
    { name: 'Batas waktu', value: data.timeouts },
  ]
  const total = data.wins + data.losses + data.timeouts
  const winRate = total > 0 ? (data.wins / total) * 100 : 0

  return (
    <Panel className="min-w-0 p-4 sm:p-6">
      <p className="text-xs font-semibold tracking-[0.16em] text-violet-300 uppercase">
        Komposisi hasil
      </p>
      <h3 id="distribution-title" className="mt-1 text-lg font-semibold text-white">
        Menang, kalah & batas waktu
      </h3>
      <p className="mt-1 text-sm text-slate-400">
        {total} hasil dievaluasi dengan rasio menang {formatPercent(winRate)}.
      </p>

      <div
        className="relative mt-2 h-56"
        role="img"
        aria-labelledby="distribution-title"
        aria-label={`${data.wins} menang, ${data.losses} kalah, dan ${data.timeouts} batas waktu.`}
      >
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Pie
              data={chartData}
              dataKey="value"
              nameKey="name"
              cx="50%"
              cy="50%"
              innerRadius={62}
              outerRadius={88}
              paddingAngle={4}
              stroke="transparent"
            >
              {chartData.map((entry, index) => (
                <Cell key={entry.name} fill={chartColors[index]} />
              ))}
            </Pie>
            <Tooltip content={<ChartTooltip />} />
          </PieChart>
        </ResponsiveContainer>
        <div className="pointer-events-none absolute inset-0 grid place-items-center text-center">
          <div>
            <p className="text-3xl font-semibold text-white">{total}</p>
            <p className="text-[0.65rem] tracking-[0.14em] text-slate-500 uppercase">Hasil</p>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-3 gap-2">
        {chartData.map((item, index) => (
          <div key={item.name} className="rounded-xl border border-white/[0.06] bg-slate-950/30 p-3">
            <div className="flex items-center gap-2 text-xs text-slate-400">
              <span className="size-2 rounded-full" style={{ backgroundColor: chartColors[index] }} />
              {item.name}
            </div>
            <p className="mt-1 text-lg font-semibold text-white">{item.value}</p>
            <p className="text-[0.65rem] text-slate-500">
              {total ? formatPercent((item.value / total) * 100) : '0.0%'}
            </p>
          </div>
        ))}
      </div>
    </Panel>
  )
}
