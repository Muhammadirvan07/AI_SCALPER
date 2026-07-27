import {
  Area,
  AreaChart,
  CartesianGrid,
  ReferenceLine,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'
import type { ReadinessPoint } from '../../types/dashboard'
import { Panel } from '../ui/Panel'
import { PanelState } from '../ui/PanelState'
import { ChartTooltip } from './ChartTooltip'
import { StatusBadge } from './StatusBadge'

interface ReadinessTrendChartProps {
  data: ReadinessPoint[]
}

export function ReadinessTrendChart({ data }: ReadinessTrendChartProps) {
  const currentScore = data.at(-1)?.score ?? 0

  return (
    <Panel className="min-w-0 p-4 sm:p-6">
      <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
        <div>
          <p className="text-xs font-semibold tracking-[0.16em] text-cyan-300 uppercase">
            Trajektori kualitas
          </p>
          <h3 id="readiness-title" className="mt-1 text-lg font-semibold text-white">
            Tren kesiapan
          </h3>
          <p className="mt-1 text-sm text-slate-400">
            Perkembangan pada sesi evaluasi terbaru.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <span className="text-2xl font-semibold text-white">{currentScore}</span>
          <StatusBadge label="WATCH" tone="warning" />
        </div>
      </div>

      {data.length === 0 ? (
        <div className="mt-5">
          <PanelState state="empty" />
        </div>
      ) : (
        <div
          className="mt-5 h-72"
          role="img"
          aria-labelledby="readiness-title"
          aria-label={`Kesiapan meningkat menjadi ${currentScore}. Ambang WATCH adalah 55 dan ambang READY adalah 80. Status saat ini WATCH.`}
        >
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={data} margin={{ top: 10, right: 8, left: -18, bottom: 0 }}>
              <defs>
                <linearGradient id="readinessFill" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#a78bfa" stopOpacity={0.28} />
                  <stop offset="100%" stopColor="#a78bfa" stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid stroke="#1e293b" strokeDasharray="3 6" vertical={false} />
              <XAxis
                dataKey="session"
                tick={{ fill: '#64748b', fontSize: 10 }}
                axisLine={false}
                tickLine={false}
              />
              <YAxis
                domain={[40, 100]}
                ticks={[40, 55, 68, 80, 100]}
                tick={{ fill: '#64748b', fontSize: 10 }}
                axisLine={false}
                tickLine={false}
              />
              <ReferenceLine
                y={55}
                stroke="#fbbf24"
                strokeDasharray="5 5"
                label={{ value: 'WATCH 55', fill: '#fbbf24', fontSize: 10, position: 'insideTopLeft' }}
              />
              <ReferenceLine
                y={80}
                stroke="#34d399"
                strokeDasharray="5 5"
                label={{ value: 'READY 80', fill: '#34d399', fontSize: 10, position: 'insideTopLeft' }}
              />
              <Tooltip content={<ChartTooltip labelPrefix="Sesi" />} />
              <Area
                type="monotone"
                dataKey="score"
                name="Kesiapan"
                stroke="#a78bfa"
                strokeWidth={2.4}
                fill="url(#readinessFill)"
                activeDot={{ r: 4, fill: '#c4b5fd', stroke: '#07101f', strokeWidth: 2 }}
              />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      )}
    </Panel>
  )
}
