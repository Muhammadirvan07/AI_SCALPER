import {
  BrainCircuit,
  Database,
  FileCheck2,
  RotateCw,
  ShieldAlert,
  type LucideIcon,
} from 'lucide-react'
import type { ActivityEvent } from '../../types/dashboard'
import { formatTime } from '../../utils/formatters'
import { Panel } from '../ui/Panel'
import { PanelState } from '../ui/PanelState'

const iconMap: Record<ActivityEvent['category'], LucideIcon> = {
  data: Database,
  guard: ShieldAlert,
  score: BrainCircuit,
  paper: FileCheck2,
  system: RotateCw,
}

const toneClass = {
  positive: 'border-emerald-400/20 bg-emerald-400/10 text-emerald-300',
  warning: 'border-amber-400/20 bg-amber-400/10 text-amber-200',
  negative: 'border-red-400/20 bg-red-400/10 text-red-300',
  info: 'border-cyan-400/20 bg-cyan-400/10 text-cyan-200',
  neutral: 'border-slate-400/20 bg-slate-400/10 text-slate-300',
}

interface ActivityTimelineProps {
  events: ActivityEvent[]
}

export function ActivityTimeline({ events }: ActivityTimelineProps) {
  return (
    <Panel className="p-4 sm:p-6">
      <p className="text-xs font-semibold tracking-[0.16em] text-violet-300 uppercase">
        Jurnal sistem
      </p>
      <h3 id="activity-title" className="mt-1 text-lg font-semibold text-white">
        Log aktivitas
      </h3>
      <p className="mt-1 text-sm text-slate-400">Peristiwa pemantauan dan diagnostik terbaru.</p>

      {events.length === 0 ? (
        <div className="mt-5">
          <PanelState state="empty" compact />
        </div>
      ) : (
        <ol className="relative mt-6 space-y-0" aria-labelledby="activity-title">
          {events.map((event, index) => {
            const Icon = iconMap[event.category]
            return (
              <li key={event.id} className="relative grid grid-cols-[2.25rem_1fr] gap-3 pb-5 last:pb-0">
                {index < events.length - 1 ? (
                  <span
                    aria-hidden="true"
                    className="absolute top-8 bottom-0 left-[1.08rem] w-px bg-slate-800"
                  />
                ) : null}
                <span
                  className={`relative z-10 grid size-9 place-items-center rounded-xl border ${toneClass[event.tone]}`}
                >
                  <Icon aria-hidden="true" className="size-4" />
                </span>
                <div className="min-w-0 pt-0.5">
                  <div className="flex flex-col gap-1 sm:flex-row sm:items-center sm:justify-between">
                    <p className="text-sm font-semibold text-slate-200">{event.title}</p>
                    <time dateTime={event.time} className="text-[0.68rem] text-slate-500">
                      {formatTime(event.time)}
                    </time>
                  </div>
                  <p className="mt-1 text-xs leading-5 text-slate-500">{event.detail}</p>
                </div>
              </li>
            )
          })}
        </ol>
      )}
    </Panel>
  )
}
