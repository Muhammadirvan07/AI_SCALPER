import {
  Ban,
  CheckCircle2,
  CircleOff,
  Info,
  LockKeyhole,
  ShieldCheck,
  TriangleAlert,
} from 'lucide-react'
import type { SafetyControl, SystemSafetyStatus } from '../../types/dashboard'
import { Panel } from '../ui/Panel'
import { StatusBadge } from './StatusBadge'

const formatSafetyValue = (value: string) => {
  const labels: Record<string, string> = {
    ACTIVE: 'AKTIF (ACTIVE)',
    DISABLED: 'NONAKTIF (DISABLED)',
    ENABLED: 'AKTIF (ENABLED)',
    LOCKED: 'TERKUNCI (LOCKED)',
  }
  return labels[value] ?? value
}

const statusStyle: Record<SafetyControl['status'], string> = {
  safe: 'border-emerald-400/15 bg-emerald-400/[0.045]',
  caution: 'border-amber-400/15 bg-amber-400/[0.045]',
  protected: 'border-red-400/15 bg-red-400/[0.045]',
  unavailable: 'border-slate-500/15 bg-slate-500/[0.04]',
}

const statusIcon = {
  safe: CheckCircle2,
  caution: TriangleAlert,
  protected: LockKeyhole,
  unavailable: CircleOff,
}

interface SystemSafetyPanelProps {
  data: SystemSafetyStatus
}

export function SystemSafetyPanel({ data }: SystemSafetyPanelProps) {
  return (
    <Panel className="relative overflow-hidden border-red-400/15 p-4 sm:p-6">
      <div className="pointer-events-none absolute top-0 right-0 size-80 rounded-full bg-red-400/[0.035] blur-3xl" />
      <div className="relative flex flex-col gap-5 lg:flex-row lg:items-start lg:justify-between">
        <div>
          <p className="flex items-center gap-2 text-xs font-semibold tracking-[0.16em] text-red-300 uppercase">
            <ShieldCheck aria-hidden="true" className="size-4" />
            Pusat kontrol perlindungan
          </p>
          <h3 id="system-safety-title" className="mt-1 text-xl font-semibold text-white">
            Keselamatan sistem
          </h3>
          <p className="mt-2 max-w-2xl text-sm leading-6 text-slate-400">
            Penghalang eksekusi merupakan kontrol keselamatan yang disengaja. Dashboard dapat
            mengamati dan menganalisis, tetapi tidak dapat membuat order live atau demo.
          </p>
        </div>
        <div className="flex flex-wrap gap-2">
          <StatusBadge label="TRADING LIVE TERKUNCI (LOCKED)" tone="negative" />
          <StatusBadge label="PAPER AKTIF" tone="positive" pulse />
        </div>
      </div>

      <div className="relative mt-6 grid gap-4 md:grid-cols-[1fr_2fr]">
        <aside className="rounded-2xl border border-red-400/20 bg-red-400/[0.055] p-5">
          <div className="grid size-12 place-items-center rounded-2xl border border-red-400/20 bg-red-400/10 text-red-300">
            <LockKeyhole aria-hidden="true" className="size-6" />
          </div>
          <p className="mt-5 text-xs font-semibold tracking-[0.14em] text-red-300 uppercase">
            Trading live
          </p>
          <p className="mt-1 text-3xl font-semibold tracking-tight text-white">TERKUNCI (LOCKED)</p>
          <p className="mt-3 text-sm leading-6 text-slate-400">
            <strong className="font-semibold text-slate-200">Perlindungan aktif.</strong> Kontrol
            eksekusi tidak tersedia pada antarmuka ini.
          </p>
          <dl className="mt-5 space-y-3 border-t border-red-400/10 pt-4 text-sm">
            <div className="flex justify-between gap-4">
              <dt className="text-slate-500">live_allowed</dt>
              <dd className="font-mono font-semibold text-red-300">{String(data.liveAllowed)}</dd>
            </div>
            <div className="flex justify-between gap-4">
              <dt className="text-slate-500">mode</dt>
              <dd className="font-mono font-semibold text-cyan-200">{data.mode}</dd>
            </div>
            <div className="flex justify-between gap-4">
              <dt className="text-slate-500">max_lot</dt>
              <dd className="font-mono font-semibold text-amber-200">{data.maxLot.toFixed(2)}</dd>
            </div>
          </dl>
        </aside>

        <div className="grid gap-2 sm:grid-cols-2">
          {data.controls.map((control) => {
            const Icon = statusIcon[control.status]
            return (
              <article
                key={control.id}
                className={`flex min-h-[5.5rem] items-center gap-3 rounded-xl border p-3.5 ${statusStyle[control.status]}`}
              >
                <span
                  className={`grid size-9 shrink-0 place-items-center rounded-lg ${
                    control.status === 'safe'
                      ? 'bg-emerald-400/10 text-emerald-300'
                      : control.status === 'caution'
                        ? 'bg-amber-400/10 text-amber-200'
                        : control.status === 'protected'
                          ? 'bg-red-400/10 text-red-300'
                          : 'bg-slate-400/10 text-slate-400'
                  }`}
                >
                  <Icon aria-hidden="true" className="size-4" />
                </span>
                <div className="min-w-0">
                  <p className="text-xs text-slate-400">{control.label}</p>
                  <p
                    className={`mt-1 truncate text-xs font-semibold tracking-wide ${
                      control.status === 'safe'
                        ? 'text-emerald-200'
                        : control.status === 'caution'
                          ? 'text-amber-200'
                          : control.status === 'protected'
                            ? 'text-red-200'
                            : 'text-slate-400'
                    }`}
                    title={control.value}
                  >
                    {formatSafetyValue(control.value)}
                  </p>
                  {control.note ? (
                    <p className="mt-1 flex items-center gap-1 text-[0.62rem] text-slate-500">
                      <Info aria-hidden="true" className="size-3" />
                      {control.note}
                    </p>
                  ) : null}
                </div>
              </article>
            )
          })}
        </div>
      </div>

      <div className="relative mt-4 flex items-start gap-3 rounded-xl border border-cyan-400/10 bg-cyan-400/[0.035] p-3 text-xs leading-5 text-slate-400">
        <Ban aria-hidden="true" className="mt-0.5 size-4 shrink-0 text-cyan-300" />
        <p>
          <span className="font-semibold text-slate-200">Batas khusus observasi:</span>{' '}
          safe_to_demo_observe bernilai true; safe_to_demo_auto_order bernilai false.
        </p>
      </div>
    </Panel>
  )
}
