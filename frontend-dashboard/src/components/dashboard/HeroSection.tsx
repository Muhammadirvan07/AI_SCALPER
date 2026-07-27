import {
  ArrowDownRight,
  BrainCircuit,
  CheckCircle2,
  LockKeyhole,
  Radar,
  ShieldCheck,
  Sparkles,
} from 'lucide-react'
import { useNavigate } from '../../routing/routerContext'
import type { DashboardSummary } from '../../types/dashboard'
import type { DashboardSourceMode } from '../../types/dashboardApi'
import { StatusBadge } from './StatusBadge'

interface HeroSectionProps {
  summary: DashboardSummary
  sourceMode: DashboardSourceMode
}

export function HeroSection({ summary, sourceMode }: HeroSectionProps) {
  const navigate = useNavigate()
  const mockMode = sourceMode === 'MOCK FALLBACK'

  return (
    <section id="top" className="future-hero">
      <div className="future-hero__grid" aria-hidden="true" />
      <div className="future-hero__horizon" aria-hidden="true" />

      <div className="page-container future-hero__layout relative grid min-h-[680px] items-center gap-12 py-16 lg:grid-cols-[1.08fr_0.92fr] lg:py-20">
        <div className="max-w-3xl motion-safe:animate-rise-in">
          <div className="future-hero__protocol mb-6" aria-label="Status protokol antarmuka">
            <span>SYS/AI-SCALPER</span>
            <span>OBSERVATION NODE 01</span>
          </div>
          <div className="mb-6 flex flex-wrap items-center gap-2">
            <StatusBadge label="Trading Live Terkunci (LOCKED)" tone="negative" />
            <StatusBadge
              label={mockMode ? 'Mock Development — Bukan Data Aktual' : 'Pemantauan Paper Aktif'}
              tone={mockMode ? 'neutral' : 'positive'}
              pulse={!mockMode}
            />
          </div>

          <p className="future-eyebrow mb-4">
            <Sparkles aria-hidden="true" className="size-4" />
            Intelijen trading adaptif
          </p>
          <h1 className="future-hero__title text-5xl leading-none font-semibold text-balance text-white sm:text-6xl lg:text-7xl">
            AI_<span className="text-gradient">SCALPER</span>
          </h1>
          <p className="mt-6 max-w-2xl text-xl leading-8 font-medium text-slate-200 sm:text-2xl">
            Sistem Intelijen Trading AI Adaptif dan Pemantauan Paper
          </p>
          <p className="mt-5 max-w-2xl text-base leading-7 text-slate-400 sm:text-lg">
            Pantau intelijen pasar, kualitas strategi, kontrol risiko, performa paper, dan
            kesehatan sistem adaptif melalui satu dashboard terpadu.
          </p>

          <div className="mt-8 flex flex-col gap-3 sm:flex-row">
            <button type="button" className="button-primary" onClick={() => navigate('/overview')}>
              Lihat Dashboard
              <ArrowDownRight aria-hidden="true" className="size-4" />
            </button>
            <button
              type="button"
              className="button-secondary"
              onClick={() => navigate('/system-health')}
            >
              <ShieldCheck aria-hidden="true" className="size-4" />
              Status Sistem
            </button>
          </div>

          <dl className="future-hero__metrics mt-10 grid max-w-2xl grid-cols-2 sm:grid-cols-4">
            <div>
              <dt className="text-xs tracking-wider text-slate-500 uppercase">Mode</dt>
              <dd className="mt-1 text-sm font-semibold text-cyan-200">{summary.systemMode}</dd>
            </div>
            <div>
              <dt className="text-xs tracking-wider text-slate-500 uppercase">Referensi</dt>
              <dd className="mt-1 text-sm font-semibold text-white">
                ${summary.balanceReference.toFixed(0)}
              </dd>
            </div>
            <div>
              <dt className="text-xs tracking-wider text-slate-500 uppercase">Lot maks.</dt>
              <dd className="mt-1 text-sm font-semibold text-white">{summary.maxLot.toFixed(2)}</dd>
            </div>
            <div>
              <dt className="text-xs tracking-wider text-slate-500 uppercase">Kesiapan</dt>
              <dd className="mt-1 text-sm font-semibold text-amber-200">
                {summary.readinessScore} / 100
              </dd>
            </div>
          </dl>
        </div>

        <div className="future-hero__visual relative mx-auto w-full max-w-xl lg:max-w-none" aria-hidden="true">
          <div className="terminal-frame future-terminal-frame relative overflow-hidden p-4 sm:p-5">
            <div className="mb-5 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <span className="size-2 rounded-full bg-red-400/70" />
                <span className="size-2 rounded-full bg-amber-300/70" />
                <span className="size-2 rounded-full bg-emerald-400/70" />
              </div>
              <span className="flex items-center gap-2 text-[0.65rem] font-semibold tracking-[0.16em] text-slate-500 uppercase">
                <Radar className="size-3.5 text-cyan-300" />
                Pemindaian pasar / Hanya observasi
              </span>
            </div>

            <div className="future-chart-window relative h-60 overflow-hidden border border-white/[0.06] bg-[#050b17]/80 p-4 sm:h-72">
              <div className="chart-grid absolute inset-0" />
              <div className="scan-line absolute inset-x-0 top-1/3 h-px bg-cyan-300/80 shadow-[0_0_18px_3px_rgba(34,211,238,0.35)]" />
              <svg
                viewBox="0 0 520 250"
                preserveAspectRatio="none"
                className="absolute inset-4 h-[calc(100%-2rem)] w-[calc(100%-2rem)] overflow-visible"
              >
                <defs>
                  <linearGradient id="heroLine" x1="0" y1="0" x2="1" y2="0">
                    <stop offset="0%" stopColor="#22d3ee" stopOpacity="0.35" />
                    <stop offset="55%" stopColor="#22d3ee" />
                    <stop offset="100%" stopColor="#a78bfa" />
                  </linearGradient>
                  <linearGradient id="heroArea" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#22d3ee" stopOpacity="0.2" />
                    <stop offset="100%" stopColor="#22d3ee" stopOpacity="0" />
                  </linearGradient>
                </defs>
                <path
                  d="M0 205 L35 190 L70 198 L105 161 L140 174 L175 135 L210 148 L245 112 L280 126 L315 80 L350 97 L385 64 L420 78 L455 42 L490 58 L520 26 L520 250 L0 250 Z"
                  fill="url(#heroArea)"
                />
                <path
                  d="M0 205 L35 190 L70 198 L105 161 L140 174 L175 135 L210 148 L245 112 L280 126 L315 80 L350 97 L385 64 L420 78 L455 42 L490 58 L520 26"
                  fill="none"
                  stroke="url(#heroLine)"
                  strokeWidth="3"
                  vectorEffect="non-scaling-stroke"
                />
                <circle cx="520" cy="26" r="5" fill="#a78bfa" />
              </svg>

              <div className="future-chart-label absolute top-4 left-4 flex items-center gap-2 border border-emerald-400/15 bg-emerald-400/[0.08] px-2.5 py-1.5 text-[0.65rem] font-medium text-emerald-200">
                <CheckCircle2 className="size-3" />
                {mockMode ? 'FEED MOCK DEVELOPMENT' : 'FEED DATA SEHAT'}
              </div>
              <div className="future-chart-score absolute right-4 bottom-4 border border-white/[0.08] bg-slate-950/80 px-4 py-3 backdrop-blur">
                <p className="text-[0.6rem] tracking-[0.15em] text-slate-500 uppercase">
                  Skor intelijen
                </p>
                <p className="mt-1 text-2xl font-semibold text-white">
                  {summary.readinessScore.toFixed(1)}
                </p>
                <span className="text-[0.65rem] font-medium text-amber-200">WATCH RANGE</span>
              </div>
            </div>

            <div className="mt-4 grid grid-cols-3 gap-3">
              <div className="terminal-stat">
                <BrainCircuit className="size-4 text-violet-300" />
                <span>Guard AI</span>
                <strong>7 / 7</strong>
              </div>
              <div className="terminal-stat">
                <LockKeyhole className="size-4 text-red-300" />
                <span>Jalur live</span>
                <strong>LOCKED</strong>
              </div>
              <div className="terminal-stat">
                <ShieldCheck className="size-4 text-emerald-300" />
                <span>Observasi demo</span>
                <strong>{mockMode ? 'MOCK' : 'AMAN'}</strong>
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>
  )
}
