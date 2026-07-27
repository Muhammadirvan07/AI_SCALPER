import { useMemo, useState } from 'react'
import type {
  MarketCandle,
  MarketInstrument,
  TerminalPanelState,
} from '../../types/terminal'
import { formatPercent, formatPrice, formatTime } from '../../utils/formatters'
import { formatStatusLabel } from '../../utils/statusHelpers'
import { terminalChartColors as chartColors } from '../../utils/terminalTheme'
import { MetricValue } from './common/MetricValue'
import { TechnicalPanel } from './common/TechnicalPanel'
import { TerminalStatusBadge } from './common/TerminalStatusBadge'

const timeframes = ['M5', 'M15', 'M30', 'H1'] as const

interface MarketCandlestickChartProps {
  instruments: MarketInstrument[]
  state: TerminalPanelState
  onRetry: () => void
}

interface CandleGeometry {
  candle: MarketCandle
  x: number
  openY: number
  closeY: number
  highY: number
  lowY: number
  volumeHeight: number
}

export function MarketCandlestickChart({
  instruments,
  state,
  onRetry,
}: MarketCandlestickChartProps) {
  const [selectedSymbol, setSelectedSymbol] = useState('EURUSD')
  const [timeframe, setTimeframe] = useState<(typeof timeframes)[number]>('M15')
  const [hoveredCandle, setHoveredCandle] = useState<MarketCandle | null>(null)
  const instrument = instruments.find((item) => item.symbol === selectedSymbol) ?? instruments[0]
  const activeTimeframe =
    instrument?.candles[timeframe]?.length
      ? timeframe
      : instrument?.selectedTimeframe ?? timeframe

  const chart = useMemo(() => {
    if (!instrument) return null
    const candles = instrument.candles[activeTimeframe] ?? []
    if (candles.length === 0) return null
    const width = 780
    const height = 320
    const left = 12
    const right = 62
    const top = 12
    const priceBottom = 242
    const volumeBottom = 304
    const plotWidth = width - left - right
    const priceValues = candles.flatMap((candle) => [candle.low, candle.high])
    const references = [
      instrument.referenceLevels.entry,
      instrument.referenceLevels.stopLoss,
      instrument.referenceLevels.takeProfit,
      instrument.latestPrice,
    ].filter((value): value is number => value !== null)
    const min = Math.min(...priceValues, ...references)
    const max = Math.max(...priceValues, ...references)
    const range = Math.max(max - min, 0.00001)
    const priceToY = (value: number) => top + ((max - value) / range) * (priceBottom - top)
    const maxVolume = Math.max(...candles.map((candle) => candle.volume), 1)
    const step = plotWidth / candles.length
    const geometry: CandleGeometry[] = candles.map((candle, index) => ({
      candle,
      x: left + step * index + step / 2,
      openY: priceToY(candle.open),
      closeY: priceToY(candle.close),
      highY: priceToY(candle.high),
      lowY: priceToY(candle.low),
      volumeHeight: (candle.volume / maxVolume) * (volumeBottom - priceBottom - 14),
    }))
    return { width, height, left, right, top, priceBottom, volumeBottom, min, max, step, priceToY, geometry }
  }, [activeTimeframe, instrument])

  if (!instrument || !chart) {
    return (
      <TechnicalPanel code="Q02" title="Grafik Pasar" state="empty" className="qt-grid-span-7">
        <span />
      </TechnicalPanel>
    )
  }

  const activeCandle = hoveredCandle ?? instrument.candles[activeTimeframe]?.at(-1)
  const referenceLines = [
    { label: 'MASUK PAPER', value: instrument.referenceLevels.entry, tone: chartColors.caution },
    { label: 'PAPER SL', value: instrument.referenceLevels.stopLoss, tone: chartColors.blocked },
    { label: 'PAPER TP', value: instrument.referenceLevels.takeProfit, tone: chartColors.safe },
    { label: 'SAAT INI', value: instrument.latestPrice, tone: chartColors.positive },
  ]
  const displayPrice = instrument.latestPrice ?? activeCandle?.close ?? 0
  const displayChange = instrument.changePercent ?? 0
  const valueOrDash = (value: number | null, precision = instrument.precision) =>
    value === null ? '—' : formatPrice(value, precision)

  return (
    <TechnicalPanel
      code="Q02"
      title="Struktur Pasar / Referensi Paper"
      subtitle={`${instrument.symbol} / ${instrument.quote} · ${activeTimeframe} · hanya-baca`}
      state={state}
      onRetry={onRetry}
      className="qt-grid-span-7"
      action={<TerminalStatusBadge label="LEVEL REFERENSI PAPER" tone="caution" />}
      summary={`Candle aktual terakhir ${instrument.symbol} adalah ${formatPrice(displayPrice, instrument.precision)}. Sumber ${formatStatusLabel(instrument.freshness)} dan tidak disimulasikan ketika API terhubung.`}
    >
      <div className="qt-market-tabs" role="tablist" aria-label="Pemilihan pair pasar">
        {instruments.map((item) => (
          <button
            key={item.symbol}
            type="button"
            role="tab"
            aria-selected={selectedSymbol === item.symbol}
            className={`qt-tab ${selectedSymbol === item.symbol ? 'is-active' : ''}`}
            onClick={() => setSelectedSymbol(item.symbol)}
          >
            {item.symbol}
          </button>
        ))}
        <span className="qt-market-tabs__spacer" />
        {timeframes.map((option) => (
          <button
            key={option}
            type="button"
            role="tab"
            aria-selected={activeTimeframe === option}
            className={`qt-tab qt-tab--timeframe ${activeTimeframe === option ? 'is-active' : ''}`}
            onClick={() => setTimeframe(option)}
            disabled={!instrument.candles[option]?.length}
            title={
              instrument.candles[option]?.length
                ? `Tampilkan ${option}`
                : `${option} tidak tersedia pada CSV sumber`
            }
          >
            {option}
          </button>
        ))}
      </div>

      <div className="qt-market-stats">
        <MetricValue label="Terbaru" value={formatPrice(displayPrice, instrument.precision)} detail={instrument.changePercent === null ? '—' : formatPercent(displayChange, 2, true)} tone={displayChange >= 0 ? 'positive' : 'blocked'} />
        <MetricValue label="O / H / L" value={`${valueOrDash(instrument.open)} / ${valueOrDash(instrument.high)} / ${valueOrDash(instrument.low)}`} />
        <MetricValue label="Spread" value={valueOrDash(instrument.spread)} detail="Tidak dihitung bila sumber tidak tersedia" />
        <MetricValue label="ATR" value={valueOrDash(instrument.atr)} />
        <MetricValue label="Volatilitas" value={instrument.volatilityPercent === null ? '—' : formatPercent(instrument.volatilityPercent, 2)} tone="caution" />
        <MetricValue label="Bias / skor" value={`${formatStatusLabel(instrument.signalBias)} / ${instrument.strategyScore ?? '—'}/5`} tone={instrument.signalBias === 'BLOCKED' ? 'blocked' : 'warning'} />
      </div>

      <div className="qt-candle-chart">
        <svg
          viewBox={`0 0 ${chart.width} ${chart.height}`}
          role="img"
          aria-label={`Grafik candle sumber aktual untuk ${instrument.symbol} pada ${activeTimeframe}.`}
          preserveAspectRatio="none"
        >
          {Array.from({ length: 6 }, (_, index) => {
            const y = chart.top + (index / 5) * (chart.priceBottom - chart.top)
            const price = chart.max - (index / 5) * (chart.max - chart.min)
            return (
              <g key={`grid-${index.toString()}`}>
                <line x1={chart.left} y1={y} x2={chart.width - chart.right} y2={y} className="qt-chart-grid-line" />
                <text x={chart.width - chart.right + 6} y={y + 3} className="qt-chart-axis-label">
                  {formatPrice(price, instrument.precision)}
                </text>
              </g>
            )
          })}

          {referenceLines.map((line) => {
            if (line.value === null) return null
            const y = chart.priceToY(line.value)
            return (
              <g key={line.label}>
                <line
                  x1={chart.left}
                  y1={y}
                  x2={chart.width - chart.right}
                  y2={y}
                  stroke={line.tone}
                  strokeDasharray="5 4"
                  strokeWidth="1"
                />
                <text x={chart.left + 4} y={y - 4} fill={line.tone} className="qt-reference-label">
                  {line.label}
                </text>
              </g>
            )
          })}

          {chart.geometry.map(({ candle, x, openY, closeY, highY, lowY, volumeHeight }) => {
            const rising = candle.close >= candle.open
            const color = rising ? chartColors.positive : chartColors.warning
            const bodyTop = Math.min(openY, closeY)
            const bodyHeight = Math.max(2, Math.abs(openY - closeY))
            return (
              <g
                key={candle.id}
                role="button"
                tabIndex={0}
                aria-label={`${formatTime(candle.timestamp)} buka ${candle.open}, tertinggi ${candle.high}, terendah ${candle.low}, tutup ${candle.close}`}
                onMouseEnter={() => setHoveredCandle(candle)}
                onMouseLeave={() => setHoveredCandle(null)}
                onFocus={() => setHoveredCandle(candle)}
                onBlur={() => setHoveredCandle(null)}
              >
                <rect x={x - chart.step / 2} y={chart.top} width={chart.step} height={chart.volumeBottom - chart.top} fill="transparent" />
                <line x1={x} y1={highY} x2={x} y2={lowY} stroke={color} strokeWidth="1" />
                <rect x={x - Math.max(1.4, chart.step * 0.28)} y={bodyTop} width={Math.max(2.8, chart.step * 0.56)} height={bodyHeight} fill={rising ? chartColors.surfaceRaised : color} stroke={color} strokeWidth="1" />
                <rect x={x - Math.max(1.2, chart.step * 0.22)} y={chart.volumeBottom - volumeHeight} width={Math.max(2.4, chart.step * 0.44)} height={volumeHeight} fill={color} opacity="0.45" />
              </g>
            )
          })}
          <line x1={chart.left} y1={chart.priceBottom + 7} x2={chart.width - chart.right} y2={chart.priceBottom + 7} className="qt-chart-grid-line" />
        </svg>

        {activeCandle ? (
          <div className="qt-candle-tooltip" aria-live="polite">
            <span>{formatTime(activeCandle.timestamp)}</span>
            <span>O {formatPrice(activeCandle.open, instrument.precision)}</span>
            <span>H {formatPrice(activeCandle.high, instrument.precision)}</span>
            <span>L {formatPrice(activeCandle.low, instrument.precision)}</span>
            <span>C {formatPrice(activeCandle.close, instrument.precision)}</span>
            <span>V {activeCandle.volume}</span>
          </div>
        ) : null}
      </div>
    </TechnicalPanel>
  )
}
