import { AlertTriangle, RadioTower } from 'lucide-react'
import { useMemo } from 'react'
import type { Timeframe } from '../../api/types'
import { useRealtimeDashboard } from '../../hooks/useRealtimeDashboard'
import { formatNullableNumber, formatTimestamp } from '../../utils/apiDisplay'
import { formatStatusLabel } from '../../utils/statusHelpers'
import { TechnicalPanel } from '../terminal/common/TechnicalPanel'
import { FreshnessBadge } from './FreshnessBadge'
import { ResourceStateView } from './ResourceStateView'

const timeframes: Timeframe[] = ['M1', 'M5', 'M15', 'M30', 'H1', 'H4', 'D1']

export function MarketPanel({ className = 'qt-grid-span-8' }: { className?: string }) {
  const {
    resources,
    connection,
    activeSymbol,
    timeframe,
    candleLimit,
    setActiveSymbol,
    setTimeframe,
    setCandleLimit,
    refreshResource,
  } = useRealtimeDashboard()
  const series = resources.candles.data
  const candles = useMemo(() => series?.candles.slice(-120) ?? [], [series])
  const geometry = useMemo(() => {
    if (candles.length === 0) return null
    const width = 960
    const height = 330
    const padding = { top: 18, right: 68, bottom: 28, left: 18 }
    const lows = candles.map((item) => item.low)
    const highs = candles.map((item) => item.high)
    const minimum = Math.min(...lows)
    const maximum = Math.max(...highs)
    const span = maximum - minimum || Math.max(Math.abs(maximum) * 0.001, 0.0001)
    const plotHeight = height - padding.top - padding.bottom
    const plotWidth = width - padding.left - padding.right
    const y = (price: number) => padding.top + ((maximum - price) / span) * plotHeight
    const step = plotWidth / candles.length
    return { width, height, padding, minimum, maximum, y, step }
  }, [candles])
  const activeSignal = resources.signals.data?.items.find((signal) => signal.symbol === activeSymbol) ?? null
  const precision = activeSymbol?.includes('JPY') ? 3 : activeSymbol === 'BTCUSD' ? 2 : activeSymbol?.includes('USD') ? 5 : 4
  const marketState = resources.candles.status === 'loading'
    ? 'loading'
    : resources.candles.error && !series
      ? 'error'
      : resources.candles.meta?.stale
        ? 'stale'
        : candles.length > 0
          ? 'connected'
          : 'empty'

  return (
    <TechnicalPanel
      code="M01"
      title="Market Intelligence"
      subtitle="Backend OHLCV · actual resolution · no synthetic quote"
      state={marketState}
      onRetry={() => void refreshResource('candles')}
      preserveContent
      className={className}
      collapsible={false}
      action={<FreshnessBadge meta={resources.candles.meta} connection={connection} />}
    >
      <div className="market-controls">
        <label>
          <span>Symbol</span>
          <select aria-label="Market symbol" value={activeSymbol ?? ''} onChange={(event) => setActiveSymbol(event.target.value)}>
            {(resources.symbols.data ?? []).map((symbol) => <option key={symbol} value={symbol}>{symbol}</option>)}
          </select>
        </label>
        <div className="market-timeframes" aria-label="Pilih timeframe">
          {timeframes.map((item) => (
            <button key={item} type="button" className={timeframe === item ? 'is-active' : ''} onClick={() => setTimeframe(item)} aria-pressed={timeframe === item}>{item}</button>
          ))}
        </div>
        <label>
          <span>Candle limit</span>
          <select aria-label="Candle limit" value={candleLimit} onChange={(event) => setCandleLimit(Number(event.target.value))}>
            {[100, 200, 300, 500].map((limit) => <option key={limit} value={limit}>{limit}</option>)}
          </select>
        </label>
      </div>

      <div className="market-telemetry">
        <span><em>Last</em><strong>{formatNullableNumber(resources.quote.data?.last ?? null, precision)}</strong></span>
        <span><em>Bid</em><strong>{formatNullableNumber(resources.quote.data?.bid ?? null, precision)}</strong></span>
        <span><em>Ask</em><strong>{formatNullableNumber(resources.quote.data?.ask ?? null, precision)}</strong></span>
        <span><em>Spread</em><strong>{formatNullableNumber(resources.quote.data?.spread ?? null, precision)}</strong></span>
        <span><em>ATR 14</em><strong>{formatNullableNumber(resources.indicators.data?.atr14 ?? null, precision)}</strong></span>
        <span><em>ADX 14</em><strong>{formatNullableNumber(resources.indicators.data?.adx14 ?? null, 1)}</strong></span>
        <span><em>Trend</em><strong>{formatStatusLabel(resources.indicators.data?.trend)}</strong></span>
        <span><em>Regime</em><strong>{formatStatusLabel(resources.indicators.data?.market_regime)}</strong></span>
      </div>

      {series?.resolution_warning ? (
        <div className="market-resolution-warning" role="status">
          <AlertTriangle aria-hidden="true" />
          <span><strong>{series.requested_timeframe} data unavailable.</strong> Showing actual {series.actual_timeframe} data. {series.resolution_warning}</span>
        </div>
      ) : series ? (
        <div className="market-resolution-ok"><RadioTower aria-hidden="true" /> Requested {series.requested_timeframe} · actual {series.actual_timeframe}{series.derived ? ' · resampled by backend' : ''}</div>
      ) : null}

      <ResourceStateView resource={resources.candles} onRetry={() => void refreshResource('candles')} emptyMessage="Candle backend belum tersedia untuk simbol ini.">
        {() => geometry ? (
          <div className="market-canvas" tabIndex={0} role="img" aria-label={`Candlestick ${activeSymbol ?? 'symbol'} resolusi aktual ${series?.actual_timeframe ?? 'unknown'}`}>
            <svg viewBox={`0 0 ${geometry.width} ${geometry.height}`} preserveAspectRatio="none">
              {Array.from({ length: 6 }, (_, index) => {
                const y = geometry.padding.top + index * ((geometry.height - geometry.padding.top - geometry.padding.bottom) / 5)
                const value = geometry.maximum - index * ((geometry.maximum - geometry.minimum) / 5)
                return (
                  <g key={`grid-${value}`}>
                    <line x1={geometry.padding.left} x2={geometry.width - geometry.padding.right} y1={y} y2={y} className="market-gridline" />
                    <text x={geometry.width - geometry.padding.right + 8} y={y + 3} className="market-axis-label">{value.toFixed(precision)}</text>
                  </g>
                )
              })}
              {candles.map((candle, index) => {
                const x = geometry.padding.left + geometry.step * index + geometry.step / 2
                const open = geometry.y(candle.open)
                const close = geometry.y(candle.close)
                const rising = candle.close >= candle.open
                const bodyTop = Math.min(open, close)
                const bodyHeight = Math.max(1.2, Math.abs(close - open))
                return (
                  <g key={candle.timestamp} className={rising ? 'market-candle market-candle--up' : 'market-candle market-candle--down'}>
                    <line x1={x} x2={x} y1={geometry.y(candle.high)} y2={geometry.y(candle.low)} />
                    <rect x={x - Math.max(1.5, geometry.step * 0.28)} y={bodyTop} width={Math.max(3, geometry.step * 0.56)} height={bodyHeight} />
                    <title>{formatTimestamp(candle.timestamp)} · O {candle.open} H {candle.high} L {candle.low} C {candle.close}</title>
                  </g>
                )
              })}
              {([
                ['Entry', activeSignal?.entry, 'market-level--entry'],
                ['SL', activeSignal?.stop_loss, 'market-level--sl'],
                ['TP', activeSignal?.take_profit, 'market-level--tp'],
              ] as const).map(([label, value, className]) => value === null || value === undefined ? null : (
                <g key={label} className={`market-level ${className}`}>
                  <line x1={geometry.padding.left} x2={geometry.width - geometry.padding.right} y1={geometry.y(value)} y2={geometry.y(value)} />
                  <text x={geometry.padding.left + 4} y={geometry.y(value) - 4}>{label} {value.toFixed(precision)}</text>
                </g>
              ))}
              {candles.length > 0 ? (
                <g className="market-current-marker">
                  <line x1={geometry.padding.left} x2={geometry.width - geometry.padding.right} y1={geometry.y(candles[candles.length - 1]!.close)} y2={geometry.y(candles[candles.length - 1]!.close)} />
                </g>
              ) : null}
            </svg>
          </div>
        ) : <p className="domain-empty-inline">Candle kosong; chart tidak membuat titik palsu.</p>}
      </ResourceStateView>
      <p className="market-source-note">
        Quote source: {resources.quote.data?.source_kind ?? 'unavailable'} · last update {formatTimestamp(resources.quote.data?.timestamp ?? null)}. Bid, ask, dan spread yang tidak disediakan engine tetap ditampilkan sebagai —.
      </p>
    </TechnicalPanel>
  )
}
