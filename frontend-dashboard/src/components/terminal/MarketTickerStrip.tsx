import { ArrowDownRight, ArrowUpRight, Minus } from 'lucide-react'
import type { MarketTicker } from '../../types/terminal'
import { formatPercent, formatPrice } from '../../utils/formatters'
import { formatStatusLabel } from '../../utils/statusHelpers'
import { TerminalStatusBadge } from './common/TerminalStatusBadge'

interface MarketTickerStripProps {
  tickers: MarketTicker[]
}

export function MarketTickerStrip({ tickers }: MarketTickerStripProps) {
  return (
    <div className="qt-ticker-strip" aria-label="Strip ticker pasar">
      <div className="qt-ticker-strip__track">
        {tickers.map((ticker) => {
          const DirectionIcon =
            ticker.direction === 'UP'
              ? ArrowUpRight
              : ticker.direction === 'DOWN'
                ? ArrowDownRight
                : Minus
          const tone =
            ticker.guardStatus === 'BLOCKED'
              ? 'blocked'
              : ticker.guardStatus === 'WATCH'
                ? 'warning'
                : 'safe'
          return (
            <article key={ticker.id} className="qt-ticker">
              <div>
                <strong>{ticker.symbol}</strong>
                <span>{formatStatusLabel(ticker.assetType)}</span>
              </div>
              <div className="qt-ticker__price">
                <span>{formatPrice(ticker.price, ticker.precision)}</span>
                <span
                  className={
                    ticker.changePercent >= 0 ? 'qt-tone--positive' : 'qt-tone--blocked'
                  }
                >
                  <DirectionIcon aria-hidden="true" className="size-3" />
                  {formatPercent(ticker.changePercent, 2, true)}
                </span>
              </div>
              <TerminalStatusBadge label={ticker.guardStatus} tone={tone} compact />
            </article>
          )
        })}
      </div>
    </div>
  )
}
