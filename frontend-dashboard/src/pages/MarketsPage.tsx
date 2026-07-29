import { CandlestickChart } from 'lucide-react'
import { DomainPageLayout } from '../components/domain/DomainPageLayout'
import { MarketPanel } from '../components/domain/MarketPanel'
import { WatchlistPanel } from '../components/domain/WatchlistPanel'

export function MarketsPage() {
  return <DomainPageLayout eyebrow="Market intelligence" title="Markets" description="OHLCV, indikator, actual timeframe, dan seluruh pair yang ditemukan backend." icon={CandlestickChart}><MarketPanel /><WatchlistPanel /></DomainPageLayout>
}
