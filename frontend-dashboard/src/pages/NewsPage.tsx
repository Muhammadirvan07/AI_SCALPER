import { Newspaper } from 'lucide-react'
import { DomainPageLayout } from '../components/domain/DomainPageLayout'
import { LatestNewsPanel, NewsProviderPanel, NewsSentimentPanel, RecentOfficialReleasesPanel, SymbolNewsPanel } from '../components/domain/NewsIntelligencePanels'

export function NewsPage() {
  return (
    <DomainPageLayout eyebrow="External context" title="News Intelligence" description="Berita finansial, sentimen, relevansi simbol, dan kalender ekonomi dari provider backend tepercaya—read-only terhadap trading engine." icon={Newspaper}>
      <NewsProviderPanel />
      <LatestNewsPanel />
      <NewsSentimentPanel />
      <RecentOfficialReleasesPanel />
      <SymbolNewsPanel />
    </DomainPageLayout>
  )
}
