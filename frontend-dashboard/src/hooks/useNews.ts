import { useRealtimeDashboard } from './useRealtimeDashboard'

export function useNews() {
  const { resources, refreshResource } = useRealtimeDashboard()
  return {
    latest: resources.news,
    recent: resources.recentNews,
    breaking: resources.breakingNews,
    providers: resources.newsProviders,
    status: resources.newsStatus,
    symbol: resources.symbolNews,
    refresh: () => Promise.all([
      refreshResource('news'),
      refreshResource('recentNews'),
      refreshResource('breakingNews'),
      refreshResource('newsProviders'),
      refreshResource('newsStatus'),
      refreshResource('symbolNews'),
    ]),
  }
}
