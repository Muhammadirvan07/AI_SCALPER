import { useRealtimeDashboard } from './useRealtimeDashboard'

export function useNewsSentiment() {
  const { resources, refreshResource } = useRealtimeDashboard()
  return {
    resource: resources.newsSentiment,
    timeline: resources.newsTimeline,
    refresh: () => Promise.all([refreshResource('newsSentiment'), refreshResource('newsTimeline')]),
  }
}
