export const defaultSubscriptions = [
  'overview',
  'signals',
  'orders',
  'quality',
  'risk',
  'system',
  'activity',
  'news',
  'news:breaking',
  'news:sentiment',
  'news:provider:investing_rss',
  'economic-calendar',
  'economic-calendar:live',
  'economic-calendar:high-impact',
] as const

export const marketChannel = (symbol: string) => `market:${symbol.toUpperCase()}`
export const newsSymbolChannel = (symbol: string) => `news:symbol:${symbol.toUpperCase()}`
export const economicCalendarSymbolChannel = (symbol: string) => `economic-calendar:symbol:${symbol.toUpperCase()}`
