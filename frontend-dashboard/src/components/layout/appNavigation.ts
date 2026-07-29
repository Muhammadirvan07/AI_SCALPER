import {
  Activity,
  BrainCircuit,
  CalendarClock,
  CandlestickChart,
  ChartNoAxesCombined,
  ClipboardList,
  LayoutDashboard,
  Newspaper,
  RadioTower,
  ScrollText,
  Settings,
  ShieldAlert,
  Workflow,
  type LucideIcon,
} from 'lucide-react'

export interface AppNavigationItem {
  label: string
  shortLabel: string
  to: string
  icon: LucideIcon
}

export interface AppNavigationSection {
  label: string
  items: AppNavigationItem[]
}

export const appNavigation: AppNavigationSection[] = [
  {
    label: 'Workspace',
    items: [
      { label: 'Overview', shortLabel: 'Overview', to: '/overview', icon: LayoutDashboard },
      { label: 'Market', shortLabel: 'Market', to: '/markets', icon: CandlestickChart },
      { label: 'Trading Signals', shortLabel: 'Signals', to: '/signals', icon: RadioTower },
      { label: 'Paper Orders', shortLabel: 'Orders', to: '/paper-orders', icon: ClipboardList },
      { label: 'Performance', shortLabel: 'Performance', to: '/performance', icon: ChartNoAxesCombined },
    ],
  },
  {
    label: 'Intelligence',
    items: [
      { label: 'Strategy', shortLabel: 'Strategy', to: '/strategy', icon: Workflow },
      { label: 'AI Diagnostics', shortLabel: 'AI', to: '/ai-diagnostics', icon: BrainCircuit },
      { label: 'Risk Management', shortLabel: 'Risk', to: '/risk-management', icon: ShieldAlert },
      { label: 'News Intelligence', shortLabel: 'News', to: '/news', icon: Newspaper },
      { label: 'Economic Intelligence', shortLabel: 'Calendar', to: '/economic-calendar', icon: CalendarClock },
    ],
  },
  {
    label: 'System',
    items: [
      { label: 'System Logs', shortLabel: 'Logs', to: '/system-logs', icon: ScrollText },
      { label: 'System Health', shortLabel: 'Health', to: '/system-health', icon: Activity },
      { label: 'Settings', shortLabel: 'Settings', to: '/settings', icon: Settings },
    ],
  },
]

export const pageMetaByPath: Record<string, { title: string; context: string }> = {
  '/': { title: 'Operations Home', context: 'Project readiness and safety boundary' },
  '/overview': { title: 'Overview', context: 'Realtime command center' },
  '/markets': { title: 'Market', context: 'Price structure and watchlist' },
  '/signals': { title: 'Trading Signals', context: 'Decision stream and evidence' },
  '/paper-orders': { title: 'Paper Orders', context: 'Simulated execution ledger' },
  '/performance': { title: 'Performance', context: 'Paper equity and quality analytics' },
  '/analytics': { title: 'Analytics', context: 'Extended performance diagnostics' },
  '/strategy': { title: 'Strategy', context: 'Scoring, guards, and pair rotation' },
  '/ai-diagnostics': { title: 'AI Diagnostics', context: 'Reasoning and decision-state telemetry' },
  '/risk-management': { title: 'Risk Management', context: 'Fail-closed safety controls' },
  '/news': { title: 'News Intelligence', context: 'Event impact and readiness' },
  '/economic-calendar': { title: 'Economic Intelligence', context: 'Official macro release timeline' },
  '/system-logs': { title: 'System Logs', context: 'Operational and decision events' },
  '/system-health': { title: 'System Health', context: 'Sources, guards, and heartbeat' },
  '/settings': { title: 'Settings', context: 'Read-only runtime configuration' },
}

export const defaultPageMeta = {
  title: 'AI_SCALPER',
  context: 'Institutional paper-trading intelligence',
}
