import type { ApiSourceState } from '../../types/dashboardApi'
import { TerminalStatusBadge } from '../terminal/common/TerminalStatusBadge'

export function DataFreshnessBadge({ status }: { status: ApiSourceState }) {
  const tone =
    status === 'fresh'
      ? 'safe'
      : status === 'stale' || status === 'partial'
        ? 'warning'
        : 'blocked'
  return <TerminalStatusBadge label={status.toUpperCase()} tone={tone} compact />
}
