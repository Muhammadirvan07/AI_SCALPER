import { dashboardDataConfig } from '../config/dataSources'
import type { DashboardApiSnapshot } from '../types/dashboardApi'
import { isDashboardSnapshot } from '../utils/realtimeGuards'

export class DashboardApiError extends Error {
  constructor(
    message: string,
    public readonly status: number | null = null,
  ) {
    super(message)
    this.name = 'DashboardApiError'
  }
}

export async function fetchDashboardSnapshot(
  signal?: AbortSignal,
): Promise<DashboardApiSnapshot> {
  let response: Response
  try {
    response = await fetch(`${dashboardDataConfig.apiBaseUrl}/api/v1/snapshot`, {
      method: 'GET',
      headers: { Accept: 'application/json' },
      signal,
    })
  } catch (error) {
    if (error instanceof DOMException && error.name === 'AbortError') throw error
    throw new DashboardApiError('Backend dashboard tidak dapat dijangkau.')
  }
  if (!response.ok) {
    throw new DashboardApiError(
      `Snapshot API gagal dengan status ${response.status}.`,
      response.status,
    )
  }
  const payload: unknown = await response.json()
  if (!isDashboardSnapshot(payload)) {
    throw new DashboardApiError('Snapshot API tidak sesuai kontrak keselamatan.')
  }
  return payload
}
