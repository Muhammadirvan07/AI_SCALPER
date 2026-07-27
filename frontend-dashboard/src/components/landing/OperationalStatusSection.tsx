import { Activity, Database, RadioTower } from 'lucide-react'
import type {
  DashboardApiSnapshot,
  RealtimeConnectionInfo,
} from '../../types/dashboardApi'
import { operationalLabel } from '../../utils/landingViewModel'
import { HeartbeatAge } from './HeartbeatAge'
import { OperationalSection } from './OperationalSection'
import { OperationalStatusTag } from './OperationalStatusTag'
import { OperationalTimestamp } from './OperationalTimestamp'

interface OperationalStatusSectionProps {
  snapshot: DashboardApiSnapshot | null
  connection: RealtimeConnectionInfo
}

export function OperationalStatusSection({
  snapshot,
  connection,
}: OperationalStatusSectionProps) {
  const backendStatus = snapshot && connection.sourceMode !== 'DISCONNECTED'
    ? 'CONNECTED'
    : 'DISCONNECTED'
  const channel = connection.sourceMode === 'REALTIME'
    ? 'WEBSOCKET REALTIME'
    : connection.sourceMode === 'REST POLLING'
      ? 'REST POLLING'
      : connection.sourceMode

  return (
    <OperationalSection
      id="status-operasional"
      eyebrow="01 / Telemetri"
      title="Status Operasional"
      description="Keadaan koneksi dan sumber diambil dari provider realtime bersama."
    >
      <div className="ops-status-overview">
        <div>
          <Database aria-hidden="true" className="size-4" />
          <span>Backend</span>
          <OperationalStatusTag value={backendStatus} />
        </div>
        <div>
          <RadioTower aria-hidden="true" className="size-4" />
          <span>Jalur data</span>
          <OperationalStatusTag value={snapshot ? channel : 'UNVERIFIED'} />
        </div>
        <div>
          <Activity aria-hidden="true" className="size-4" />
          <span>Kondisi sumber</span>
          <OperationalStatusTag value={snapshot?.connection.status ?? 'UNVERIFIED'} />
        </div>
        <div>
          <Activity aria-hidden="true" className="size-4" />
          <span>Socket</span>
          <OperationalStatusTag
            value={connection.socketActive ? 'ACTIVE' : 'DISCONNECTED'}
            label={connection.socketActive ? 'WEBSOCKET AKTIF' : 'WEBSOCKET TIDAK AKTIF'}
          />
        </div>
      </div>

      <dl className="ops-definition-grid">
        <div>
          <dt>Versi snapshot</dt>
          <dd>{snapshot ? `v${snapshot.version}` : 'TIDAK TERVERIFIKASI'}</dd>
        </div>
        <div>
          <dt>Waktu snapshot</dt>
          <dd><OperationalTimestamp value={snapshot?.generated_at} /></dd>
        </div>
        <div>
          <dt>Pembaruan sumber terakhir</dt>
          <dd><OperationalTimestamp value={snapshot?.source_updated_at} /></dd>
        </div>
        <div>
          <dt>Heartbeat terakhir</dt>
          <dd><OperationalTimestamp value={connection.lastHeartbeatAt} /></dd>
        </div>
        <div>
          <dt>Umur heartbeat</dt>
          <dd><HeartbeatAge timestamp={connection.lastHeartbeatAt} /></dd>
        </div>
        <div>
          <dt>Sumber kedaluwarsa</dt>
          <dd>{snapshot ? snapshot.connection.stale_source_count : 'TIDAK TERVERIFIKASI'}</dd>
        </div>
        <div>
          <dt>Status pasar</dt>
          <dd>{operationalLabel(snapshot?.session.market_open_status)}</dd>
        </div>
        <div>
          <dt>Sesi saat ini</dt>
          <dd>{operationalLabel(snapshot?.session.current_session)}</dd>
        </div>
        <div>
          <dt>Pair utama diamati</dt>
          <dd>
            {snapshot?.decision_health.current_symbol ??
              snapshot?.summary.active_pairs[0] ??
              'TIDAK TERVERIFIKASI'}
          </dd>
        </div>
        <div>
          <dt>Latensi adapter</dt>
          <dd>{snapshot ? `${snapshot.connection.latency_ms.toFixed(1)} ms` : 'TIDAK TERVERIFIKASI'}</dd>
        </div>
      </dl>
    </OperationalSection>
  )
}
