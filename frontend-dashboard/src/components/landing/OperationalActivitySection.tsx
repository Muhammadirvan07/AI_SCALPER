import { Activity, ArrowRight } from 'lucide-react'
import { Link } from '../../routing/Router'
import type {
  DashboardApiSnapshot,
  RealtimeConnectionInfo,
} from '../../types/dashboardApi'
import { buildOperationalActivity } from '../../utils/landingViewModel'
import { OperationalSection } from './OperationalSection'
import { OperationalStatusTag } from './OperationalStatusTag'
import { OperationalTimestamp } from './OperationalTimestamp'

export function OperationalActivitySection({
  snapshot,
  connection,
}: {
  snapshot: DashboardApiSnapshot | null
  connection: RealtimeConnectionInfo
}) {
  const activity = buildOperationalActivity(snapshot, connection)
  return (
    <OperationalSection
      id="aktivitas-operasional"
      eyebrow="06 / Event timeline"
      title="Aktivitas Operasional Terkini"
      description="Event aktual dibatasi agar status kritis tetap mudah dipindai."
    >
      {activity.length ? (
        <ol className="ops-activity-list">
          {activity.map((item) => (
            <li key={item.id}>
              <span className={`ops-activity-marker ops-activity-marker--${item.tone}`} aria-hidden="true" />
              <div>
                <header>
                  <h3>{item.title}</h3>
                  <OperationalStatusTag value={item.tone} label={item.tone === 'safe' ? 'TERVERIFIKASI' : item.tone === 'blocked' ? 'DIBLOKIR' : item.tone === 'warning' ? 'PERLU DITINJAU' : 'INFORMASI'} tone={item.tone} />
                </header>
                <p>{item.detail}</p>
                <OperationalTimestamp value={item.timestamp} />
              </div>
            </li>
          ))}
        </ol>
      ) : (
        <div className="ops-empty-panel">
          <Activity aria-hidden="true" className="size-5" />
          <strong>Aktivitas belum terverifikasi</strong>
          <p>Snapshot aktual atau timestamp event belum tersedia.</p>
        </div>
      )}
      <Link to="/system-health" className="ops-inline-link">
        Buka kesehatan sistem
        <ArrowRight aria-hidden="true" className="size-4" />
      </Link>
    </OperationalSection>
  )
}
