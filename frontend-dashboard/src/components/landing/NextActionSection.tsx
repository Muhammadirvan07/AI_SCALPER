import { ArrowRight, ClipboardCheck } from 'lucide-react'
import { Link } from '../../routing/Router'
import type {
  DashboardApiSnapshot,
  DashboardSourceMode,
} from '../../types/dashboardApi'
import { deriveRecommendedAction } from '../../utils/landingViewModel'
import { OperationalSection } from './OperationalSection'
import { OperationalStatusTag } from './OperationalStatusTag'

export function NextActionSection({
  snapshot,
  sourceMode,
}: {
  snapshot: DashboardApiSnapshot | null
  sourceMode: DashboardSourceMode
}) {
  const action = deriveRecommendedAction(snapshot, sourceMode)
  return (
    <OperationalSection
      id="langkah-berikutnya"
      eyebrow="07 / Operator guidance"
      title="Langkah Berikutnya"
      description="Rekomendasi diturunkan dari blocker dan freshness snapshot aktual."
      className={`ops-next-action ops-next-action--${action.tone}`}
    >
      <div className="ops-next-action__content">
        <ClipboardCheck aria-hidden="true" className="size-6" />
        <div>
          <OperationalStatusTag value={action.tone} label="TINDAKAN READ-ONLY" tone={action.tone} />
          <h3>{action.title}</h3>
          <p>{action.detail}</p>
          <small>Evidence: {action.evidence}</small>
        </div>
      </div>
      <Link to="/system-health" className="button-secondary">
        Periksa evidence sistem
        <ArrowRight aria-hidden="true" className="size-4" />
      </Link>
    </OperationalSection>
  )
}
