import {
  BookOpen,
  Braces,
  ExternalLink,
  FileClock,
  Network,
  ShieldCheck,
  Wrench,
} from 'lucide-react'
import { dashboardDataConfig } from '../../config/dataSources'
import { Link } from '../../routing/Router'
import { OperationalSection } from './OperationalSection'

const docs = [
  { slug: 'architecture', label: 'Dokumentasi arsitektur', Icon: Network },
  { slug: 'operator-runbook', label: 'Runbook operator', Icon: Wrench },
  { slug: 'release-history', label: 'Riwayat rilis', Icon: FileClock },
  { slug: 'safety-audit', label: 'Audit keselamatan', Icon: ShieldCheck },
  { slug: 'api-contract', label: 'Kontrak API', Icon: Braces },
]

export function DocumentationLinksSection() {
  const baseUrl = dashboardDataConfig.apiBaseUrl.replace(/\/$/, '')
  return (
    <OperationalSection
      id="dokumentasi"
      eyebrow="08 / Reference"
      title="Dokumentasi dan Jalur Analisis"
      description="Tautan dokumentasi dilayani read-only dari allowlist backend."
    >
      <nav className="ops-documentation-grid" aria-label="Dokumentasi operasional">
        <Link to="/overview" className="ops-document-link">
          <BookOpen aria-hidden="true" className="size-5" />
          <span><strong>Overview</strong><small>Terminal analitik mendalam</small></span>
          <ExternalLink aria-hidden="true" className="size-4" />
        </Link>
        <Link to="/system-health" className="ops-document-link">
          <ShieldCheck aria-hidden="true" className="size-5" />
          <span><strong>Kesehatan Sistem</strong><small>Sumber, guard, dan freshness</small></span>
          <ExternalLink aria-hidden="true" className="size-4" />
        </Link>
        {docs.map(({ slug, label, Icon }) => (
          <a
            key={slug}
            href={`${baseUrl}/api/v1/documentation/${slug}`}
            target="_blank"
            rel="noreferrer"
            className="ops-document-link"
          >
            <Icon aria-hidden="true" className="size-5" />
            <span><strong>{label}</strong><small>Buka dokumen Markdown</small></span>
            <ExternalLink aria-hidden="true" className="size-4" />
          </a>
        ))}
      </nav>
    </OperationalSection>
  )
}
