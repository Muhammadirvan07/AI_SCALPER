import { Building2, ChevronDown, Server } from 'lucide-react'
import type { ApiBrokerReadiness } from '../../types/dashboardApi'
import { operationalLabel } from '../../utils/landingViewModel'
import { OperationalSection } from './OperationalSection'
import { OperationalStatusTag } from './OperationalStatusTag'
import { OperationalTimestamp } from './OperationalTimestamp'

const brokerFacts = (broker: ApiBrokerReadiness) => [
  ['Environment', broker.environment],
  ['Server', broker.server],
  ['Mata uang', broker.account_currency],
  ['Leverage', broker.leverage],
] as const

const brokerChecks = (broker: ApiBrokerReadiness) => [
  ['Discovery', broker.discovery],
  ['Evidence regulasi', broker.regulatory_evidence],
  ['Review kalender', broker.calendar_review],
  ['Registrasi kontrak', broker.contract_registration],
  ['Runtime shadow', broker.shadow_runtime],
  ['Demo auto-order', broker.demo_auto_order_eligibility],
  ['Live eligibility', broker.live_eligibility],
] as const

function BrokerEvidence({
  broker,
  symbols,
}: {
  broker: ApiBrokerReadiness
  symbols: Array<[string, string]>
}) {
  return (
    <>
      <div className="ops-broker-symbols">
        <span>Simbol ditemukan</span>
        {symbols.length ? (
          <ul>
            {symbols.map(([canonical, brokerSymbol]) => (
              <li key={canonical}>
                <strong>{canonical}</strong>
                <span>{brokerSymbol}</span>
              </li>
            ))}
          </ul>
        ) : (
          <p>BELUM TERVERIFIKASI</p>
        )}
      </div>

      <dl className="ops-broker-checks">
        {brokerChecks(broker).map(([label, value]) => (
          <div key={label}>
            <dt>{label}</dt>
            <dd><OperationalStatusTag value={value} /></dd>
          </div>
        ))}
      </dl>

      <div className="ops-broker-window">
        <Server aria-hidden="true" className="size-4" />
        <div>
          <span>Blind until</span>
          <OperationalTimestamp value={broker.blind_until} />
        </div>
        <strong>
          {broker.expected_complete_sessions !== null
            ? `${broker.expected_complete_sessions} sesi`
            : 'SESI BELUM TERVERIFIKASI'}
        </strong>
      </div>
    </>
  )
}

function BrokerCard({ broker }: { broker: ApiBrokerReadiness }) {
  const symbols = Object.entries(broker.symbols_found)
  return (
    <article className="ops-broker-card">
      <header>
        <div>
          <Building2 aria-hidden="true" className="size-4" />
          <span>{broker.role ? operationalLabel(broker.role) : 'PERAN BELUM TERVERIFIKASI'}</span>
        </div>
        <h3>{broker.display_name}</h3>
        <OperationalStatusTag value={broker.source_status} label={`EVIDENCE ${operationalLabel(broker.source_status)}`} />
      </header>

      <dl className="ops-broker-facts">
        {brokerFacts(broker).map(([label, value]) => (
          <div key={label}>
            <dt>{label}</dt>
            <dd>{value ?? 'BELUM TERVERIFIKASI'}</dd>
          </div>
        ))}
      </dl>

      <div className="ops-broker-evidence-desktop">
        <BrokerEvidence broker={broker} symbols={symbols} />
      </div>
      <details className="ops-broker-details">
        <summary>
          Lihat evidence kandidat
          <ChevronDown aria-hidden="true" className="size-4" />
        </summary>
        <BrokerEvidence broker={broker} symbols={symbols} />
      </details>
    </article>
  )
}

export function BrokerReadinessSection({ brokers }: { brokers: ApiBrokerReadiness[] }) {
  return (
    <OperationalSection
      id="kesiapan-broker"
      eyebrow="04 / Candidate evidence"
      title="Kesiapan Broker"
      description="Kandidat bersifat read-only dan tidak menyediakan kemampuan order."
    >
      {brokers.length ? (
        <div className="ops-broker-grid">
          {brokers.map((broker) => <BrokerCard key={broker.candidate_id} broker={broker} />)}
        </div>
      ) : (
        <div className="ops-empty-panel">
          <Building2 aria-hidden="true" className="size-5" />
          <strong>Kandidat broker belum terverifikasi</strong>
          <p>Snapshot API tidak menyediakan evidence kandidat yang lolos validasi.</p>
        </div>
      )}
    </OperationalSection>
  )
}
