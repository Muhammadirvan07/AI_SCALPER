import { BrainCircuit } from 'lucide-react'
import { DomainPageLayout } from '../components/domain/DomainPageLayout'
import { SignalsPanel } from '../components/domain/SignalsPanel'

export function SignalsPage() {
  return <DomainPageLayout eyebrow="Decision observability" title="Trading Signals" description="Sinyal ternormalisasi beserta score, guard, blocking reason, source, dan mode." icon={BrainCircuit}><SignalsPanel /></DomainPageLayout>
}
