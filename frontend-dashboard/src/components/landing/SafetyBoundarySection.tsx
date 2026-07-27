import { LockKeyhole, ShieldCheck } from 'lucide-react'
import type { DashboardApiSnapshot } from '../../types/dashboardApi'
import { OperationalSection } from './OperationalSection'
import { OperationalStatusTag } from './OperationalStatusTag'

const booleanLabel = (value: boolean | null | undefined) => {
  if (value === null || value === undefined) return 'TIDAK TERVERIFIKASI'
  return value ? 'TRUE / YA' : 'FALSE / TIDAK'
}

export function SafetyBoundarySection({
  snapshot,
}: {
  snapshot: DashboardApiSnapshot | null
}) {
  const safety = snapshot?.safety
  const rows = [
    {
      label: 'live_allowed',
      value: safety ? booleanLabel(safety.live_allowed) : 'TIDAK TERVERIFIKASI',
      status: safety ? 'PASSED' : 'UNVERIFIED',
      note: 'Kontrak frontend hanya menerima nilai false.',
    },
    {
      label: 'live_trading',
      value: safety ? safety.live_trading : 'TIDAK TERVERIFIKASI · UI MEMAKSA LOCKED',
      status: 'LOCKED',
      note: 'LOCKED adalah batas perlindungan, bukan kegagalan sistem.',
    },
    {
      label: 'safe_to_demo_observe',
      value: safety ? booleanLabel(safety.safe_to_demo_observe) : 'TIDAK TERVERIFIKASI',
      status: safety?.safe_to_demo_observe === true ? 'PASSED' : 'UNVERIFIED',
      note: 'Hanya menyatakan kelayakan observasi.',
    },
    {
      label: 'safe_to_demo_auto_order',
      value: safety ? booleanLabel(safety.safe_to_demo_auto_order) : 'TIDAK TERVERIFIKASI',
      status: safety ? 'BLOCKED' : 'UNVERIFIED',
      note: 'Demo auto-order tetap di luar cakupan.',
    },
    {
      label: 'max_lot',
      value: safety ? safety.max_lot.toFixed(2) : 'TIDAK TERVERIFIKASI',
      status: safety ? 'PASSED' : 'UNVERIFIED',
      note: 'Batas tampilan immutable maksimum 0.01.',
    },
    {
      label: 'order capability',
      value: safety?.order_capability ?? 'TIDAK TERVERIFIKASI',
      status: safety?.order_capability ?? 'UNVERIFIED',
      note: 'Dashboard tidak menyediakan kemampuan mutasi broker.',
    },
    {
      label: 'safety violation',
      value: safety ? booleanLabel(safety.safety_violation) : 'TIDAK TERVERIFIKASI',
      status: safety ? (safety.safety_violation ? 'VIOLATION' : 'PASSED') : 'UNVERIFIED',
      note: safety?.violations[0] ?? 'Tidak ada detail kontradiksi pada snapshot.',
    },
    {
      label: 'guard status',
      value: safety?.guard_enabled === null || safety?.guard_enabled === undefined
        ? 'TIDAK TERVERIFIKASI'
        : safety.guard_enabled
          ? 'AKTIF'
          : 'NONAKTIF',
      status: safety?.guard_enabled === true
        ? 'ENABLED'
        : safety?.guard_enabled === false
          ? 'DISABLED'
          : 'UNVERIFIED',
      note: safety?.bridge_mode
        ? `Mode bridge teramati: ${safety.bridge_mode}.`
        : 'Mode bridge belum terverifikasi.',
    },
  ]

  return (
    <OperationalSection
      id="batas-keselamatan"
      eyebrow="02 / Safety"
      title="Batas Keselamatan"
      description="Nilai aktual ditampilkan apa adanya setelah lolos runtime validation."
      className="ops-section--safety"
    >
      <div className="ops-safety-lock" role="status">
        <LockKeyhole aria-hidden="true" className="size-5" />
        <div>
          <strong>LIVE ORDER TERKUNCI</strong>
          <span>Tidak ada kontrol order, aktivasi live, atau mutasi broker pada dashboard.</span>
        </div>
        <ShieldCheck aria-hidden="true" className="size-5" />
      </div>
      <div className="ops-safety-grid">
        {rows.map((row) => (
          <article key={row.label} className="ops-safety-item">
            <header>
              <h3>{row.label}</h3>
              <OperationalStatusTag value={row.status} />
            </header>
            <strong>{row.value}</strong>
            <p>{row.note}</p>
          </article>
        ))}
      </div>
    </OperationalSection>
  )
}
