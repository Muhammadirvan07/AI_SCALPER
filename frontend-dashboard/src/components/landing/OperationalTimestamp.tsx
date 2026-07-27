import { formatDualTime } from '../../utils/landingViewModel'

export function OperationalTimestamp({ value }: { value: string | null | undefined }) {
  const formatted = formatDualTime(value)
  if (!formatted) return <span className="ops-unverified">TIDAK TERVERIFIKASI</span>

  return (
    <time dateTime={formatted.iso} className="ops-timestamp">
      <span>{formatted.jst} JST</span>
      <span>{formatted.utc} UTC</span>
    </time>
  )
}
