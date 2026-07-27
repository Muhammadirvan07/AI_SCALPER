import { useEffect, useState } from 'react'

const describeAge = (timestamp: string | null, nowMs: number) => {
  if (!timestamp || !Number.isFinite(Date.parse(timestamp))) return 'TIDAK TERVERIFIKASI'
  const seconds = Math.max(0, Math.floor((nowMs - Date.parse(timestamp)) / 1_000))
  if (seconds < 60) return `${seconds} detik`
  const minutes = Math.floor(seconds / 60)
  if (minutes < 60) return `${minutes} menit`
  return `${Math.floor(minutes / 60)} jam ${minutes % 60} menit`
}

export function HeartbeatAge({ timestamp }: { timestamp: string | null }) {
  const [nowMs, setNowMs] = useState(() => Date.now())

  useEffect(() => {
    const timer = window.setInterval(() => setNowMs(Date.now()), 10_000)
    return () => window.clearInterval(timer)
  }, [])

  return <span data-testid="heartbeat-age">{describeAge(timestamp, nowMs)}</span>
}
