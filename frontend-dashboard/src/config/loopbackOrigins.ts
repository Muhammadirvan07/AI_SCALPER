export const LOOPBACK_API_ORIGINS = Object.freeze([
  'http://127.0.0.1:8000',
  'http://localhost:8000',
])

export const LOOPBACK_WS_ORIGINS = Object.freeze([
  'ws://127.0.0.1:8000',
  'ws://localhost:8000',
])

type ServiceUrlKey = 'VITE_API_BASE_URL' | 'VITE_WS_URL'

const allowedOrigins: Readonly<Record<ServiceUrlKey, readonly string[]>> = {
  VITE_API_BASE_URL: LOOPBACK_API_ORIGINS,
  VITE_WS_URL: LOOPBACK_WS_ORIGINS,
}

export function validateLoopbackServiceUrl(key: ServiceUrlKey, rawValue: string): string {
  let parsed: URL
  try {
    parsed = new URL(rawValue)
  } catch {
    throw new Error(`Konfigurasi ${key} bukan URL yang valid.`)
  }

  if (
    parsed.username
    || parsed.password
    || parsed.search
    || parsed.hash
    || !allowedOrigins[key].includes(parsed.origin)
  ) {
    throw new Error(
      `Konfigurasi ${key} harus memakai service loopback AI_SCALPER pada port 8000.`,
    )
  }

  return rawValue.replace(/\/$/, '')
}
