import { validateLoopbackServiceUrl } from './loopbackOrigins'

type ViteEnvironment = Partial<
  Record<
    | 'VITE_API_BASE_URL'
    | 'VITE_WS_URL',
    string
  >
> & {
  DEV?: boolean
}

const viteEnvironment = ((import.meta as ImportMeta & { env?: ViteEnvironment }).env ?? {})

const requiredValue = (key: 'VITE_API_BASE_URL' | 'VITE_WS_URL', fallback: string) => {
  const value = viteEnvironment[key]?.trim()
  if (value) return validateLoopbackServiceUrl(key, value)
  if (viteEnvironment.DEV) {
    throw new Error(
      `Konfigurasi ${key} belum tersedia. Salin .env.example ke .env.local sebelum menjalankan dashboard.`,
    )
  }
  return validateLoopbackServiceUrl(key, fallback)
}

export const environment = Object.freeze({
  apiBaseUrl: requiredValue('VITE_API_BASE_URL', 'http://127.0.0.1:8000/api/v1'),
  websocketUrl: requiredValue('VITE_WS_URL', 'ws://127.0.0.1:8000/api/v1/ws'),
  isDevelopment: Boolean(viteEnvironment.DEV),
  requestTimeoutMs: 10_000,
  maximumRequestRetries: 2,
})
