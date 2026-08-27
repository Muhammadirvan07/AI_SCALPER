import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'
import { LOOPBACK_API_ORIGINS, LOOPBACK_WS_ORIGINS } from './src/config/loopbackOrigins'

const contentSecurityPolicy = (allowViteDevelopmentPreamble: boolean) => [
  "default-src 'self'",
  // @vitejs/plugin-react injects an inline Fast Refresh preamble in development only.
  `script-src 'self'${allowViteDevelopmentPreamble ? " 'unsafe-inline'" : ''}`,
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data:",
  "font-src 'self' data:",
  [
    "connect-src 'self'",
    ...LOOPBACK_API_ORIGINS,
    ...LOOPBACK_WS_ORIGINS,
    ...(allowViteDevelopmentPreamble
      ? ['ws://127.0.0.1:5173', 'ws://localhost:5173']
      : []),
  ].join(' '),
  "frame-src 'none'",
  "child-src 'none'",
  "object-src 'none'",
  "base-uri 'self'",
  "frame-ancestors 'self'",
].join('; ')

const securityHeaders = (allowViteDevelopmentPreamble = false) => ({
  'Content-Security-Policy': contentSecurityPolicy(allowViteDevelopmentPreamble),
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'X-Content-Type-Options': 'nosniff',
})

export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    port: 5173,
    headers: securityHeaders(true),
  },
  preview: {
    port: 4173,
    headers: securityHeaders(),
  },
  build: {
    sourcemap: true,
    rollupOptions: {
      output: {
        manualChunks(id) {
          if (/node_modules\/victory-vendor\//.test(id)) {
            return 'chart-math'
          }
          if (
            /node_modules\/(?:recharts|@reduxjs\/toolkit|clsx|decimal\.js-light|es-toolkit|eventemitter3|immer|react-redux|reselect|tiny-invariant|use-sync-external-store)\//.test(id)
          ) {
            return 'chart-vendor'
          }
        },
      },
    },
  },
})
