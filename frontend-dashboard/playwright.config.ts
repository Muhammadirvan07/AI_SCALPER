import { defineConfig, devices } from '@playwright/test'

const backendPython = process.env.AI_SCALPER_E2E_PYTHON ?? 'python'

export default defineConfig({
  testDir: './e2e',
  fullyParallel: false,
  forbidOnly: true,
  retries: 1,
  workers: 1,
  reporter: [['list']],
  use: {
    baseURL: 'http://127.0.0.1:5173',
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
  },
  projects: [
    {
      name: 'desktop-chromium',
      use: { ...devices['Desktop Chrome'] },
    },
    {
      name: 'mobile-chromium',
      use: { ...devices['Pixel 5'] },
    },
  ],
  webServer: [
    {
      command: `"${backendPython}" run_backend.py`,
      cwd: '../backend',
      url: 'http://127.0.0.1:8000/api/v1/health/live',
      reuseExistingServer: true,
      timeout: 30_000,
    },
    {
      command: 'npm run dev -- --host 127.0.0.1 --port 5173',
      cwd: '.',
      url: 'http://127.0.0.1:5173/overview',
      reuseExistingServer: true,
      timeout: 30_000,
    },
  ],
})
