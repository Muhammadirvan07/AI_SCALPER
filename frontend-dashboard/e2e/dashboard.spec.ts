import { expect, test } from '@playwright/test'

test('overview terhubung ke API domain dan menampilkan safety invariant', async ({ page }) => {
  await page.goto('/overview')
  await expect(page.getByRole('heading', { name: 'AI_SCALPER Command Center' })).toBeVisible()
  const safety = page.getByTestId('safety-banner')
  await expect(safety).toContainText('DRY_RUN')
  await expect(safety).toContainText('LIVE EXECUTION LOCKED')
  await expect(safety).toContainText('Maximum effective lot: 0.01')
  await expect(page.getByText('Account Balance').first()).toBeVisible()
  await expect(page.getByText('52.5683')).toHaveCount(0)
  await expect(page.getByText(/MOCK|DUMMY/i)).toHaveCount(0)
})

test('connection indicator memakai satu shared WebSocket API v1', async ({ page }) => {
  const sockets = new Set<object>()
  page.on('websocket', (socket) => {
    if (!socket.url().endsWith('/api/v1/ws')) return
    sockets.add(socket)
    socket.on('close', () => sockets.delete(socket))
  })
  await page.goto('/overview')
  await expect(page.getByTestId('connection-indicator')).toContainText(/Connected|Reconnecting/)
  await expect.poll(() => sockets.size).toBe(1)
})

test('market symbol berasal dari backend dan M1 menampilkan fallback aktual', async ({ page }) => {
  await page.goto('/markets')
  const symbol = page.getByLabel('Market symbol')
  await expect(symbol).toBeVisible()
  await expect(symbol.locator('option')).toHaveCount(17)
  await symbol.selectOption('XAUUSD')
  await expect(symbol).toHaveValue('XAUUSD')
  await page.getByRole('button', { name: 'M1', exact: true }).click()
  await expect(page.getByText(/M1 data unavailable/i)).toBeVisible()
  await expect(page.getByText(/Showing actual M15 data/i)).toBeVisible()
  await expect(page.getByRole('img', { name: /Candlestick XAUUSD resolusi aktual M15/i })).toBeVisible()
})

test('watchlist mempertahankan null bid ask spread sebagai em dash', async ({ page }) => {
  await page.goto('/markets')
  const table = page.getByRole('region', { name: 'Watchlist aktual' })
  await expect(table).toBeVisible()
  const eurusd = table.getByRole('row').filter({ hasText: 'EURUSD' }).first()
  await expect(eurusd).toContainText('—')
  await eurusd.getByRole('button', { name: 'EURUSD' }).click()
  await expect(page.getByLabel('Market symbol')).toHaveValue('EURUSD')
})

test('signals dan blocking reason berasal dari endpoint signals', async ({ page }) => {
  await page.goto('/signals')
  await expect(page.getByRole('heading', { name: 'Trading Signals' }).first()).toBeVisible()
  const table = page.getByRole('region', { name: 'Trading signals aktual' })
  await expect(table).toBeVisible()
  await expect(table).toContainText('signal-')
  await expect(table).toContainText('WAIT')
  const reason = table.locator('.domain-reason button').first()
  await reason.click()
  await expect(table.getByText('Blocking reasons').first()).toBeVisible()
})

test('paper orders aktual mendukung tab dan tidak menyediakan live execution', async ({ page }) => {
  await page.goto('/paper-orders')
  await expect(page.getByRole('heading', { name: 'Paper Orders' }).first()).toBeVisible()
  await expect(page.getByRole('region', { name: 'Paper orders aktual' })).toContainText('PAPER_EURUSD')
  await page.getByRole('tab', { name: 'CLOSED' }).click()
  await expect(page.getByRole('region', { name: 'Paper orders aktual' })).toContainText('CLOSED')
  await expect(page.getByRole('button', { name: /enable live/i })).toHaveCount(0)
})

test('risk, quality, dan degraded system tidak disamarkan', async ({ page }) => {
  await page.goto('/risk-management')
  await expect(page.getByText('Effective max lot')).toBeVisible()
  await expect(page.getByText('0.01').first()).toBeVisible()
  await expect(page.getByText('Live trade locked')).toBeVisible()
  await page.goto('/system-health')
  await expect(page.getByText(/DEGRADED|MENURUN/i).first()).toBeVisible()
  await expect(page.getByText(/Decision Engine/i)).toBeVisible()
})

test('News Intelligence menampilkan state provider aktual tanpa headline dummy', async ({ page }) => {
  await page.goto('/news')
  await expect(page.locator('#main-content').getByRole('heading', { name: 'News Intelligence', exact: true })).toBeVisible()
  await expect(page.getByText('News Intelligence Runtime')).toBeVisible()
  await expect(page.getByText('Live Financial News')).toBeVisible()
  await expect(page.getByText('Recent Financial Releases')).toBeVisible()
  await expect(page.locator('iframe')).toHaveCount(0)
  await expect(page.getByText('RECENT', { exact: true }).first()).toBeVisible()
  await expect(page.getByText('3–7 DAYS OLD').first()).toBeVisible()
  await expect(page.getByText(/Alpha Vantage/i).first()).toBeVisible()
  await expect(page.getByText('UNCONFIGURED', { exact: true }).first()).toBeVisible()
  await expect(page.getByText('Sentiment Overview')).toBeVisible()
  await expect(page.getByText('Symbol Intelligence')).toBeVisible()
  await expect(page.getByText(/MOCK|DUMMY/i)).toHaveCount(0)
  await expect(page.getByRole('button', { name: /enable live/i })).toHaveCount(0)
})

test('Economic Intelligence native menampilkan timeline resmi tanpa iframe', async ({ page }) => {
  await page.goto('/economic-calendar')
  await expect(page.getByRole('heading', { name: 'Economic Intelligence', exact: true })).toBeVisible()
  await expect(page.getByText('Official Schedule')).toBeVisible()
  await expect(page.getByRole('tab', { name: 'timeline' })).toHaveAttribute('aria-selected', 'true')
  await expect(page.locator('section[aria-labelledby="next-critical-title"]')).toBeVisible()
  await expect(page.getByText('Source Health')).toBeVisible()
  await expect(page.locator('iframe')).toHaveCount(0)
  await expect(page.getByText(/READ ONLY/).first()).toBeVisible()
  await expect(page.getByTestId('safety-banner')).toContainText('LIVE EXECUTION LOCKED')
  await expect(page.getByRole('button', { name: /enable live/i })).toHaveCount(0)
})

test('AI Diagnostics menampilkan calendar guard preview sebagai read-only context', async ({ page }) => {
  await page.goto('/ai-diagnostics')
  await expect(page.getByText('Economic Event Context')).toBeVisible()
  await expect(page.getByText('READ-ONLY', { exact: true })).toBeVisible()
  await expect(page.getByText('DOES NOT AFFECT EXECUTION', { exact: true })).toBeVisible()
  await expect(page.getByRole('button', { name: /enable.*calendar|execution guard/i })).toHaveCount(0)
  await expect(page.getByTestId('safety-banner')).toContainText('LIVE EXECUTION LOCKED')
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth)
  expect(overflow).toBeLessThanOrEqual(1)
})

test('Overview menampilkan next economic risk tanpa recommendation trading', async ({ page }) => {
  await page.goto('/overview')
  await expect(page.getByText('Next Economic Risk')).toBeVisible()
  await expect(page.getByText(/diagnostic: .*read-only/i)).toBeVisible()
  await expect(page.getByText(/calendar.*BUY|calendar.*SELL/i)).toHaveCount(0)
})

test('backend offline menampilkan error tanpa mock fallback', async ({ page }) => {
  await page.route('http://127.0.0.1:8000/api/v1/**', (route) => route.abort('connectionfailed'))
  await page.routeWebSocket('ws://127.0.0.1:8000/api/v1/ws', (socket) => socket.close())
  await page.goto('/overview')
  await expect(page.getByText(/Backend unavailable|Data tidak tersedia/i).first()).toBeVisible()
  await expect(page.getByTestId('safety-banner')).toContainText('LIVE EXECUTION LOCKED')
  await expect(page.getByText(/MOCK|DUMMY/i)).toHaveCount(0)
})

test('WebSocket disconnect menampilkan reconnecting tanpa mengosongkan data REST', async ({ page }) => {
  await page.routeWebSocket('ws://127.0.0.1:8000/api/v1/ws', (socket) => socket.close())
  await page.goto('/overview')
  await expect(page.getByText(/WEBSOCKET RECONNECTING/i)).toBeVisible()
  await expect(page.getByText('Account Balance').first()).toBeVisible()
})

test('semua route bebas console error dan horizontal overflow tak disengaja', async ({ page }) => {
  const errors: string[] = []
  page.on('console', (message) => { if (message.type() === 'error') errors.push(message.text()) })
  page.on('pageerror', (error) => errors.push(error.message))
  const routes = ['/', '/overview', '/analytics', '/markets', '/news', '/economic-calendar', '/signals', '/paper-orders', '/performance', '/strategy', '/ai-diagnostics', '/risk-management', '/system-logs', '/system-health', '/settings']
  for (const route of routes) {
    await page.goto(route)
    await expect(page.locator('#main-content')).toBeVisible()
    const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth)
    expect(overflow, `overflow pada ${route}`).toBeLessThanOrEqual(1)
  }
  expect(errors).toEqual([])
})

test('API browser tidak mempublikasikan endpoint mutasi', async ({ request }) => {
  const schema = await request.get('http://127.0.0.1:8000/openapi.json')
  expect(schema.ok()).toBeTruthy()
  const paths = (await schema.json()).paths as Record<string, Record<string, unknown>>
  expect(Object.keys(paths).some((path) => path.startsWith('/api/v1/commands'))).toBeFalsy()
  expect(Object.values(paths).every((methods) => Object.keys(methods).every((method) => method === 'get'))).toBeTruthy()
  const response = await request.post('http://127.0.0.1:8000/api/v1/commands', { data: { command: 'enable_live_trading' } })
  expect(response.status()).toBe(404)
})
