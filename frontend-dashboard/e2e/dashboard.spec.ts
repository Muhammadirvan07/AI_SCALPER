import { expect, test } from '@playwright/test'

test('overview connects to the domain API and preserves safety invariants', async ({ page }) => {
  await page.goto('/overview')
  await expect(page.getByRole('heading', { name: 'Performance Overview' })).toBeVisible()
  const safety = page.getByTestId('safety-banner')
  await expect(safety).toContainText('DRY_RUN')
  await expect(safety).toContainText('LIVE EXECUTION LOCKED')
  await expect(page.getByText('52.5683')).toHaveCount(0)
  await expect(page.getByText(/MOCK|DUMMY/i)).toHaveCount(0)
})

test('connection indicator uses one shared WebSocket API v1', async ({ page }) => {
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

test('empty market does not fabricate symbols or quotes', async ({ page }) => {
  await page.goto('/markets')
  const symbol = page.getByLabel('Market symbol')
  await expect(symbol).toBeVisible()
  await expect(symbol.locator('option')).toHaveCount(0)
  await expect(page.getByText(/MOCK|DUMMY/i)).toHaveCount(0)
})

test('empty watchlist does not fabricate bid ask or spread', async ({ page }) => {
  await page.goto('/markets')
  await expect(page.getByRole('region', { name: 'Watchlist aktual' })).toHaveCount(0)
  await expect(page.getByText(/MOCK|DUMMY/i)).toHaveCount(0)
})

test('empty signals state does not fabricate trading signals', async ({ page }) => {
  await page.goto('/signals')
  await expect(page.getByRole('heading', { name: 'Trading Signals' }).first()).toBeVisible()
  await expect(page.getByRole('region', { name: 'Trading signals aktual' })).toHaveCount(0)
  await expect(page.getByText(/MOCK|DUMMY/i)).toHaveCount(0)
})

test('empty paper orders state cannot expose live execution', async ({ page }) => {
  await page.goto('/paper-orders')
  await expect(page.getByRole('heading', { name: 'Paper Orders' }).first()).toBeVisible()
  await expect(page.getByRole('region', { name: 'Paper orders aktual' })).toHaveCount(0)
  await expect(page.getByRole('button', { name: /enable live/i })).toHaveCount(0)
})

test('risk and degraded system states remain fail closed', async ({ page }) => {
  await page.goto('/risk-management')
  await expect(page.getByTestId('safety-banner')).toContainText('LIVE EXECUTION LOCKED')
  await expect(page.getByRole('button', { name: /enable live/i })).toHaveCount(0)
  await page.goto('/system-health')
  await expect(page.locator('#main-content')).toBeVisible()
  await expect(page.getByText(/MOCK|DUMMY/i)).toHaveCount(0)
})

test('News Intelligence shows provider state without dummy headlines', async ({ page }) => {
  await page.goto('/news')
  await expect(page.locator('#main-content').getByRole('heading', { name: 'News Intelligence', exact: true })).toBeVisible()
  await expect(page.getByText('News Intelligence Runtime')).toBeVisible()
  await expect(page.getByText('Live Financial News')).toBeVisible()
  await expect(page.getByText('Recent Financial Releases')).toBeVisible()
  await expect(page.locator('iframe')).toHaveCount(0)
  await expect(page.getByText('RECENT', { exact: true }).first()).toBeVisible()
  await expect(page.getByText(/Alpha Vantage/i).first()).toBeVisible()
  await expect(page.getByText('UNCONFIGURED', { exact: true }).first()).toBeVisible()
  await expect(page.getByText('Sentiment Overview')).toBeVisible()
  await expect(page.getByText('Symbol Intelligence')).toBeVisible()
  await expect(page.getByText(/MOCK|DUMMY/i)).toHaveCount(0)
  await expect(page.getByRole('button', { name: /enable live/i })).toHaveCount(0)
})

test('Economic Intelligence uses a native read-only timeline', async ({ page }) => {
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

test('AI Diagnostics cannot mutate the calendar execution guard', async ({ page }) => {
  await page.goto('/ai-diagnostics')
  await expect(page.getByText('Economic Event Context')).toBeVisible()
  await expect(page.getByRole('button', { name: /enable.*calendar|execution guard/i })).toHaveCount(0)
  await expect(page.getByTestId('safety-banner')).toContainText('LIVE EXECUTION LOCKED')
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth)
  expect(overflow).toBeLessThanOrEqual(1)
})

test('Overview reports unavailable economic context without a trade recommendation', async ({ page }) => {
  await page.goto('/overview')
  await expect(page.getByText('Next Economic Risk')).toBeVisible()
  await expect(page.getByText('Economic context unavailable')).toBeVisible()
  await expect(page.getByText(/calendar.*BUY|calendar.*SELL/i)).toHaveCount(0)
})

test('backend offline shows an error without a mock fallback', async ({ page }) => {
  await page.route('http://127.0.0.1:8000/api/v1/**', (route) => route.abort('connectionfailed'))
  await page.routeWebSocket('ws://127.0.0.1:8000/api/v1/ws', (socket) => socket.close())
  await page.goto('/overview')
  await expect(page.getByText(/Backend unavailable|Data tidak tersedia/i).first()).toBeVisible()
  await expect(page.getByTestId('safety-banner')).toContainText('LIVE EXECUTION LOCKED')
  await expect(page.getByText(/MOCK|DUMMY/i)).toHaveCount(0)
})

test('WebSocket disconnect preserves the fail-closed REST view', async ({ page }) => {
  await page.routeWebSocket('ws://127.0.0.1:8000/api/v1/ws', (socket) => socket.close())
  await page.goto('/overview')
  await expect(page.getByText(/WEBSOCKET RECONNECTING/i)).toBeVisible()
  await expect(page.getByTestId('safety-banner')).toContainText('LIVE EXECUTION LOCKED')
})

test('all routes avoid console errors and unintended horizontal overflow', async ({ page }) => {
  const errors: string[] = []
  page.on('console', (message) => {
    const text = message.text()
    const expectedUnavailable = text === 'Failed to load resource: the server responded with a status of 503 (Service Unavailable)'
    if (message.type() === 'error' && !expectedUnavailable) errors.push(text)
  })
  page.on('pageerror', (error) => errors.push(error.message))
  const routes = ['/', '/overview', '/analytics', '/markets', '/news', '/economic-calendar', '/signals', '/paper-orders', '/performance', '/strategy', '/ai-diagnostics', '/risk-management', '/system-logs', '/system-health', '/settings']
  for (const route of routes) {
    await page.goto(route)
    await expect(page.locator('#main-content')).toBeVisible()
    const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth)
    expect(overflow, `overflow on ${route}`).toBeLessThanOrEqual(1)
  }
  expect(errors).toEqual([])
})

test('browser API does not expose mutation endpoints', async ({ request }) => {
  const schema = await request.get('http://127.0.0.1:8000/openapi.json')
  expect(schema.ok()).toBeTruthy()
  const paths = (await schema.json()).paths as Record<string, Record<string, unknown>>
  expect(Object.keys(paths).some((path) => path.startsWith('/api/v1/commands'))).toBeFalsy()
  expect(Object.values(paths).every((methods) => Object.keys(methods).every((method) => method === 'get'))).toBeTruthy()
  const response = await request.post('http://127.0.0.1:8000/api/v1/commands', { data: { command: 'enable_live_trading' } })
  expect(response.status()).toBe(404)
})
