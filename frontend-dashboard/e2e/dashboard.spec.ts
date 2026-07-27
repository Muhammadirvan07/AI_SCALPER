import { expect, test } from '@playwright/test'

test('dashboard memuat snapshot aktual tanpa membuka live trading', async ({ page }) => {
  const consoleErrors: string[] = []
  page.on('console', (message) => {
    if (message.type() === 'error') consoleErrors.push(message.text())
  })

  await page.goto('/overview')
  await expect(page.getByText('AI_SCALPER', { exact: false }).first()).toBeVisible()
  await expect(
    page.getByText(/LIVE.*TERKUNCI|LIVE.*LOCKED/i).filter({ visible: true }).first(),
  ).toBeVisible()
  await expect(
    page.getByText('PAPER TERAMATI', { exact: true }).filter({ visible: true }).first(),
  ).toBeVisible()
  await expect(page.getByRole('button', { name: /buy|sell|place order|enable live/i })).toHaveCount(0)
  await expect(page.getByText(/MOCK FALLBACK|MOCK DEVELOPMENT/i)).toHaveCount(0)
  await expect(page.locator('main')).toBeVisible()
  expect(consoleErrors).toEqual([])
})

test('halaman berita tetap fail-closed terhadap eksekusi live', async ({ page }) => {
  await page.goto('/news')
  await expect(page.getByRole('heading', { name: 'Intelijen Berita' })).toBeVisible()
  await expect(
    page.getByText(/LIVE.*TERKUNCI|LIVE.*LOCKED/i).filter({ visible: true }).first(),
  ).toBeVisible()
  await expect(page.getByText(/PAPER READY|WAIT|BLOCKED|UNAVAILABLE|TIDAK TERSEDIA/i).first()).toBeVisible()
  expect(
    await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1),
  ).toBeTruthy()
})

test('frontend production tidak mengganti kegagalan backend dengan mock', async ({ page }) => {
  await page.route('http://127.0.0.1:8000/**', (route) =>
    route.abort('connectionrefused'),
  )
  await page.routeWebSocket('ws://127.0.0.1:8000/**', (socket) => socket.close())

  await page.goto('/')
  await expect(page.getByText('Data observasi belum tersedia')).toBeVisible()
  await expect(
    page
      .getByText('PAPER TIDAK TERAMATI', { exact: true })
      .filter({ visible: true })
      .first(),
  ).toBeVisible()
  await expect(page.getByText(/MOCK FALLBACK|MOCK DEVELOPMENT/i)).toHaveCount(0)
  await expect(
    page.getByRole('button', { name: /buy|sell|place order|enable live/i }),
  ).toHaveCount(0)
})

test('API hanya mengekspos operasi baca', async ({ request }) => {
  const openApi = await request.get('http://127.0.0.1:8000/openapi.json')
  expect(openApi.ok()).toBeTruthy()
  const document = await openApi.json()
  for (const pathItem of Object.values(document.paths as Record<string, Record<string, unknown>>)) {
    expect(Object.keys(pathItem)).not.toEqual(
      expect.arrayContaining(['post', 'put', 'patch', 'delete']),
    )
  }
})

test('snapshot API mempertahankan kontrak safety fail-closed', async ({ request }) => {
  const response = await request.get('http://127.0.0.1:8000/api/v1/snapshot')
  expect(response.ok()).toBeTruthy()
  const snapshot = await response.json()
  expect(snapshot.safety).toMatchObject({
    live_allowed: false,
    live_trading: 'LOCKED',
    max_lot: 0.01,
    safe_to_demo_observe: true,
    safe_to_demo_auto_order: false,
    demo_auto_order: 'OUT_OF_SCOPE',
  })
})
