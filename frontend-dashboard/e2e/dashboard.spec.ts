import { expect, test } from '@playwright/test'

const forbiddenOrderControl = /buy|sell|place order|enable live|auto trade|aktifkan live|buat order/i

test('landing menampilkan snapshot aktual dan batas observasi', async ({ page }) => {
  const consoleErrors: string[] = []
  page.on('console', (message) => {
    if (message.type() === 'error') consoleErrors.push(message.text())
  })

  await page.goto('/')
  await expect(page.getByRole('heading', { name: /AI_SCALPER/i })).toBeVisible()
  await expect(page.getByText('LIVE ORDER TERKUNCI', { exact: true }).first()).toBeVisible()
  await expect(page.getByTestId('operational-mode')).not.toHaveText('TIDAK TERVERIFIKASI')
  await expect(page.getByTestId('observation-status')).not.toContainText('TIDAK TERVERIFIKASI')
  await expect(page.getByText(/Snapshot v\d+ diterima/).first()).toBeVisible()
  await expect(page.getByRole('heading', { name: 'Batas Keselamatan' })).toBeVisible()
  await expect(page.getByText('order capability', { exact: true })).toBeVisible()
  const viewportWidth = page.viewportSize()?.width ?? 1440
  if (viewportWidth < 640) {
    await page.getByText('Lihat evidence kandidat', { exact: true }).first().click()
  }
  await expect(
    page.getByText('Discovery', { exact: true }).filter({ visible: true }).first(),
  ).toBeVisible()
  await expect(page.getByText('MOCK DEVELOPMENT — BUKAN DATA AKTUAL')).toHaveCount(0)
  await expect(page.getByRole('button', { name: forbiddenOrderControl })).toHaveCount(0)
  await expect(page.getByRole('link', { name: forbiddenOrderControl })).toHaveCount(0)
  expect(
    await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1),
  ).toBeTruthy()
  expect(consoleErrors).toEqual([])
})

test('CTA dan tautan landing menuju rute yang tersedia', async ({ page, request }) => {
  await page.goto('/')
  await expect(page.getByRole('link', { name: /Buka Dashboard/ })).toHaveAttribute('href', '/overview')
  await expect(page.getByRole('link', { name: /Lihat Kesehatan Sistem/ })).toHaveAttribute('href', '/system-health')
  await expect(page.getByRole('link', { name: /Overview/ })).toHaveAttribute('href', '/overview')
  await expect(page.getByRole('link', { name: /Kesehatan Sistem/ }).last()).toHaveAttribute('href', '/system-health')

  for (const slug of [
    'architecture',
    'operator-runbook',
    'release-history',
    'safety-audit',
    'api-contract',
  ]) {
    const response = await request.get(`http://127.0.0.1:8000/api/v1/documentation/${slug}`)
    expect(response.ok(), `dokumen ${slug} harus tersedia`).toBeTruthy()
  }
})

test('overview tetap menjadi terminal mendalam tanpa membuka live trading', async ({ page }) => {
  await page.goto('/overview')
  await expect(page.getByText('AI_SCALPER', { exact: false }).first()).toBeVisible()
  await expect(
    page.getByText(/LIVE.*TERKUNCI|LIVE.*LOCKED/i).filter({ visible: true }).first(),
  ).toBeVisible()
  await expect(
    page.getByText('PAPER TERAMATI', { exact: true }).filter({ visible: true }).first(),
  ).toBeVisible()
  await expect(page.getByRole('button', { name: forbiddenOrderControl })).toHaveCount(0)
  await expect(page.getByText(/MOCK FALLBACK|MOCK DEVELOPMENT/i)).toHaveCount(0)
  await expect(page.locator('main')).toBeVisible()
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
  await expect(page.getByTestId('operational-mode')).toHaveText('TIDAK TERVERIFIKASI')
  await expect(page.getByText(/TIDAK TERVERIFIKASI · UI MEMAKSA LOCKED/)).toBeVisible()
  await expect(
    page
      .getByText('PAPER TIDAK TERAMATI', { exact: true })
      .filter({ visible: true })
      .first(),
  ).toBeVisible()
  await expect(page.getByText(/MOCK FALLBACK|MOCK DEVELOPMENT/i)).toHaveCount(0)
  await expect(page.getByRole('button', { name: forbiddenOrderControl })).toHaveCount(0)
  expect(
    await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1),
  ).toBeTruthy()
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
  expect(snapshot.schema_version).toBe('1.2')
  expect(snapshot.safety).toMatchObject({
    live_allowed: false,
    live_trading: 'LOCKED',
    max_lot: 0.01,
    safe_to_demo_observe: true,
    safe_to_demo_auto_order: false,
    demo_auto_order: 'OUT_OF_SCOPE',
    order_capability: 'DISABLED',
  })
})
