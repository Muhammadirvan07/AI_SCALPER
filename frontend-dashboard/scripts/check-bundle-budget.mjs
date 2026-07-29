import { readFile, readdir } from 'node:fs/promises'
import { gzipSync } from 'node:zlib'

const budgets = JSON.parse(
  await readFile(new URL('../performance-budget.json', import.meta.url), 'utf8'),
).bundle_gzip_kb
const assetDirectory = new URL('../dist/assets/', import.meta.url)
const files = await readdir(assetDirectory)
const sizes = new Map()

for (const file of files) {
  if (!file.endsWith('.js') && !file.endsWith('.css')) continue
  const content = await readFile(new URL(file, assetDirectory))
  sizes.set(file, gzipSync(content).byteLength / 1024)
}

const failures = []
const check = (label, file, maximum) => {
  const size = sizes.get(file)
  if (size === undefined) {
    failures.push(`${label}: artefak tidak ditemukan`)
    return
  }
  if (size > maximum) {
    failures.push(`${label}: ${size.toFixed(2)} KiB > ${maximum} KiB (${file})`)
  }
}

const entry = files.find((file) => /^index-[^.]+\.js$/.test(file))
const chartVendor = files
  .filter((file) => /^(?:chart-vendor|AreaChart|CategoricalChart|ComposedChart)-[^.]+\.js$/.test(file))
  .sort((left, right) => (sizes.get(right) ?? 0) - (sizes.get(left) ?? 0))[0]
const stylesheet = files.find((file) => /^index-[^.]+\.css$/.test(file))
check('entry_js', entry, budgets.entry_js_max)
check('chart_vendor', chartVendor, budgets.chart_vendor_max)
check('css', stylesheet, budgets.css_max)

for (const file of files.filter(
  (candidate) =>
    candidate.endsWith('.js') &&
    candidate !== entry &&
    candidate !== chartVendor,
)) {
  check('route_chunk', file, budgets.route_chunk_max)
}

if (failures.length > 0) {
  console.error(`BUNDLE_BUDGET_REJECTED\n${failures.join('\n')}`)
  process.exitCode = 1
} else {
  const summary = [...sizes.entries()]
    .sort((left, right) => right[1] - left[1])
    .slice(0, 5)
    .map(([file, size]) => `${file}: ${size.toFixed(2)} KiB gzip`)
  console.log(`BUNDLE_BUDGET_PASS\n${summary.join('\n')}`)
}
