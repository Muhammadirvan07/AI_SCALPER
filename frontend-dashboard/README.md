# AI_SCALPER Frontend Dashboard

React 19, Vite, dan TypeScript dashboard untuk backend production-ready
AI_SCALPER. Backend adalah satu-satunya sumber data; frontend tidak membaca file
engine, tidak membuat angka trading sintetis, dan tidak memakai compatibility
snapshot lama.

## Konfigurasi

```bash
cp .env.example .env.local
npm ci
npm run dev
```

```env
VITE_API_BASE_URL=http://127.0.0.1:8000/api/v1
VITE_WS_URL=ws://127.0.0.1:8000/api/v1/ws
```

Frontend berjalan di <http://127.0.0.1:5173/overview>. Jalankan backend dari
`../backend` pada port 8000 terlebih dahulu.

## Windows PowerShell

`dashboard_api/run_dashboard_api.py` adalah compatibility server lama dan
tidak menyediakan kontrak granular frontend ini. Hentikan server lama pada
port 8000, lalu jalankan backend canonical dari root repository di terminal
pertama:

```powershell
cd C:\AI_SCALPER
$env:AI_SCALPER_ROOT = "C:\AI_SCALPER"
.\.venv-dashboard\Scripts\python.exe -m pip install `
  --requirement .\backend\requirements.txt
.\.venv-dashboard\Scripts\python.exe -B .\backend\run_backend.py
```

Verifikasi `http://127.0.0.1:8000/api/v1/health/ready`. Di terminal kedua:

```powershell
cd C:\AI_SCALPER\frontend-dashboard
node --version
npm.cmd --version
Copy-Item .\.env.example .\.env.local -Force
npm.cmd ci
npm.cmd run typecheck
npm.cmd run test:unit
npm.cmd run build
npm.cmd run dev -- --host 127.0.0.1 --port 5173
```

Vite 8.1.5 yang dipin repository memerlukan Node `^20.19.0` atau
`>=22.12.0`. Browser harus dibuka pada
`http://127.0.0.1:5173/overview`.

## Arsitektur data

1. `DashboardRealtimeProvider` memuat domain data awal lewat REST.
2. API client memvalidasi envelope, menormalisasi error, menerapkan timeout,
   retry GET terbatas, request deduplication, dan TTL cache.
3. Satu `SharedWebSocketClient` berlangganan channel overview, signals,
   orders, quality, risk, system, news, kalender ekonomi, serta symbol aktif.
4. Event file-change menginvalidasi dan memuat ulang hanya domain terkait.
5. Polling TTL-aware tetap tersedia sebagai fallback saat event realtime tidak
   membawa payload domain lengkap.

Domain frontend memakai endpoint:

- overview/KPI: `/overview`
- performa: `/performance`
- market: `/market/symbols`, quote, candles, indicators, status
- watchlist: `/watchlist`
- signal: `/signals`
- paper order: `/orders`
- AI diagnostics: `/diagnostics`, `/diagnostics/calendar`,
  `/diagnostics/calendar/{symbol}`
- risk: `/risk`
- quality/readiness: `/quality`
- system: `/system/status`, `/system/components`
- activity: `/activity`
- logs: `/logs`
- read-only snapshot refresh: pemuatan ulang endpoint GET yang sama; frontend
  tidak mempunyai client POST dan backend tidak memublikasikan `/commands*`
- news: `/news/latest`, `/news/breaking`, `/news/providers`, `/news/status`
- news sentiment: `/news/sentiment/overview`, `/news/sentiment/timeline`
- economic calendar native: `/economic-calendar`, `/today`, `/upcoming`,
  `/high-impact`, `/live`, `/sources`, `/health`, `/metrics`,
  `/{event_id}/audit`, dan `/guard-preview/{symbol}`
- symbol intelligence: `/news/symbols/{symbol}/summary`

Halaman News membedakan loading, provider unconfigured/disabled, rate-limited,
stale, offline, reconnecting, error, dan empty. Tanpa provider tepercaya,
frontend menampilkan instruksi konfigurasi dan tidak menggantinya dengan
headline atau sentiment lokal.

Investing.com Official RSS menjadi sumber berita utama tanpa API key. UI
memisahkan artikel `REALTIME` dari `RECENT`, menampilkan atribusi
`Source: Investing.com`, dan selalu membuka URL artikel asli dengan
`noopener noreferrer`. Artikel tidak dirender sebagai HTML provider.

### Economic Intelligence native

Route `/economic-calendar` adalah terminal kalender milik AI_SCALPER sendiri.
Ia memuat initial state melalui REST dan menerima event domain dari shared
WebSocket. Tidak ada iframe, widget pihak ketiga, HTML provider, atau request
langsung dari browser ke sumber jadwal.

Tampilan menyediakan Timeline/Day/Week, filter tanggal/currency/impact/category/
status/symbol, countdown lokal, Next Critical Event, event drawer, currency dan
symbol impact, serta source health. Countdown hanya berjalan untuk jadwal resmi
yang memiliki presisi waktu; jadwal dengan tanggal saja ditampilkan `TIME TBA`.
`actual`, `forecast`, dan `previous` yang tidak tersedia selalu tampil `—`.

Event realtime berikut digabungkan langsung ke cache tanpa reload halaman:
`calendar.event.created`, `updated`, `released`, `revised`, `rescheduled`, dan
`cancelled`. Perubahan source/sync hanya memuat ulang resource kalender terkait.
Guard preview berlabel read-only dan tidak terhubung ke execution gate.

AI Diagnostics menampilkan panel `Economic Event Context` dengan hierarchy
status preview, event berikutnya, countdown, impact/currency, alasan, lalu
source/freshness. Badge `READ-ONLY` dan `DOES NOT AFFECT EXECUTION` selalu
terlihat. Overview menampilkan ringkasan `Next Economic Risk` untuk simbol aktif.
Perubahan simbol menggunakan subscription shared WebSocket yang sama; frontend
tidak membuka koneksi baru.

Event release mengubah cache kalender dan context simbol terkait tanpa reload
halaman. Nilai actual yang belum diterbitkan tampil `—` dengan keterangan
`Actual pending from official source`. Highlight release dibatasi sepuluh detik,
status `AWAITING RELEASE` hanya memberi pulse pada dot, dan seluruh motion
dinonaktifkan oleh `prefers-reduced-motion`. Latency WebSocket-ke-render diukur
lokal memakai Performance API; timestamp yang tidak tersedia tidak direka.

Economic Calendar currently provides diagnostic context only. It does not
block, approve, modify, or execute trades.

Flags `VITE_INVESTING_CALENDAR_*` hanya dipertahankan sebagai compatibility
environment yang deprecated; aplikasi tidak membaca atau merendernya. CSP
frontend menetapkan `frame-src 'none'` dan `child-src 'none'`.

## Safety

UI selalu fail-closed:

- mode `DRY_RUN`
- `live_allowed=false`
- `LIVE EXECUTION LOCKED`
- `effective_max_lot <= 0.01`

Tidak ada kontrol untuk enable live trading atau mengubah safety limit. Respons
`live_allowed=true`, `safe_to_live_trade=true`, atau effective lot di atas
0.01 diperlakukan sebagai anomali kritis.

## Verifikasi

```bash
npm run lint
npm run typecheck
npm test
npm run build
npm run check:bundle
npm run test:e2e
```

Playwright menguji desktop dan mobile terhadap backend aktual, termasuk
offline/reconnect, null values, stale state, M1 ke M15 resolution fallback,
ketiadaan route mutasi, console error, dan horizontal overflow.
