# AI_SCALPER Backend

Backend FastAPI ini adalah gateway read-only dan realtime antara dashboard Vite dan engine file-based AI_SCALPER. Backend tidak mengubah strategi, source JSON/CSV, konfigurasi executor, atau state MT5. Semua normalisasi dilakukan melalui adapter.

## Safety invariants

- `live_allowed` selalu `false` pada respons efektif.
- `effective_max_lot` tidak pernah melebihi `0.01`.
- Nilai engine yang melampaui batas tetap dilaporkan sebagai `engine_max_lot`, disertai warning dan `guard_applied=true`.
- Tidak ada endpoint live order, perubahan akun broker, arbitrary Python, arbitrary shell, delete file, atau perubahan safety config.
- Browser API hanya memublikasikan `GET` dan WebSocket; `/api/v1/commands*` tidak ada dan menghasilkan `404`.

Safety engine tetap menjadi sumber kebenaran. Backend menambahkan lapisan fail-closed yang tidak dapat dilonggarkan dari environment atau frontend.

## Arsitektur

```text
HTTP / WebSocket
      │
api/routes ── schemas ── standard response/error envelope
      │
services ─── cache TTL ── calculations / safety policy
      │
adapters ─── field aliases and status normalization
      │
repositories ── atomic read / retry / size limit / last-known-good
      │
AI_SCALPER JSON, CSV, and allowlisted logs (read-only)

file watcher ── event bus ── broadcaster ── subscribed WebSocket clients
```

News Intelligence mengikuti pipeline yang sama:

```text
configured File/RSS providers → repository → adapter → deduplication
→ relevance + impact + sentiment → TTL cache → REST + shared WebSocket
```

News hanya merupakan intelligence layer read-only. Ia tidak menulis ke
`trade_signals.json`, `mt5_trade_signals.json`, order executor, atau akun MT5.

Repository dan service dipisahkan agar penyimpanan dapat diganti ke PostgreSQL/TimescaleDB tanpa mengubah kontrak route. Operasi file dan pandas dijalankan di thread worker. Cache mengembalikan deep copy, memiliki TTL, dan di-invalidasi saat watcher mendeteksi perubahan.

## Instalasi

```bash
cd /Users/muhammadirvan/Documents/AI_SCALPER/backend

python3.12 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

Jalankan:

```bash
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

atau:

```bash
python run_backend.py
```

Windows PowerShell dari root repository:

```powershell
cd C:\AI_SCALPER
.\.venv-dashboard\Scripts\python.exe -B .\backend\run_backend.py
```

Dokumentasi tersedia di:

- Swagger UI: `http://127.0.0.1:8000/docs`
- ReDoc: `http://127.0.0.1:8000/redoc`
- OpenAPI: `http://127.0.0.1:8000/openapi.json`

## Environment

Lihat `.env.example`. Konfigurasi utama:

```env
AI_SCALPER_ROOT=/Users/muhammadirvan/Documents/AI_SCALPER
DATA_DIRECTORY=/Users/muhammadirvan/Documents/AI_SCALPER/data
FRONTEND_ORIGINS=http://localhost:5173,http://127.0.0.1:5173,http://localhost:4173,http://127.0.0.1:4173
LIVE_TRADING_ALLOWED=false
MAX_ALLOWED_LOT=0.01
NEWS_ENABLED=true
NEWS_EXTERNAL_REQUESTS_ENABLED=true
NEWS_PRIMARY_PROVIDER=investing_rss
NEWS_FALLBACK_PROVIDERS=official_rss,gdelt,file
INVESTING_RSS_ENABLED=true
INVESTING_RSS_FEEDS_CONFIG=backend/config/investing_rss_feeds.json
INVESTING_RSS_REFRESH_INTERVAL_SECONDS=300
INVESTING_RSS_USE_CONDITIONAL_REQUESTS=true
NEWS_REALTIME_MAX_AGE_HOURS=72
NEWS_RECENT_MAX_AGE_HOURS=168
NEWS_HISTORICAL_RETENTION_DAYS=30
NEWS_DEFAULT_FRESHNESS=live
NEWS_RECENT_FALLBACK_ENABLED=true
ALPHA_VANTAGE_ENABLED=false
ALPHA_VANTAGE_API_KEY=
FINNHUB_ENABLED=false
FINNHUB_API_KEY=
TRADING_ECONOMICS_ENABLED=false
TRADING_ECONOMICS_API_KEY=
TRADING_ECONOMICS_API_SECRET=
GDELT_ENABLED=true
OFFICIAL_RSS_ENABLED=true
OFFICIAL_RSS_FEEDS_CONFIG=backend/config/news_feeds.json
FILE_NEWS_PROVIDER_ENABLED=true
FILE_NEWS_PATH=
FILE_ECONOMIC_CALENDAR_PATH=
ECONOMIC_CALENDAR_ENABLED=true
ECONOMIC_CALENDAR_EXTERNAL_REQUESTS_ENABLED=true
ECONOMIC_CALENDAR_SYNC_INTERVAL_SECONDS=900
ECONOMIC_CALENDAR_WATCH_INTERVAL_SECONDS=120
ECONOMIC_CALENDAR_PRE_RELEASE_INTERVAL_SECONDS=30
ECONOMIC_CALENDAR_RELEASE_INTERVAL_SECONDS=10
ECONOMIC_CALENDAR_POST_RELEASE_INTERVAL_SECONDS=60
ECONOMIC_CALENDAR_CACHE_PATH=
ECONOMIC_CALENDAR_ENGINE_INTEGRATION_ENABLED=false
ECONOMIC_CALENDAR_DIAGNOSTICS_ENABLED=true
ECONOMIC_CALENDAR_EXECUTION_GUARD_ENABLED=false
NEWS_FINBERT_ENABLED=false
NEWS_ENGINE_INTEGRATION_ENABLED=false
```

Artikel dinormalisasi dan dideduplikasi sebelum freshness diklasifikasikan. `REALTIME` berarti umur maksimal 72 jam, `RECENT` berarti lebih dari 72 hingga 168 jam, dan `HISTORICAL` berada di atas 168 jam (dengan retensi default 30 hari). `GET /news/latest` memakai `freshness=live&fallback=recent`; fallback selalu ditandai di data dan metadata, sehingga rilis resmi lama tidak pernah disajikan sebagai live atau breaking. Konfigurasi lama `NEWS_MAX_ARTICLE_AGE_HOURS` masih diterima sebagai threshold realtime dan menghasilkan warning deprecation.

Daftar RSS institusi berada di `config/news_feeds.json`, sedangkan feed resmi
Investing.com berada di `config/investing_rss_feeds.json`. Hanya entri HTTPS
yang `verified=true`, `enabled=true`, dan host-nya sesuai `official_domain`
yang dimuat. Provider menyimpan ETag/Last-Modified per feed dan menggunakan
respons 304 dari cache. File di `examples/` hanya menjelaskan schema dan tidak
pernah dibaca sebagai data produksi.

`DATA_DIRECTORY` harus berada di dalam `AI_SCALPER_ROOT`. `APP_HOST`, setiap
`FRONTEND_ORIGINS`, dan setiap `TRUSTED_HOSTS` harus loopback
(`localhost`, `127.0.0.1`, atau `::1`); wildcard dan alamat LAN/public ditolak.
Meskipun environment mencoba mengaktifkan live, model konfigurasi
mengembalikannya ke `false`.

## REST API

Semua endpoint utama menggunakan prefix `/api/v1` dan envelope konsisten `{success,data,meta}` atau `{success,error,meta}`.

| Domain | Endpoint |
|---|---|
| Health | `GET /health`, `/health/ready`, `/health/live` |
| Version | `GET /version` |
| Overview | `GET /overview`, `/overview/kpis`, `/overview/status` |
| Performance | `GET /performance`, `/performance/equity-curve`, `/performance/pnl`, `/performance/drawdown`, `/performance/statistics` |
| Market | `GET /market/symbols`, `/market/{symbol}/quote`, `/market/{symbol}/candles`, `/market/{symbol}/indicators`, `/market/{symbol}/status` |
| Watchlist | `GET /watchlist`, `/watchlist/{symbol}` |
| Signals | `GET /signals`, `/signals/latest`, `/signals/{signal_id}` |
| Paper orders | `GET /orders`, `/orders/open`, `/orders/closed`, `/orders/{order_id}` |
| Diagnostics | `GET /diagnostics`, `/diagnostics/decision`, `/diagnostics/strategy`, `/diagnostics/guards`, `/diagnostics/health-snapshot`, `/diagnostics/calendar`, `/diagnostics/calendar/{symbol}` |
| Risk | `GET /risk`, `/risk/current`, `/risk/limits`, `/risk/status` |
| Quality | `GET /quality`, `/quality/readiness`, `/quality/progress`, `/quality/blockers` |
| System | `GET /system/status`, `/system/components`, `/system/files`, `/system/session` |
| Logs | `GET /logs`, `/logs/errors`, `/logs/recent` |
| Activity | `GET /activity` |
| News | `GET /news?freshness=live\|recent\|historical\|all`, `/news/latest?fallback=none\|recent`, `/news/breaking`, `/news/{article_id}` |
| Symbol news | `GET /news/symbols/{symbol}`, `/sentiment`, `/summary` |
| News sentiment | `GET /news/sentiment`, `/news/sentiment/overview`, `/timeline`, `/distribution` |
| News calendar compatibility | `GET /news/calendar`, `/today`, `/upcoming`, `/high-impact`, `/{event_id}` |
| Native economic calendar | `GET /economic-calendar`, `/today`, `/upcoming`, `/high-impact`, `/live`, `/{event_id}`, `/{event_id}/audit`, `/symbols/{symbol}`, `/currencies/{currency}`, `/sources`, `/health`, `/status`, `/metrics`, `/guard-preview/{symbol}` |
| News runtime | `GET /news/providers`, `/news/providers/{provider_name}`, `/news/health`, `/news/status`, `/news/guard-preview/{symbol}` |
| Browser boundary | Tidak ada route `POST`; refresh provider dimiliki scheduler backend |
| Compatibility | `GET /snapshot` (deprecated migration contract) |
| Documentation | `GET /documentation`, `/documentation/{slug}` |

Performance filters: `range=1d|7d|30d|3m|all`, `symbol`, dan `strategy`. Karena dataset paper dapat offline, range di-anchor ke record sumber terbaru dan hal ini dijelaskan pada `meta.warnings`.

Market candle menerima `timeframe=M1|M5|M15|M30|H1|H4|D1` dan `limit` maksimum 2.000. CSV aktual adalah M15; M30/H1/H4/D1 di-resample, sedangkan M1/M5 tidak direka dan respons menyatakan `actual_timeframe=M15` serta `resolution_warning`.

## WebSocket

Endpoint subscription:

```text
ws://127.0.0.1:8000/api/v1/ws
```

Origin harus cocok dengan `FRONTEND_ORIGINS`.

```json
{
  "action": "subscribe",
  "channels": ["overview", "market:EURUSD", "signals", "orders", "system", "news", "news:provider:investing_rss"]
}
```

Action: `subscribe`, `unsubscribe`, `ping`, `pong`. Event memiliki `type`, `channel`, timestamp UTC, `sequence`, dan `data`.

Event yang tersedia:

- `overview.updated`, `kpi.updated`
- `market.quote.updated`, `market.candle.updated`
- `signal.created`, `signal.updated`
- `order.opened`, `order.updated`, `order.closed`
- `quality.updated`, `risk.updated`, `system.updated`
- `news.article.created`, `news.article.updated`, `news.breaking.created`
- `news.sentiment.updated`, `news.symbol.sentiment.updated`
- `news.calendar.created`, `news.calendar.updated`, `news.provider.status.updated`
- `news.provider.recovered`, `news.provider.failed`, `news.cache.loaded`, `news.freshness.updated`
- `calendar.event.created`, `calendar.event.updated`, `calendar.event.countdown`
- `calendar.event.awaiting-release`, `calendar.event.released`, `calendar.event.revised`
- `calendar.event.rescheduled`, `calendar.event.cancelled`, `calendar.schedule.changed`
- `calendar.guard-preview.updated`, `calendar.source.status.updated`
- `calendar.sync.completed`, `calendar.sync.failed`
- `connection.ready`, `connection.heartbeat`, `connection.pong`, `subscription.updated`, `error`

Channel news: `news`, `news:breaking`, `news:calendar`, `news:sentiment`, dan
`news:symbol:{SYMBOL}`, dan `news:provider:investing_rss`. Semuanya tetap
memakai endpoint WebSocket yang sama.

Channel kalender native: `economic-calendar`, `economic-calendar:live`,
`economic-calendar:high-impact`, `economic-calendar:currency:{CURRENCY}`, dan
`economic-calendar:symbol:{SYMBOL}`. Countdown per detik dihitung frontend;
backend hanya mengirim transisi state yang bermakna.

Gateway menerapkan connection limit, message size limit, bounded per-client queue, slow-client disconnect, heartbeat, sequence, deduplication payload, cleanup, dan graceful shutdown.

Frontend yang masih memakai snapshot lama dapat tetap menggunakan `ws://127.0.0.1:8000/ws/v1/dashboard` selama migrasi.

## Integrasi Vite

Untuk client endpoint granular baru:

```env
VITE_API_BASE_URL=http://127.0.0.1:8000/api/v1
VITE_WS_URL=ws://127.0.0.1:8000/api/v1/ws
```

Frontend existing tetap mendukung:

```env
VITE_AI_SCALPER_API_BASE_URL=http://127.0.0.1:8000
VITE_AI_SCALPER_WS_URL=ws://127.0.0.1:8000/ws/v1/dashboard
```

Frontend tidak perlu dan tidak boleh membaca JSON engine secara langsung.

## Test, lint, type check

```bash
pytest
pytest --cov=app --cov-report=term-missing
ruff check .
ruff format --check .
mypy app
python -c "from app.main import app; print(app.title)"
```

Coverage minimum dikunci pada 90% di `pyproject.toml`.

## News Intelligence

### Provider

Registry menggabungkan provider berikut tanpa mengekspos schema atau credential
provider ke frontend:

1. `InvestingRssNewsProvider` untuk financial, forex, commodities, crypto,
   economy, equities, economic-indicator, dan central-bank news. Provider ini
   tidak membutuhkan API key dan hanya membaca feed pada katalog RSS resmi.
2. `OfficialRssNewsProvider` untuk feed institusi terverifikasi di
   `config/news_feeds.json` (Federal Reserve monetary policy dan ECB press).
3. GDELT DOC 2.0 untuk macro/geopolitik melalui template query dan topic
   allowlist internal. Tidak ada endpoint arbitrary query/proxy.
4. File provider untuk replay, test, offline snapshot, dan last-known-good.
5. Alpha Vantage dan Finnhub tetap tersedia sebagai provider opsional; keduanya
   default nonaktif dan tidak dibutuhkan untuk menjalankan News Intelligence.
6. Trading Economics tetap opsional untuk economic calendar terstruktur.

Prioritas financial adalah Investing RSS → Official RSS → GDELT → file →
provider API opsional. Prioritas macro adalah Investing RSS → GDELT → Official
RSS → file → provider API opsional. Calendar terstruktur adalah Trading
Economics → file; jika keduanya tidak dikonfigurasi, statusnya `unconfigured`.
Kegagalan satu provider menghasilkan partial collection, bukan kegagalan domain.

Feed Investing yang aktif dan diverifikasi pada 29 Juli 2026 adalah All News,
Forex, Commodities, Cryptocurrency, Stock Market, Economy, Economic Indicators,
dan Central Banks. Entri Breaking, Gold, serta Oil/Energy disimpan nonaktif:
Breaking mengembalikan HTTP 404 ketika diverifikasi, sementara katalog resmi
tidak memublikasikan feed khusus Gold atau Oil/Energy. Backend tidak menebak URL.

Setiap provider memiliki limiter, circuit breaker `CLOSED/OPEN/HALF_OPEN`,
cooldown, bounded parallelism, last-known-good, capability report, authentication,
entitlement, rate-limit, dan quota state. Nilai quota tidak dibuat bila provider
tidak mengirimkannya. `force=true` hanya melewati jadwal refresh dan tidak pernah
melewati limiter, circuit breaker, disabled state, atau authentication failure.

Provider eksternal menerapkan timeout, redirect-disabled policy, content-type
validation, response-size limit, trusted fixed host, serta private-address
rejection. Investing RSS mendukung RSS 2.0/Atom, ETag, Last-Modified, 304,
per-feed lock/circuit breaker, partial failure, dan last-known-good. XML yang
mengandung DTD atau external entity ditolak. Backend hanya menyimpan headline,
ringkasan pendek dari feed, metadata, atribusi, dan URL sumber—bukan isi artikel
lengkap. Tidak ada scraping HTML, private API, cookie browser, atau paywall
bypass.

Refresh seluruh provider dijalankan scheduler backend sesuai interval dan
backoff masing-masing. Browser hanya membaca hasil melalui REST/WebSocket; ia
tidak dapat memaksa provider, mengirim URL, atau mengubah cache server.

### Deduplication dan scoring

Deduplication memakai canonical URL, provider ID, normalized title, jendela
waktu enam jam, dan similarity title. Artikel mirip tetap tersimpan dengan
`is_duplicate=true`, `duplicate_group_id`, dan `canonical_article_id`; query
default hanya menampilkan canonical article.

Relevance `0..1` menggabungkan direct-symbol match, currency/entity match,
recency, dan provider confidence. Parser mendukung pair forex generik, metal
(`XAU`, `XAG`, dan keluarga `X*`), crypto, serta simbol lain yang tersedia di
data market. Breakdown disertakan per simbol.

Impact `0..1` memakai kategori ekonomi, keyword central-bank/rate/CPI/NFP/GDP,
geopolitik/regulasi, breaking flag, simbol terdampak, dan provider confidence:

- `0.00–0.24 LOW`
- `0.25–0.49 MEDIUM`
- `0.50–0.74 HIGH`
- `0.75–1.00 CRITICAL`

Sentiment default adalah baseline deterministik berbasis financial lexicon,
negation, intensifier, headline weighting, dan summary weighting. FinBERT
bersifat opsional/lazy melalui `NEWS_FINBERT_ENABLED=true`; bila dependency atau
model tidak tersedia, backend mencatat warning dan tetap memakai `baseline`.
FinBERT tidak termasuk dependency wajib. Alpha Vantage provider sentiment
disimpan sebagai evidence terpisah dan tidak menggantikan nilai internal. Bila
FinBERT aktif, ensemble terkalibrasi memakai FinBERT, baseline, dan provider
evidence tanpa menjumlahkan skor mentah secara langsung.

### Economic calendar

Economic Calendar native menggunakan registry source resmi: BLS release ICS,
BEA release schedule/current releases, Federal Reserve FOMC calendar/statements,
dan ECB weekly schedule. Setiap adapter memvalidasi host HTTPS resmi, ukuran dan
content type, menggunakan timeout/cooldown/last-known-good, lalu menghasilkan
schema internal yang sama. Source yang menolak akses atau belum menyediakan
format aman tetap dilaporkan degraded/unconfigured; kegagalannya tidak membuat
backend berhenti.

Scheduler memakai interval adaptif: normal 15 menit, watch 2 menit, pre-release
30 detik, release 10 detik, dan post-release 60 detik. Polling berjalan satu kali
di backend, tidak per browser. Reconciliation mempertahankan audit schedule,
menandai reschedule/cancel/pending verification, serta tidak langsung menghapus
event yang hilang dari satu fetch.

Lifecycle rilis menggunakan urutan `NORMAL -> WATCH -> PRE_RELEASE -> RELEASE
-> AWAITING_RELEASE -> RELEASED -> POST_RELEASE -> NORMAL`. Status
`AWAITING_RELEASE` adalah keadaan normal ketika jadwal sudah lewat tetapi sumber
resmi belum menerbitkan actual. `RELEASED` hanya dibuat setelah adapter sumber
resmi menemukan actual dengan event name, reference period, release date, dan
unit yang cocok. Respons sumber yang sama dideduplikasi; revisi disimpan sebagai
`revised_previous`, `revision_source`, dan `revised_at` lalu menghasilkan event
`calendar.event.revised`.

Metadata setiap pemeriksaan rilis tersimpan pada buffer audit terbatas dan dapat
dibaca melalui `GET /economic-calendar/{event_id}/audit?limit=100&offset=0`.
Audit tidak menyimpan credential atau body sumber. Counter runtime serta latency
yang benar-benar terukur tersedia di `GET /economic-calendar/metrics`. Field
source-publish atau frontend-render tetap `null` bila timestamp tersebut tidak
tersedia; backend tidak mengarangnya.

Waktu dan actual hanya disimpan bila ditemukan pada sumber resmi. Forecast tidak
diestimasi: nilainya `null` sampai ada consensus source tepercaya/berlisensi.
Surprise juga `null` saat forecast tidak ada dan tidak pernah dihitung terhadap
`previous`. Jadwal date-only memakai metadata `schedule_precision=DATE`, sehingga
frontend menampilkan `TIME TBA`, bukan countdown palsu.

File provider lokal bersifat read-only dan opsional melalui
`ECONOMIC_CALENDAR_FILE_PATH`; backend tidak membuat fixture produksi.
`ECONOMIC_CALENDAR_CACHE_PATH` dapat diisi untuk persistence last-known-good
atomic, atau dibiarkan kosong untuk memory-only. Guard preview calendar hanya
menjelaskan `NORMAL`, `CAUTION`, `HIGH_RISK`, `BLOCK_PREVIEW`,
`POST_RELEASE_VOLATILITY`, atau `INSUFFICIENT_DATA`; integrasi engine dipaksa
nonaktif.

### Calendar diagnostics (read-only)

`GET /diagnostics/calendar` dan `GET /diagnostics/calendar/{symbol}` membangun
konteks currency exposure, event resmi berikutnya, countdown, freshness, serta
guard preview untuk simbol aktif. Setiap respons membawa
`diagnostic_only=true`, `execution_guard_enabled=false`, dan
`affects_execution=false`. Adapter melakukan assertion terhadap field execution
yang dilindungi; percobaan mutasi ditolak dengan `SafetyLockError`, dicatat
sebagai `calendar_execution_mutation_blocked`, dan menaikkan metric mutation
block.

`ECONOMIC_CALENDAR_DIAGNOSTICS_ENABLED=false` mematikan konteks ini tanpa
memengaruhi kalender. `ECONOMIC_CALENDAR_ENGINE_INTEGRATION_ENABLED` dan
`ECONOMIC_CALENDAR_EXECUTION_GUARD_ENABLED` dipaksa `false` oleh safety config.
Backend tidak menulis `decision_health_snapshot.json` atau file engine lain untuk
fitur ini; snapshot diagnostics dibentuk in-memory melalui adapter dan API.

Economic Calendar currently provides diagnostic context only. It does not
block, approve, modify, or execute trades.

Simulasi lifecycle BEA memakai fixture resmi-berbentuk di
`tests/fixtures/bea_gdp_release_q2_2026_simulation.html`. Fixture berlabel test
only, tidak berada pada provider path, dan tidak pernah dibaca saat production.
Jalankan replay terisolasi dengan:

```bash
pytest -q tests/unit/test_economic_calendar_release_diagnostics.py
```

`/news/guard-preview` hanya menjelaskan potensi `ALLOW`, `CAUTION`,
`BLOCK_PREVIEW`, atau `INSUFFICIENT_DATA`. Preview ini tidak terhubung ke
execution gate dan tidak dapat mengirim order.

## Freshness dan fallback

Setiap response data menyertakan `source_updated_at`, `server_timestamp`, `age_seconds`, `stale`, `source_available`, dan `data_status`. Data lama tidak dilabeli live.

Saat file berubah, watcher menunggu debounce, memverifikasi signature stabil, meng-invalidasi cache aktif, lalu broadcast. Repository mempertahankan last-known-good terpisah dari cache sehingga JSON/CSV kosong atau invalid sementara tidak membuat backend crash.

## Data aktual yang belum tersedia

- CSV engine menyediakan OHLCV M15, bukan tick/live bid-ask. Karena itu `bid`, `ask`, dan `spread` tetap `null`, dan quote diberi `source_kind=historical_close`.
- Tidak ada source candle M1/M5 yang dapat diverifikasi; backend tidak melakukan upsampling palsu.
- Balance awal diambil dari `paper_quality_report.json -> drawdown.starting_balance`. Jika field ini hilang, balance KPI menjadi `null`, bukan angka buatan.
- Test coverage atau missing-test inventory hanya ditampilkan jika engine menyediakannya.
- Alpha Vantage, Finnhub, dan Trading Economics tetap nonaktif sampai API key
  dikonfigurasi. Investing RSS, GDELT, dan feed institusi terverifikasi aktif
  secara default bila `NEWS_EXTERNAL_REQUESTS_ENABLED=true`. Tidak ada dummy
  bila seluruh sumber gagal.

## Troubleshooting

- `503 DATA_SOURCE_UNAVAILABLE`: cek `AI_SCALPER_ROOT`, permission, dan nama source pada registry.
- `stale=true`: engine source lebih tua dari threshold; cek collector/session runner. Data tetap dapat ditampilkan sebagai cached/historical, bukan live.
- WebSocket close `1008`: Origin tidak ada di `FRONTEND_ORIGINS`.
- WebSocket close `1009`: message melampaui batas.
- WebSocket close `1013`: connection penuh atau client terlalu lambat.
- `404` pada `/api/v1/commands*`: perilaku yang benar; browser API tidak memublikasikan endpoint mutasi.
- `provider_unconfigured`: aktifkan provider dan isi credential/path backend,
  lalu tunggu siklus scheduler berikutnya atau restart backend lokal.
- `authentication_failed`: periksa key/secret backend; credential tidak pernah
  dikembalikan oleh status API.
- `entitlement_error`: paket provider tidak mengizinkan capability tersebut;
  fallback lain tetap berjalan.
- `circuit_open`: tunggu `cooldown_until`; `force=true` tidak dapat melewatinya.
- `rate_limited`: tunggu interval provider; scheduler memakai backoff dan data
  last-known-good ditandai stale.
- `FinBERT unavailable`: instal dependency ML secara terpisah atau biarkan
  `NEWS_FINBERT_ENABLED=false`; baseline deterministic tetap tersedia.
