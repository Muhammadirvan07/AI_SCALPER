# AI_SCALPER Dashboard API (legacy compatibility)

> **Jangan pasangkan service ini dengan `frontend-dashboard/`.** Service ini
> mempertahankan kontrak dashboard lama seperti `/api/health`, `/api/v1/summary`,
> dan `/api/v1/paper-orders`. Dashboard React granular memakai service canonical
> di `backend/`, dengan health `/api/v1/health/ready`, seluruh domain API v1,
> dan WebSocket `/api/v1/ws`. Pada Windows, jalankan
> `.\.venv-dashboard\Scripts\python.exe -B .\backend\run_backend.py` dari root
> repository.

Adapter observasi read-only yang menghubungkan file proyek AI_SCALPER ke dashboard
React melalui REST dan WebSocket. Adapter ini tidak mengimpor MetaTrader5, tidak
menjalankan decision engine/bridge/trading loop, tidak memiliki endpoint trading,
dan tidak menulis kembali ke file sumber.

## Arsitektur

```text
Provider pasar (Yahoo M15 finalized)
  -> market_data_updater.py (FAST 60 dtk / FULL 15 mnt)
  -> data_collector.py (atomic CSV + status)
File JSON/CSV AI_SCALPER
  -> registry recursive + pembaca aman read-only
  -> normalizer schema 1.2 + audit kontrak producer
  -> dashboard snapshot tunggal di memori
  -> REST initial load / fallback polling
  -> WebSocket snapshot updates + heartbeat
  -> React DashboardRealtimeProvider
```

File watcher memeriksa kombinasi modification time dan ukuran file. Snapshot hanya
dibangun ulang saat signature sumber berubah, didebounce, lalu dibroadcast hanya
jika hash semantiknya berubah. Cache last-known-good berada di memori dan hilang
saat API dihentikan; tidak ada file cache yang ditulis.

## Sumber

Registry mencari nama berikut secara recursive dari `AI_SCALPER_ROOT`, dengan
prioritas file pada path paling dangkal:

- `offline_dashboard_report.json`
- `trade_signals.json`
- `mt5_trade_signals.json`
- `paper_orders.json`
- `decision_health_snapshot.json`
- `paper_forward_session_tracker.json`
- `paper_quality_rules.json`
- `paper_quality_report.json`
- `paper_report.json`
- `active_pairs.json`
- `paper_replay_candidates.json`
- `bridge_status.json`
- `bridge_rejected_signals.json`
- `data_collector_status.json`
- `broker_candidates.phase3.json`
- `broker_evidence_profiles.v1.json`
- `windows_broker_preparation_profiles.v1.json`
- `manual_demo_readiness.v1.json`
- `demo_readiness_evaluator.json`
- `phase4_clean_sample_gate.json`
- calendar window kandidat broker yang terdaftar di `app/config.py`
- `market_news.json|economic_calendar.json|news_feed.json`
- kalender ekonomi mingguan publik (fallback remote read-only)
- `regime_analytics.json|market_regime_history.json`
- `signal_analytics.json|signal_radar_snapshot.json`
- `data/*.csv`

CSV mendukung variasi kolom `time|timestamp|datetime`, OHLC, dan
`volume|tick_volume`. Hanya bar terakhir sampai batas konfigurasi yang dibaca.
Timeframe diturunkan dari jarak dua candle terakhir. Dashboard tidak menyebut
tick-by-tick bila sumber hanya menyediakan candle.

## Menjalankan backend

```bash
cd /Users/muhammadirvan/Documents/AI_SCALPER
python3 -m venv .venv-dashboard
source .venv-dashboard/bin/activate
pip install -r dashboard_api/requirements.txt

export AI_SCALPER_ROOT=/Users/muhammadirvan/Documents/AI_SCALPER
uvicorn dashboard_api.app.main:app --host 127.0.0.1 --port 8000 --reload
```

Alternatif tanpa reload:

```bash
.venv-dashboard/bin/python dashboard_api/run_dashboard_api.py
```

Pada Windows PowerShell, runner yang sama dapat dipanggil langsung dari root
repository tanpa mengubah environment trading:

```powershell
$env:AI_SCALPER_ROOT = "C:\AI_SCALPER"
.\.venv-dashboard\Scripts\python.exe -B .\dashboard_api\run_dashboard_api.py
```

API sengaja dan secara fail-closed hanya menerima bind host loopback
(`127.0.0.1`, `::1`, atau `localhost`). Origin CORS juga harus berupa origin
HTTP(S) loopback tanpa wildcard. WebSocket memerlukan header `Origin` yang
termasuk pada allowlist yang sama; middleware CORS saja tidak melindungi
WebSocket. Public/non-loopback deployment sengaja ditolak sampai TLS,
authentication, CSP/security headers, dan network policy direview terpisah.

## Menjalankan frontend legacy

Bagian ini hanya dipertahankan sebagai referensi migrasi. Untuk
`frontend-dashboard/` saat ini, ikuti
[`frontend-dashboard/README.md`](../frontend-dashboard/README.md) dan jalankan
backend granular dari `backend/`.

Di terminal kedua:

```bash
cd /Users/muhammadirvan/Documents/AI_SCALPER/frontend-dashboard
cp .env.example .env.local
npm install
npm run dev
```

- Dashboard: <http://localhost:5173/#overview>
- Health: <http://127.0.0.1:8000/api/health>
- Snapshot: <http://127.0.0.1:8000/api/v1/snapshot>

Frontend menerjemahkan hash lama seperti `#overview` ke route halaman
`/overview`. URL langsung `http://localhost:5173/overview` juga didukung oleh Vite.

## Environment variables backend

| Nama | Default | Fungsi |
|---|---:|---|
| `AI_SCALPER_ROOT` | root project | Root pencarian sumber |
| `AI_SCALPER_API_HOST` | `127.0.0.1` | Bind host |
| `AI_SCALPER_API_PORT` | `8000` | Port API |
| `AI_SCALPER_WATCH_INTERVAL_SECONDS` | `1.0` | Interval mtime polling |
| `AI_SCALPER_DEBOUNCE_MS` | `200` | Debounce perubahan cepat |
| `AI_SCALPER_STALE_AFTER_SECONDS` | `180` | Ambang stale default |
| `AI_SCALPER_EVIDENCE_STALE_AFTER_SECONDS` | `2592000` | Ambang 30 hari untuk evidence konfigurasi/broker non-telemetry |
| `AI_SCALPER_MARKET_STALE_M5_SECONDS` | `900` | Ambang M5 termasuk finalization lag |
| `AI_SCALPER_MARKET_STALE_M15_SECONDS` | `2700` | Ambang M15 termasuk finalization lag |
| `AI_SCALPER_MARKET_STALE_M30_SECONDS` | `5400` | Ambang M30 termasuk finalization lag |
| `AI_SCALPER_MARKET_STALE_H1_SECONDS` | `10800` | Ambang H1 termasuk finalization lag |
| `AI_SCALPER_HEARTBEAT_SECONDS` | `15` | Interval heartbeat WS |
| `AI_SCALPER_MARKET_CANDLE_LIMIT` | `500` | Maksimum candle per CSV |
| `AI_SCALPER_WEBSOCKET_CANDLE_LIMIT` | `200` | Candle/pair pada full event WS |
| `AI_SCALPER_MAX_JSON_BYTES` | `8388608` | Batas ukuran JSON |
| `AI_SCALPER_CORS_ORIGINS` | empat origin lokal | Allowlist CORS |
| `AI_SCALPER_DASHBOARD_LOG_LEVEL` | `INFO` | Level log |
| `AI_SCALPER_DASHBOARD_LOG_FILE` | kosong | Log dashboard dengan rotasi |
| `AI_SCALPER_NEWS_API_URL` | `https://nfs.faireconomy.media/ff_calendar_thisweek.json` | Endpoint kalender JSON read-only; isi kosong untuk menonaktifkan provider remote |
| `AI_SCALPER_NEWS_PROVIDER_NAME` | `FOREX FACTORY / FAIR ECONOMY` | Label provider pada snapshot dan UI |
| `AI_SCALPER_NEWS_API_KEY` | kosong | Secret provider, backend-only |
| `AI_SCALPER_NEWS_API_KEY_HEADER` | `X-API-Key` | Nama header autentikasi |
| `AI_SCALPER_NEWS_POLL_SECONDS` | `3600` | Interval polling kalender publik |
| `AI_SCALPER_NEWS_STALE_AFTER_SECONDS` | `7200` | Ambang kedaluwarsa khusus kalender |
| `AI_SCALPER_NEWS_TIMEOUT_SECONDS` | `5` | Timeout pembacaan provider remote |

Backend juga membaca `dashboard_api/.env` bila file tersebut ada. Secret tidak
diperlukan untuk file lokal; API key provider news bersifat opsional, backend-only,
dan tidak pernah dikirim ke frontend atau ditulis ke log.

## Environment variables frontend

```dotenv
VITE_AI_SCALPER_API_BASE_URL=http://127.0.0.1:8000
VITE_AI_SCALPER_WS_URL=ws://127.0.0.1:8000/ws/v1/dashboard
VITE_AI_SCALPER_USE_MOCK_FALLBACK=true
VITE_AI_SCALPER_STALE_AFTER_MS=180000
```

Fallback mock selalu diberi label `MOCK FALLBACK`. Saat snapshot nyata tersedia,
random price, signal, PnL, closed orders, dan regime probability tidak dijalankan.

## REST API read-only

Semua route data adalah `GET`:

- `GET /api/health`
- `GET /api/v1/snapshot`
- `GET /api/v1/summary`
- `GET /api/v1/safety`
- `GET /api/v1/performance`
- `GET /api/v1/watchlist`
- `GET /api/v1/market/{symbol}?limit=500&timeframe=M15`
- `GET /api/v1/signals?symbol=&status=&strategy=&limit=100`
- `GET /api/v1/paper-orders?symbol=&status=&limit=100`
- `GET /api/v1/decision-health`
- `GET /api/v1/session`
- `GET /api/v1/guards`
- `GET /api/v1/sources`
- `GET /api/v1/news`
- `GET /api/v1/decision-readiness`
- `GET /api/v1/source-contracts`
- `GET /api/v1/project-progress`
- `GET /api/v1/broker-readiness`
- `GET /api/v1/documentation`
- `GET /api/v1/documentation/{slug}`

Tidak ada route `POST`, `PUT`, `PATCH`, atau `DELETE`.

## WebSocket

URL: `ws://127.0.0.1:8000/ws/v1/dashboard`

Envelope:

```json
{
  "type": "snapshot.updated",
  "version": 2,
  "timestamp": "2026-07-25T00:00:00Z",
  "payload": {}
}
```

Event yang didukung kontrak:

- `connection.ready`
- `snapshot.full`
- `snapshot.updated`
- `market.updated`
- `signal.created`
- `signal.updated`
- `paper_order.updated`
- `decision_health.updated`
- `session.updated`
- `news.updated`
- `source.stale`
- `source.recovered`
- `safety.warning`
- `heartbeat`
- `error`

Versi pertama mengirim full schema snapshot pada `snapshot.updated`; candle tiap
pair pada transport WS dibatasi 200 agar frame tetap kompatibel dengan batas klien
umum. REST `/market/{symbol}` tetap menyediakan sampai batas market 500. Jenis delta sudah
dicadangkan pada schema, tetapi belum dipancarkan agar konsistensi klien lebih
mudah.

## Stale dan data parsial

Setiap sumber memiliki:

- `source_timestamp`
- `received_at`
- `age_seconds`
- `stale`
- `status`: `fresh|stale|partial|unavailable|invalid`
- `from_last_known_good`

Invalid JSON sementara diretry tiga kali. Bila sebelumnya pernah valid, nilai
last-known-good tetap digunakan dengan status `partial`; satu file invalid tidak
menjatuhkan API. Stale dihitung per sumber dan per panel. Status seluruh koneksi
baru menjadi stale bila sumber kritis ikut stale, bukan hanya karena satu file
lama.

Evidence konfigurasi, broker, dan calendar window memakai ambang terpisah 30 hari
karena bukan telemetry frekuensi tinggi. Evaluator readiness, signal, decision
health, dan data pasar tetap mengikuti ambang aktual masing-masing; pemisahan ini
mencegah konfigurasi statis memicu notifikasi stale palsu.

## Landing operasional

Snapshot schema `1.2` menambahkan `project_progress` dan `broker_readiness`.
Keduanya dinormalisasi dari evidence proyek yang ditemukan registry, bukan dari
nilai dekoratif frontend. Jika evidence tidak ada, field nullable dan status
`unavailable|partial|invalid` dipertahankan. Landing `/` menampilkan ringkasan
eksekutif fail-closed, sedangkan `/overview` tetap menjadi terminal analitik.

Dokumentasi landing dilayani oleh endpoint GET berbasis allowlist. Slug tidak
dapat memilih path arbitrer dan endpoint tidak menyediakan fungsi tulis.

## Pengunci keselamatan

Sebelum broadcast, `safety_guard.py` memindai kontradiksi:

- `live_allowed` selalu dipaksa `false`
- `live_trading` selalu `LOCKED`
- `max_lot` tampilan selalu `0.01`
- `safe_to_demo_auto_order` selalu `false`
- auto-order selalu `OUT_OF_SCOPE`

Jika sumber meminta nilai yang lebih permisif, sumber tidak diubah. Snapshot
ditandai `safety_violation=true`, status menjadi
`LOCKED_BY_DASHBOARD_SAFETY_GUARD`, dan warning lokal dicatat.

## Test

```bash
cd /Users/muhammadirvan/Documents/AI_SCALPER
source .venv-dashboard/bin/activate
pytest dashboard_api/tests -q
```

Test memakai temporary directory dan tidak membaca/menulis file proyek nyata.

E2E frontend:

```bash
cd frontend-dashboard
npm run test:e2e:list
npm run test:e2e
```

E2E memeriksa desktop/mobile, browser console, safety lock, halaman news, dan
OpenAPI read-only. Browser Chromium harus tersedia pada mesin pengujian.

## Menjalankan kedua proses

Setelah dependency backend dan frontend terpasang:

```bash
dashboard_api/start_dashboard.sh
```

Script menjalankan Uvicorn, Vite, dan updater data pasar terpisah. Decision engine,
bridge, paper executor, dan trading loop tidak dijalankan. Set
`AI_SCALPER_ENABLE_MARKET_UPDATER=false` untuk menjalankan dashboard tanpa
collector otomatis.

## Update data pasar otomatis dan latensi

`market_data_updater.py` menjalankan `data_collector.py` secara eksklusif dalam
dua tingkat:

- **FAST (60 detik):** pair aktif, pair dengan paper order terbuka, BTCUSD, dan
  pair WATCH yang dikonfigurasi collector.
- **FULL (15 menit):** seluruh simbol terdaftar untuk memperbarui watchlist.

Updater memakai single-instance lock, timeout, exponential backoff, dan shutdown
bersih. Tidak ada decision engine, bridge, atau executor yang dipanggil. Setelah
CSV ditulis atomik, watcher API mendeteksi mtime dalam sekitar 1 detik dan
WebSocket mengirim snapshot baru tanpa refresh browser.

Sumber saat ini adalah candle Yahoo M15 dengan finalization lag satu candle.
Karena itu target latensi adalah **maksimal sekitar 60 detik setelah candle final
tersedia di provider**, bukan tick-by-tick atau broker realtime. Pasar tutup,
keterlambatan provider, atau kegagalan jaringan tetap akan ditampilkan sebagai
STALE secara transparan.

Ambang stale market menghitung timestamp awal candle, durasi candle, dan satu
bar finalization lag. Ini mencegah candle M15 terbaru yang sah ditandai kadaluarsa
sesaat setelah diunduh. Status keputusan/signal tetap dapat STALE bila engine yang
menghasilkan file tersebut memang tidak sedang berjalan; updater ini tidak akan
menjalankannya secara diam-diam.

Menjalankan updater saja:

```bash
cd /Users/muhammadirvan/Documents/AI_SCALPER
.venv/bin/python market_data_updater.py
```

Uji satu kali tanpa daemon:

```bash
.venv/bin/python market_data_updater.py --once fast
```

Konfigurasi:

| Nama | Default | Fungsi |
|---|---:|---|
| `AI_SCALPER_MARKET_FAST_INTERVAL_SECONDS` | `60` | Refresh pair prioritas; minimum 15 detik |
| `AI_SCALPER_MARKET_FULL_INTERVAL_SECONDS` | `900` | Refresh seluruh simbol; minimum 60 detik |
| `AI_SCALPER_MARKET_COLLECTOR_TIMEOUT_SECONDS` | `240` | Timeout satu proses collector |
| `AI_SCALPER_MARKET_FAILURE_BACKOFF_MAX_SECONDS` | `300` | Batas retry backoff |
| `AI_SCALPER_MARKET_FULL_ON_START` | `true` | Jalankan FULL saat startup |
| `AI_SCALPER_COLLECTOR_PYTHON` | `.venv/bin/python` | Interpreter dengan yfinance |

Template autostart macOS tersedia di
`dashboard_api/launchd/com.ai-scalper.market-data-updater.plist.example`.
Template API tetap berada di
`dashboard_api/launchd/com.ai-scalper.dashboard-api.plist.example`.

Pasang dan aktifkan updater saat login macOS:

```bash
cp dashboard_api/launchd/com.ai-scalper.market-data-updater.plist.example \
  "$HOME/Library/LaunchAgents/com.ai-scalper.market-data-updater.plist"
launchctl bootstrap "gui/$(id -u)" \
  "$HOME/Library/LaunchAgents/com.ai-scalper.market-data-updater.plist"
launchctl print "gui/$(id -u)/com.ai-scalper.market-data-updater"
```

Log operasional berada di `/tmp/ai-scalper-market-updater.stderr.log`. Jika
updater juga dimulai dari `start_dashboard.sh`, instance kedua akan ditolak oleh
lock sehingga tidak ada download paralel.

### Asumsi dan target operasional updater

- Satu pengguna lokal, satu host, tanpa tenancy dan tanpa secret provider.
- Data bersifat internal/indicative; API dashboard tetap hanya bind localhost.
- Beban default berjalan sequential: tiga simbol FAST per menit dan 17 simbol
  FULL per 15 menit (daftar mengikuti konfigurasi collector).
- Target pickup p95: maksimal 75 detik setelah candle finalized tersedia di
  provider; target ini tidak mencakup outage atau throttling provider.
- RPO: paling banyak satu candle M15 finalized. RTO lokal: maksimal 5 menit
  melalui exponential backoff. Availability bersifat best-effort workstation,
  bukan SLA broker atau production trading.

## Kontrak producer

Kontrak JSON Schema dan panduan atomic write producer tersedia di
`dashboard_api/CONTRACTS.md`. Endpoint `/api/v1/source-contracts` menunjukkan
sumber `COMPLIANT`, `LEGACY`, `INVALID`, atau `UNAVAILABLE`. Adapter tidak
memigrasikan atau menulis ulang producer legacy.

## Menambah sumber atau schema baru

1. Tambahkan nama file tunggal pada `SOURCE_FILE_NAMES` di `app/config.py`.
2. Tambahkan mapping toleran terhadap field hilang di `app/data_normalizer.py`.
3. Perluas model Pydantic di `app/models.py` bila field menjadi bagian kontrak.
4. Perluas tipe dan mapper frontend di `src/types/dashboardApi.ts` serta
   `src/utils/snapshotMapper.ts`.
5. Tambahkan fixture temporary dan assertion regresi.
6. Pastikan safety guard tetap berjalan setelah normalisasi.

Jangan membaca file Python lokal langsung dari browser dan jangan menambahkan
write endpoint untuk “memperbaiki” kontradiksi.

## Troubleshooting

- **Port sudah dipakai:** periksa proses pada 8000/5173 atau pilih port lokal lain
  dan samakan `.env.local`.
- **CORS:** gunakan origin 5173/4173 yang diizinkan, bukan hostname lain.
- **Backend disconnected:** buka `/api/health`, periksa root, lalu lihat log startup.
- **Invalid JSON:** API akan memakai last-known-good; tunggu engine menyelesaikan
  write berikutnya. Backend tidak memperbaiki file.
- **Stale:** bandingkan `source_timestamp` dengan frekuensi aktual generator.
- **File not found:** periksa `/api/v1/sources` dan `AI_SCALPER_ROOT`.
- **Reconnect loop:** pastikan URL WS, port, dan protokol `ws://` benar.
- **Frontend tetap mock:** pastikan backend hidup, `.env.local` benar, lalu restart
  Vite agar variable `VITE_` dimuat.
- **Chart kosong:** CSV mungkin kosong, kolom tidak dikenali, atau timeframe yang
  dipilih tidak tersedia. UI tidak menggandakan candle ke timeframe lain.
- **Berita tidak tersedia:** periksa koneksi internet backend dan endpoint
  `AI_SCALPER_NEWS_API_URL`, atau sediakan salah satu file kalender lokal yang
  didukung. Backend menerima timestamp payload maupun header HTTP `Last-Modified`,
  menyimpan last-known-good di memori, dan tidak pernah menulis ke sumber.
- **Berita tampak kedaluwarsa:** status berita memakai ambang khusus
  `AI_SCALPER_NEWS_STALE_AFTER_SECONDS`; status sumber dashboard lain tidak lagi
  mengubah badge panel berita. Feed default adalah kalender ekonomi mingguan,
  bukan layanan headline atau harga tick.
