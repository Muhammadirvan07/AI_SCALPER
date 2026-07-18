# Crypto Weekend Shadow — Binance Primary / Coinbase Validator

Status: **DIAGNOSTIC-ONLY / SHADOW-ONLY / NO CREDENTIALS / NO ORDERS**

Lane ini menjaga AI_SCALPER tetap melakukan observasi saat forex berada dalam
weekend closure. Lane crypto tidak menggantikan XM, tidak masuk journal XM, dan
tidak dapat menjadi broker-forward promotion evidence.

## Arsitektur

```text
Binance public M15 + best bid/ask
                 |
                 v
        cross-feed fail-closed <--- Coinbase public bid/ask + timestamp
                 |
                 v
       shared pure decision core
                 |
                 v
 isolated crypto SQLite WAL journal
                 |
                 v
 verified read-only performance report
```

Instrument mapping:

| Canonical lane | Primary | Validator |
|---|---|---|
| `BTCUSD` | Binance `BTCUSDT` | Coinbase `BTC-USD` |
| `ETHUSD` | Binance `ETHUSDT` | Coinbase `ETH-USD` |

Binance USDT spot bukan broker CFD USD. Mapping canonical hanya membuat
decision core konsisten; hasilnya tidak membuktikan fill, contract economics,
margin, funding, atau slippage broker.

## Kontrol fail-closed

- HTTPS GET hanya ke `data-api.binance.vision` dan
  `api.exchange.coinbase.com`.
- Tidak ada input API key, credential, account, wallet, atau order.
- Finalized M15 harus UTC-aligned, unique, contiguous, dan lolos OHLC checks.
- Binance server time harus berada dalam bounded request interval dengan
  toleransi clock drift satu detik.
- Coinbase ticker maksimal berumur 30 detik.
- Cross-feed midpoint deviation maksimal 50 bps.
- Spread setiap feed maksimal 25 bps.
- Missing/stale/crossed/divergent/schema-invalid data menghasilkan `HOLD`.
- Entry hanya memakai primary quote yang diterima maksimal 10 detik setelah
  M15 close. Jika runner dimulai di tengah candle, `ENTRY_WINDOW_MISSED` adalah
  hasil normal dan candle itu tidak diperdagangkan secara virtual.
- `BTCUSD` dan `ETHUSD` selalu shadow-only. Tidak ada permit atau config yang
  dapat mengubah hard lock dari jalur ini.

## Jalankan di Windows

MT5 tidak diperlukan untuk lane crypto publik. Di PowerShell:

```powershell
cd C:\AI_SCALPER
git pull origin agent/live-grade-phase3
.\.venv\Scripts\Activate.ps1

python -B .\run_crypto_weekend_shadow.py `
  --acknowledge-diagnostic-only `
  --continuous `
  --poll-seconds 2
```

Default scheduler hanya aktif dari Jumat 21:00 UTC sampai Minggu 22:00 UTC.
Di luar window tersebut runner berhenti aman dengan
`INACTIVE_OUTSIDE_FOREX_WEEKEND_FOCUS_WINDOW`. Flag
`--allow-weekday-diagnostic` hanya untuk pengujian feed; flag itu tidak membuka
order, promotion, maupun live.

Tekan `Ctrl+C` untuk berhenti. Jangan menghapus atau mengedit journal:

```text
runtime_state\diagnostic\crypto-weekend-shadow.sqlite3
```

Summary operasional:

```text
runtime_state\diagnostic\crypto-weekend-summary.json
```

## Laporan performa

Setelah menghentikan runner:

```powershell
python -B .\generate_crypto_diagnostic_report.py `
  --acknowledge-diagnostic-only
```

Output:

```text
runtime_state\diagnostic\crypto-weekend-performance.json
```

Report membuka SQLite dalam mode read-only/query-only, memverifikasi profile,
schema, row/envelope binding dan seluruh hash chain sebelum menghitung metrik
BTC serta ETH secara terpisah.

## Interpretasi status

- `WAIT`: decision core tidak menyetujui setup.
- `PAPER_OPENED`: posisi virtual dibuka; tidak ada order exchange.
- `ALREADY_PROCESSED`: candle sudah tercatat dan tidak diduplikasi.
- `ENTRY_WINDOW_MISSED`: runner tidak memperoleh quote dalam jendela entry.
- `STALE_BAR`: finalized candle terlalu lama.
- `HOLD:<Error>`: satu atau lebih trust checks gagal.

Outcome posisi diperiksa dari sampled best bid/ask setiap cycle. Intracycle
touch dapat terlewat, sehingga hasil ini hanya diagnostic dan tidak boleh
dianggap sebagai execution-quality evidence.

## Sumber resmi

- Binance Spot market-data REST:
  <https://developers.binance.com/en/docs/products/spot/rest-api>
- Binance WebSocket/kline semantics:
  <https://developers.binance.com/zh-CN/docs/products/spot/testnet/web-socket-streams>
- Coinbase public market-data WebSocket:
  <https://docs.cdp.coinbase.com/coinbase-business/advanced-trade-apis/websocket/websocket-overview>
