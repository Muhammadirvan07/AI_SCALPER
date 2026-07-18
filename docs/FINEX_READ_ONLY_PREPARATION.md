# FINEX Read-Only Preparation

Status: `SELECTED_TARGET_PREPARATION / NO ORDER / NOT PROMOTION EVIDENCE`

FINEX adalah broker target pilihan operator. Bappebti mencatat PT Finex Bisnis
Solusi Futures dengan izin `47/BAPPEBTI/SI/04/2013` dan izin SPA
`77/BAPPEBTI/SP/12/2014`. Situs resmi FINEX menyatakan akun demo tersedia dan
platform trading yang digunakan adalah MetaTrader 5.

Pemilihan ini tidak mengubah safety lock:

```text
primary_shadow_broker = null
execution_enabled = false
credentials_allowed = false
live_allowed = false
safe_to_demo_auto_order = false
max_lot = 0.01
```

## Fakta binding yang wajib ada

Jangan kirim password atau credential ke repository maupun chat. Setelah akun
demo FINEX dibuat dan terminal MT5 terhubung, catat hanya:

1. exact nama demo server;
2. tipe akun demo;
3. mata uang akun dan leverage;
4. broker symbol untuk `XAUUSD`, `EURUSD`, `USDJPY`, dan `AUDUSD`;
5. digits, point, tick size, contract size, volume min/max/step, stop/freeze
   level, calculation mode, execution mode, dan filling mode;
6. konfirmasi investor/read-only login serta external Python API trading lock;
7. eligibility penggunaan akun saat operating jurisdiction masih Jepang.

## Binding parsial 2026-07-18

Fakta non-rahasia berikut telah direview dari screenshot operator:

```text
server = FinexBisnisSolusi-Demo
server_endpoint = prod-mt5-demo1.fnx.xmt.mx:443
account_type = Demo Reguler
leverage = 500:1
account_currency = USD
EURUSD broker symbol = EURUSD
USDJPY broker symbol = USDJPY
```

EURUSD dan USDJPY teramati memakai market execution, volume minimum/step
`0.01`, volume maksimum `50`, serta filling `Fill or Kill` atau
`Immediate or Cancel`. Nilai tersebut masih screenshot facts dan harus
ditangkap ulang oleh API sebelum menjadi `BrokerSpec` evidence.

Screenshot pengganti telah mengonfirmasi `XAUUSD` dan `AUDUSD`, sehingga exact
four-symbol map sekarang lengkap tanpa suffix:

```text
XAUUSD = XAUUSD
EURUSD = EURUSD
USDJPY = USDJPY
AUDUSD = AUDUSD
```

XAUUSD teramati memiliki contract size `100`, digits `2`, stop level `10`, dan
volume minimum/step `0.01`. Tampilan MT5 membulatkan tick size menjadi `0.00`,
sehingga nilai itu tidak boleh dipakai untuk risk math sebelum API capture.

Operator mengonfirmasi mata uang akun `USD` melalui screenshot tampilan saldo
berformat dolar; fakta ini masih menunggu attestation API. Nominal saldo dan
identifier akun tidak disimpan. Investor/read-only login attestation, terminal
external Python API lock, API-captured specification, dan eligibility lintas
yurisdiksi masih belum lengkap. Karena itu
`read_only_discovery_allowed=false` tetap dikunci walaupun fakta akun dan
four-symbol map sudah lengkap.

`mt5_readonly_discovery.py --candidate finex` sengaja menolak berjalan sebelum
exact server dan empat-symbol map direview serta dimasukkan ke
`config/broker_candidates.phase3.json`. Jangan menebak suffix simbol.

Setelah seluruh fakta disetujui, urutannya adalah discovery v3, signed calendar,
forward contract, lalu read-only evidence collection. Order tetap tidak aktif.

## Sumber resmi

- Bappebti: `https://bappebti.go.id/pialang_berjangka/detail/133`
- FINEX account/demo/MT5: `https://finex.co.id/trading/accounts`
- Japan FSA FX warning: `https://www.fsa.go.jp/ordinary/iwagai/`
