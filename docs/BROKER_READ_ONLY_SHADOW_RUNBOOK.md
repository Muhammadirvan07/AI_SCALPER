# Phase 3 — Broker Read-Only Shadow

Status: **LOCAL RUNNER READY / BROKER BINDING PENDING / NOT_READY**

Prioritas operasional saat ini adalah **XM sebagai primary read-only shadow**
dan **FINEX sebagai standby preparation**. FBS tetap disimpan sebagai deferred
benchmark, bukan jalur aktif. Daftar terencana ada di
`config/broker_candidates.phase3.json`. Nilai yang belum diamati langsung dari
terminal demo MT5 tetap `null`. Jangan menyimpan login, password, investor
password, token, atau secret di repository.

## Urutan onboarding

Selesaikan XM terlebih dahulu dan mulai evidence shadow setelah exact binding
lolos. FINEX disiapkan dengan kontrak dan proses yang sama, tetapi evidence-nya
tidak boleh dicampur dengan XM. Setiap broker memiliki candidate ID, server,
instrument spec hash, forward contract, dan ledger sesi sendiri.

1. Buat akun **demo MT5** dan catat exact legal/company name, server, account
   type, currency, serta trade mode yang dilaporkan terminal.
2. Verifikasi eligibility/legalitas secara independen. Status yang belum
   diverifikasi harus tetap `legal_eligible=false` dan tidak dapat lolos
   benchmark.
3. Temukan exact broker symbol untuk XAUUSD, EURUSD, USDJPY, dan AUDUSD,
   termasuk suffix/prefix. Jika satu simbol tidak tersedia, kandidat HOLD.
4. Ekspor `digits`, `point`, `trade_tick_size`, `trade_contract_size`,
   `trade_tick_value`, `volume_min/max/step`, stops/freeze level, currency,
   margin mode, dan session calendar; hash menjadi exact binding.
5. Buat `BrokerCandidateRegistration`, lalu jalankan satu
   `ReadOnlyShadowService.run_once()` per sesi. Hanya
   `FINALIZED_EVIDENCE_APPENDED` untuk keempat simbol yang dihitung COMPLETE.
6. Kumpulkan minimal 20 sesi COMPLETE per kandidat. Angka 20 hanya membuka
   review benchmark manual; tidak membuka demo-auto ataupun live.

## Kontrol tetap

```text
live_allowed = false
safe_to_demo_auto_order = false
promotion_eligible = false
max_lot = 0.01
```

`live_runtime.shadow_phase` tidak mengimpor adapter order dan hanya menerima
callable eksportir read-only. Kegagalan satu simbol dicatat durable sebagai
HOLD. Penggunaan ulang `candidate_id + session_id` dengan payload berbeda
ditolak. Ledger menggunakan SQLite WAL dan dapat dilanjutkan setelah restart.

## Discovery XM di Windows

Pastikan terminal XM MT5 sudah terbuka dan login ke demo server exact
`XMTrading-MT5 3`. Dari PowerShell di root proyek, aktifkan environment lalu
jalankan:

```powershell
.\.venv\Scripts\Activate.ps1
python .\mt5_readonly_discovery.py --candidate xm --output .\runtime_state\broker_discovery\xm-first.json
```

Perintah tidak menerima login/password dan hanya membaca `account_info()` serta
`symbol_info()`. Output dibuat exclusive dengan permission lokal terbatas,
menolak overwrite, tidak menyimpan MT ID, nama akun, balance, atau equity, dan
mengikat hash payload. Jangan unggah file tersebut sebelum memeriksa isinya.

## Calendar window 01

Window pertama sengaja dibatasi menjadi 10 sesi, bukan langsung 20, karena
special-hours notice Agustus belum diterbitkan sebelum window dimulai. Plan
`config/xm_calendar_window_01.json` mencakup pembukaan server Senin 20 Juli
hingga penutupan Jumat 31 Juli 2026. Sumber resmi Juli tidak mencantumkan
perubahan GOLD atau FX wajib setelah 6 Juli.

Sesudah pull commit calendar terbaru di Windows, jalankan:

```powershell
python .\build_xm_calendar.py --output .\runtime_state\broker_discovery\xm-calendar-window-01.json
```

Generator memakai `Europe/Helsinki` untuk aturan GMT+2/GMT+3, mengubah semua
bucket ke UTC, memasukkan weekend closure untuk seluruh simbol dan daily break
GOLD, lalu memvalidasi exact partition dengan verifier evidence yang sama.
Output tidak memberi izin trading. Window kedua baru boleh didaftarkan setelah
notice special-hours Agustus tersedia dan direview sebelum observasi.

## Bukti yang belum ada

- Exact field XM yang belum tersedia melalui screenshot dan seluruh exact demo
  binding FINEX.
- Independent legal/regulatory eligibility review.
- Exact four-symbol mapping dan instrument specification hash.
- 20 sesi lengkap XM; FINEX tetap membutuhkan 20 sesi tersendiri sebelum dapat
  dibandingkan atau dipilih.
- Measured spread, fill quality, feed uptime, dan operational scores.
- Pemilihan satu exact broker server melalui manual review.

Karena itu Fase 3 sudah memiliki jalur software lokal, tetapi pengumpulan
broker-forward nyata belum dimulai dan sistem tetap **NOT_READY**.
