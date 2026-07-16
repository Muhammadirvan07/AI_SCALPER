# Phase 3 — Broker Read-Only Shadow

Status: **XM JAPAN LEGAL-BLOCKED / FINEX BINDING PENDING /
BROKER-FORWARD DATA NOT STARTED / NOT_READY**

Belum ada primary shadow broker yang boleh dijalankan. XM tetap terkonfigurasi
sebagai referensi teknis, tetapi diblokir untuk operasi dari Jepang. FINEX
tetap standby preparation dan harus memiliki discovery, key, contract, symbol
specification, calendar, serta ledger terpisah. FBS deferred. Evidence
antarbroker tidak boleh dicampur.

Kontrol permanen fase ini:

```text
live_allowed = false
safe_to_demo_auto_order = false
promotion_eligible = false
max_lot = 0.01
```

## Urutan onboarding broker

1. Verifikasi legal eligibility secara independen.
2. Rekam exact legal entity, server, DEMO environment, account currency, dan
   empat broker symbol.
3. Buat HMAC discovery receipt tanpa menyimpan login atau credential.
4. Bind instrument specification serta session calendar ke satu contract.
5. Jalankan read-only shadow; tidak ada adapter order pada jalur ini.
6. Kumpulkan minimal 20 sesi COMPLETE per kandidat sebelum benchmark manual.

Angka minimum sesi hanya membuka review benchmark. Itu tidak membuka
demo-auto, live, promotion permit, atau peningkatan lot.

Setiap runner broker wajib memiliki journal SQLite sendiri dengan:

- hash-chained receipt untuk seluruh startup/cycle outcome;
- heartbeat, last-success, serta status failed/stale yang eksplisit;
- free-disk guard sebelum evidence append;
- verified create-exclusive audit export+manifest per invocation untuk
  dipindahkan off-host, ditambah backup SQLite terjadwal untuk restore.

Kegagalan journal, disk, heartbeat, audit export, atau backup adalah `HOLD`.
Stdout bukan sumber audit. Jangan memakai journal, export, atau backup XM untuk
FINEX.

## Jalur XM diblokir untuk Jepang

Gunakan prosedur lengkap di `docs/XM_READ_ONLY_SHADOW_RUNBOOK.md` hanya sebagai
runbook masa depan. Japan FSA legal gate saat ini menolak XM/Tradexfin, sehingga
artefak Window 02 v3 berikut belum boleh dibuat:

- discovery: `xm-window-02-v3.json`
- plan: `xm-calendar-window-02-plan-v3.json`
- calendar: `xm-calendar-window-02-v3.json`
- contract: `xm-window-02-diagnostic-v3`

`xm-window-01-diagnostic-v2` dan artefak pendahulunya tetap immutable,
read-only, dan tidak boleh ditimpa atau dilanjutkan oleh runtime v3.

## FINEX standby

Jangan menyalin binding XM ke FINEX. Sebelum menyiapkan contract FINEX,
lengkapi:

- exact legal/company name dan regulatory eligibility;
- exact demo server dan account type;
- exact XAUUSD/EURUSD/USDJPY/AUDUSD symbol mapping;
- digits, point, tick size, contract size, lot step, stop/freeze level,
  currencies, margin mode, dan session calendar;
- key dan source-instance ID yang berbeda dari XM.

Registrasi broker FINEX di Bappebti telah dicatat dari sumber resmi, tetapi itu
belum membuktikan eligibility operasi saat user masih berada di Jepang.
Sampai eligibility dan data terminal FINEX tersedia, kandidat tetap
`BROKER BINDING PENDING / NO OPERATION`.

## Bukti yang masih belum ada

- Minimal 20 sesi broker-forward XM yang valid.
- Minimal 20 sesi FINEX terpisah.
- Measured spread, uptime, cost, serta fill quality.
- Demo manual order/reconciliation evidence.
- Demo-auto soak 30 hari/50 fill.
- Acceptance gate lane XAUUSD dan secondary FX.

Karena bukti itu belum ada, sistem tetap **NOT_READY** walaupun infrastruktur
read-only telah di-hardening.
