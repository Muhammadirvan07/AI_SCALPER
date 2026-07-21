# Phase 3 — Broker Read-Only Shadow

Status: **FBS DIAGNOSTIC SHADOW ACTIVE / EVIDENCE GATES PENDING / XM JAPAN LEGAL-BLOCKED /
BROKER-FORWARD DATA NOT STARTED / NOT_READY**

Belum ada primary evidence broker yang boleh dipromosikan. FBS adalah target
read-only diagnostic yang dipilih operator dengan binding `FBS-Demo`, akun demo
USD 500:1 retail hedging, dan empat simbol canonical tanpa suffix. FINEX tetap
standby historis dan XM diblokir untuk operasi dari Jepang. Setiap broker wajib
memiliki discovery, key, contract, specification, calendar, serta ledger
terpisah. Evidence antarbroker tidak boleh dicampur.

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
Stdout bukan sumber audit. Jangan memakai journal, export, atau backup XM atau
FINEX untuk FBS.

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

## FBS target diagnostic

Read-only binding dan preflight FBS telah diamati, dan diagnostic paper shadow
sedang berjalan. Sebelum evidence collection, FBS masih harus melewati:

- durable sanitized preflight receipt pada source terbaru;
- API instrument specification untuk empat simbol;
- session timezone/calendar dan holiday overrides;
- independent regulatory eligibility review untuk lokasi operasi;
- discovery v3, contract, key, dan source-instance ID khusus FBS.

Diagnostic paper boleh dimulai setelah preflight lulus, tetapi tidak dihitung
sebagai promotion evidence.

Pipeline evidence generik, profile FBS, kalender explicit-session, contract
registration, dan broker-neutral one-shot collector telah tersedia secara
lokal. Seluruhnya tetap fail-closed melalui profile
`registration_enabled=false`; urutan aktivasi dan gate ada di
`docs/FBS_EVIDENCE_PIPELINE.md`.

## FINEX historical standby

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

- Minimal 20 sesi FBS terpisah untuk benchmark.
- Measured spread, uptime, cost, serta fill quality.
- Demo manual order/reconciliation evidence.
- Demo-auto soak 30 hari/50 fill.
- Acceptance gate lane XAUUSD dan secondary FX.

Karena bukti itu belum ada, sistem tetap **NOT_READY** walaupun infrastruktur
read-only telah di-hardening.
