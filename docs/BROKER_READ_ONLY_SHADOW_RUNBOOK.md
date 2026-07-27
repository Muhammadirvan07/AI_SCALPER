# Phase 3 — Broker Read-Only Shadow

Status: **PHILLIP COMMODITY V5 PROOF VERIFIED / V4 AND V5 TASK FAILURES
PRESERVED / V6 SCHEDULER-ONLY REMEDIATION PREPARED /
FBS DIAGNOSTIC-ONLY / XM JAPAN LEGAL-BLOCKED / NOT_READY**

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
sedang berjalan. Japan FSA mencantumkan `FBS Markets Inc.` dalam peringatan
penyedia luar negeri tanpa registrasi. Karena itu FBS dibatasi ke diagnostic
paper; evidence discovery dan order tidak boleh diaktifkan selama operasi dari
Jepang. Jika yurisdiksi berubah, seluruh gate berikut harus direview ulang:

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

## Phillip Commodity current evidence lane

Phillip Commodity is the only currently registration-enabled broker-forward
lane. Its v2 contract and authenticated pre-window proof are valid:
`runtime_state=HEALTHY`, `cycle_status=IDLE`,
`source_chain_from_genesis=true`, and order capability disabled. Phillip FX
remains independently registration-disabled.

The v2 timestamps measured about 202.635 seconds from process invocation to
cycle receipt because the exact installed environment was rehashed at every
one-shot launch. Since the evidence contract allows only 60 seconds of append
grace, do not install the v2 one-shot command as a once-per-minute task.

The first bounded-worker v3 contract is preserved as failed evidence. Its
first child correctly failed closed because the session re-entered the
non-idempotent site-packages activator after the process-level verification.
No broker mutation occurred. The immutable v4 contract then proved the
corrected bounded worker with 13 authenticated children, one dependency
session, and a source chain verified from genesis. Its Task Scheduler
installation failed closed after registration because Windows omitted the
optional `RunLevel` element from exported XML; the handler disabled the task
before scheduled execution. The v4 contract, proof receipt, task XML, and
disabled task remain preserved.

The v5 bounded worker proof is valid: it binds the immutable v5 contract,
12 authenticated children, one dependency session, and a source chain from
genesis. Its task installation then failed closed after Windows legally
elided the XSD-default node `StartWhenAvailable=false`. The StrictMode
validator accessed that missing XML child dynamically, raised
`PropertyNotFoundStrict`, and disabled V5 before its scheduled run. V5 proof,
task, review XML, and installed XML remain immutable.

V6 is a scheduler-only remediation. It retains frozen worker commit
`290cc23d9d87f93e914612afdfecfc481d2c232f`, contract
`phillip-commodity-window-01-diagnostic-v5`, the V5 journal/audit chain, and
the exact proof receipt SHA-256
`29e14f81bbd87d460f171484d59a40e9bdd6ae00611c3453ade4aa6c846b3aec`.
It creates only a new V6 task and create-exclusive V6 task evidence. The
shared validator applies XSD defaults to omitted optional nodes, rejects
missing non-default settings, and independently validates every effective
CIM value. It registers V6 disabled, requires 900 seconds of lead, verifies
the exact first `NextRunTime`, and enables only after the disabled definition
passes. Rollback unconditionally attempts stop plus disable and must prove
effective state `Disabled`. Health freshness comes only from the monotonic
HMAC-signed runtime heartbeat, never audit/journal file mtimes. The installer
anchors every exact V5 proof child and the full predecessor sequence/hash/HMAC
chain into a signed genesis checkpoint. Health checks append signed
checkpoints and verify only the new committed-manifest suffix; an audit without
its manifest is treated as an in-progress publication, while a manifest with
missing or invalid audit bytes fails closed. The signed checkpoint/audit head
must exactly equal the authenticated read-only SQLite journal head, preventing
tail rollback. A named mutex serializes health plus checkpoint commit, and
only a byte-identical collision is idempotent. Installation performs a full
archive audit; later operators can request the same re-read with
`Test-PhillipCommodityV6TaskHealth.ps1 -FullArchiveAudit`, but only while the
task is `Ready`, outside an active interval, and at least 3600 seconds before
the next start. Checkpoints are flushed to a non-chain temporary file and
atomically moved to their create-exclusive final name. Default online health
intentionally revalidates only the new suffix plus live journal head.
Phase is recomputed after evidence verification, `Queued` is accepted only
during startup grace before any run attempt, immediate startup exits are
rejected, and the end boundary cannot invent a post-expiry trigger. V4 and V5
must remain present and
`Disabled`; they are never deleted or overwritten.

The first V6 transport attempt failed before task installation: Windows
PowerShell 5.1 treated the parsed top-level JSON inventory as one pipeline
object although the valid ZIP extracted six files. V6.1 corrected extraction,
but its immutable first scheduler boundary expired before transfer and no V6.1
task was installed. V6.2 retained exact recursive verification and extracted
successfully, but Windows PowerShell 5.1 coerced the self-test's empty
`<Principal />` element to `String("")` before the typed `XmlElement` boundary;
the installer stopped before task registration. Use only transport V6.3. It
uses exact XPath element selection, retains the reviewed start
`2026-07-30T06:45:00+09:00`, and defaults to a new commit-specific operator
root. Keep any V6/V6.1/V6.2 transfer or operator path that exists unchanged
for forensic review; absence of a never-created path is not an error.

Worker failure, stale status, audit-export failure, Task Scheduler overlap, or
loss of the exact terminal is `HOLD`. The worker does not carry an order API.

## FINEX future Indonesia preparation

Registrasi FINEX di Bappebti telah diverifikasi, tetapi ini belum membuktikan
personal/account eligibility maupun izin operasi dari Jepang. Jangan menyalin
binding XM/FBS ke FINEX. Sebelum menyiapkan contract FINEX setelah kembali ke
Indonesia,
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
