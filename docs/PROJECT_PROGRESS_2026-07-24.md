# AI_SCALPER Progress — 2026-07-24

Status: **LOCAL THREE-SERVICE FOUNDATION COMPLETE / DEMO-AUTO ACTIVATION
BLOCKED / LIVE NOT READY**

## Ringkasan angka

Persentase berikut adalah estimasi engineering, bukan izin trading:

- fondasi software lokal yang diperlukan sebelum acceptance Windows:
  **100%**;
- kesiapan untuk **memulai** demo-auto soak: sekitar **75%**;
- roadmap Live-Grade v1 end-to-end: sekitar **49%**.

Perbedaan tersebut disengaja. Source code lokal dapat selesai, tetapi demo-auto
baru boleh dimulai setelah acceptance Windows, provider/key custody, sepuluh
manual-demo lifecycles, dan approval manusia. Live masih membutuhkan soak 30
hari/50 closed fills/20 XAU, bukti per lane, serta gate statistik dan keamanan.

Validasi lokal terakhir menjalankan **1.421 test** tanpa kegagalan pada mode
normal dan `PYTHONOPTIMIZE=2`. Seluruh tracked Python source berhasil
dikompilasi, validator decision/execution/status-monitor lulus dengan
`production_execution_ready=false`, dan safety locks tetap:

```text
live_allowed = false
safe_to_demo_auto_order = false
max_lot = 0.01
promotion_eligible = false
```

Dependency lock Windows, install manifest, dan CycloneDX SBOM juga tervalidasi.
Audit environment development dengan `pip-audit 2.10.1` melaporkan tidak ada
kerentanan yang diketahui. Hasil ini adalah pemeriksaan lokal saat ini, bukan
pengganti signed OSV release receipt dari Windows host target.
Audit ship-gate terperinci tersedia di
[SHIP_GATE_AUDIT_2026-07-24.md](SHIP_GATE_AUDIT_2026-07-24.md); verdict-nya
adalah source lokal lulus, sedangkan demo-auto dan live tetap ditolak sampai
bukti eksternal selesai.

Empat deterministic archive untuk commit `d153361`—decision, execution,
status monitor, dan configured-release operator tooling—sudah dibangun pada
Windows lalu direproduksi dari clean checkout independen. Seluruh archive
SHA-256 dan release identity identik. Exact receipt tersedia di
[WINDOWS_BASE_RELEASE_REPRODUCIBILITY_2026-07-24.md](WINDOWS_BASE_RELEASE_REPRODUCIBILITY_2026-07-24.md).
Ini menutup base-release gate untuk exact source `d153361`, bukan
provider/configured-release gate. Setelah signed decision-feed handoff
ditambahkan, artefak itu menjadi baseline historis; candidate baru harus
dibangun ulang dari clean commit berikutnya.

## Yang selesai pada fondasi lokal

- Pure decision core dan brokerless finalized-M15 decision producer dipakai
  melalui signed, one-use decision IPC.
- Signed append-only decision-feed handoff sekarang menutup boundary lokal
  antara broker-side read-only observation dan role `FINALIZED_M15_DATA`.
  Packet mengikat exact broker/account/lane/source/calendar, sequence serta
  predecessor, HMAC, canonical JSON, dan first-eligible quote; consumer
  stable-read mengembalikan exact `FinalizedM15DecisionInput`. Transport ini
  tidak memberi broker/order capability dan bukan promotion evidence.
- Reference MT5 read-only publisher sekarang mengisi sisi broker dari boundary
  tersebut. Setiap siklus melakukan attestation dan exact account binding
  sebelum serta sesudah market read, hanya menerima finalized current-boundary
  M15 dan first eligible tick dalam 10 detik, membatasi publish lag maksimal
  satu detik, meminta receipt independen untuk setiap session gap, lalu
  mendelegasikan write ke signed feed. Publisher masuk exact 33-file Windows
  shadow-service closure, tetapi tidak masuk decision process dan tidak
  memiliki order, risk, permit, credential provisioning, atau terminal
  lifecycle capability. Publisher juga mengikat deadline efektif yang lebih
  awal antara batas entry dan publish lag; signed feed membaca ulang trusted
  UTC tepat sebelum write baru sehingga pergantian waktu di antara validasi
  publisher dan create-exclusive write tetap fail-closed.
- Decision, gated execution/reconciliation, dan external status monitor
  memiliki tiga release profile, allowlist, service identity, runtime root,
  serta state domain yang terpisah.
- Decision production loader memverifikasi exact configured release, full
  inventory, source/import origin, short-lived RSA launcher attestation,
  sealed factory result, binding, dan bounded cycle deadline sebelum runtime.
- External status monitor memiliki typed snapshot/assessment/checkpoint/latch
  contract, 12-role factory contract, exact configured-release loader, public
  RSA trust boundary, bounded runner, dan deterministic release.
- Critical monitor cycle wajib melatch incident, memperoleh verified alert dan
  heartbeat acknowledgement, lalu baru memajukan external checkpoint CAS.
  Monitor tidak memiliki broker, risk, permit, executor, atau order authority.
- Execution path tetap journal-bound, idempotent, reconciled, dan fail-closed
  untuk uncertain submit, duplicate intent, orphan position, missing
  server-side protection, risk breach, maupun restart.
- Configured-release tooling menghasilkan identity baru untuk exact
  secret-free provider overlay tanpa memasukkan credential atau melonggarkan
  base release provenance.
- Configured-overlay candidate preparer kini menghilangkan perakitan descriptor
  manual: ia memilih exact factory-template member dari base profile,
  stable-read Task Scheduler definition, menghitung factory contract serta
  seluruh inventory/hash, menolak import closure yang tidak lengkap, dan
  menulis factory manifest/descriptor secara create-exclusive. Hasilnya tetap
  kandidat yang wajib direview eksternal, bukan configured release atau izin
  order.
- Provider conformance reviewer kini merekonstruksi tiga authoritative factory
  template dan mengikat seluruh 65 decision/execution/status-monitor provider
  bindings ke fresh external suite/artifact hashes. Packet canonical ini
  memberi target `details_sha256` yang granular untuk signature owner
  independen, tetapi tetap menetapkan `provider_accepted=false`, tidak
  mengimpor provider, dan tidak mempunyai activation/order authority.
- Provider evidence input assembler kini menghapus transkripsi manual 65
  binding: operator hanya memasukkan compact external test evidence, sedangkan
  contract/implementation/configuration/binding/custody/kind/credential truth
  diturunkan dari tiga exact factory template. Output langsung diuji oleh
  reviewer lama sebelum ditulis, tetapi tidak membuat evidence, signature,
  acceptance, atau authority.
- Account-level soak projection dapat menghitung 30 clean days, 50 closed
  fills, dan minimal 20 XAU closed fills, tetapi tidak dapat memberi execution
  atau promotion authority.
- Operations review v3 sekarang mengikat tepat tiga configured release,
  runtime, service identity, decision IPC, monitor custody, failure-drill
  manifest, dan tiga validation-only scheduler review. Strict loader menolak
  unknown/duplicate/non-finite/oversized/symlink/unstable/secret input; verifier
  merekonstruksi seluruh isi sehingga recomputed outer hash tidak dapat
  menyamarkan tampering.
- External-acceptance verifier sekarang merekonstruksi exact review v3,
  memverifikasi externally pinned RSA policy, fixed owner map, serta satu
  signed observation per blocker. Missing/failed/future/expired evidence tetap
  pending; bahkan sepuluh gate yang valid hanya menghasilkan
  `EXTERNAL_ACCEPTANCE_COMPLETE_ACTIVATION_REVIEW_REQUIRED` dengan seluruh
  activation, execution, demo-auto, promotion, dan live lock tetap false.
- Pre-manual entry verifier memisahkan urutan fase secara eksplisit. Tepat
  sembilan gate pra-run harus accepted dan gate hasil sepuluh lifecycle wajib
  masih `MISSING`. Hasil lengkap hanya meminta review manusia untuk penerbitan
  stage evidence terpisah; ia menolak observation hasil manual-demo yang muncul
  terlalu awal dan tidak memiliki order, activation, permit, atau issuer
  capability.
- Configured-release admission sekarang membaca tiga ZIP role-specific secara
  stabil dan hanya sekali, memverifikasi byte yang sama, lalu mengikat exact
  archive/manifest, base/configured identity, profile, Git, factory,
  configuration, dan task hash ke signed operations bundle sebelum
  pre-manual assessment. Ini menutup substitusi paket valid yang salah tanpa
  menambah provider, credential, task, process, MT5, broker, atau activation
  capability.
- Stage-readiness v2 sekarang mengikat exact hash/status/check time hasil
  pre-manual review ke readiness receipt, request, sealed validation, dan
  supervisor startup receipt v3. Runtime menolak substitusi hash dan stage
  evidence parsial sebelum `READY`; receipt juga divalidasi sebelum append agar
  kegagalan konstruksi tidak meninggalkan row durable.
- Health threshold sekarang menolak `NaN`, infinity, dan pecahan untuk field
  yang secara kontrak bertipe integer.

## Sisa menuju demo-auto soak

1. Materialisasi serta uji provider nyata untuk finalized data, trusted clock,
   news, decision IPC, reconciliation, risk facts, off-host CAS, checkpoint,
   incident latch, WORM audit, heartbeat, dan alert; kemudian hasil per-provider
   diikat melalui conformance packet dan ditandatangani owner independen.
   Untuk finalized data, materialisasikan binding/custody eksternal bagi
   reference broker-side read-only publisher dan buktikan
   latency/fork/restart/key-custody behavior pada exact Windows host;
   keberadaan implementation dan handoff lokal belum merupakan provider
   acceptance.
2. Provision tiga least-privilege Windows identities, Credential Manager,
   exact Task Scheduler definitions/ACL, offline RSA issuer, VPN/MFA, backup,
   restore, serta failure-drill evidence.
3. Gunakan candidate preparer pada masing-masing exact base ZIP yang sudah
   direproduksi, provider/task
   set, review output secara independen, lalu bangun ketiga configured release
   pada exact Windows x86-64, CPython 3.12, NTFS, MT5 terminal, account,
   server, dan symbol specification. Jalankan exact configured-release
   admission terhadap tiga ZIP yang benar-benar akan diekstrak.
4. Buktikan risiko minimum `0.01` lot XAUUSD masih berada di bawah risk cap
   menggunakan `order_calc_profit()` dan measured spread/commission/slippage.
5. Kumpulkan sembilan signed observation pra-manual, jalankan pre-manual entry
   verifier, lalu lakukan review manusia terpisah atas penerbitan short-lived
   `MANUAL_DEMO` stage evidence. Verifier tidak memberi authority.
6. Selesaikan sepuluh controlled manual-demo order lifecycles tanpa duplicate,
   orphan, unresolved `UNCERTAIN`, missing SL/TP, atau critical alert failure.
7. Setelah hasil run tersedia, terbitkan observation hasil ke-10 melalui
   authority yang independen, verifikasi full external-acceptance dossier,
   lalu review activation release DEMO_AUTO secara terpisah. Source saat ini
   tidak boleh diubah hanya untuk melewati gate.

## Sisa setelah demo-auto dimulai

- Soak minimal 30 hari, 50 broker-reconciled closed demo fills, dan 20 XAU
  closed fills dengan nol critical incident.
- Minimal 100 OOS closed trades, 50 broker-forward closed trades dan delapan
  minggu observasi per lane.
- Purged folds, PF, bootstrap lower-bound expectancy, drawdown, cost stress,
  serta 100% deterministic replay/runtime parity.
- XAUUSD live canary lebih dahulu; EURUSD, USDJPY, dan AUDUSD mengulang gate
  secara terpisah. Scaling tetap di luar v1.

Dengan demikian, proyek sudah jauh melewati fase prototipe, tetapi hasil yang
benar saat ini tetap **NOT_READY / DO NOT SHIP**. Sisa pekerjaan utama bukan
menambah strategi atau membuka lock, melainkan membuktikan implementasi pada
host dan broker nyata melalui urutan acceptance yang dapat diaudit.
