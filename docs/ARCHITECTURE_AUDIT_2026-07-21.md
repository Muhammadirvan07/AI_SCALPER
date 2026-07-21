# Architecture and Software Audit — 2026-07-21

Status: **LOCAL SOFTWARE FOUNDATION COMPLETED / DO NOT SHIP / NOT_READY**

Audit memakai boundary modular-monolith/ports-adapters, fail-closed review,
dependency audit, dan ship-gate acceptance review. Diagnostic shadow yang
sedang berjalan tidak diubah dan tidak dihitung sebagai promotion evidence.

Verifikasi lokal setelah penutupan fondasi: `558/558` unit/integration tests lulus,
project source berhasil di-compile, `pip check` tidak menemukan dependency
rusak, Windows CPython 3.12 lock/SBOM/install manifest valid, release import
closure lulus, dan diff whitespace bersih.

## Temuan yang ditutup

- Writer discovery/calendar/plan/preflight yang terduplikasi disatukan menjadi
  create-exclusive durable JSON writer. Partial file, overwrite, symlink, dan
  non-canonical JSON ditolak.
- Durable sanitized MT5 preflight receipt ditambahkan tanpa login, nama,
  balance, equity, atau credential.
- Evidence collector tidak lagi hardcoded ke satu XM contract: exact contract,
  store, fence, head, export result, dan build identity harus cocok.
- Broker-neutral profile, explicit weekly M15 schedule, special-hours closure,
  plan, calendar, contract registration, dan Windows runner ditambahkan untuk
  FBS/future brokers.
- Absolute/outside-repository/traversal/symlink build config tidak dapat masuk
  ke evidence identity.
- Circular gate diperbaiki: discovery dapat diselesaikan sebelum contract
  registration di-enable; collector tetap tidak dapat berjalan sebelum enable.
- Windows release allowlist/import closure diperbarui untuk pipeline baru.
- Status FBS diselaraskan dengan fakta operator: binding/preflight observed dan
  diagnostic shadow active, sementara full discovery/evidence/legal gate tetap
  false.
- Periodic reconciliation supervisor kini memiliki durable SQLite WAL lease,
  fencing, startup reconciliation, hash-chained cycle receipt, serta
  fail-closed kill-switch latch untuk exception, status asing, corruption, dan
  critical broker state.
- Independent promotion issuer menghitung ulang raw ledger, lima fold, seeded
  bootstrap lower bound, drawdown, cost stress, parity corpus, dan verifier-only
  validation binding. Caller tidak dapat membentuk status receipt terverifikasi
  secara langsung.
- Minimal Windows read-only shadow service profile kini terpisah dari operator
  tooling, memakai exact 25-file allowlist dan tetap menolak executor, setup,
  credential, runtime artifact, serta primitive order.
- Clean-checkout Windows reproducibility comparison dan signed HMAC receipt
  tersedia untuk exact commit/tree/archive/manifest/release hashes.
- Provider-neutral signed off-host envelope, durable idempotent outbox, remote
  acknowledgement verification, tamper detection, dan create-exclusive
  directory-drop adapter tersedia. Adapter lokal tidak diklaim sebagai WORM.

## Kekurangan yang bukan bug lokal dan masih terbuka

- FBS tercantum pada official Japan FSA unregistered-operator warning dan kini
  project-blocked untuk evidence/order/live selama operasi dari Jepang. FINEX
  terverifikasi terdaftar Bappebti untuk future-Indonesia preparation, tetapi
  personal/account eligibility setelah kembali tetap membutuhkan review.
- Exact official session/holiday attestation dan signed discovery v3 belum ada.
- Minimal 20 sesi benchmark, delapan minggu/50 forward trades, dan 100 OOS
  trades per lane belum tersedia.
- WORM/object-lock export, off-host heartbeat/alert, VPS hardening, restore
  drill, clock/disk/network failure drill, dan actual vulnerability receipt
  memerlukan Windows/external infrastructure.
- Sepuluh manual-demo order, 30-day demo-auto soak, reconciliation soak, dan
  XAU live canary belum boleh dimulai.

## Batas klaim 100% fondasi

Empat gap software lokal dalam audit ini sudah ditutup. Arti `100% fondasi`
adalah kontrak, komponen, port/adaptor netral, persistence, fail-closed behavior,
acceptance tests, dan dokumentasi tersedia di repository. Ini bukan `100% live
readiness`: production composition pada exact Windows VPS, provider WORM,
independent key custody, broker evidence, statistical sample, failure drill,
demo soak, dan approval manusia tetap harus dibuktikan secara eksternal.

Tidak ada penyelesaian fondasi yang membuka lock. Hingga acceptance evidence dan
approval manual tersedia, status final tetap `DO NOT SHIP / NOT_READY`.
