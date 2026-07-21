# Architecture and Software Audit — 2026-07-21

Status: **LOCAL HARDENING COMPLETED / DO NOT SHIP / NOT_READY**

Audit memakai boundary modular-monolith/ports-adapters, fail-closed review,
dependency audit, dan ship-gate acceptance review. Diagnostic shadow yang
sedang berjalan tidak diubah dan tidak dihitung sebagai promotion evidence.

Verifikasi lokal setelah hardening: `529/529` unit/integration tests lulus,
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

## Kekurangan yang bukan bug lokal dan masih terbuka

- FBS regulatory/operating eligibility belum diverifikasi independen.
- Exact official session/holiday attestation dan signed discovery v3 belum ada.
- Minimal 20 sesi benchmark, delapan minggu/50 forward trades, dan 100 OOS
  trades per lane belum tersedia.
- WORM/object-lock export, off-host heartbeat/alert, VPS hardening, restore
  drill, clock/disk/network failure drill, dan actual vulnerability receipt
  memerlukan Windows/external infrastructure.
- Sepuluh manual-demo order, 30-day demo-auto soak, reconciliation soak, dan
  XAU live canary belum boleh dimulai.

## Kekurangan software fase berikutnya

- Production reconciliation supervisor/watchdog masih one-shot/component
  foundation; periodic lifecycle harus dibangun dan diuji sebelum demo-auto.
- Promotion evidence issuer independen yang menghitung ulang seluruh ledger,
  bootstrap confidence bound, folds, cost stress, parity corpus, dan evidence
  store receipt belum tersedia.
- Deployment-tooling bundle sudah deterministic, tetapi minimal read-only
  service-runtime allowlist dan clean-checkout Windows reproducibility receipt
  belum dibuat.
- Off-host storage/monitor adapters serta signed delivery acknowledgement
  belum diimplementasikan karena provider dan credential custody belum dipilih.

Empat item software fase berikutnya tidak boleh diselesaikan dengan membuka
lock. Hingga acceptance evidence dan approval manual tersedia, status final
tetap `DO NOT SHIP`.
