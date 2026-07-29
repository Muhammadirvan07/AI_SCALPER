# AI_SCALPER Project Progress — 2026-07-30

## Outcome

Windows operator bridge untuk konsumsi satu-kali authorization LIVE-canary kini
lengkap secara source lokal dan tetap deny-only. Workflow membentuk exact
target-host replay profile, membuat genesis registry/checkpoint, memverifikasi
ulang seluruh evidence dan authorization, mengonsumsi authorization secara
atomik, menerbitkan successor checkpoint, serta mendukung independent verify
dan deterministic recovery setelah post-commit publication failure.

Audit TDD menemukan lalu menutup dua defect yang tidak terlihat pada happy
path: registry path dengan komponen `..` sebelumnya dinormalisasi dan diterima,
serta dua authorization berbeda dapat melewati predecessor yang sama sebelum
SQLite lock sehingga event kedua baru ditolak setelah commit. Path traversal
kini berhenti sebelum credential access. Exact signed predecessor kini dicek
lagi di dalam transaksi `BEGIN IMMEDIATE` sebelum `INSERT`, sehingga stale
consumer tidak dapat meninggalkan orphan event.

```text
LOCAL_SOURCE_GATE = PASS
LIVE_CANARY_ACTIVATION_CONSUMPTION_OPERATOR = PASS_LOCALLY_DENY_ONLY
ATOMIC_STALE_PREDECESSOR_GUARD = PASS
WINDOWS_OPERATOR_RELEASE_ISOLATION = PASS_FOCUSED
REAL_30_DAY_50_FILL_20_XAU_COHORT = ABSENT
REAL_LIVE_PROMOTION_AND_NINE_GATES = ABSENT
REAL_THREE_PERSON_APPROVAL_CEREMONY = NOT_PERFORMED
TARGET_WINDOWS_REPLAY_REGISTRY = NOT_INITIALIZED
CENTRAL_LIVE_UNLOCK = FALSE
BROKER_MUTATION = NOT_PERFORMED
LIVE_TRADING = DO_NOT_SHIP
```

## V6.3 post-run acceptance hardening

Audit adversarial lanjutan terhadap toolkit bukti pemicu otomatis Phillip
Commodity menemukan dan menutup empat kelas ambiguity/race:

- event 107 sekarang wajib memiliki EventRecordID lebih rendah daripada event
  start 100; task `Ready` wajib memiliki completion 102 setelah start;
- task V6.3/V4/V5 masing-masing harus resolve tepat satu kali pada root path
  Task Scheduler, sehingga same-name task di folder lain gagal tertutup;
- semua JSON evidence/manifest/checkpoint menolak duplicate object key dan
  semua file evidence dibaca melalui satu stable regular-file handle;
- kegagalan verifikasi pascapublikasi membersihkan hanya exact output identity
  milik invocation, tanpa menghapus replacement milik proses lain.

Focused gate lulus 41/41 normal dan 41/41 optimized. Full serial repository
gate lulus 2.087 test normal dengan tiga platform skip serta 2.087 test di
bawah `-O` dengan empat belas platform/optimized skip. Paket clean-commit belum
dibangun ulang pada saat catatan ini; scheduled proof Windows dan custody WORM
aktual tetap belum ada.

## Implemented

- Canonical replay profile mengikat binding, trust policy, registry ID,
  absolute-path hash, registry authority, dan policy-pinned checkpoint
  authority.
- Registry/checkpoint keys hanya diterima dari injected provider di library
  dan Windows Credential Manager di CLI; material minimal 256 bit, fingerprint
  constant-time, dan seluruh activation-authority reuse ditolak.
- Genesis initialization memvalidasi kedua credential sebelum membuat SQLite,
  memverifikasi exact DDL/triggers/integrity, dan membuat signed zero-event
  checkpoint.
- Consumption memerlukan current signed predecessor, memverifikasi ulang
  request, three approvals, deployment authorization, cohort, promotion,
  eligibility, nine gates, serta original evidence sebelum mutation.
- Atomic predecessor guard mengulang exact current-head comparison di dalam
  `BEGIN IMMEDIATE`, menutup interleaving dua authorization berbeda.
- Verification dan recovery mengambil historical consumed time dari exact
  HMAC-authenticated event, menolak future event, tetap bekerja setelah
  authorization expiry, dan tidak menambah event.
- Output preflight mendahului Credential Manager/SQLite, final publication
  create-exclusive dan fsync-backed, output race mempertahankan byte pemenang,
  serta recovery memakai destination baru.
- CLI hanya memiliki `prepare-profile`, `initialize`, `consume`, `verify`, dan
  `recover`; semua success/failure menyatakan live/activation false,
  `order_capability=DISABLED`, dan broker mutation tidak dilakukan.
- Modul/CLI baru hanya masuk `WINDOWS_SHADOW_DEPLOYMENT_TOOLING_V1` dan tidak
  masuk Decision, Execution, Status Monitor, read-only shadow, atau configured
  service releases.

## Verified so far

- Consumption operator spec: 100/100, Grade A, 0 error, 0 warning.
- Focused activation/consumption/release cluster: 43 tests passed in normal
  mode; 42 passed plus one intentional optimized nested-run skip under `-O`.
- Full serial repository regression: 2,081 tests passed in normal mode with
  three platform skips; 2,081 passed under `-O` with fourteen intentional
  platform/optimized skips.
- Windows dependency lock, install manifest, dependency SBOM, and pinned
  MetaTrader5 wheel identity: passed.
- Python compilation, scoped whitespace, JSON allowlist closure, constant-time
  authority comparison, output-race recovery, and no-effect AST checks passed.
- A deliberately parallel full-suite run exposed shared test-resource
  interference in three legacy executor tests; all three passed in isolated
  normal/optimized reruns and both authoritative serial full suites passed.

## Remaining external work

Source completion is not production evidence. Windows still requires authentic
cohort/promotion/gate/approval/authorization inputs, independently provisioned
Credential Manager authorities, exact target-host registry initialization,
off-host checkpoint/WORM/CAS custody, provider-bound prebootstrap acceptance,
central policy ceremony, bounded first canary, broker acknowledgement,
reconciliation, and rollback evidence.

Deterministic clean-commit Windows artifacts and hashes are recorded only after
this source milestone is committed and rebuilt twice from a clean worktree.
