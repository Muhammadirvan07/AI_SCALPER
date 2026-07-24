# AI_SCALPER Progress — 2026-07-25

Status: **ATOMIC FIVE-ROLE BASE SUITE AND CONFIGURED ANCESTRY COMPLETE
LOCALLY / WINDOWS ACCEPTANCE PENDING / DEMO-AUTO BLOCKED / LIVE DO NOT SHIP**

## Hasil pengembangan hari ini

Fondasi packaging candidate Windows sekarang memiliki satu entrypoint
fail-closed:

```text
build_windows_base_release_suite.py
```

Entrypoint tersebut membangun tepat lima base artifact dari satu clean Git
commit/tree:

- decision service;
- gated execution service;
- external status monitor;
- read-only shadow service yang memuat finalized-M15 publisher;
- configured-release operator tooling.

Setiap ZIP dan sidecar diverifikasi ulang dari bytes staging. Satu
`BASE_RELEASE_SUITE.json` mengikat seluruh hash, ukuran, release identity,
profile, commit/tree, effect, dan safety state. Final directory hanya terbit
melalui OS-level atomic no-replace rename. Destination concurrent tidak dapat
ditimpa.

Audit juga menemukan dan memperbaiki dua cacat sebelum operator Windows
memakai tool:

1. nama allowlist status monitor semula tidak sesuai file versioned resmi;
2. effect manifest semula tidak mengakui subprocess Git yang memang dibutuhkan
   untuk pemeriksaan packaging.

Manifest sekarang transparan: `git_subprocess=true` hanya untuk packaging,
sementara network, provider, credential, task, runtime/service process, MT5,
broker, activation, permit, dan order effect tetap false.

Audit lanjutan menemukan satu celah provenance pada jalur configured release.
Admission sebelumnya dapat membuktikan tiga configured archive memakai
commit/tree yang sama, tetapi belum membuktikan bahwa tiga base archive
tersebut merupakan role exact dari satu `BASE_RELEASE_SUITE.json`. Celah itu
sekarang ditutup:

1. verifier baru memverifikasi ulang tepat lima ZIP, lima sidecar, dan manifest
   suite dari bytes;
2. configured-release builder wajib menerima root suite dan hanya menerima
   canonical archive path untuk role yang sedang dibangun;
3. configured manifest mengikat suite identity, suite-manifest hash, role,
   base archive hash, dan base sidecar hash;
4. pre-manual admission mengulang verifikasi seluruh suite dan menolak
   configured release legacy, mixed-suite, role mismatch, atau supporting-role
   tamper.

Audit activation berikutnya menemukan siklus bukti pada provider-conformance
v1: packet meminta admission hash, sedangkan admission yang tersedia baru
dapat dibuat setelah provider evidence ditandatangani. Provider-conformance v2
sekarang menghapus input masa depan tersebut, menurunkan configured-release
set dari tiga exact identity, mempertahankan byte/hash v1 historis, dan
menetapkan urutan operator non-sirkular. Packet v2 tetap deny-only dan bukan
provider acceptance.

Regression paralel kemudian menemukan satu flake pada acceptance demo-auto
dormant. Fake adapter di test menggunakan account-runtime identity tetap,
sehingga proses regression normal dan optimized yang berjalan bersamaan saling
ditolak oleh production split-brain fence. Fence production terbukti bekerja
sesuai kontrak; fixture sekarang memakai identity sintetis unik per test
instance. Dua belas acceptance process paralel seluruhnya kembali `FILLED`,
sedangkan dedicated split-brain test tetap memakai identity bersama dan tetap
membuktikan runtime kedua ditolak.

## Bukti lokal

- Spec validator: `100/100`, grade A, tanpa error/warning.
- Acceptance/adversarial suite: `19/19 PASS` normal dan optimized.
- Suite-binding/provider-v2 focused regression: `95/95 PASS` normal dan
  optimized.
- Full tracked-project regression: `1.456/1.456 PASS` normal.
- Full tracked-project regression dengan `PYTHONOPTIMIZE=2`:
  `1.456/1.456 PASS`.
- Focused activation/packaging regression normal dan optimized dijalankan
  bersamaan: `155/155 PASS` pada masing-masing proses.
- Dormant demo-auto acceptance dijalankan dalam 12 proses paralel:
  `12/12 FILLED`, tanpa `ACCOUNT_RUNTIME_FENCE_UNAVAILABLE`.
- Dua independent clean-repository build menggunakan kelima builder nyata:
  seluruh 5 ZIP, 5 sidecar, dan suite manifest byte-identical.
- Windows dependency lock, install manifest, dan CycloneDX SBOM: PASS.
- Decision, execution, dan status-monitor port validator: PASS dengan
  `production_execution_ready=false`.
- Secret/private-key, unsafe eval/deserialization, `shell=True`, network,
  credential, MT5, dan order-capability scan pada surface baru: tidak ada
  finding.

Direktori dashboard yang belum masuk fase integrasi tidak dibaca, dimodifikasi,
atau dimasukkan ke test/release.

## Safety state

```text
live_allowed = false
safe_to_demo_auto_order = false
max_lot = 0.01
promotion_eligible = false
```

Execution ZIP tetap memiliki `order_capability=GATED_PRESENT` secara dormant.
Suite boundary, empat role lain, dan seluruh activation/promotion state tetap
tertutup.

## Posisi roadmap

Software foundation dan packaging lokal sudah cukup untuk membuat candidate
baru. Demo-auto soak belum boleh dimulai hanya karena test lokal hijau.
Urutan berikutnya:

1. commit/push exact source ini tanpa direktori dashboard;
2. clean pull pada Windows dan build atomic five-role suite;
3. verifikasi SHA-256 serta suite manifest;
4. buat tiga suite-bound configured service release;
5. buat operations plan/review lalu provider-conformance v2 dan independent
   validation receipt;
6. kumpulkan sembilan signed pre-manual observations lalu luluskan exact
   configured-release admission;
7. jalankan 10 controlled manual-demo lifecycles dengan review manusia;
8. setelah hasil manual-demo diterima, lakukan activation review terpisah;
9. baru mulai demo-auto soak 30 hari, 50 broker-reconciled closed fills, dan
   minimal 20 XAUUSD closed fills.

Live trading tetap tahap sesudah soak, statistical lane gates, failure drills,
dan approval manual. Frontend dashboard baru akan dihubungkan ke read-only
status/receipt surface setelah demo soak berfungsi; dashboard tidak akan
mendapat credential, permit, arm, atau order authority.
