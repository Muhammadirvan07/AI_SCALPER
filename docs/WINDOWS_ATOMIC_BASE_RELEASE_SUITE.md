# Windows Atomic Base-Release Suite v1

Status: **BUILD EVIDENCE ONLY / ORDER DISABLED / PRODUCTION NOT READY**

Tool ini membangun satu direktori base release yang berisi lima role exact dari
satu clean Git commit dan tree:

1. `decision-base-v1.zip`
2. `execution-base-v1.zip`
3. `status-monitor-base-v1.zip`
4. `read-only-shadow-base-v1.zip`
5. `configured-release-tooling-v1.zip`

Setiap ZIP memiliki canonical sidecar manifest. Satu manifest tambahan,
`BASE_RELEASE_SUITE.json`, mengikat SHA-256, ukuran, release identity, profile,
Git commit/tree, safety lock, dan status production setiap role.

Suite ini mencegah operator melewatkan read-only shadow, mencampur ZIP dari
commit berbeda, atau menerbitkan direktori release parsial. Tool hanya
menjalankan executable Git lokal untuk pemeriksaan packaging. Tool tidak
mengimpor provider, membaca credential, memasang task, menjalankan
runtime/service process, menginisialisasi MT5, mengakses broker, menerbitkan
permit, atau membuka order.

## Prasyarat

- Jalankan dari exact clean checkout; perubahan tracked, staged, atau untracked
  membuat build ditolak.
- Gunakan Python 3.12.
- Output parent harus sudah ada, berada di luar repository, bukan symlink atau
  junction, dan final output root belum boleh ada.
- Jangan memasukkan runtime state, credential, provider overlay, broker
  evidence, atau dashboard ke checkout release.

## Build pada Windows

Gunakan satu command berikut sebagai pengganti lima build terpisah:

```powershell
cd C:\AI_SCALPER
git status --short
git log -1 --oneline
.\.venv\Scripts\Activate.ps1

$commit = (git rev-parse --short=12 HEAD).Trim()
$releaseParent = "C:\AI_SCALPER_RELEASES\$commit"
New-Item -ItemType Directory -Force $releaseParent | Out-Null

$suiteRoot = "$releaseParent\base-release-suite-v1"

python -B .\build_windows_base_release_suite.py `
  --output-root $suiteRoot
```

Jika `$suiteRoot` sudah ada, gunakan directory baru. Jangan menghapus atau
menimpa release yang sudah dipakai sebagai evidence.

## Verifikasi operator

Gunakan tiga nilai yang dipin dari build receipt atau channel audit
independen. Jangan menurunkan expected value dari `BASE_RELEASE_SUITE.json`
yang sedang diverifikasi.

```powershell
$expectedSuiteIdentity = "<PINNED_SUITE_IDENTITY_SHA256>"
$expectedCommit = "<PINNED_FULL_GIT_COMMIT>"
$expectedTree = "<PINNED_FULL_GIT_TREE>"

python -I -S -B .\verify_windows_base_release_suite.py `
  --suite-root $suiteRoot `
  --expected-suite-identity-sha256 $expectedSuiteIdentity `
  --expected-git-commit $expectedCommit `
  --expected-git-tree $expectedTree

if ($LASTEXITCODE -ne 0) {
  throw "Atomic base-release suite verification failed."
}
```

CLI yang sama tersedia di `configured-release-tooling-v1.zip`. Ia
stable-read dan merekonstruksi manifest suite, lima archive, lima sidecar,
embedded manifest, source inventory, ZIP determinism, safety state, serta
source identity. Mismatch pin, tamper, symlink/reparse, file ekstra/hilang,
atau non-canonical bytes ditolak dengan
`BASE_RELEASE_SUITE_VERIFICATION_REJECTED: <STABLE_REASON>`.

Expected safety state:

```text
live_allowed = false
safe_to_demo_auto_order = false
max_lot = 0.01
promotion_eligible = false
production_execution_ready = false pada seluruh role
```

Role execution sengaja memiliki `order_capability=GATED_PRESENT`, karena kode
executor dormant berada di release tersebut. Empat role lain wajib
`DISABLED`. Keberadaan primitive yang gated bukan izin menjalankan order.

## Makna hasil

Build sukses hanya membuktikan lima base artifact:

- berasal dari satu exact source identity;
- lengkap dan deterministik;
- mempertahankan safety lock;
- dipublikasikan atomik setelah validasi.

Build ini belum membuktikan provider conformance, configured release,
credential custody, Task Scheduler/ACL, MT5 account binding, external
acceptance, manual-demo lifecycle, demo-auto soak, atau live readiness.
Urutan berikutnya tetap:

`atomic base suite → suite-bound configured releases → operations plan/review
bundle → provider-conformance v2 → independent validation receipt → signed
pre-manual observations → pre-manual admission → 10 controlled manual-demo
lifecycles → demo-auto activation review → 30-day/50-fill/20-XAU soak`.

Configured-release builder dan pre-manual admission sekarang wajib menerima
exact `$suiteRoot` ini. Tiga ZIP yang dibangun terpisah tidak dapat menggantikan
membership suite walaupun commit/tree-nya sama.

Artefak tiga-role atau empat-role lama tetap dapat disimpan sebagai historical
evidence untuk commit asalnya, tetapi tidak boleh dipakai sebagai candidate
baru setelah read-only finalized-M15 publisher menjadi bagian closure.
