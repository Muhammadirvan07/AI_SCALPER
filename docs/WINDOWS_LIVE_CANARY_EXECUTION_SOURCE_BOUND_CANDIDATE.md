# Windows LIVE Canary Execution Source-Bound Candidate v1

Status: **IMPLEMENTED LOCALLY / DENY-ONLY / TARGET-WINDOWS EVIDENCE REQUIRED**

Boundary ini mengemas dua bukti yang sebelumnya terpisah menjadi satu ZIP
deterministik:

- exact Windows Execution source-bound candidate v1 yang sudah diverifikasi;
  dan
- seluruh 15 file exact Windows LIVE Execution configured candidate.

Verifier membangun ulang kedua input dari byte yang berada di dalam ZIP,
menjalankan validator authoritative, lalu membuktikan bahwa source,
bootstrap, atomic suite, Execution role, Git commit/tree, base release, dan
configured-release identity semuanya konsisten. Hasil sukses hanya menutup
source ancestry; ia tidak menerima provider atau mengizinkan runtime/order.

```text
provider_accepted=false
production_execution_ready=false
promotion_eligible=false
order_capability=DISABLED
safe_to_demo_auto_order=false
live_allowed=false
max_lot=0.01
```

## Inventory tertutup

ZIP luar berisi tepat 17 member:

```text
WINDOWS_LIVE_CANARY_EXECUTION_SOURCE_BOUND_CANDIDATE.json
source/windows-execution-source-bound-candidate-v1.zip
candidate/LIVE_EXECUTION_CONFIGURED_CANDIDATE.json
candidate/configured-overlay.json
candidate/configured-overlay/config/windows_factory_manifest.json
candidate/configured-overlay/config/windows_service_config.json
candidate/configured-overlay/configured_providers/__init__.py
candidate/configured-overlay/configured_providers/execution_provider.py
candidate/configured-overlay/reviewed_windows_factory.py
candidate/live-execution-configured-v1.zip
candidate/live-execution-configured-v1.zip.manifest.json
candidate/live-execution-factory-template.json
candidate/provider-pack/config/windows_service_config.json
candidate/provider-pack/configured_providers/__init__.py
candidate/provider-pack/configured_providers/execution_provider.py
candidate/provider-pack/reviewed_windows_factory.py
candidate/reviewed-task-definition.xml
```

Member kurang/tambahan, duplicate atau case-fold collision, path traversal,
metadata ZIP yang berubah, data descriptor, trailing bytes, symlink/reparse,
oversize, atau JSON noncanonical selalu ditolak.

## Sepuluh pin independen

Validator tidak mempercayai identity yang hanya dibaca dari artefak. Operator
wajib memasok sepuluh pin dari receipt atau channel review terpisah:

1. SHA-256 ZIP LIVE source-bound yang baru;
2. SHA-256 ZIP DEMO source-bound yang tertanam;
3. SHA-256 production-config source ZIP;
4. SHA-256 champion archive;
5. SHA-256 model artifact;
6. SHA-256 training snapshot;
7. SHA-256 champion config;
8. full 40-hex Git commit;
9. full 40-hex Git tree; dan
10. SHA-256 atomic-suite identity.

Semua SHA-256 harus lowercase 64-hex non-zero. Git commit/tree harus full
lowercase 40-hex. Pin outer LIVE ZIP untuk validasi wajib berasal dari output
atau receipt yang ditinjau independen, bukan dari manifest ZIP yang sama.

## Prepare pada Windows

Jalankan dari exact extracted
`WINDOWS_CONFIGURED_RELEASE_OPERATOR_TOOLING_V1` milik commit/suite yang sama.
Gunakan output baru di luar repository dan di luar seluruh input root.

```powershell
$suiteRoot = "C:\AI_SCALPER_RELEASES\<COMMIT>\base-release-suite-v1"
$executionBase = "$suiteRoot\execution-base-v1.zip"
$demoBoundZip = "C:\AI_SCALPER_PRIVATE\xm-demo-execution-source-bound-v1.zip"
$liveCandidateRoot = "C:\AI_SCALPER_PRIVATE\xm-live-execution-configured-v1"
$liveBoundZip = "C:\AI_SCALPER_PRIVATE\xm-live-execution-source-bound-v1.zip"

python -I -S -B `
  .\prepare_windows_live_canary_execution_source_bound_candidate.py `
  --base-suite-root $suiteRoot `
  --execution-base-release $executionBase `
  --demo-source-bound-archive $demoBoundZip `
  --live-configured-candidate-root $liveCandidateRoot `
  --expected-source-bound-archive-sha256 <DEMO_BOUND_ZIP_SHA256> `
  --expected-source-archive-sha256 <SOURCE_ZIP_SHA256> `
  --expected-champion-archive-sha256 <CHAMPION_ZIP_SHA256> `
  --expected-model-artifact-sha256 <MODEL_SHA256> `
  --expected-training-snapshot-sha256 <SNAPSHOT_SHA256> `
  --expected-config-sha256 <CHAMPION_CONFIG_SHA256> `
  --expected-git-commit <FULL_GIT_COMMIT> `
  --expected-git-tree <FULL_GIT_TREE> `
  --expected-suite-identity-sha256 <SUITE_IDENTITY_SHA256> `
  --output $liveBoundZip

if ($LASTEXITCODE -ne 0) {
  throw "LIVE source-bound preparation gagal; safety lock tetap aktif."
}
```

Sukses wajib mencetak
`WINDOWS_LIVE_CANARY_EXECUTION_SOURCE_BOUND_CANDIDATE_READY`. Simpan
`Archive SHA-256` melalui channel review terpisah untuk langkah validasi.

## Verifikasi independen

```powershell
python -I -S -B `
  .\validate_windows_live_canary_execution_source_bound_candidate.py `
  --archive $liveBoundZip `
  --base-suite-root $suiteRoot `
  --execution-base-release $executionBase `
  --expected-live-bound-archive-sha256 <LIVE_BOUND_ZIP_SHA256> `
  --expected-source-bound-archive-sha256 <DEMO_BOUND_ZIP_SHA256> `
  --expected-source-archive-sha256 <SOURCE_ZIP_SHA256> `
  --expected-champion-archive-sha256 <CHAMPION_ZIP_SHA256> `
  --expected-model-artifact-sha256 <MODEL_SHA256> `
  --expected-training-snapshot-sha256 <SNAPSHOT_SHA256> `
  --expected-config-sha256 <CHAMPION_CONFIG_SHA256> `
  --expected-git-commit <FULL_GIT_COMMIT> `
  --expected-git-tree <FULL_GIT_TREE> `
  --expected-suite-identity-sha256 <SUITE_IDENTITY_SHA256>

if ($LASTEXITCODE -ne 0) {
  throw "LIVE source-bound validation gagal; jangan lanjut."
}
```

Sukses wajib mencetak
`WINDOWS_LIVE_CANARY_EXECUTION_SOURCE_BOUND_CANDIDATE_VERIFIED`, 49 provider,
12 credential reference, dan seluruh capability tetap false/`DISABLED`.

## Efek dan batas authority

Prepare/verify hanya melakukan temporary extraction untuk verifikasi. Ia
tidak mengimpor atau mematerialisasi generated provider, membaca credential
atau private key, membuka SQLite production, mengakses network, memasang atau
menjalankan task/service, menginisialisasi MT5, menerbitkan permit/signature,
mengubah central policy, menyentuh broker, atau mengirim order.

Tool ini hanya dibundel di configured-release operator tooling dan dilarang
dari Decision, Execution, Status Monitor, serta Read-Only Shadow service
release.

## Langkah sesudahnya

Artefak target-Windows yang lulus menjadi input evidence untuk external LIVE
provider conformance dan prebootstrap review. Sebelum live canary, proyek
masih memerlukan real independently eligible selected-broker demo-auto soak
(untuk operating jurisdiction JP saat ini: `phillip-commodity`), concrete
provider acceptance, launcher/task/ACL approval, WORM/CAS custody, promotion
dan gate receipts, central unlock ceremony, serta per-order fresh evidence.
XM tetap diagnostic/paper-only selama yurisdiksi operasi adalah JP. Karena
bukti itu belum ada, status tetap `LIVE_TRADING = DO_NOT_SHIP`.

Kontrak normatif berada di
`specs/windows_live_canary_execution_source_bound_candidate_v1.md`.
