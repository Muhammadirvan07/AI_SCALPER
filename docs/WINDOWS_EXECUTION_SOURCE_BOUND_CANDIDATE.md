# Windows Execution Source-Bound Candidate v1

Status: **IMPLEMENTED LOCALLY / DENY-ONLY / EXTERNAL WINDOWS EVIDENCE REQUIRED**

Artefak ini menutup gap antara tiga bukti yang sebelumnya terpisah:

- production-config source tujuh-pin;
- `production_config_sha256` di Execution provider pack; dan
- `bootstrap_binding_sha256` di configured Execution candidate.

Builder mengemas exact source ZIP dan seluruh 15 file configured candidate ke
satu ZIP deterministik. Verifier kemudian membangun ulang candidate di
direktori sementara privat dan menjalankan validator authoritative terhadap
atomic base suite serta canonical Execution base release yang dipasok secara
eksternal.

Keberhasilan tetap berarti:

```text
provider_accepted=false
production_execution_ready=false
promotion_eligible=false
order_capability=DISABLED
safe_to_demo_auto_order=false
live_allowed=false
max_lot=0.01
```

Tidak ada provider import/materialization, credential/private-key read,
production SQLite open, MT5 initialization, network request, task/service
start, permit issuance, atau broker mutation. Temporary extraction hanya
digunakan untuk verifikasi dan selalu dibersihkan.

## Inventory tertutup

ZIP luar hanya boleh berisi:

```text
WINDOWS_EXECUTION_SOURCE_BOUND_CANDIDATE.json
source/windows-execution-production-config-source-v1.zip
candidate/EXECUTION_CONFIGURED_CANDIDATE.json
candidate/configured-overlay.json
candidate/configured-overlay/config/windows_factory_manifest.json
candidate/configured-overlay/config/windows_service_config.json
candidate/configured-overlay/configured_providers/__init__.py
candidate/configured-overlay/configured_providers/execution_provider.py
candidate/configured-overlay/reviewed_windows_factory.py
candidate/execution-configured-v1.zip
candidate/execution-configured-v1.zip.manifest.json
candidate/execution-factory-template.json
candidate/provider-pack/config/windows_service_config.json
candidate/provider-pack/configured_providers/__init__.py
candidate/provider-pack/configured_providers/execution_provider.py
candidate/provider-pack/reviewed_windows_factory.py
candidate/reviewed-task-definition.xml
```

Manifest canonical mengikat size/hash setiap payload, identitas source dan
champion, identitas configured candidate/provider/configured release, atomic
suite, Execution role, full Git commit/tree, safety, dan effect claims. Safety
serta effect object dibandingkan sebagai byte JSON canonical agar perbedaan
tipe scalar seperti boolean `false` dan integer `0` selalu ditolak.

## Sembilan pin independen

Verifier tidak mempercayai nilai yang hanya dibaca dari ZIP. Operator harus
memasok sembilan pin dari channel review independen:

1. outer source-bound archive SHA-256;
2. source archive SHA-256;
3. champion archive SHA-256;
4. model artifact SHA-256;
5. training snapshot SHA-256;
6. champion config SHA-256;
7. full Git commit;
8. full Git tree; dan
9. atomic-suite identity SHA-256.

Semua nilai harus lowercase, full-length, dan non-zero. Hash outer source ZIP
harus sama dengan provider `production_config_sha256`; safe binding dari
source report harus sama dengan candidate `bootstrap_binding_sha256`.

## Persiapan pada Windows

Jalankan dari exact configured-release operator tooling dengan CPython 3.12
isolated. Seluruh output harus baru dan berada di luar repository, suite, dan
candidate root.

```powershell
$suiteRoot = "C:\AI_SCALPER_RELEASES\<COMMIT>\base-release-suite-v1"
$executionBase = "$suiteRoot\execution-base-v1.zip"
$sourceZip = "C:\AI_SCALPER_PRIVATE\execution-production-source-v1.zip"
$candidateRoot = "C:\AI_SCALPER_PRIVATE\execution-configured-candidate-v1"
$boundZip = "C:\AI_SCALPER_PRIVATE\execution-source-bound-candidate-v1.zip"

python -I -S -B .\prepare_windows_execution_source_bound_candidate.py `
  --base-suite-root $suiteRoot `
  --execution-base-release $executionBase `
  --production-config-source-archive $sourceZip `
  --configured-candidate-root $candidateRoot `
  --expected-source-archive-sha256 <SOURCE_ZIP_SHA256> `
  --expected-champion-archive-sha256 <CHAMPION_ZIP_SHA256> `
  --expected-model-artifact-sha256 <MODEL_SHA256> `
  --expected-training-snapshot-sha256 <SNAPSHOT_SHA256> `
  --expected-config-sha256 <CHAMPION_CONFIG_SHA256> `
  --expected-git-commit <FULL_GIT_COMMIT> `
  --expected-git-tree <FULL_GIT_TREE> `
  --expected-suite-identity-sha256 <SUITE_IDENTITY_SHA256> `
  --output $boundZip
```

Builder memverifikasi seluruh input, membangun byte deterministik,
self-verify, lalu memublikasikan output secara create-exclusive. Existing
file, symlink/reparse, input drift, output overlap, atau mismatch menolak tanpa
overwrite.

## Verifikasi independen

Pin `--expected-bound-archive-sha256` harus diperoleh dari receipt/channel
review, bukan hanya disalin dari ZIP yang sedang diuji.

```powershell
python -I -S -B .\verify_windows_execution_source_bound_candidate.py `
  --archive $boundZip `
  --base-suite-root $suiteRoot `
  --execution-base-release $executionBase `
  --expected-bound-archive-sha256 <BOUND_ZIP_SHA256> `
  --expected-source-archive-sha256 <SOURCE_ZIP_SHA256> `
  --expected-champion-archive-sha256 <CHAMPION_ZIP_SHA256> `
  --expected-model-artifact-sha256 <MODEL_SHA256> `
  --expected-training-snapshot-sha256 <SNAPSHOT_SHA256> `
  --expected-config-sha256 <CHAMPION_CONFIG_SHA256> `
  --expected-git-commit <FULL_GIT_COMMIT> `
  --expected-git-tree <FULL_GIT_TREE> `
  --expected-suite-identity-sha256 <SUITE_IDENTITY_SHA256>
```

Sukses wajib menampilkan
`WINDOWS_EXECUTION_SOURCE_BOUND_CANDIDATE_VERIFIED` dan seluruh lock tetap
false/`DISABLED`.

## Posisi dalam alur

Provider pack atau configured-candidate v1 yang lulus sendiri tetap
**unbound** dan tidak boleh dipakai sebagai source-bound conformance evidence.
Artefak ini menjadi input Execution untuk provider-conformance v3 yang masih
merupakan increment terpisah. External provider runtime, Windows custody,
launcher attestation, operations review, signed observations, manual demo,
demo-auto soak, dan live approval tetap wajib.

Kontrak normatif berada di
`specs/windows_execution_source_bound_candidate_v1.md`.
