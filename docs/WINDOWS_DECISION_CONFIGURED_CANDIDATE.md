# Windows Decision Configured Candidate v1

## Status

```text
SOURCE_IMPLEMENTATION = COMPLETE_LOCALLY
WINDOWS_EXACT_ASSEMBLY = PENDING
EXTERNAL_PROVIDER_CONFORMANCE = REQUIRED
PROVIDER_ACCEPTED = false
ORDER_CAPABILITY = DISABLED
PRODUCTION_EXECUTION_READY = false
```

Boundary ini menyatukan atomic five-role base suite, exact Decision base
release, reviewed four-file Decision provider pack, dan reviewed Task
Scheduler XML menjadi satu candidate yang tertutup. Ia tidak menerima
provider, tidak mengimpor factory, tidak membaca credential, tidak memasang
task, tidak menjalankan service, tidak menginisialisasi MT5, dan tidak
menyentuh broker.

## Mengapa assembler khusus diperlukan

Generic configured-overlay preparer menambahkan
`config/windows_factory_manifest.json`. Jika preparer dijalankan langsung pada
root provider pack, evidence empat file tersebut berubah dan validator pack
akan menolaknya dengan benar.

Assembler baru mempertahankan dua domain:

```text
provider-pack/       exact evidence copy, tetap empat file
configured-overlay/  working copy, empat file + factory manifest
```

`bootstrap_binding_sha256` diturunkan dari exact Decision producer binding
dalam runtime config. Operator tidak dapat memasukkan atau menggantinya.
Decision factory template tujuh-provider juga diturunkan dari exact configured
release identity serta hash factory/config, bukan ditranskripsi manual.

## Prasyarat

1. Gunakan clean Windows checkout dari exact reviewed commit.
2. Bangun dan verifikasi atomic five-role base suite.
3. Generate dan validate exact Decision provider pack.
4. Siapkan satu Task Scheduler XML yang sudah direview, secret-free, dan belum
   dipasang.
5. Gunakan tooling dari
   `WINDOWS_CONFIGURED_RELEASE_OPERATOR_TOOLING_V1` pada commit yang sama.

## Assembly

```powershell
$commit = "<exact-commit>"
$suite = "C:\AI_SCALPER_RELEASES\$commit\base-release-suite-v1"
$decisionBase = "$suite\decision-base-v1.zip"
$providerPack = "C:\AI_SCALPER_PRIVATE\decision-provider-overlay-v1"
$task = "C:\AI_SCALPER_PRIVATE\decision-service-task.xml"
$candidate = "C:\AI_SCALPER_PRIVATE\decision-configured-candidate-v1"

python -I -S -B .\assemble_windows_decision_configured_candidate.py `
  --base-suite-root $suite `
  --decision-base-release $decisionBase `
  --provider-pack-root $providerPack `
  --task-definition $task `
  --candidate-id decision-demo-auto-window-01 `
  --output-root $candidate
```

Output sukses wajib tetap menyatakan:

```text
Status: EXTERNAL_PROVIDER_CONFORMANCE_REQUIRED
Provider acceptance: REQUIRED_EXTERNAL
Order capability: DISABLED
Production execution ready: false
Live allowed: false
Safe to demo auto order: false
Max lot: 0.01
```

## Validasi independen

```powershell
python -I -S -B .\validate_windows_decision_configured_candidate.py `
  --base-suite-root $suite `
  --decision-base-release $decisionBase `
  --candidate-root $candidate
```

Validator mengulang:

- verifikasi seluruh five-role suite dan exact Decision role;
- authoritative validation pada immutable `provider-pack/`;
- equality empat file pack terhadap working overlay;
- configured ZIP, sidecar, descriptor, task, suite ancestry, dan source
  partition;
- derived bootstrap binding;
- exact seven-provider Decision factory template;
- full 14-file inventory dan receipt content hash.

Tidak ada provider yang diimpor atau dimaterialisasi selama proses tersebut.

## Exact output

Candidate valid berisi tepat 15 file:

```text
DECISION_CONFIGURED_CANDIDATE.json
configured-overlay.json
configured-overlay/config/windows_factory_manifest.json
configured-overlay/config/windows_service_config.json
configured-overlay/configured_providers/__init__.py
configured-overlay/configured_providers/decision_provider.py
configured-overlay/reviewed_windows_factory.py
decision-configured-v1.zip
decision-configured-v1.zip.manifest.json
decision-factory-template.json
provider-pack/config/windows_service_config.json
provider-pack/configured_providers/__init__.py
provider-pack/configured_providers/decision_provider.py
provider-pack/reviewed_windows_factory.py
reviewed-task-definition.xml
```

Receipt ditulis terakhir. File hilang/tambahan, symlink/reparse, hash drift,
noncanonical JSON, pack/overlay mismatch, suite mismatch, atau safety drift
menyebabkan fail-closed.

## Langkah sesudah candidate valid

Candidate ini baru menjadi input provider-conformance v2. Tahap berikutnya
tetap memerlukan external custody/ACL/clock/CAS/provider evidence, independent
validation receipt, operations plan/review, launcher attestation, dan sembilan
signed pre-manual observations. Tidak ada output assembler yang dapat membuka
manual demo, demo-auto, atau live.
