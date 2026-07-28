# Windows Execution Configured Candidate v1

Status: **IMPLEMENTED LOCALLY / EXTERNAL CONFORMANCE REQUIRED / DENY-ONLY**

Assembler mempertahankan four-file Execution provider pack sebagai immutable
evidence, membuat working overlay terpisah, membangun exact suite-bound
configured Execution ZIP, dan menulis receipt terakhir. Candidate mempunyai
inventaris tertutup 15 file:

```text
EXECUTION_CONFIGURED_CANDIDATE.json
configured-overlay.json
configured-overlay/config/windows_factory_manifest.json
configured-overlay/config/windows_service_config.json
configured-overlay/configured_providers/__init__.py
configured-overlay/configured_providers/execution_provider.py
configured-overlay/reviewed_windows_factory.py
execution-configured-v1.zip
execution-configured-v1.zip.manifest.json
execution-factory-template.json
provider-pack/config/windows_service_config.json
provider-pack/configured_providers/__init__.py
provider-pack/configured_providers/execution_provider.py
provider-pack/reviewed_windows_factory.py
reviewed-task-definition.xml
```

Receipt mengikat suite/role ancestry, base archive/release identity,
provider-pack identity, bootstrap binding, overlay descriptor, configured
archive/manifest/release identity, exact 46-port template, Task Scheduler
definition, seluruh file hash/size, commit/tree, effects, dan safety state.

## Assemble dan validate di Windows

Task definition harus merupakan reviewed validation-only XML dan belum
di-install. Candidate input memakai schema
`windows-execution-configured-candidate-input-v1` dan hanya membawa exact
bootstrap binding serta non-secret Task Scheduler identity hashes.

```powershell
$suiteRoot = "C:\AI_SCALPER_RELEASES\<COMMIT>\base-release-suite-v1"
$executionBase = "$suiteRoot\execution-base-v1.zip"
$packRoot = "C:\AI_SCALPER_PRIVATE\execution-provider-pack-v1"
$task = "C:\AI_SCALPER_PRIVATE\execution-validation-task.xml"
$candidateInput = "C:\AI_SCALPER_PRIVATE\execution-candidate-input.json"
$candidate = "C:\AI_SCALPER_PRIVATE\execution-configured-candidate-v1"

python -I -S -B .\assemble_windows_execution_configured_candidate.py `
  --base-suite-root $suiteRoot `
  --execution-base-release $executionBase `
  --provider-pack-root $packRoot `
  --task-definition $task `
  --candidate-input $candidateInput `
  --candidate-id execution-demo-window-01 `
  --output-root $candidate

python -I -S -B .\validate_windows_execution_configured_candidate.py `
  --base-suite-root $suiteRoot `
  --execution-base-release $executionBase `
  --candidate-root $candidate
```

Assembler dan validator tidak mengimpor provider, membaca credential, membuka
SQLite, menginisialisasi MT5, mengirim jaringan, memasang task, memulai
service, atau menyentuh broker. Original provider pack dibaca ulang dan harus
tetap byte-identical.

Status akhir tetap:

```text
EXTERNAL_PROVIDER_CONFORMANCE_REQUIRED
provider_accepted = false
production_execution_ready = false
order_capability = DISABLED
live_allowed = false
safe_to_demo_auto_order = false
max_lot = 0.01
```

Candidate bukan provider acceptance, task installation, activation permit,
demo-auto unlock, atau live approval.

Candidate v1 yang lulus sendiri juga belum membuktikan bahwa provider source
hash dan bootstrap binding berasal dari satu source verification report.
Sebelum dipakai sebagai input conformance, bungkus exact 15-file candidate dan
exact tujuh-pin source ZIP melalui alur sembilan-pin di
[`WINDOWS_EXECUTION_SOURCE_BOUND_CANDIDATE.md`](WINDOWS_EXECUTION_SOURCE_BOUND_CANDIDATE.md).
Source-bound success tetap deny-only dan provider-conformance v3 masih
memerlukan review terpisah.
