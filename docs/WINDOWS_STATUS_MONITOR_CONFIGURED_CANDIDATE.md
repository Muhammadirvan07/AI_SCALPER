# Windows Status Monitor Configured Candidate v1

Status: **IMPLEMENTED LOCALLY / EXTERNAL CONFORMANCE REQUIRED / DENY-ONLY**

Assembler ini mempertahankan four-file provider pack asli sebagai immutable
evidence, membuat working overlay terpisah, membangun exact suite-bound
configured Status Monitor ZIP, dan menulis receipt terakhir. Ia tidak
mematerialisasi provider atau menjalankan service.

Candidate memiliki inventaris tertutup:

```text
STATUS_MONITOR_CONFIGURED_CANDIDATE.json
configured-overlay.json
configured-overlay/config/windows_factory_manifest.json
configured-overlay/config/windows_service_config.json
configured-overlay/configured_providers/__init__.py
configured-overlay/configured_providers/status_monitor_provider.py
configured-overlay/reviewed_windows_factory.py
provider-pack/config/windows_service_config.json
provider-pack/configured_providers/__init__.py
provider-pack/configured_providers/status_monitor_provider.py
provider-pack/reviewed_windows_factory.py
reviewed-task-definition.xml
status-monitor-configured-v1.zip
status-monitor-configured-v1.zip.manifest.json
status-monitor-factory-template.json
```

Receipt mengikat suite identity/manifest, base archive/release identity,
provider-pack identity, bootstrap binding, overlay descriptor, configured
archive/manifest/release identity, factory template, task definition, seluruh
file hash/size, commit/tree, effects, dan safety state.

## Assemble dan validate di Windows

Task definition harus merupakan reviewed validation-only XML dan belum
di-install.

```powershell
$suiteRoot = "C:\AI_SCALPER_RELEASES\<COMMIT>\base-release-suite-v1"
$statusBase = "$suiteRoot\status-monitor-base-v1.zip"
$packRoot = "C:\AI_SCALPER_PRIVATE\status-monitor-provider-pack-v1"
$task = "C:\AI_SCALPER_PRIVATE\status-monitor-validation-task.xml"
$candidate = "C:\AI_SCALPER_PRIVATE\status-monitor-configured-candidate-v1"

python -I -S -B .\assemble_windows_status_monitor_configured_candidate.py `
  --base-suite-root $suiteRoot `
  --status-monitor-base-release $statusBase `
  --provider-pack-root $packRoot `
  --task-definition $task `
  --candidate-id status-monitor-demo-auto-window-01 `
  --output-root $candidate

python -I -S -B .\validate_windows_status_monitor_configured_candidate.py `
  --base-suite-root $suiteRoot `
  --status-monitor-base-release $statusBase `
  --candidate-root $candidate
```

Assembler/validator menolak secret, symlink/reparse, unknown/missing file,
noncanonical JSON, provider/overlay mismatch, base-suite mismatch, template
drift, task tamper, configured ZIP tamper, dan safety drift. Original provider
pack dibaca ulang setelah assembly dan harus byte-identical.

Status akhirnya tetap
`EXTERNAL_PROVIDER_CONFORMANCE_REQUIRED`. Candidate bukan provider acceptance,
task installation, launcher issuance, demo-auto activation, atau live permit.
