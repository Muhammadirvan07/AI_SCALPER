# Windows Execution Production Configuration Source

Status: **IMPLEMENTED LOCALLY / SEVEN-PIN VERIFIED / DENY-ONLY**

Artefak ini menutup celah antara dua input operator yang sebelumnya berdiri
sendiri:

- `production_config_sha256` pada Execution provider pack; dan
- `bootstrap_binding_sha256` pada configured Execution candidate.

Satu ZIP deterministik sekarang mengikat exact
`ProductionRuntimeConfig`, exact `StageBinding`, dan exact rule-core champion.
Runtime source hanya dapat dibuat melalui loader tujuh-pin; konstruksi langsung
`WindowsExecutionProductionConfigSource` ditolak.

Keberhasilan verifier **bukan** provider acceptance, activation approval,
manual-demo approval, order permit, atau live approval.

## Inventory exact

ZIP memuat tepat empat file:

```text
WINDOWS_EXECUTION_PRODUCTION_CONFIG_SOURCE.json
config/windows_production_runtime_config.json
evidence/rule-core-champion-artifact.zip
evidence/windows_stage_binding.json
```

Manifest mengikat ukuran dan SHA-256 ketiga payload, source identity,
production-config source hash, bootstrap safe-binding, stage binding, delapan
identitas champion, safety locks, serta seluruh effect non-claims.

## Input canonical

`windows_production_runtime_config.json` adalah exact
`ProductionRuntimeConfig.reviewed_configuration_payload` dalam canonical JSON
dengan satu LF. File harus dibuat pada host Windows target karena constructor
menormalisasi path journal, supervisor, dan dependency lock. Memindahkan file
ke host/path lain dapat mengubah safe binding dan wajib gagal.

`windows_stage_binding.json` adalah wrapper tertutup:

```json
{
  "binding": {
    "...": "exact StageBinding.to_canonical_dict()"
  },
  "binding_sha256": "<EXACT_STAGE_BINDING_SHA256>",
  "schema_version": "stage-readiness-authorization-v3"
}
```

Gunakan `canonical_source_file(...)` dari
`live_runtime.windows_execution_production_config_source` untuk menulis kedua
JSON. Jangan memasukkan password, login, token, private key, environment arm,
permit, atau credential value.

## Enam pin champion

Ambil keenam pin dari channel review independen, bukan dari ZIP yang sedang
diverifikasi:

```text
champion archive SHA-256
model artifact SHA-256
training snapshot SHA-256
candidate config SHA-256
full Git commit (40 hex)
full Git tree (40 hex)
```

Verifier memperoleh package identity dan runtime-binding identity dari exact
champion, lalu mencocokkannya dengan stage dan production config.

## Prepare pada Windows

Jalankan hanya dari configured-release operator tooling dengan CPython 3.12
terisolasi:

```powershell
$toolingRoot = "C:\AI_SCALPER_PRIVATE\configured-release-tooling-v1"
$inputRoot = "C:\AI_SCALPER_PRIVATE\execution-production-source-input"
$output = "C:\AI_SCALPER_PRIVATE\execution-production-config-source-v1.zip"

& C:\AI_SCALPER\.venv\Scripts\python.exe -I -S -B `
  "$toolingRoot\prepare_windows_execution_production_config_source.py" `
  --production-config "$inputRoot\windows_production_runtime_config.json" `
  --stage-binding "$inputRoot\windows_stage_binding.json" `
  --champion-artifact "$inputRoot\rule-core-champion-artifact.zip" `
  --expected-champion-archive-sha256 <PIN_CHAMPION_ARCHIVE> `
  --expected-model-artifact-sha256 <PIN_MODEL> `
  --expected-training-snapshot-sha256 <PIN_SNAPSHOT> `
  --expected-config-sha256 <PIN_CONFIG> `
  --expected-git-commit <PIN_FULL_COMMIT> `
  --expected-git-tree <PIN_FULL_TREE> `
  --output $output
```

Output harus baru. Existing file, symlink/reparse point, unstable input, output
collision, duplicate/case-folded member, path traversal, metadata drift,
non-canonical JSON, trailing ZIP bytes, atau cross-binding mismatch ditolak
tanpa overwrite.

## Verifikasi tujuh pin

Pin ketujuh adalah SHA-256 outer ZIP dari channel custody independen:

```powershell
& C:\AI_SCALPER\.venv\Scripts\python.exe -I -S -B `
  "$toolingRoot\verify_windows_execution_production_config_source.py" `
  --archive $output `
  --expected-source-archive-sha256 <PIN_OUTER_SOURCE_ARCHIVE> `
  --expected-champion-archive-sha256 <PIN_CHAMPION_ARCHIVE> `
  --expected-model-artifact-sha256 <PIN_MODEL> `
  --expected-training-snapshot-sha256 <PIN_SNAPSHOT> `
  --expected-config-sha256 <PIN_CONFIG> `
  --expected-git-commit <PIN_FULL_COMMIT> `
  --expected-git-tree <PIN_FULL_TREE>
```

Output sukses wajib tetap menyatakan:

```text
Provider accepted: false
Production execution ready: false
Promotion eligible: false
Order capability: DISABLED
Safe to demo auto order: false
Live allowed: false
```

## Binding downstream

Gunakan hanya nilai dari report terverifikasi yang sama:

- `archive_sha256` sebagai Execution provider-pack
  `production_config_sha256`;
- `bootstrap_binding_sha256` sebagai configured Execution candidate/factory
  `bootstrap_binding_sha256`; dan
- `load_windows_execution_production_config_source(...)` sebagai satu-satunya
  constructor runtime source yang diterima.

Materialization tetap mencocokkan outer source hash dan bootstrap binding
sebelum credential backend, SQLite, provider state, MT5, network, runner, atau
broker effect. Provider hooks Windows eksternal masih memerlukan review,
launcher attestation, credential custody, conformance evidence, dan seluruh
ship gate yang berlaku.

Kontrak normatif:
[`windows_execution_production_config_source_v1.md`](../specs/windows_execution_production_config_source_v1.md).
