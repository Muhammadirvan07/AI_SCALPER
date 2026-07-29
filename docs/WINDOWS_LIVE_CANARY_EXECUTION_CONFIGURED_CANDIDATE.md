# Windows LIVE Canary Execution Configured Candidate v1

Status: **IMPLEMENTED LOCALLY / TARGET-WINDOWS ACCEPTANCE REQUIRED / DENY-ONLY**

Boundary ini mengikat satu exact four-file LIVE provider pack ke exact
Execution member dari atomic five-role base suite. Hasilnya berisi tepat 15
file: salinan pack immutable, working overlay, LIVE descriptor, configured ZIP
dan sidecar, reviewed disabled task definition, static 49-port factory
template, serta completion receipt.

Label `runtime_mode=LIVE` pada artefak ini hanya mendeskripsikan jalur runtime.
Ia bukan izin launch atau order. Semua hasil tetap mempertahankan:

```text
Status: EXTERNAL_LIVE_PROVIDER_CONFORMANCE_REQUIRED
Provider acceptance: REQUIRED_EXTERNAL
Order capability: DISABLED
Production execution ready: false
Live allowed: false
Safe to demo auto order: false
Max lot: 0.01
```

## Prasyarat

1. Gunakan configured-release operator tooling dari clean commit yang sama
   dengan atomic base suite.
2. `execution-base-v1.zip` harus merupakan exact role `EXECUTION` dari suite.
3. LIVE provider pack harus sudah lulus validator independen.
4. Task XML harus direview, mengandung `Enabled=false`, dan tidak menyimpan
   password, token, secret, atau private key.
5. Candidate input hanya boleh berisi schema, bootstrap-binding SHA-256, dan
   exact ten-field non-secret Task Scheduler binding.
6. Gunakan output directory baru. Assembler menolak overwrite, overlap,
   symlink/reparse, file ekstra, dan input yang berubah.

## Candidate input

Contoh bentuk canonical JSON (nilai hash harus diganti dengan evidence nyata):

```json
{
  "bootstrap_binding_sha256": "<64-hex-nonzero>",
  "schema_version": "windows-live-canary-execution-configured-candidate-input-v1",
  "task_scheduler": {
    "acl_policy_sha256": "<64-hex-nonzero>",
    "host_identity_sha256": "<64-hex-nonzero>",
    "launcher_path_sha256": "<64-hex-nonzero>",
    "logon_type": "SERVICE_ACCOUNT",
    "multiple_instances_policy": "IGNORE_NEW",
    "release_root_path_sha256": "<64-hex-nonzero>",
    "run_level": "LIMITED",
    "service_account_principal_sha256": "<64-hex-nonzero>",
    "service_account_sid_sha256": "<64-hex-nonzero>",
    "task_path": "\\AI_SCALPER\\ExecutionLiveCanaryWindow01"
  }
}
```

File harus encoded UTF-8 tanpa BOM, key tersortir, separator canonical, dan
diakhiri satu newline. Jangan memasukkan login broker atau nilai credential.

## Assemble dan validate

Jalankan dari root configured-release operator tooling:

```powershell
$suiteRoot = "C:\AI_SCALPER_RELEASES\<COMMIT>\base-release-suite-v1"
$executionBase = "$suiteRoot\execution-base-v1.zip"
$packRoot = "C:\AI_SCALPER_PRIVATE\xm-live-provider-pack-v1"
$taskXml = "C:\AI_SCALPER_PRIVATE\xm-live-task\reviewed-task-definition.xml"
$candidateInput = "C:\AI_SCALPER_PRIVATE\xm-live-task\configured-candidate-input.json"
$candidateRoot = "C:\AI_SCALPER_PRIVATE\xm-live-execution-configured-v1"

python -I -S -B `
  .\assemble_windows_live_canary_execution_configured_candidate.py `
  --base-suite-root $suiteRoot `
  --execution-base-release $executionBase `
  --provider-pack-root $packRoot `
  --task-definition $taskXml `
  --candidate-input $candidateInput `
  --candidate-id xm-live-canary-window-01 `
  --output-root $candidateRoot

if ($LASTEXITCODE -ne 0) {
  throw "LIVE configured candidate assembly gagal; safety lock tetap aktif."
}

python -I -S -B `
  .\validate_windows_live_canary_execution_configured_candidate.py `
  --base-suite-root $suiteRoot `
  --execution-base-release $executionBase `
  --candidate-root $candidateRoot

if ($LASTEXITCODE -ne 0) {
  throw "LIVE configured candidate validation gagal; jangan lanjut."
}
```

Validator merekonstruksi suite/base ancestry, memvalidasi pack, memastikan
pack dan overlay byte-identical, memverifikasi LIVE descriptor serta exact
base materializer hash, membandingkan sidecar dengan manifest di ZIP, dan
mencocokkan seluruh 49 provider, 12 credential reference, contract-set,
bootstrap, production/service config, task, template, serta receipt hashes.

## Arti hasil sukses

Hasil sukses hanya menyatakan bahwa source bytes dan ancestry kandidat
konsisten. Hasil ini tidak membuktikan:

- concrete provider callback sudah direview atau diterima;
- credential dapat atau boleh dibaca;
- launcher/task/ACL sudah disetujui atau dipasang;
- WORM/CAS, rollback, backup/restore, dan observability sudah diterima;
- demo-auto soak 30 hari/50 fill/20 XAUUSD sudah selesai;
- central LIVE policy sudah dibuka;
- MT5 sudah diinisialisasi atau order pernah dikirim.

Langkah berikutnya adalah source-bound packaging, external provider
conformance, brokerless target-host materialization, launcher/task review, dan
independent ship-gate ceremony. Central `LIVE_ALLOWED` harus tetap `false`
sampai seluruh evidence eksternal diterima.
