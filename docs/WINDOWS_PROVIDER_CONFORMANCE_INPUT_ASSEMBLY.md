# Windows Provider-Conformance Input Assembly

Status: **OFFLINE ASSEMBLY READY / PROVIDER ACCEPTANCE ABSENT**

Provider-conformance review membutuhkan tepat 65 provider binding. Nilai
contract, implementation, configuration, binding, custody, kind, dan
credential reference sudah terikat dalam tiga factory template dan tidak boleh
disalin ulang secara manual.

Assembler menerima:

- exact decision factory-template JSON;
- exact `DEMO_AUTO` execution factory-template JSON;
- exact external status-monitor factory-template JSON; dan
- compact external evidence manifest.

Ia menurunkan seluruh binding field dari template, mencocokkan evidence hanya
melalui exact service/provider role, lalu menguji hasil lengkap menggunakan
reviewer yang sama sebelum menulis input.

## Batas keselamatan

Assembler selalu mempertahankan:

```text
provider_accepted=false
activation_allowed=false
execution_enabled=false
task_install_allowed=false
credential_access_performed=false
provider_imported=false
provider_materialized=false
broker_mutation_performed=false
live_allowed=false
safe_to_demo_auto_order=false
promotion_eligible=false
order_capability=DISABLED
max_lot=0.01
```

Tool tidak membuat evidence, menjalankan suite provider, mengimpor provider,
membaca Credential Manager, memasang task, menandatangani acceptance,
menjalankan MT5, atau mengirim order.

## Compact evidence manifest

Manifest memakai schema:

```text
windows-three-service-provider-evidence-manifest-v1
```

Ia memiliki tepat tiga service:

```text
DECISION
EXECUTION
STATUS_MONITOR
```

Setiap provider record hanya boleh berisi:

```json
{
  "provider_role": "TRUSTED_CLOCK",
  "conformance_suite_sha256": "<NON_ZERO_SHA256>",
  "evidence_artifact_sha256": "<NON_ZERO_SHA256>",
  "reviewer_id": "independent-reviewer-01",
  "observed_at_utc": "2026-07-24T03:00:00.000000Z",
  "result": "PASS",
  "interface_contract_probe_passed": true,
  "fail_closed_probe_passed": true,
  "secret_non_export_probe_passed": true,
  "restart_recovery_probe_passed": true,
  "custody_boundary_probe_passed": true,
  "deterministic_replay_probe_passed": true
}
```

Jangan tambahkan contract/binding/configuration/custody/kind/credential fields.
Assembler mengambilnya hanya dari factory template. Missing, extra, duplicate,
case-colliding, failed, partial, stale, atau future evidence ditolak.

## Perintah Windows

Jalankan dari configured-release operator tooling yang telah diekstrak:

```powershell
python -I -S -B .\prepare_windows_three_service_provider_conformance_input.py `
  --decision-factory-template C:\AI_SCALPER_PRIVATE\providers\decision-factory-template.json `
  --execution-factory-template C:\AI_SCALPER_PRIVATE\providers\execution-factory-template.json `
  --status-monitor-factory-template C:\AI_SCALPER_PRIVATE\providers\status-monitor-factory-template.json `
  --evidence-manifest C:\AI_SCALPER_PRIVATE\providers\provider-evidence-manifest-v1.json `
  --review-id provider-review-jp-window-01 `
  --operations-plan-sha256 <EXACT_OPERATIONS_PLAN_SHA256> `
  --operations-review-bundle-sha256 <EXACT_OPERATIONS_REVIEW_BUNDLE_SHA256> `
  --configured-release-admission-sha256 <EXACT_CONFIGURED_RELEASE_ADMISSION_SHA256> `
  --output C:\AI_SCALPER_PRIVATE\providers\three-service-provider-input-v1.json
```

Output sukses harus menampilkan:

```text
Providers: 65
Review packet created: false
External provider acceptance: false
Order capability: DISABLED
```

Setelah itu buat packet deny-only:

```powershell
python -I -S -B .\prepare_windows_three_service_provider_conformance_review.py `
  --input C:\AI_SCALPER_PRIVATE\providers\three-service-provider-input-v1.json `
  --output C:\AI_SCALPER_PRIVATE\providers\three-service-provider-review-v1.json
```

Packet kedua tetap membutuhkan signature owner independen dan tidak membuka
activation/order.

## Integrity rules

- Semua input dibaca stabil dari regular file maksimal 4 MiB.
- Aggregate empat input maksimal 16 MiB.
- Duplicate key, non-finite JSON, symlink/reparse, changing file, dan unsafe
  output path ditolak.
- Output canonical UTF-8 ditulis create-exclusive dan tidak pernah overwrite.
- Tiga configured release identity wajib non-zero dan berbeda.
- Execution template wajib exact `DEMO_AUTO`.
- Evidence maksimum berumur 24 jam pada trusted UTC.

Kontrak normatif:
[`specs/windows_three_service_provider_evidence_input_assembly_v1.md`](../specs/windows_three_service_provider_evidence_input_assembly_v1.md).
