# Windows Provider-Conformance Input Assembly

Status: **V3 OFFLINE ASSEMBLY READY / PROVIDER ACCEPTANCE ABSENT**

Provider-conformance review membutuhkan tepat 65 provider binding. Nilai
contract, implementation, configuration, binding, custody, kind, dan
credential reference sudah terikat dalam tiga factory template dan tidak boleh
disalin ulang secara manual.

Assembler menerima:

- exact decision factory-template JSON;
- exact `DEMO_AUTO` execution factory-template JSON;
- exact external status-monitor factory-template JSON; dan
- compact external evidence manifest.

Untuk candidate baru, API/CLI v3 juga wajib menerima exact Execution
source-bound ZIP, atomic-suite root, Execution base release, dan sembilan pin
eksternal. Ia memverifikasi source-bound artifact terlebih dahulu dan
menurunkan `execution_source_binding` hanya dari hasil verifier tersegel.
Panduan lengkap tersedia di
[`WINDOWS_THREE_SERVICE_PROVIDER_CONFORMANCE_V3.md`](WINDOWS_THREE_SERVICE_PROVIDER_CONFORMANCE_V3.md).

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

## Perintah Windows — kontrak v3 untuk candidate baru

Gunakan alur v3 beserta seluruh source-bound pin yang didokumentasikan di
[`WINDOWS_THREE_SERVICE_PROVIDER_CONFORMANCE_V3.md`](WINDOWS_THREE_SERVICE_PROVIDER_CONFORMANCE_V3.md).
Execution factory template v3 wajib exact `DEMO` member dari source-bound
candidate. Argumen parsial atau campuran v1/v3 ditolak tanpa output.

## Perintah Windows — kontrak v2 compatibility

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
  --output C:\AI_SCALPER_PRIVATE\providers\three-service-provider-input-v2.json
```

Output sukses harus menampilkan:

```text
Contract schema: windows-three-service-provider-conformance-input-v2
Providers: 65
Review packet created: false
External provider acceptance: false
Order capability: DISABLED
```

Setelah itu buat packet deny-only:

```powershell
python -I -S -B .\prepare_windows_three_service_provider_conformance_review.py `
  --input C:\AI_SCALPER_PRIVATE\providers\three-service-provider-input-v2.json `
  --output C:\AI_SCALPER_PRIVATE\providers\three-service-provider-review-v2.json
```

Packet kedua tetap membutuhkan signature owner independen dan tidak membuka
activation/order.

Argumen `--configured-release-admission-sha256` hanya mempertahankan byte
compatibility kontrak v1 historis. Jika diberikan, output wajib melaporkan
`LEGACY_DIAGNOSTIC_ONLY`; artefak itu tidak boleh menjadi source evidence untuk
candidate pre-manual atau promotion baru.

V2 dipertahankan byte-compatible untuk candidate tanpa source-bound closure.
Candidate baru yang sudah memakai source-bound Execution wajib menggunakan
v3. Hash packet dapat menjadi `source_evidence_sha256`; hash objek validasi
terpisah menjadi `validation_receipt_sha256`.

## Integrity rules

- Semua input dibaca stabil dari regular file maksimal 4 MiB.
- Aggregate empat input maksimal 16 MiB.
- Duplicate key, non-finite JSON, symlink/reparse, changing file, dan unsafe
  output path ditolak.
- Output canonical UTF-8 ditulis create-exclusive dan tidak pernah overwrite.
- Tiga configured release identity wajib non-zero dan berbeda.
- Execution template wajib exact `DEMO_AUTO` untuk v1/v2 dan exact `DEMO`
  source-bound member untuk v3.
- Evidence maksimum berumur 24 jam pada trusted UTC.

Kontrak normatif candidate baru:
[`specs/windows_three_service_provider_conformance_v3.md`](../specs/windows_three_service_provider_conformance_v3.md).
Kontrak v2 tetap byte-compatible untuk compatibility workflow; v1 hanya untuk
legacy diagnostics.
