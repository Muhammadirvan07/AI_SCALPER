# Windows Execution Provider Pack v1

Status: **IMPLEMENTED LOCALLY / EXTERNAL WINDOWS RUNTIME REQUIRED /
DENY-ONLY**

Pack ini mengikat exact factory contract untuk service `EXECUTION` tanpa
menerbitkan order authority:

- 46 provider port total;
- 37 port wajib untuk mode `DEMO`;
- sembilan port opsional;
- dua belas referensi Windows Credential Manager yang purpose-bound; dan
- satu signed-clock authority yang independen dari dua belas domain
  credential tersebut.

Foundation memvalidasi service config, production-config source, bootstrap
binding, runtime mode, global policy lock, credential binding, setiap provider
value, dan heartbeat custody sebelum membuat
`WindowsServiceFactoryResult`. `mt5_module` selalu `None` saat composition;
production bootstrap yang sudah ada tetap menjadi satu-satunya boundary yang
kelak boleh mengimpor dan mengattest MetaTrader5.

Generated factory tidak mempunyai registry global, environment-selected
module, dynamic import, atau fallback provider. Tanpa runtime Windows yang
direview, startup wajib berhenti dengan:

```text
EXECUTION_PROVIDER_RUNTIME_NOT_CONFIGURED
```

## Batas release

- `live_runtime/windows_execution_provider_pack.py` dan shared
  `live_runtime/windows_provider_primitives.py` hanya masuk base release
  `EXECUTION`.
- Generator/validator serta configured-candidate assembler/validator hanya
  masuk `WINDOWS_CONFIGURED_RELEASE_OPERATOR_TOOLING_V1`.
- Pack yang dihasilkan berisi tepat empat file:

```text
config/windows_service_config.json
configured_providers/__init__.py
configured_providers/execution_provider.py
reviewed_windows_factory.py
```

Tooling offline tidak mengimpor generated factory, membaca credential,
membuka SQLite, mengirim request jaringan, memasang task, memulai process,
menginisialisasi MT5, atau menyentuh broker.

## Prasyarat Windows

1. Gunakan clean checkout dari satu exact reviewed commit.
2. Bangun dan verifikasi atomic five-role base suite.
3. Gunakan canonical `execution-base-v1.zip` dari suite tersebut.
4. Siapkan canonical secret-free pack input sesuai
   `specs/windows_execution_provider_pack_v1.md`.
5. Provision seluruh database, directory, external CAS/current head, outbox,
   clock-attestation source, dan Credential Manager reference melalui review
   terpisah. Generator tidak membuat state tersebut.
6. Pertahankan:

```text
runtime_mode = DEMO
order_capability = DISABLED
live_allowed = false
safe_to_demo_auto_order = false
max_lot = 0.01
promotion_eligible = false
production_execution_ready = false
```

Mode `DEMO_AUTO` tetap ditolak oleh centralized execution policy lock.

## Generate dan validate

```powershell
$suiteRoot = "C:\AI_SCALPER_RELEASES\<COMMIT>\base-release-suite-v1"
$executionBase = "$suiteRoot\execution-base-v1.zip"
$packInput = "C:\AI_SCALPER_PRIVATE\execution-provider-pack-input.json"
$packRoot = "C:\AI_SCALPER_PRIVATE\execution-provider-pack-v1"

python -I -S -B .\prepare_windows_execution_provider_pack.py `
  --base-suite-root $suiteRoot `
  --execution-base-release $executionBase `
  --pack-input $packInput `
  --output-root $packRoot

python -I -S -B .\validate_windows_execution_provider_pack.py `
  --base-suite-root $suiteRoot `
  --execution-base-release $executionBase `
  --pack-root $packRoot
```

Output yang benar tetap menyatakan:

```text
Status: EXTERNAL_PROVIDER_ACCEPTANCE_REQUIRED
Credential access: NOT_PERFORMED
Provider materialization: NOT_PERFORMED
MT5 initialization: NOT_PERFORMED
Broker mutation: NOT_PERFORMED
Order capability: DISABLED
Production execution ready: false
```

## Setelah pack valid

Pack valid belum dapat dijalankan sebagai service. Urutannya:

1. assemble immutable configured candidate;
2. validate candidate dari exact bytes;
3. provision externally reviewed runtime hooks dan pre-existing provider
   state pada Windows;
4. buktikan factory composition, restart, CAS, uncertain-submit, heartbeat,
   dan reconciliation behavior dalam independent conformance;
5. kumpulkan sembilan signed pre-manual observations;
6. lakukan human activation review;
7. baru jalankan sepuluh controlled manual-demo lifecycle.

Tidak ada langkah dalam dokumen ini yang membuka demo-auto atau live.
