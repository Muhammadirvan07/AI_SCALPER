# Windows Decision Provider Pack v1

## Status

```text
SOURCE_IMPLEMENTATION = COMPLETE_LOCALLY
LOCAL_REGRESSION = 1544_OF_1544_PASS_NORMAL_AND_OPTIMIZED
WINDOWS_EXACT_BUILD = PENDING
EXTERNAL_PROVIDER_ACCEPTANCE = REQUIRED
ORDER_CAPABILITY = DISABLED
PRODUCTION_EXECUTION_READY = false
```

Paket ini menghubungkan service `DECISION` brokerless dengan provider Windows
yang dibutuhkan untuk membaca finalized M15, memverifikasi kalender sesi,
menerbitkan signed decision IPC, menjaga checkpoint melalui external CAS, dan
memakai trusted UTC. Paket ini tidak memiliki MT5, risk approval, intent,
permit, process-launch, atau order authority.

## Pembagian boundary

- `live_runtime/windows_decision_provider_pack.py` hanya berada dalam base
  release `WINDOWS_DECISION_SERVICE_V1`.
- Primitive credential/trusted-clock tunggal berada di
  `live_runtime/windows_provider_primitives.py`, dipakai Decision melalui
  re-export identik, dan ikut base release `DECISION`, `EXECUTION`, serta
  `STATUS_MONITOR` saja.
- Generator dan validator offline hanya berada dalam
  `WINDOWS_CONFIGURED_RELEASE_OPERATOR_TOOLING_V1`.
- Decision-domain provider foundation dan generator tidak ditambahkan ke
  execution, read-only-shadow, atau status-monitor release.
- Credential value tidak boleh berada dalam repository, input JSON, output
  overlay, CLI argument, manifest, atau log.

## Prasyarat Windows

1. Gunakan clean checkout dari satu exact reviewed commit.
2. Bangun dan verifikasi atomic five-role base suite.
3. Gunakan canonical `decision-base-v1.zip` dari suite tersebut.
4. Provision terlebih dahulu:
   - finalized-M15 signed-feed directory;
   - dua SQLite database kosong yang dibuat melalui provisioning flow resmi;
   - empat directory external CAS yang terpisah;
   - signed external clock-attestation file;
   - key generik Windows Credential Manager dengan exact prefix, key ID, dan
     fingerprint yang sudah direview.
5. Seluruh path harus absolute Windows, non-symlink/non-reparse, tidak
   bertabrakan, dan tidak menjadi ancestor/descendant satu sama lain.

External CAS directory belum boleh disebut off-host/WORM hanya karena path-nya
ada. Custody, ACL, service identity, trusted clock, dan provider conformance
tetap membutuhkan bukti eksternal terpisah.

## Membuat candidate overlay

Input harus merupakan canonical JSON satu baris dengan newline akhir, memakai
schema `windows-decision-provider-pack-input-v1`, closed fields, satu sampai
empat lane M15, dan seluruh safety lock berikut:

```text
order_capability = DISABLED
live_allowed = false
safe_to_demo_auto_order = false
max_lot = 0.01
promotion_eligible = false
production_execution_ready = false
```

Jalankan tooling dari paket operator yang dibangun dari commit dan suite yang
sama:

```powershell
python -I -S -B .\prepare_windows_decision_provider_pack.py `
  --base-suite-root C:\AI_SCALPER_RELEASES\<commit>\base-release-suite-v1 `
  --decision-base-release C:\AI_SCALPER_RELEASES\<commit>\base-release-suite-v1\decision-base-v1.zip `
  --pack-input C:\AI_SCALPER_PRIVATE\decision-provider-pack-input.json `
  --output-root C:\AI_SCALPER_PRIVATE\decision-provider-overlay-v1
```

Hasil yang benar tetap menampilkan:

```text
WINDOWS_DECISION_PROVIDER_PACK_PREPARED
Status: EXTERNAL_PROVIDER_ACCEPTANCE_REQUIRED
Order capability: DISABLED
Production execution ready: false
```

## Validasi independen

```powershell
python -I -S -B .\validate_windows_decision_provider_pack.py `
  --base-suite-root C:\AI_SCALPER_RELEASES\<commit>\base-release-suite-v1 `
  --decision-base-release C:\AI_SCALPER_RELEASES\<commit>\base-release-suite-v1\decision-base-v1.zip `
  --pack-root C:\AI_SCALPER_PRIVATE\decision-provider-overlay-v1
```

Validator hanya membaca dan memverifikasi exact bytes. Ia tidak mengimpor
factory hasil generate, membaca credential, membuka database provider,
mengirim CAS request, menjalankan service, menginisialisasi MT5, atau
menyentuh broker.

## Output exact

Generator menulis tepat empat file secara create-exclusive:

```text
reviewed_windows_factory.py
configured_providers/__init__.py
configured_providers/decision_provider.py
config/windows_service_config.json
```

Semua tujuh implementation/configuration hash provider diturunkan dari exact
Decision foundation, exact shared primitive bytes, generated provider bytes,
contract hash, role, dan canonical non-secret configuration. Domain
implementation v2 mengikat daftar path+SHA-256 kedua member base release;
member hilang atau duplikat ditolak sebelum output. Hash tersebut tidak
diterima dari input operator.

## Setelah pack valid

Pack valid masih merupakan candidate, bukan izin runtime. Urutannya:

1. jangan jalankan generic preparer langsung pada root pack empat-file;
2. jalankan `assemble_windows_decision_configured_candidate.py` agar pack asli
   tetap immutable dan working overlay dibuat terpisah;
3. validasi candidate dengan
   `validate_windows_decision_configured_candidate.py`;
4. lakukan provider-conformance dan independent validation;
5. terbitkan external RSA launcher attestation;
6. review Task Scheduler identity/ACL dan Credential Manager ACL;
7. kumpulkan sembilan signed pre-manual observations;
8. baru masuk 10 controlled manual-demo lifecycle.

Panduan dan exact output tersedia di
`docs/WINDOWS_DECISION_CONFIGURED_CANDIDATE.md`.

Tidak ada langkah dalam dokumen ini yang membuka demo-auto atau live.
