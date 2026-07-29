# Windows LIVE Canary Execution Provider Pack v1

Status: **IMPLEMENTED LOCALLY / TARGET-WINDOWS ACCEPTANCE REQUIRED / DENY-ONLY**

Tooling ini menyiapkan boundary packaging untuk materializer LIVE yang sudah
direview. Ia menghasilkan tepat empat file:

```text
config/windows_service_config.json
configured_providers/__init__.py
configured_providers/execution_provider.py
reviewed_windows_factory.py
```

Pack mengikat exact atomic base-suite identity, Execution-base release
identity, reviewed foundation bytes, 49 provider contract terurut, 12
credential reference purpose-bound, service-config hash, implementation hash,
dan configuration hash. `credential_session_provider` menggunakan purpose
`MT5_LIVE_SESSION`; sembilan provider lintas-mode harus tetap tidak tersedia.

Generator dan validator tidak mengimpor generated provider, membaca
credential, membuka SQLite, memulai process, menginisialisasi MT5, mengakses
network, memasang task, atau menyentuh broker. Output selalu mempertahankan:

```text
Status: EXTERNAL_LIVE_PROVIDER_ACCEPTANCE_REQUIRED
Order capability: DISABLED
Production execution ready: false
Live allowed: false
Safe to demo auto order: false
Max lot: 0.01
```

## Prasyarat Windows

1. Gunakan clean checkout pada exact commit yang sudah direview.
2. Bangun dan verifikasi atomic five-role base suite dari commit tersebut.
3. Gunakan `execution-base-v1.zip` yang berada di suite yang sama.
4. Ekstrak salinan verifikasi Execution base dan jalankan
   `verify_windows_live_canary_provider_bound_runtime_closure.py` memakai
   `python -I -S -B`; hasil harus READY tetapi tetap locked.
5. Buat canonical secret-free input sesuai
   `specs/windows_live_canary_execution_provider_pack_v1.md`.
6. Jangan menaruh password, login, token, private key, permit, atau arm flag di
   input. Hanya referensi Credential Manager dan fingerprint non-secret yang
   boleh masuk.
7. Gunakan destination baru. Tooling menolak overwrite, symlink/reparse,
   file tambahan, dan output yang berubah.

## Generate dan validate

Jalankan dari configured-release operator tooling yang berasal dari commit
dan suite yang sama:

```powershell
$suiteRoot = "C:\AI_SCALPER_RELEASES\<COMMIT>\base-release-suite-v1"
$executionBase = "$suiteRoot\execution-base-v1.zip"
$packInput = "C:\AI_SCALPER_PRIVATE\xm-live-provider-pack-input.json"
$packRoot = "C:\AI_SCALPER_PRIVATE\xm-live-provider-pack-v1"

python -I -S -B .\prepare_windows_live_canary_execution_provider_pack.py `
  --base-suite-root $suiteRoot `
  --execution-base-release $executionBase `
  --pack-input $packInput `
  --output-root $packRoot

if ($LASTEXITCODE -ne 0) {
  throw "LIVE provider pack generation gagal; safety lock tetap aktif."
}

python -I -S -B .\validate_windows_live_canary_execution_provider_pack.py `
  --base-suite-root $suiteRoot `
  --execution-base-release $executionBase `
  --pack-root $packRoot

if ($LASTEXITCODE -ne 0) {
  throw "LIVE provider pack validation gagal; jangan lanjut."
}
```

Output sukses adalah bukti integritas pack saja. Ia bukan provider acceptance,
launcher approval, central unlock, credential authorization, MT5
initialization, atau order authority.

## Langkah berikutnya

1. Assemble dan validasi satu suite-bound LIVE configured candidate mengikuti
   `docs/WINDOWS_LIVE_CANARY_EXECUTION_CONFIGURED_CANDIDATE.md`.
2. Validasi ulang candidate terhadap suite, Execution role, commit, tree, dan
   seluruh source inventory.
3. Sediakan concrete Windows provider callbacks melalui review terpisah.
4. Jalankan brokerless materialization dan negative tests pada host target.
5. Kumpulkan external conformance, launcher, ACL/task, WORM/CAS, rollback, dan
   observability receipts.
6. Pertahankan central `LIVE_ALLOWED=false` sampai seluruh ship gate diterima.

Tidak ada langkah pada runbook ini yang mengirim order.
