# LIVE Canary Provider-Bound WORM Handoff v1

Status: **IMPLEMENTED LOCALLY / EXTERNAL CUSTODIAN REQUIRED / DENY-ONLY**

Tooling ini membuat request deterministik untuk menyerahkan exact
provider-bound prebootstrap admission kepada custodian WORM dan kemudian
memverifikasi receipt RSA serta exported byte-identical readback. Tool ini
tidak mengakses storage API, credential, private key, provider, Task
Scheduler, process, MT5, atau broker.

Hasil sukses tetap memiliki:

```text
runtime_admission_seal=false
runtime_custody_seal=false
cas_reservation_performed=false
nonce_consumed=false
central_unlock_performed=false
execution_authorized=false
broker_mutation_authorized=false
live_allowed=false
order_capability=DISABLED
```

Assessment adalah bukti offline. Ia bukan pengganti verifier-sealed runtime
custody atau signed CAS/checkpoint/nonce yang diperlukan launch-session v2.

## Input wajib

Gunakan tiga canonical JSON dari satu exact target-host evidence closure:

1. `provider-bound-admission.json`;
2. `portable-custody-policy.json`;
3. `provider-acceptance-policy.json`.

Delapan pin berikut wajib diperoleh melalui channel independen dan tidak boleh
diturunkan diam-diam dari file yang sedang diverifikasi:

- provider-bound admission SHA-256;
- custody policy SHA-256;
- provider acceptance policy SHA-256;
- target-host identity SHA-256;
- installed-environment SHA-256;
- LIVE Execution release identity SHA-256;
- LIVE Execution task-definition SHA-256;
- launcher trust-policy SHA-256.

Custody key ID dan fingerprint harus berbeda dari kedua provider authority.
Gunakan output path baru; tooling menolak overwrite, symlink, dan reparse.

## 1. Siapkan request pada Windows operator host

Jalankan dari configured-release operator tooling hasil clean committed build:

```powershell
$python = "C:\AI_SCALPER\.venv\Scripts\python.exe"
$toolingRoot = "C:\AI_SCALPER_PRIVATE\configured-release-tooling-v1"
$evidenceRoot = "C:\AI_SCALPER_PRIVATE\xm-live-provider-bound"
$handoffRoot = "C:\AI_SCALPER_PRIVATE\xm-live-worm-handoff-v1"

New-Item -ItemType Directory -Force $handoffRoot | Out-Null

# Nilai delapan pin ini harus datang dari receipt/channel independen.
$admissionSha = "<64-HEX-ADMISSION>"
$custodyPolicySha = "<64-HEX-CUSTODY-POLICY>"
$providerPolicySha = "<64-HEX-PROVIDER-POLICY>"
$hostSha = "<64-HEX-TARGET-HOST>"
$environmentSha = "<64-HEX-INSTALLED-ENVIRONMENT>"
$liveReleaseSha = "<64-HEX-LIVE-EXECUTION-RELEASE>"
$taskSha = "<64-HEX-LIVE-TASK-DEFINITION>"
$launcherPolicySha = "<64-HEX-LAUNCHER-POLICY>"

$requestedAt = "<CANONICAL-UTC-WITH-6-DIGITS-Z>"
$minimumRetainUntil = "<CANONICAL-UTC-WITH-6-DIGITS-Z>"
$requestZip = "$handoffRoot\live-canary-provider-bound-worm-request-xm-v1.zip"

& $python -I -S -B `
  "$toolingRoot\manage_live_canary_provider_bound_worm_handoff.py" `
  prepare-request `
  --admission "$evidenceRoot\provider-bound-admission.json" `
  --custody-policy "$evidenceRoot\portable-custody-policy.json" `
  --provider-policy "$evidenceRoot\provider-acceptance-policy.json" `
  --expected-provider-bound-admission-sha256 $admissionSha `
  --expected-custody-policy-sha256 $custodyPolicySha `
  --expected-provider-policy-sha256 $providerPolicySha `
  --expected-target-host-identity-sha256 $hostSha `
  --expected-installed-environment-sha256 $environmentSha `
  --expected-live-execution-release-identity-sha256 $liveReleaseSha `
  --expected-live-execution-task-definition-sha256 $taskSha `
  --expected-launcher-trust-policy-sha256 $launcherPolicySha `
  --request-id xm-live-provider-bound-worm-request-v1 `
  --requested-at-utc $requestedAt `
  --minimum-retain-until-utc $minimumRetainUntil `
  --output $requestZip

if ($LASTEXITCODE -ne 0) {
  throw "WORM request gagal; seluruh safety lock tetap aktif."
}
```

Archive berisi tepat empat member, berurutan dan byte-deterministic:

```text
provider-bound-admission.json
portable-custody-policy.json
provider-acceptance-policy.json
LIVE_CANARY_PROVIDER_BOUND_WORM_REQUEST.json
```

Catat `archive_sha256` dari output dan kirim melalui channel independen kepada
verifier/custodian.

## 2. Verifikasi request secara independen

```powershell
$requestArchiveSha = "<64-HEX-REQUEST-ARCHIVE-DARI-CHANNEL-INDEPENDEN>"

& $python -I -S -B `
  "$toolingRoot\manage_live_canary_provider_bound_worm_handoff.py" `
  verify-request `
  --request-archive $requestZip `
  --expected-request-archive-sha256 $requestArchiveSha `
  --expected-provider-bound-admission-sha256 $admissionSha `
  --expected-custody-policy-sha256 $custodyPolicySha `
  --expected-provider-policy-sha256 $providerPolicySha `
  --expected-target-host-identity-sha256 $hostSha `
  --expected-installed-environment-sha256 $environmentSha `
  --expected-live-execution-release-identity-sha256 $liveReleaseSha `
  --expected-live-execution-task-definition-sha256 $taskSha `
  --expected-launcher-trust-policy-sha256 $launcherPolicySha

if ($LASTEXITCODE -ne 0) {
  throw "Independent WORM request verification gagal; jangan upload."
}
```

## 3. Custodian eksternal

Custodian independen mengekstrak dan menyimpan byte exact
`provider-bound-admission.json` pada versioned compliance/Object Lock WORM,
menerbitkan canonical receipt v2 yang ditandatangani private key eksternal,
serta mengekspor readback dari exact stored object version. Private key,
credential, bucket/repository endpoint, dan storage client tidak boleh masuk
ke repository atau tooling ZIP.

Tool lokal tidak melakukan langkah ini dan tidak boleh mengklaim
`direct_storage_api_inspection_performed=true`.

## 4. Verifikasi receipt dan exported readback

```powershell
$receipt = "$handoffRoot\provider-bound-admission-worm-receipt-v2.json"
$readback = "$handoffRoot\provider-bound-admission-worm-readback.json"
$readbackSha = "<64-HEX-READBACK-DARI-CHANNEL-INDEPENDEN>"
$verifiedAt = "<TRUSTED-CANONICAL-UTC-WITH-6-DIGITS-Z>"
$assessment = "$handoffRoot\live-canary-provider-bound-worm-assessment-xm-v1.json"

& $python -I -S -B `
  "$toolingRoot\manage_live_canary_provider_bound_worm_handoff.py" `
  verify-receipt `
  --request-archive $requestZip `
  --expected-request-archive-sha256 $requestArchiveSha `
  --expected-provider-bound-admission-sha256 $admissionSha `
  --expected-custody-policy-sha256 $custodyPolicySha `
  --expected-provider-policy-sha256 $providerPolicySha `
  --expected-target-host-identity-sha256 $hostSha `
  --expected-installed-environment-sha256 $environmentSha `
  --expected-live-execution-release-identity-sha256 $liveReleaseSha `
  --expected-live-execution-task-definition-sha256 $taskSha `
  --expected-launcher-trust-policy-sha256 $launcherPolicySha `
  --receipt $receipt `
  --readback $readback `
  --expected-readback-sha256 $readbackSha `
  --verified-at-utc $verifiedAt `
  --assessment-output $assessment

if ($LASTEXITCODE -ne 0) {
  throw "WORM receipt/readback assessment gagal; jangan lanjut ke CAS."
}
```

Sukses harus menampilkan
`LIVE_CANARY_PROVIDER_BOUND_WORM_RECEIPT_VERIFIED`, tetapi tetap
`runtime_sealed_custody_emitted=false` dan `order_capability=DISABLED`.

## Batas berikutnya

Setelah assessment ini, runtime tetap wajib:

1. merekonstruksi fresh sealed provider-bound admission dari raw upstream
   evidence pada trusted clock;
2. memverifikasi receipt/readback melalui runtime custody verifier untuk
   menghasilkan exact verifier-sealed custody object;
3. memakai independent atomic CAS/checkpoint/nonce custodian;
4. membentuk exact provider-bound launch-session v2;
5. melewati seluruh ship gate dan ceremony central unlock terpisah.

Tanpa kelima langkah tersebut, LIVE trading tetap **DO NOT SHIP**.
