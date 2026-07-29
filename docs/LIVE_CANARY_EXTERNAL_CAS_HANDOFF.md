# LIVE Canary External CAS Handoff v1

Status: **HANDOFF + WINDOWS CLIENT IMPLEMENTED LOCALLY / EXTERNAL CAS PROVIDER REQUIRED / DENY-ONLY**

Tooling ini membuat archive deterministik dari exact launch-reservation
proposal dan public custody policy, lalu memverifikasi empat exported response:

1. signed launch checkpoint;
2. separately signed CAS acknowledgement;
3. byte-identical head readback;
4. signed nonce readback attestation dengan `nonce_seen=true`.

Tool ini tidak menjalankan runtime CAS callback, tidak mengonsumsi nonce,
tidak membuat `LiveCanaryOneUseLaunchCapability`, tidak membuka central lock,
dan tidak mengakses network, credential, private key, process, MT5, atau broker.

Hasil sukses tetap menyatakan:

```text
runtime_cas_callback_executed=false
runtime_nonce_consumed_by_tool=false
runtime_launch_capability_emitted=false
central_unlock_performed=false
process_launch_performed=false
execution_authorized=false
broker_mutation_authorized=false
live_allowed=false
order_capability=DISABLED
```

## Batas waktu penting

Proposal valid paling lama 60 detik dan biasanya dibatasi policy menjadi 30
detik. Karena itu proses ini bukan workflow copy/paste manusia. Exact proposal
harus berasal dari invocation runtime yang fresh dan diteruskan oleh adapter
provider otomatis/sinkron. CLI ini dipakai untuk:

- menguji dan mengunci kontrak integrasi provider;
- membuat request deterministik oleh automation yang sudah direview;
- memverifikasi exported response secara independen;
- mengarsipkan assessment deny-only untuk audit.

Jangan menangkap proposal lalu mencoba ulang dengan nonce yang sama setelah
hasil CAS ambigu. Runtime protocol memperlakukan ambiguity sebagai nonce yang
terbakar.

## Input wajib

Gunakan dua canonical JSON dari exact invocation yang sama:

- `launch-proposal.json` — exact bytes yang diberikan runtime kepada callback
  CAS;
- `portable-custody-policy.json` — public RSA policy yang dipin runtime.

Lima belas SHA-256 berikut wajib diperoleh melalui channel independen:

- proposal dan custody policy;
- predecessor checkpoint dan launcher nonce;
- candidate, legacy admission, dan custody verification;
- authorization dan validation;
- launcher policy dan launcher attestation;
- release identity, deployment host, service account, dan task definition.

Pin tidak boleh dihitung diam-diam dari file yang sedang diverifikasi.

## 1. Siapkan variabel operator Windows

Jalankan dari configured-release operator tooling hasil clean committed build:

```powershell
$python = "C:\AI_SCALPER\.venv\Scripts\python.exe"
$toolingRoot = "C:\AI_SCALPER_PRIVATE\configured-release-tooling-v1"
$handoffRoot = "C:\AI_SCALPER_PRIVATE\xm-live-cas-handoff-v1"

New-Item -ItemType Directory -Force $handoffRoot | Out-Null

$proposal = "$handoffRoot\launch-proposal.json"
$custodyPolicy = "$handoffRoot\portable-custody-policy.json"
$requestZip = "$handoffRoot\live-canary-external-cas-request-xm-v1.zip"

$proposalSha = "<64-HEX-PROPOSAL>"
$custodyPolicySha = "<64-HEX-CUSTODY-POLICY>"
$predecessorSha = "<64-HEX-PREDECESSOR-ATAU-64-NOL>"
$nonceSha = "<64-HEX-LAUNCHER-NONCE>"
$candidateSha = "<64-HEX-CANDIDATE>"
$admissionSha = "<64-HEX-LEGACY-ADMISSION>"
$custodyVerificationSha = "<64-HEX-CUSTODY-VERIFICATION>"
$authorizationSha = "<64-HEX-AUTHORIZATION>"
$validationSha = "<64-HEX-VALIDATION>"
$launcherPolicySha = "<64-HEX-LAUNCHER-POLICY>"
$launcherAttestationSha = "<64-HEX-LAUNCHER-ATTESTATION>"
$releaseSha = "<64-HEX-RELEASE-IDENTITY>"
$hostSha = "<64-HEX-DEPLOYMENT-HOST>"
$serviceSha = "<64-HEX-SERVICE-ACCOUNT>"
$taskSha = "<64-HEX-TASK-DEFINITION>"

$pinArgs = @(
  "--expected-proposal-sha256", $proposalSha,
  "--expected-custody-policy-sha256", $custodyPolicySha,
  "--expected-predecessor-checkpoint-sha256", $predecessorSha,
  "--expected-launcher-nonce-sha256", $nonceSha,
  "--expected-candidate-sha256", $candidateSha,
  "--expected-admission-sha256", $admissionSha,
  "--expected-custody-verification-sha256", $custodyVerificationSha,
  "--expected-authorization-sha256", $authorizationSha,
  "--expected-validation-sha256", $validationSha,
  "--expected-launcher-trust-policy-sha256", $launcherPolicySha,
  "--expected-launcher-attestation-sha256", $launcherAttestationSha,
  "--expected-release-identity-sha256", $releaseSha,
  "--expected-deployment-host-alias-sha256", $hostSha,
  "--expected-service-account-alias-sha256", $serviceSha,
  "--expected-task-definition-sha256", $taskSha
)
```

## 2. Buat dan verifikasi request

Langkah ini harus dijalankan automation di dalam window proposal, bukan setelah
operator menunggu atau menyalin berkas secara manual.

```powershell
& $python -I -S -B `
  "$toolingRoot\manage_live_canary_external_cas_handoff.py" `
  prepare-request `
  --proposal $proposal `
  --custody-policy $custodyPolicy `
  @pinArgs `
  --request-id xm-live-cas-reservation-v1 `
  --output $requestZip

if ($LASTEXITCODE -ne 0) {
  throw "CAS request gagal; jangan retry nonce yang hasilnya ambigu."
}

$requestArchiveSha = (
  Get-FileHash $requestZip -Algorithm SHA256
).Hash.ToLowerInvariant()

& $python -I -S -B `
  "$toolingRoot\manage_live_canary_external_cas_handoff.py" `
  verify-request `
  --request-archive $requestZip `
  --expected-request-archive-sha256 $requestArchiveSha `
  @pinArgs

if ($LASTEXITCODE -ne 0) {
  throw "Independent CAS request verification gagal."
}
```

Archive berisi tepat tiga member dan tidak boleh diubah:

```text
launch-proposal.json
portable-custody-policy.json
LIVE_CANARY_EXTERNAL_CAS_REQUEST.json
```

## 3. Kewajiban custodian CAS eksternal

Adapter/custodian yang independen harus secara atomik:

1. membandingkan current head dengan exact predecessor;
2. menolak nonce yang sudah pernah terlihat;
3. menulis signed checkpoint sebagai new head;
4. menandatangani acknowledgement pada domain CAS yang berbeda;
5. membaca kembali exact head;
6. membuktikan nonce terlihat melalui signed nonce-readback domain v1.

Private key dan credential tetap di luar repository, tooling ZIP, dan Windows
Execution service. Response harus dikembalikan sebelum `expires_at_utc`.

## 4. Verifikasi exported response

```powershell
$checkpoint = "$handoffRoot\launch-checkpoint.json"
$ack = "$handoffRoot\launch-acknowledgement.json"
$headReadback = "$handoffRoot\head-readback.json"
$nonceReadback = "$handoffRoot\nonce-readback-attestation.json"
$assessment = "$handoffRoot\live-canary-external-cas-assessment-xm-v1.json"
$verifiedAt = "<TRUSTED-CANONICAL-UTC-WITH-6-DIGITS-Z>"
$headReadbackSha = (
  Get-FileHash $headReadback -Algorithm SHA256
).Hash.ToLowerInvariant()

& $python -I -S -B `
  "$toolingRoot\manage_live_canary_external_cas_handoff.py" `
  verify-response `
  --request-archive $requestZip `
  --expected-request-archive-sha256 $requestArchiveSha `
  @pinArgs `
  --checkpoint $checkpoint `
  --acknowledgement $ack `
  --head-readback $headReadback `
  --nonce-readback $nonceReadback `
  --expected-head-readback-sha256 $headReadbackSha `
  --verified-at-utc $verifiedAt `
  --assessment-output $assessment

if ($LASTEXITCODE -ne 0) {
  throw "CAS response assessment gagal; nonce harus dianggap terbakar."
}
```

Sukses menampilkan `LIVE_CANARY_EXTERNAL_CAS_RESPONSE_VERIFIED`. Ini hanya
menerima signed external claims; bukan bukti bahwa callback runtime yang sama
sudah menghasilkan module-sealed capability.

## 4A. Windows synchronous directory client

Windows Execution base release sekarang membawa
`WindowsLiveCanaryExternalCasDirectoryAdapter`. Client ini menjalankan exact
checkpoint/CAS/nonce callbacks melalui request dan response directory yang
dikontrol terpisah. Ia memverifikasi canonical public custody policy,
checkpoint, acknowledgement, dan nonce response secara mandiri dengan RSA
public key tanpa mengimpor producer-side custody graph.

Implementasi lokal dan isolated import tidak membuktikan provider eksternal.
Production deployment masih wajib membuktikan atomic service, mount identity,
ownership/ACL, durability, backup/restore, signed response, serta target-host
acceptance. Detail kontrak ada di
`docs/WINDOWS_LIVE_CANARY_EXTERNAL_CAS_DIRECTORY_ADAPTER.md`.

## 5. Boundary runtime yang tetap wajib

Untuk launch nyata, satu invocation fresh masih harus menjalankan
`consume_live_canary_launch_reservation(...)` secara sinkron dengan callback
adapter yang sudah direview dan layanan provider eksternal yang sudah diterima.
Fungsi itu sendiri harus:

- melakukan pre-read current head dan nonce;
- memanggil atomic CAS;
- memverifikasi checkpoint dan acknowledgement;
- melakukan post-read head dan nonce;
- membuat exact module-owned `LiveCanaryOneUseLaunchCapability`.

Kemudian provider-bound launch-session v2, central unlock ceremony, fresh
risk/news/reconciliation checks, per-order authority, dan seluruh ship gate
tetap wajib. Sampai semuanya selesai, verdict tetap **DO NOT SHIP LIVE**.
