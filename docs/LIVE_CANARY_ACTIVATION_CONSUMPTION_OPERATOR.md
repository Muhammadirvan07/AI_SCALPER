# LIVE Canary Activation Consumption Operator V1

Status: **DENY-ONLY / ONE-USE REPLAY EVIDENCE / NOT AN ORDER AUTHORIZATION**

Workflow ini mengikat satu authorization LIVE-canary yang sudah diverifikasi ke
satu replay registry SQLite target-host, mengonsumsinya tepat satu kali, lalu
menerbitkan signed successor checkpoint dan receipt canonical. Semua hasil
tetap `live_allowed=false`, `activation_authorized=false`, dan
`order_capability=DISABLED`.

Workflow ini tidak membuka central LIVE lock, tidak membuat launch session,
tidak menjalankan process/service, tidak menginisialisasi MT5, dan tidak
mengirim order broker. Output hanya dapat diteruskan ke admission/prebootstrap
yang direview secara terpisah.

## Prasyarat

- Gunakan exact verified operator release
  `WINDOWS_SHADOW_DEPLOYMENT_TOOLING_V1` dari clean commit.
- Selesaikan workflow di
  `LIVE_CANARY_ACTIVATION_OPERATOR.md` dengan evidence autentik dan
  authorization yang masih current.
- Pin SHA-256 policy WORM dari kanal independen harus dipertahankan; semua
  operasi consume, verify, dan recover merekonstruksi ulang semantic Phillip
  V6 custody bridge sebelum mengakses replay event.
- Registry key dan policy-pinned replay-checkpoint key sudah diprovision secara
  terpisah di Windows Credential Manager. Tool ini tidak membuat, menerima,
  atau mengekspor raw secret.
- Registry key ID/fingerprint harus berbeda dari seluruh promotion, gate,
  approval, deployment, dan checkpoint authority.
- Parent registry/output adalah directory lokal nyata yang sudah ada, bukan
  symlink/reparse point. Registry dan semua output harus belum ada.
- Trusted-clock provider, Credential Manager ACL, host identity, serta off-host
  checkpoint custody harus sudah direview secara operasional.

## Variabel Windows

Jalankan PowerShell dari root operator release yang sudah diverifikasi.

```powershell
$operatorRoot = "C:\AI_SCALPER_PRIVATE\live-canary-activation-operator"
Set-Location $operatorRoot
$python = "C:\AI_SCALPER\.venv\Scripts\python.exe"
if (-not (Test-Path $python -PathType Leaf)) {
  throw "Exact AI_SCALPER Python tidak ditemukan: $python"
}

$inputRoot = "C:\AI_SCALPER_PRIVATE\live-canary-activation-input"
$outputRoot = Join-Path `
  "C:\AI_SCALPER_PRIVATE\live-canary-activation-output" `
  (Get-Date -Format "yyyyMMdd-HHmmss")

if (Test-Path $outputRoot) {
  throw "Output root sudah ada; jangan overwrite evidence."
}
New-Item -ItemType Directory $outputRoot | Out-Null

$binding = "$inputRoot\REQUIRED_live-canary-binding.json"
$policy = "$inputRoot\REQUIRED_live-canary-trust-policy.json"
$soakBinding = "$inputRoot\REQUIRED_demo-auto-cohort-binding.json"
$soakReceipt = "$inputRoot\REQUIRED_demo-auto-cohort-receipt.json"
$promotion = "$inputRoot\REQUIRED_live-promotion-receipt.json"
$eligibilityReview = "$inputRoot\REQUIRED_broker-eligibility-review.json"
$regulatoryObservation = "$inputRoot\REQUIRED_regulatory-observation.json"
$gateSet = "$inputRoot\REQUIRED_nine-domain-gate-set.json"
$authorization = "$inputRoot\REQUIRED_live-canary-activation-authorization.json"
$wormPolicySha256 = Read-Host `
  "Exact WORM custody policy SHA-256 dari kanal independen"

$registryPath = "C:\AI_SCALPER_PRIVATE\live-canary-replay\registry-v1.sqlite3"
$profile = "$outputRoot\replay-registry-profile.json"
$initialization = "$outputRoot\replay-registry-initialization.json"
$consumption = "$outputRoot\live-canary-activation-consumption.json"

$gateEvidence = [ordered]@{
  BACKUP_RESTORE = "$inputRoot\REQUIRED_backup-restore.evidence"
  FAILURE_DRILL = "$inputRoot\REQUIRED_failure-drill.evidence"
  LIVE_BROKER_ACCOUNT = "$inputRoot\REQUIRED_live-broker-account.evidence"
  OPERATIONAL_ROLLBACK = "$inputRoot\REQUIRED_operational-rollback.evidence"
  SECURITY = "$inputRoot\REQUIRED_security.evidence"
  SINGLE_ACCOUNT_SCOPE = "$inputRoot\REQUIRED_single-account-scope.evidence"
  WINDOWS_HOST = "$inputRoot\REQUIRED_windows-host.evidence"
  WORM_CUSTODY = `
    "$inputRoot\REQUIRED_phillip-v6-live-canary-worm-gate-evidence.zip"
}
```

Gunakan exact live account alias dan candidate dari binding/evidence; jangan
masukkan login atau password broker.

```powershell
$sourceArgs = @(
  "--binding", $binding,
  "--trust-policy", $policy,
  "--soak-binding", $soakBinding,
  "--soak-receipt", $soakReceipt,
  "--promotion-receipt", $promotion,
  "--live-account-alias", "REQUIRED_EXACT_LIVE_ACCOUNT_ALIAS",
  "--candidate", "REQUIRED_EXACT_CANDIDATE_ID",
  "--eligibility-review", $eligibilityReview,
  "--regulatory-observation", $regulatoryObservation,
  "--gate-receipt-set", $gateSet,
  "--worm-custody-policy-sha256", $wormPolicySha256
)

foreach ($entry in $gateEvidence.GetEnumerator()) {
  $sourceArgs += @("--gate-evidence", "$($entry.Key)=$($entry.Value)")
}
```

## Prepare exact target-host profile

`REQUIRED_*` di bawah harus berasal dari custody/policy review, bukan tebakan.

```powershell
$profileOutput = @(& $python -B `
  .\manage_live_canary_activation_consumption.py `
  prepare-profile `
  --binding $binding `
  --trust-policy $policy `
  --registry-path $registryPath `
  --profile-id "REQUIRED_EXACT_PROFILE_ID" `
  --registry-id "REQUIRED_EXACT_REGISTRY_ID" `
  --registry-key-id "REQUIRED_EXACT_REGISTRY_KEY_ID" `
  --registry-key-fingerprint-sha256 `
    "REQUIRED_POLICY_REVIEWED_REGISTRY_KEY_FINGERPRINT" `
  --output $profile 2>&1)
$profileExit = $LASTEXITCODE
$profileOutput | ForEach-Object { Write-Host $_ }
if ($profileExit -ne 0) { throw "Replay profile preparation gagal." }

$profileMatch = @(
  $profileOutput |
    ForEach-Object { [regex]::Match([string]$_, '^Profile SHA-256: ([0-9a-f]{64})$') } |
    Where-Object { $_.Success }
)

if ($profileMatch.Count -ne 1) {
  throw "Profile identity output tidak exact satu."
}
$profileSha = $profileMatch[0].Groups[1].Value

if ($profileSha -notmatch '^[0-9a-f]{64}$') {
  throw "Profile identity invalid."
}
```

## Initialize genesis registry

Registry path dan initialization receipt harus sama-sama belum ada.

```powershell
& $python -B .\manage_live_canary_activation_consumption.py `
  initialize `
  --profile $profile `
  --expected-profile-sha256 $profileSha `
  --registry-path $registryPath `
  --binding $binding `
  --trust-policy $policy `
  --output $initialization
if ($LASTEXITCODE -ne 0) {
  throw "Replay registry initialization gagal; preserve seluruh artefak."
}
```

Jika process berhenti setelah registry dibuat tetapi sebelum initialization
receipt terbit, jangan menghapus database, jangan rerun secara buta, dan jangan
membuat receipt manual. Preserve registry/output/log untuk review; gunakan
profile/registry baru hanya setelah insiden ditutup.

## Consume authorization tepat satu kali

Consumption harus selesai sebelum authorization/request/evidence window
kedaluwarsa. Predecessor pertama adalah initialization receipt; consumption
berikutnya memakai exact receipt terakhir.

```powershell
& $python -B .\manage_live_canary_activation_consumption.py `
  consume `
  --profile $profile `
  --expected-profile-sha256 $profileSha `
  --registry-path $registryPath `
  --predecessor-receipt $initialization `
  --authorization $authorization `
  @sourceArgs `
  --output $consumption
if ($LASTEXITCODE -ne 0) {
  throw "Consumption gagal; periksa apakah event sudah committed sebelum retry."
}
```

Predecessor diverifikasi lagi secara atomik di dalam transaksi SQLite sebelum
`INSERT`. Dua authorization berbeda yang berangkat dari predecessor yang sama
tidak dapat sama-sama menambah event.

## Independent verification

Verification bersifat read-only dan tetap dapat memverifikasi event historis
setelah authorization kedaluwarsa, karena waktu konsumsi diambil dari event
HMAC-authenticated. Event yang bertanggal lebih baru dari trusted clock tetap
ditolak.

```powershell
& $python -B .\manage_live_canary_activation_consumption.py `
  verify `
  --profile $profile `
  --expected-profile-sha256 $profileSha `
  --registry-path $registryPath `
  --predecessor-receipt $initialization `
  --authorization $authorization `
  @sourceArgs `
  --receipt $consumption
if ($LASTEXITCODE -ne 0) { throw "Consumption verification gagal." }
```

## Recovery setelah publication failure

Gunakan recovery hanya bila consumption mungkin sudah committed tetapi output
tidak terbit. Jangan menjalankan `consume` kedua kali. Destination recovery
harus path baru yang belum ada.

```powershell
$recovered = "$outputRoot\live-canary-activation-consumption-recovered.json"

& $python -B .\manage_live_canary_activation_consumption.py `
  recover `
  --profile $profile `
  --expected-profile-sha256 $profileSha `
  --registry-path $registryPath `
  --predecessor-receipt $initialization `
  --authorization $authorization `
  @sourceArgs `
  --output $recovered
if ($LASTEXITCODE -ne 0) { throw "Consumption recovery gagal." }
```

Recovery hanya menerima authorization sebagai exact current registry head,
merekonstruksi receipt yang sama tanpa event baru, dan tidak menimpa file yang
sudah ada. Hash seluruh profile, predecessor, authorization, consumption, serta
successor checkpoint harus dipindahkan ke custody eksternal sesuai policy.

## Batas tahap berikutnya

Receipt konsumsi bukan izin order. Sebelum canary pertama masih diperlukan:

1. provider-bound prebootstrap admission autentik pada exact Windows host;
2. independently signed provider acceptance dan WORM/CAS readback;
3. launch-session/capability yang current dan one-use;
4. central LIVE policy unlock melalui ceremony terpisah;
5. per-order risk, news, account fence, journal, reconciliation, dan rollback;
6. bounded first canary dengan lot maksimum 0.01 dan satu posisi.
