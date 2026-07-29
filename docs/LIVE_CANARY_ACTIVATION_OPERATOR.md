# LIVE Canary Activation Operator V1

Status: **DENY-ONLY / OPERATOR EVIDENCE / NOT AN ORDER AUTHORIZATION**

Workflow ini membuat tiga jenis artefak canonical yang sebelumnya hanya dapat
dibentuk in-memory: request activation, tiga human approval terpisah, dan satu
deployment authorization. Seluruh output tetap memiliki `live_allowed=false`,
`activation_authorized=false`, dan `order_capability=DISABLED`.

Workflow ini tidak mengubah `execution_policy.LIVE_ALLOWED`, tidak mengonsumsi
replay registry, tidak membuat launch capability, tidak membuka MT5, dan tidak
mengirim order. Artefak asli harus berasal dari review independen; jangan
mengisi server, account, reviewer, key, hash, atau evidence dengan tebakan.

## Prasyarat

- Gunakan exact committed operator ZIP profile
  `WINDOWS_SHADOW_DEPLOYMENT_TOOLING_V1` yang sudah diverifikasi manifest dan
  hash-nya.
- Semua source JSON harus canonical, current, create-exclusive, dan berasal
  dari ceremony yang direview.
- Delapan source gate non-legal harus berupa delapan file berbeda.
  `LEGAL_COMPLIANCE` tidak diberikan sebagai file; hash-nya diturunkan dari
  broker-eligibility evidence yang diverifikasi ulang.
- Key cohort, promotion, eligibility, sembilan gate, tiga approval, dan
  deployment harus sudah ada di Windows Credential Manager dengan exact key ID
  dan fingerprint yang dipin trust policy. Tool ini tidak membuat atau
  mengekspor key tersebut.
- Selesaikan seluruh ceremony request/approval/authorization dalam window
  request maksimal lima menit.

## Variabel input Windows

Jalankan PowerShell dari root operator yang diekstrak. Ganti seluruh nilai
`REQUIRED_*` dengan path artefak autentik yang telah direview.

```powershell
$operatorRoot = "C:\AI_SCALPER_PRIVATE\live-canary-activation-operator"
Set-Location $operatorRoot

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

$gateEvidence = [ordered]@{
  BACKUP_RESTORE = "$inputRoot\REQUIRED_backup-restore.evidence"
  FAILURE_DRILL = "$inputRoot\REQUIRED_failure-drill.evidence"
  LIVE_BROKER_ACCOUNT = "$inputRoot\REQUIRED_live-broker-account.evidence"
  OPERATIONAL_ROLLBACK = "$inputRoot\REQUIRED_operational-rollback.evidence"
  SECURITY = "$inputRoot\REQUIRED_security.evidence"
  SINGLE_ACCOUNT_SCOPE = "$inputRoot\REQUIRED_single-account-scope.evidence"
  WINDOWS_HOST = "$inputRoot\REQUIRED_windows-host.evidence"
  WORM_CUSTODY = "$inputRoot\REQUIRED_worm-custody.evidence"
}

$required = @(
  $binding, $policy, $soakBinding, $soakReceipt, $promotion,
  $eligibilityReview, $regulatoryObservation, $gateSet
) + @($gateEvidence.Values)

foreach ($path in $required) {
  if (-not (Test-Path $path -PathType Leaf)) {
    throw "Required artifact tidak ditemukan: $path"
  }
}
```

## Assemble dan verifikasi request

```powershell
$request = "$outputRoot\live-canary-activation-request.json"
$expiresAtUtc = [DateTimeOffset]::UtcNow.AddMinutes(4).ToString(
  "yyyy-MM-ddTHH:mm:ss.ffffffZ"
)
$nonce = "live-canary-" + [Guid]::NewGuid().ToString("N")

$requestSources = @(
  "--binding", $binding,
  "--trust-policy", $policy,
  "--soak-binding", $soakBinding,
  "--soak-receipt", $soakReceipt,
  "--promotion-receipt", $promotion,
  "--live-account-alias", "REQUIRED_EXACT_LIVE_ACCOUNT_ALIAS",
  "--candidate", "REQUIRED_EXACT_CANDIDATE_ID",
  "--eligibility-review", $eligibilityReview,
  "--regulatory-observation", $regulatoryObservation,
  "--gate-receipt-set", $gateSet
)

foreach ($entry in $gateEvidence.GetEnumerator()) {
  $requestSources += @("--gate-evidence", "$($entry.Key)=$($entry.Value)")
}

python -I -S -B .\assemble_live_canary_activation_request.py `
  @requestSources `
  --expires-at-utc $expiresAtUtc `
  --nonce $nonce `
  --output $request
if ($LASTEXITCODE -ne 0) { throw "Request assembly gagal." }

python -I -S -B .\verify_live_canary_activation_request.py `
  --request $request `
  @requestSources
if ($LASTEXITCODE -ne 0) { throw "Request verification gagal." }
```

`REQUIRED_EXACT_LIVE_ACCOUNT_ALIAS` dan candidate harus cocok dengan binding,
promotion receipt, eligibility evidence, serta tracked configuration. Jangan
menyimpan login/password broker di command line atau JSON.

## Tiga approval independen

Masukkan identitas reviewer sebenarnya yang hash-nya sudah dipin policy.
Ketiga orang, key ID, fingerprint, dan secret harus berbeda.

```powershell
$reviewers = [ordered]@{
  RISK_OWNER = Read-Host "ID reviewer Risk Owner sebenarnya"
  OPERATIONS_OWNER = Read-Host "ID reviewer Operations Owner sebenarnya"
  COMPLIANCE_OWNER = Read-Host "ID reviewer Compliance Owner sebenarnya"
}

$approvalPaths = [ordered]@{}
foreach ($entry in $reviewers.GetEnumerator()) {
  $role = $entry.Key
  $approval = Join-Path $outputRoot "$($role.ToLowerInvariant())-approval.json"

  python -I -S -B .\sign_live_canary_human_approval.py `
    --request $request `
    --trust-policy $policy `
    --role $role `
    --approver-id $entry.Value `
    --output $approval
  if ($LASTEXITCODE -ne 0) { throw "Approval $role gagal." }

  python -I -S -B .\verify_live_canary_human_approval.py `
    --request $request `
    --trust-policy $policy `
    --approval $approval `
    --role $role
  if ($LASTEXITCODE -ne 0) { throw "Verification $role gagal." }

  $approvalPaths[$role] = $approval
}
```

## Assemble dan verifikasi deployment authorization

```powershell
$authorization = "$outputRoot\live-canary-activation-authorization.json"
$approvalArgs = @()
foreach ($entry in $approvalPaths.GetEnumerator()) {
  $approvalArgs += @("--approval", "$($entry.Key)=$($entry.Value)")
}

python -I -S -B .\assemble_live_canary_activation_authorization.py `
  --request $request `
  --trust-policy $policy `
  @approvalArgs `
  --output $authorization
if ($LASTEXITCODE -ne 0) { throw "Authorization assembly gagal." }

python -I -S -B .\verify_live_canary_activation_authorization.py `
  --authorization $authorization `
  --request $request `
  --trust-policy $policy `
  @approvalArgs
if ($LASTEXITCODE -ne 0) { throw "Authorization verification gagal." }

$artifactPaths = @($request) + @($approvalPaths.Values) + @($authorization)
Get-FileHash -LiteralPath $artifactPaths -Algorithm SHA256
```

Status sukses hanya membuktikan consistency/HMAC ceremony. Authorization ini
masih deny-only dan belum boleh diberikan ke MT5 atau dianggap sebagai izin
trading. Tahap terpisah masih memerlukan one-use replay consumption, off-host
checkpoint/WORM/CAS custody, accepted target-host provider closure, central
unlock ceremony, per-order risk/news/reconciliation checks, dan bounded first
canary.
