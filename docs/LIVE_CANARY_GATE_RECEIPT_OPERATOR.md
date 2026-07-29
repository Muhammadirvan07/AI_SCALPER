# LIVE Canary Gate Receipt Operator

Status: **IMPLEMENTED LOCALLY / NINE EXTERNAL REVIEWS REQUIRED / DENY-ONLY**

Workflow ini menerbitkan dan memverifikasi sembilan receipt gate eksternal
yang diwajibkan oleh activation core. Workflow ini tidak membuat activation
request, tidak membuka central policy, tidak menginisialisasi MT5, dan tidak
mengirim order. Semua output tetap `Live allowed: false` dan
`Order capability: DISABLED`.

## Prasyarat wajib

- Gunakan exact extracted `WINDOWS_SHADOW_DEPLOYMENT_TOOLING_V1` release yang
  manifest, commit, release identity, ukuran, dan SHA-256 seluruh membernya
  sudah diverifikasi sesuai bagian 1
  [LIVE_CANARY_BROKER_ELIGIBILITY_REVIEW.md](LIVE_CANARY_BROKER_ELIGIBILITY_REVIEW.md).
- `binding.json` dan `trust-policy.json` harus berasal dari review aktivasi
  terpisah. Jangan membuatnya dari nilai fixture atau menebak identitas LIVE.
- Sembilan key ID pada trust policy harus sudah diprovision secara terpisah di
  Windows Credential Manager dan fingerprint setiap key harus persis cocok.
- Delapan domain non-legal memerlukan delapan file evidence berbeda, dari
  owner/reviewer sebenarnya, dengan path dan byte hash yang berbeda.
- `LEGAL_COMPLIANCE` hanya menerima assembled broker-eligibility review yang
  masih valid dan exact regulatory observation asalnya. File legal generik
  sengaja ditolak.
- Receipt maksimal berlaku 30 hari, tetapi sebaiknya dibatasi sesingkat
  mungkin. Semua receipt dan eligibility harus mencakup `$requiredUntil`.

## 1. Tentukan exact input dan output baru

Jalankan setelah verifikasi extracted release selesai dan `Set-Location
$operatorRoot` sudah dilakukan.

```powershell
$python = "C:\AI_SCALPER\.venv\Scripts\python.exe"
$candidate = "phillip-commodity"

$binding = Read-Host "Path canonical reviewed live-canary binding.json"
$policy = Read-Host "Path canonical reviewed live-canary trust-policy.json"
$eligibilityReview = Read-Host "Path assembled LIVE broker eligibility review"
$regulatoryObservation = Read-Host "Path exact signed regulatory observation"

$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$gateRoot = "C:\AI_SCALPER_PRIVATE\live-canary-gates-$stamp"
if (Test-Path $gateRoot) {
  throw "Gate root sudah ada; jangan overwrite evidence."
}
New-Item -ItemType Directory $gateRoot | Out-Null

$expiresAt = [DateTimeOffset]::UtcNow.AddDays(7).ToString(
  "yyyy-MM-ddTHH:mm:ss.ffffffZ"
)
$requiredUntil = [DateTimeOffset]::UtcNow.AddHours(4).ToString(
  "yyyy-MM-ddTHH:mm:ss.ffffffZ"
)

$evidence = [ordered]@{
  BACKUP_RESTORE = Read-Host "Path signed backup/restore evidence"
  FAILURE_DRILL = Read-Host "Path signed failure-drill evidence"
  LIVE_BROKER_ACCOUNT = Read-Host "Path reviewed LIVE broker-account evidence"
  OPERATIONAL_ROLLBACK = Read-Host "Path signed rollback evidence"
  SECURITY = Read-Host "Path signed security evidence"
  SINGLE_ACCOUNT_SCOPE = Read-Host "Path signed single-account-scope evidence"
  WINDOWS_HOST = Read-Host "Path signed Windows-host evidence"
  WORM_CUSTODY = Read-Host "Path signed WORM-custody evidence"
}

$receipt = @{}
foreach ($domain in $evidence.Keys) {
  $receipt[$domain] = Join-Path $gateRoot (
    $domain.ToLowerInvariant() + "-receipt.json"
  )
}
$receipt["LEGAL_COMPLIANCE"] = Join-Path $gateRoot `
  "legal-compliance-receipt.json"
$receiptSet = Join-Path $gateRoot "live-canary-gate-receipt-set.json"
```

## 2. Terbitkan delapan receipt berbasis exact file bytes

`$issuerId` harus merupakan ID issuer/reviewer yang benar untuk domain itu.
Satu operator tidak boleh mengaku sebagai sembilan authority independen.

```powershell
foreach ($domain in $evidence.Keys) {
  $issuerId = Read-Host "Masukkan exact issuer ID untuk $domain"

  & $python -B .\sign_live_canary_gate_receipt.py `
    --domain $domain `
    --binding $binding `
    --trust-policy $policy `
    --issuer-id $issuerId `
    --expires-at-utc $expiresAt `
    --evidence $evidence[$domain] `
    --output $receipt[$domain]

  if ($LASTEXITCODE -ne 0) {
    throw "Signing $domain gagal; safety lock tetap aktif."
  }
}
```

## 3. Terbitkan receipt `LEGAL_COMPLIANCE`

```powershell
$legalIssuer = Read-Host "Masukkan exact LEGAL_COMPLIANCE issuer ID"

& $python -B .\sign_live_canary_gate_receipt.py `
  --domain LEGAL_COMPLIANCE `
  --binding $binding `
  --trust-policy $policy `
  --issuer-id $legalIssuer `
  --expires-at-utc $expiresAt `
  --candidate $candidate `
  --eligibility-review $eligibilityReview `
  --regulatory-observation $regulatoryObservation `
  --output $receipt["LEGAL_COMPLIANCE"]

if ($LASTEXITCODE -ne 0) {
  throw "LEGAL_COMPLIANCE receipt gagal; safety lock tetap aktif."
}
```

## 4. Verifikasi setiap receipt secara independen

```powershell
foreach ($domain in $evidence.Keys) {
  & $python -B .\verify_live_canary_gate_receipt.py `
    --domain $domain `
    --binding $binding `
    --trust-policy $policy `
    --receipt $receipt[$domain] `
    --required-until-utc $requiredUntil `
    --evidence $evidence[$domain]

  if ($LASTEXITCODE -ne 0) {
    throw "Verification $domain gagal."
  }
}

& $python -B .\verify_live_canary_gate_receipt.py `
  --domain LEGAL_COMPLIANCE `
  --binding $binding `
  --trust-policy $policy `
  --receipt $receipt["LEGAL_COMPLIANCE"] `
  --required-until-utc $requiredUntil `
  --candidate $candidate `
  --eligibility-review $eligibilityReview `
  --regulatory-observation $regulatoryObservation

if ($LASTEXITCODE -ne 0) {
  throw "Verification LEGAL_COMPLIANCE gagal."
}
```

## 5. Assemble dan verifikasi exact nine-domain set

```powershell
$assembleArgs = @(
  "-B", ".\assemble_live_canary_gate_receipt_set.py",
  "--binding", $binding,
  "--trust-policy", $policy,
  "--candidate", $candidate,
  "--eligibility-review", $eligibilityReview,
  "--regulatory-observation", $regulatoryObservation,
  "--required-until-utc", $requiredUntil,
  "--output", $receiptSet
)
foreach ($domain in $receipt.Keys) {
  $assembleArgs += @("--receipt", "$domain=$($receipt[$domain])")
}
foreach ($domain in $evidence.Keys) {
  $assembleArgs += @("--evidence", "$domain=$($evidence[$domain])")
}
& $python @assembleArgs
if ($LASTEXITCODE -ne 0) { throw "Receipt-set assembly gagal." }

$verifyArgs = @(
  "-B", ".\verify_live_canary_gate_receipt_set.py",
  "--binding", $binding,
  "--trust-policy", $policy,
  "--receipt-set", $receiptSet,
  "--candidate", $candidate,
  "--eligibility-review", $eligibilityReview,
  "--regulatory-observation", $regulatoryObservation,
  "--required-until-utc", $requiredUntil
)
foreach ($domain in $evidence.Keys) {
  $verifyArgs += @("--evidence", "$domain=$($evidence[$domain])")
}
& $python @verifyArgs
if ($LASTEXITCODE -ne 0) { throw "Receipt-set verification gagal." }

@($receipt.Values) + @($receiptSet) |
  Get-FileHash -Algorithm SHA256
```

Sukses wajib melaporkan `Receipts verified: 9`, tetapi tetap:

- `Live allowed: false`
- `Order capability: DISABLED`
- `Broker mutation: NOT_PERFORMED`

Receipt set ini baru menutup sembilan input gate eksternal. Activation request,
tiga approval manusia, deployment authorization, replay checkpoint, provider
acceptance, WORM/CAS custody, central unlock, one-use launch capability, dan
per-order authority masih merupakan gate terpisah.
