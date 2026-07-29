# LIVE Canary Broker Eligibility Review

Status: **IMPLEMENTED LOCALLY / HUMAN REVIEW REQUIRED / DENY-ONLY**

Workflow ini mengubah signed diagnostic regulatory observation menjadi bukti
eligibility yang dapat dikonsumsi boundary aktivasi LIVE-canary. Workflow ini
tidak mengaktifkan trading, tidak membuka central unlock, dan tidak mengirim
order.

Approval lama `COMPLIANCE_REVIEW` dan `LEGAL_REVIEW` hanya menyetujui
`DIAGNOSTIC_EVIDENCE_REGISTRATION_REVIEW_ONLY`. Keduanya diverifikasi ulang
sebagai source, tetapi tidak boleh digunakan sebagai approval LIVE. Dua orang
berbeda harus menandatangani keputusan baru dengan role:

- `LIVE_CANARY_COMPLIANCE_REVIEW`
- `LIVE_CANARY_LEGAL_REVIEW`

Kedua reviewer baru, key ID, fingerprint, dan key material harus berbeda satu
sama lain dan dari dua authority diagnostic lama.

## Prasyarat Windows

- Jalankan dari exact Windows shadow deployment-tooling release yang telah
  diverifikasi hash/manifest-nya.
- File signed observation harus tersedia sebagai file private, misalnya
  `C:\AI_SCALPER_PRIVATE\phillip-commodity-review\regulatory-observation.json`.
- Empat key diagnostic/LIVE disimpan hanya di Windows Credential Manager.
- `$liveServer` harus diisi dari exact broker LIVE-account evidence. Jangan
  menyalin nilai fixture atau menebak nama server.
- Reviewer harus benar-benar independen. ID palsu atau ID diagnostic lama tidak
  boleh dipakai.

## 1. Siapkan directory immutable

```powershell
cd C:\AI_SCALPER
.\.venv\Scripts\Activate.ps1

$candidate = "phillip-commodity"
$brokerId = "phillip-jp"
$liveServer = Read-Host "Masukkan exact LIVE server dari reviewed account evidence"
$observation = "C:\AI_SCALPER_PRIVATE\phillip-commodity-review\regulatory-observation.json"
$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$reviewRoot = "C:\AI_SCALPER_PRIVATE\phillip-live-eligibility-$stamp"

if (Test-Path $reviewRoot) {
  throw "Review root sudah ada; jangan overwrite evidence."
}

New-Item -ItemType Directory $reviewRoot | Out-Null
$body = "$reviewRoot\review-body.json"
$compliance = "$reviewRoot\live-compliance-approval.json"
$legal = "$reviewRoot\live-legal-approval.json"
$review = "$reviewRoot\assembled-review.json"
$expiresAt = [DateTimeOffset]::UtcNow.AddDays(14).ToString(
  "yyyy-MM-ddTHH:mm:ssZ"
)
```

## 2. Prepare exact pending body

```powershell
python -B .\prepare_live_canary_broker_eligibility_review.py `
  --candidate $candidate `
  --broker-id $brokerId `
  --live-server $liveServer `
  --registration-authority JAPAN-FSA `
  --registration-identifier KANTO-KINSHO-127 `
  --expires-at-utc $expiresAt `
  --regulatory-observation $observation `
  --output $body

if ($LASTEXITCODE -ne 0) {
  throw "Prepare eligibility gagal; safety lock tetap aktif."
}
```

## 3. Provision dua dedicated key

```powershell
python -B .\setup_live_canary_broker_eligibility_review_key.py `
  --candidate $candidate `
  --role LIVE_CANARY_COMPLIANCE_REVIEW

if ($LASTEXITCODE -ne 0) { throw "Setup compliance key gagal." }

python -B .\setup_live_canary_broker_eligibility_review_key.py `
  --candidate $candidate `
  --role LIVE_CANARY_LEGAL_REVIEW

if ($LASTEXITCODE -ne 0) { throw "Setup legal key gagal." }
```

## 4. Dua reviewer independen menandatangani

```powershell
$complianceReviewer = Read-Host "ID LIVE compliance reviewer yang sebenarnya"
$legalReviewer = Read-Host "ID LIVE legal reviewer yang sebenarnya"

if ($complianceReviewer -eq $legalReviewer) {
  throw "Reviewer LIVE compliance dan legal harus berbeda."
}

python -B .\sign_live_canary_broker_eligibility_review.py `
  --candidate $candidate `
  --role LIVE_CANARY_COMPLIANCE_REVIEW `
  --approver-id $complianceReviewer `
  --review-body $body `
  --regulatory-observation $observation `
  --output $compliance

if ($LASTEXITCODE -ne 0) { throw "LIVE compliance approval gagal." }

python -B .\sign_live_canary_broker_eligibility_review.py `
  --candidate $candidate `
  --role LIVE_CANARY_LEGAL_REVIEW `
  --approver-id $legalReviewer `
  --review-body $body `
  --regulatory-observation $observation `
  --output $legal

if ($LASTEXITCODE -ne 0) { throw "LIVE legal approval gagal." }
```

## 5. Assemble dan verifikasi ulang

```powershell
python -B .\assemble_live_canary_broker_eligibility_review.py `
  --candidate $candidate `
  --review-body $body `
  --regulatory-observation $observation `
  --compliance-approval $compliance `
  --legal-approval $legal `
  --output $review

if ($LASTEXITCODE -ne 0) { throw "Assembly eligibility gagal." }

python -B .\verify_live_canary_broker_eligibility_review.py `
  --candidate $candidate `
  --review $review `
  --regulatory-observation $observation

if ($LASTEXITCODE -ne 0) { throw "Verification eligibility gagal." }

Get-FileHash $body, $compliance, $legal, $review -Algorithm SHA256
```

Output sukses wajib tetap menyatakan:

- `Separate LEGAL_COMPLIANCE gate required: true`
- `Live allowed: false`
- `Order capability: DISABLED`

Review yang valid hanya menyediakan exact
`LiveCanaryBrokerEligibilityEvidence`. Tahap berikutnya masih memerlukan gate
`LEGAL_COMPLIANCE` yang mengikat hash evidence tersebut, seluruh external
provider/custody/Windows acceptance, tiga human activation approvals, central
unlock, one-use authorization, dan per-order authorization.
