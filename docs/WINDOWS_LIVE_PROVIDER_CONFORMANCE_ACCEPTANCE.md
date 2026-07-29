# Windows LIVE Provider-Conformance External Acceptance

Status: **SOURCE READY / TARGET-WINDOWS EVIDENCE REQUIRED / NON-EXECUTABLE**

Boundary ini menerima tepat satu provider-conformance review v4 yang berisi
68 provider dan terikat ke exact ten-pin LIVE source-bound candidate. Hasil
sukses hanya menetapkan `provider_accepted=true`; ia tetap mewajibkan binding
prebootstrap berikutnya dan tidak membuka activation, credential, MT5,
broker, demo-auto, LIVE, atau order.

Kontrak normatif berada di
[`windows_live_provider_conformance_acceptance_v1.md`](../specs/windows_live_provider_conformance_acceptance_v1.md).

## Bukti yang wajib tersedia

Siapkan seluruh file berikut dari satu exact target Windows dan satu review
yang sama:

1. LIVE source-bound ZIP yang lulus seluruh sepuluh pin independen;
2. atomic base-suite root dan Execution base ZIP yang dipakai verifier;
3. canonical provider-conformance v4 review dengan tepat 68 record;
4. canonical public trust policy yang mengikat review, LIVE archive/binding,
   nested source archive, suite, tiga configured-release identity, target-host
   identity, dan dua RSA public authority yang benar-benar berbeda;
5. signed service-owner acceptance RSA;
6. signed Windows-runtime attestation RSA dari authority/key yang berbeda;
7. exact owner validation receipt bytes;
8. exact runtime provider evidence bytes;
9. exact runtime validation receipt bytes; dan
10. policy SHA-256 serta target-host identity SHA-256 yang dipertahankan lewat
    kanal independen, bukan disalin dari dokumen yang sedang diverifikasi.

Policy dan dua signed document harus compact canonical JSON, boleh diakhiri
satu newline. RSA wajib `RSASSA-PKCS1-v1_5-SHA256`, modulus 3072–8192 bit,
exponent 65537. Private key tidak boleh berada di repository atau operator
tooling ini.

Ketiga evidence file harus regular, non-empty, stabil selama pembacaan, paling
besar 64 MiB, berbeda satu sama lain, dan berbeda dari review. Runtime
observation tidak boleh lebih lama daripada provider evidence terbaru.

## Verifikasi pada Windows

Jalankan dari extracted
`WINDOWS_CONFIGURED_RELEASE_OPERATOR_TOOLING_V1` menggunakan CPython yang
telah lolos dependency-lock verification. Ganti seluruh placeholder dengan
pin yang dipertahankan secara independen:

```powershell
$toolingRoot = "C:\AI_SCALPER_PRIVATE\configured-release-tooling-v1"
$evidenceRoot = "C:\AI_SCALPER_PRIVATE\live-provider-acceptance"
$suiteRoot = "C:\AI_SCALPER_RELEASES\<commit>\base-release-suite-v1"
$executionBase = "$suiteRoot\execution-base-v1.zip"
$output = "$evidenceRoot\live-provider-conformance-acceptance-v1.json"

Set-Location $toolingRoot

& C:\AI_SCALPER\.venv\Scripts\python.exe -I -S -B `
  .\verify_windows_live_provider_conformance_acceptance.py `
  --live-source-bound-candidate "$evidenceRoot\live-source-bound-v1.zip" `
  --base-suite-root $suiteRoot `
  --execution-base-release $executionBase `
  --expected-live-bound-archive-sha256 "<PIN_LIVE_BOUND_SHA256>" `
  --expected-source-bound-archive-sha256 "<PIN_SOURCE_BOUND_SHA256>" `
  --expected-source-archive-sha256 "<PIN_SOURCE_SHA256>" `
  --expected-champion-archive-sha256 "<PIN_CHAMPION_SHA256>" `
  --expected-model-artifact-sha256 "<PIN_MODEL_SHA256>" `
  --expected-training-snapshot-sha256 "<PIN_SNAPSHOT_SHA256>" `
  --expected-config-sha256 "<PIN_CONFIG_SHA256>" `
  --expected-git-commit "<PIN_FULL_GIT_COMMIT>" `
  --expected-git-tree "<PIN_FULL_GIT_TREE>" `
  --expected-suite-identity-sha256 "<PIN_SUITE_SHA256>" `
  --conformance-review "$evidenceRoot\provider-conformance-v4.json" `
  --trust-policy "$evidenceRoot\acceptance-policy.json" `
  --owner-acceptance "$evidenceRoot\owner-acceptance.json" `
  --runtime-attestation "$evidenceRoot\runtime-attestation.json" `
  --owner-validation-receipt "$evidenceRoot\owner-validation-receipt.bin" `
  --runtime-evidence "$evidenceRoot\runtime-provider-evidence.bin" `
  --runtime-validation-receipt "$evidenceRoot\runtime-validation-receipt.bin" `
  --expected-policy-sha256 "<INDEPENDENT_POLICY_SHA256>" `
  --expected-target-host-identity-sha256 "<INDEPENDENT_HOST_SHA256>" `
  --output $output

if ($LASTEXITCODE -ne 0) {
  throw "LIVE provider acceptance gagal; semua execution lock tetap aktif."
}

$result = Get-Content $output -Raw | ConvertFrom-Json
$result | Select-Object `
  status,
  provider_accepted,
  prebootstrap_binding_required,
  execution_enabled,
  live_allowed,
  order_capability,
  content_sha256 | Format-List
```

Expected success:

```text
status = LIVE_PROVIDER_CONFORMANCE_ACCEPTED_PREBOOTSTRAP_BINDING_REQUIRED
provider_accepted = true
prebootstrap_binding_required = true
execution_enabled = false
live_allowed = false
order_capability = DISABLED
```

`provider_accepted=true` tidak boleh ditafsirkan sebagai izin menjalankan
service atau mengirim order. Output ini masih harus diikat oleh kontrak
prebootstrap additive berikutnya. Checked-in central LIVE lock tetap false.

## Fail-closed behavior

CLI keluar dengan kode `2` dan tidak menulis output bila salah satu kondisi
berikut terjadi:

- satu dari sepuluh source pin tidak cocok;
- review bukan exact sealed v4/68-provider reconstruction;
- policy atau host pin eksternal tidak cocok;
- authority/key/fingerprint/public key dipakai ulang;
- signature, TTL, timestamp, count, runtime mode, atau outcome salah;
- evidence hilang, berubah, oversized, indirect, atau hash-nya tidak cocok;
- runtime observation mendahului provider evidence terbaru; atau
- output sudah ada.

Jangan menghapus output lama untuk mengulang verification. Gunakan directory
baru agar evidence dan kegagalan sebelumnya tetap tersedia untuk forensic
review.

## Efek yang tidak dilakukan

Tooling ini tidak:

- membaca Windows Credential Manager atau private key;
- mengimpor/materialisasi provider;
- membuka SQLite atau network;
- menjalankan subprocess, task, atau service;
- menginisialisasi MT5;
- mengubah central policy; atau
- memanggil broker/order primitive.
