# Windows Pre-Manual Configured-Release Admission

Admission ini menutup celah substitusi artefak antara tiga configured release
dan dossier operasi Windows v3. Verifier configured-release dan verifier
pre-manual sebelumnya sama-sama ketat, tetapi dapat dijalankan sebagai dua
langkah terpisah. Akibatnya, operator masih dapat memilih ZIP valid yang bukan
ZIP persis yang hash-nya tercatat di dossier.

`verify_windows_pre_manual_configured_release_admission.py` sekarang melakukan
satu pemeriksaan atomik:

1. merekonstruksi dossier operasi tiga-service v3;
2. membaca masing-masing ZIP decision, execution, dan status monitor satu kali
   dengan pemeriksaan regular-file, non-symlink/non-reparse, batas 64 MiB, serta
   identitas stat sebelum/sesudah baca;
3. memverifikasi byte yang sama dengan configured-release verifier;
4. mengikat archive, manifest, base/configured identity, profile, runtime mode,
   Git commit/tree, factory contract, factory manifest, service config, dan
   Task Scheduler definition ke role yang tepat di dossier;
5. menjalankan verifier signed pre-manual yang sudah ada; dan
6. menulis report baru secara create-exclusive bila diminta.

Tool ini berada hanya di operator deployment tooling. Ia tidak masuk decision,
execution, status-monitor, configured-service runtime, atau shadow service
release.

## Perintah Windows

Gunakan tiga ZIP configured release yang benar-benar akan diekstrak:

```powershell
python -B .\verify_windows_pre_manual_configured_release_admission.py `
  --decision-release C:\AI_SCALPER_RELEASES\decision-configured.zip `
  --execution-release C:\AI_SCALPER_RELEASES\execution-configured.zip `
  --status-monitor-release C:\AI_SCALPER_RELEASES\status-monitor-configured.zip `
  --review-bundle C:\AI_SCALPER_PRIVATE\operations\three-service-review-v3.json `
  --trust-policy C:\AI_SCALPER_PRIVATE\operations\external-acceptance-policy.json `
  --observations C:\AI_SCALPER_PRIVATE\operations\pre-manual-observations.json `
  --expected-policy-sha256 <INDEPENDENTLY_PINNED_POLICY_SHA256> `
  --checked-at-utc <TRUSTED_CANONICAL_UTC_WITH_6_DIGITS_Z> `
  --output C:\AI_SCALPER_PRIVATE\operations\configured-release-admission.json
```

Exit code `0` berarti seluruh input dapat diverifikasi dan report valid dibuat;
status report tetap wajib diperiksa. Exit code `2` berarti tidak ada admission
yang dapat dipercaya.

Status lengkap hanya:

```text
PRE_MANUAL_CONFIGURED_RELEASE_ADMISSION_COMPLETE_ACTIVATION_REVIEW_REQUIRED
```

Status tersebut hanya meminta review manusia terpisah. Ia bukan authorization,
permit, environment arm, Task Scheduler installation, broker capability, atau
izin demo-auto. Bukti signed yang kurang tetap menghasilkan:

```text
BLOCKED_PRE_MANUAL_CONFIGURED_RELEASE_ADMISSION
```

ZIP tertukar, berubah, salah role/profile, atau berbeda dari dossier membuat
proses ditolak dan output tidak dibuat.

## Safety invariant

Setiap report mempertahankan:

```text
manual_demo_authorized = false
activation_authorized = false
execution_enabled = false
ready_for_demo_auto_soak = false
safe_to_demo_auto_order = false
live_allowed = false
promotion_eligible = false
order_capability = "DISABLED"
max_lot = 0.01
```

Sesudah admission lengkap, manusia masih harus meninjau dan menerbitkan stage
evidence terpisah. Setiap satu dari sepuluh lifecycle manual-demo tetap
membutuhkan approval per-intent, arm satu detik, risk/news/margin checks,
idempotency, broker preflight, server-side SL/TP, reconciliation, dan external
monitor acknowledgement.
