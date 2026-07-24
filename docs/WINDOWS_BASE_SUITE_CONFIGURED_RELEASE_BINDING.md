# Windows Base-Suite Configured-Release Binding

Status: **PROVENANCE FOUNDATION READY / ACTIVATION STILL BLOCKED**

Configured decision, execution, dan status-monitor release untuk candidate baru
wajib berasal dari tiga role yang tepat di dalam satu atomic five-role base
suite. Kesamaan Git commit/tree saja tidak lagi cukup.

Verifier sekarang membuktikan:

- `BASE_RELEASE_SUITE.json` canonical dan identitasnya valid;
- kelima ZIP serta sidecar ada, deterministic, dan cocok hash/ukurannya;
- decision, execution, dan status-monitor configured release menunjuk role
  suite yang tepat;
- ketiganya mengikat suite identity dan suite-manifest hash yang sama; dan
- read-only shadow serta configured-release tooling ikut ada dan utuh.

Semua lock tetap:

```text
live_allowed=false
safe_to_demo_auto_order=false
max_lot=0.01
promotion_eligible=false
production_execution_ready=false
```

## Build configured releases

Jalankan setelah atomic suite selesai dibangun dari satu clean commit:

```powershell
$suiteRoot = "C:\AI_SCALPER_RELEASES\<COMMIT>\base-release-suite-v1"

python -I -S -B .\build_windows_configured_service_release.py `
  --base-release-suite-root $suiteRoot `
  --base-release "$suiteRoot\decision-base-v1.zip" `
  --overlay-root C:\AI_SCALPER_PRIVATE\decision-overlay `
  --descriptor C:\AI_SCALPER_PRIVATE\decision-overlay.json `
  --output C:\AI_SCALPER_RELEASES\<COMMIT>\decision-configured-v1.zip

python -I -S -B .\build_windows_configured_service_release.py `
  --base-release-suite-root $suiteRoot `
  --base-release "$suiteRoot\execution-base-v1.zip" `
  --overlay-root C:\AI_SCALPER_PRIVATE\execution-overlay `
  --descriptor C:\AI_SCALPER_PRIVATE\execution-overlay.json `
  --output C:\AI_SCALPER_RELEASES\<COMMIT>\execution-configured-v1.zip

python -I -S -B .\build_windows_configured_service_release.py `
  --base-release-suite-root $suiteRoot `
  --base-release "$suiteRoot\status-monitor-base-v1.zip" `
  --overlay-root C:\AI_SCALPER_PRIVATE\status-monitor-overlay `
  --descriptor C:\AI_SCALPER_PRIVATE\status-monitor-overlay.json `
  --output C:\AI_SCALPER_RELEASES\<COMMIT>\status-monitor-configured-v1.zip
```

Base ZIP di luar `$suiteRoot`, path alias, symlink/reparse, role tertukar,
supporting artifact yang hilang, atau hash suite yang berubah ditolak.

## Evidence and pre-manual admission

Setelah tiga configured release selesai, buat operations plan/review, susun
provider-conformance v2, dan dapatkan independent validation receipt serta
sembilan signed pre-manual observations. Baru setelah semuanya tersedia,
gunakan suite root yang sama untuk admission:

```powershell
python -B .\verify_windows_pre_manual_configured_release_admission.py `
  --base-release-suite-root $suiteRoot `
  --decision-release C:\AI_SCALPER_RELEASES\<COMMIT>\decision-configured-v1.zip `
  --execution-release C:\AI_SCALPER_RELEASES\<COMMIT>\execution-configured-v1.zip `
  --status-monitor-release C:\AI_SCALPER_RELEASES\<COMMIT>\status-monitor-configured-v1.zip `
  --review-bundle <EXACT_THREE_SERVICE_REVIEW_V3_JSON> `
  --trust-policy <PINNED_PUBLIC_POLICY_JSON> `
  --observations <SIGNED_PRE_MANUAL_OBSERVATIONS_JSON> `
  --expected-policy-sha256 <INDEPENDENTLY_PINNED_SHA256> `
  --checked-at-utc <YYYY-MM-DDTHH:MM:SS.ffffffZ> `
  --output <NEW_IMMUTABLE_ADMISSION_REPORT_JSON>
```

Report complete hanya meminta review aktivasi manual-demo. Report tidak
mengizinkan order, tidak memasang task, tidak membaca credential, dan tidak
mengubah flag.

## Status artefak lama

Tiga base ZIP dari commit `d153361` yang sudah diverifikasi tetap valid sebagai
historical evidence untuk commit tersebut. Karena dibangun secara terpisah dan
tidak memiliki binding ke atomic five-role suite baru, artefak itu tidak boleh
dipakai untuk configured-release candidate atau pre-manual admission baru.

Candidate berikutnya harus dibangun ulang setelah source binding ini masuk ke
clean commit yang sama pada Mac dan Windows.
