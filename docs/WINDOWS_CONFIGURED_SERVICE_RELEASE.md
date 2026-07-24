# Windows Configured Service Release

Status: **PACKAGING FOUNDATION READY / ACTIVATION AUTHORITY ABSENT**

Decision, execution, dan status-monitor base release sengaja tidak membawa
factory, service config, atau provider deployment-specific. File tersebut juga
tidak boleh disalin ke release setelah ekstraksi karena exact release inventory
akan menolaknya. Solusinya adalah membuat configured release dengan identity
baru sebelum deployment.

Configured release tetap mempertahankan:

```text
live_allowed=false
safe_to_demo_auto_order=false
max_lot=0.01
production_execution_ready=false
```

Execution configured release boleh melaporkan
`order_capability=GATED_PRESENT` karena base executor memang mengandung adapter
tersegel. Itu bukan izin mengirim order.

## Artefak

Repository menyediakan:

- `build_windows_configured_release_tooling.py`: membangun bundle operator
  minimal dan stdlib-only dari clean Git commit;
- `prepare_windows_configured_overlay_candidate.py`: menurunkan template hash
  dari exact base ZIP, membuat factory manifest serta descriptor kandidat
  secara create-exclusive, dan menjalankan static safety validation tanpa
  mengimpor provider;
- `build_windows_configured_service_release.py`: menggabungkan exact base ZIP
  dengan exact overlay;
- `verify_windows_configured_service_release.py`: verifier offline yang
  memerlukan pin configured identity dan base identity;
- `live_runtime/configured_service_release.py`: builder/verifier fail-closed;
- `config/windows_configured_release_tooling_allowlist.v1.json`: exact tooling
  inventory; dan
- `specs/windows_configured_service_release_v1.md` serta
  `specs/windows_configured_overlay_candidate_preparation_v1.md`: kontrak
  normatif.

Tooling ini terpisah dari generic deployment tooling. Generic bundle tetap
menolak byte `order_send/order_check`; configured verifier hanya menyebut nama
tersebut sebagai aturan penolakan dan tidak memiliki executable broker call.

## Overlay non-secret

Satu overlay berisi tepat:

```text
reviewed_windows_factory.py
configured_providers/__init__.py
configured_providers/<reviewed-provider>.py
config/windows_service_config.json
config/windows_factory_manifest.json
```

Exact daftar sebenarnya ditetapkan oleh descriptor
`windows-configured-service-overlay-v1`. Descriptor mengikat:

- base profile dan base release identity;
- runtime mode `DEMO` atau `DEMO_AUTO`;
- exact factory/config/manifest path;
- setiap provider path, ukuran, dan SHA-256;
- reviewed factory-template SHA-256;
- Task Scheduler definition SHA-256;
- factory contract serta bootstrap binding melalui factory manifest; dan
- seluruh safety lock false/`0.01`.

Overlay tidak boleh mengandung password, login, token, private key, permit,
environment arm, credential value, atau account secret. Credential Manager
references boleh berada dalam reviewed configuration hanya bila nilainya tidak
ditanamkan dan kontrak factory yang terpisah mengizinkannya.

## Prepare candidate manifest dan descriptor

Sebelum perintah ini dijalankan, reviewer eksternal harus menyediakan exact
factory, service config, provider source, Task Scheduler definition, serta
`bootstrap_binding_sha256`. Jangan menaruh credential value di salah satu file.
Candidate overlay awal harus belum memiliki
`config/windows_factory_manifest.json`.

Jalankan preparer dari configured-release operator tooling yang sudah
diekstrak. Contoh untuk decision service:

```powershell
python -I -S -B .\prepare_windows_configured_overlay_candidate.py `
  --base-release C:\AI_SCALPER_RELEASES\decision-base.zip `
  --overlay-root C:\AI_SCALPER_PRIVATE\decision-overlay `
  --task-definition C:\AI_SCALPER_PRIVATE\tasks\decision-task.xml `
  --overlay-id decision-demo-auto-window-01 `
  --bootstrap-binding-sha256 <EXACT_NON_ZERO_BOOTSTRAP_BINDING_SHA256> `
  --runtime-mode DEMO_AUTO `
  --descriptor-output C:\AI_SCALPER_PRIVATE\decision-overlay.json
```

Ulangi dengan base, overlay, task definition, ID, bootstrap binding, dan output
yang terpisah untuk execution serta status monitor. Preparer:

- memverifikasi canonical base ZIP dan memilih factory-template member sesuai
  profile secara otomatis;
- stable-read dan mengikat exact Task Scheduler bytes;
- menolak file tambahan, symlink/reparse, collision, noncanonical/secret JSON,
  missing import closure, unsafe Python, dynamic code/process/native loader,
  serta order primitive;
- membuat factory manifest dan descriptor secara create-exclusive; dan
- tetap melaporkan `CANDIDATE_PREPARED_EXTERNAL_REVIEW_REQUIRED`,
  `configured_release_built=false`, serta seluruh execution lock false.

Output ini belum berarti provider diterima. Review source serta seluruh hash
secara independen sebelum memakai descriptor pada configured-release builder.
Jika kandidat perlu diubah, gunakan directory dan overlay ID baru; jangan
menimpa manifest atau descriptor lama.

## Build tooling release

Jalankan pada clean checkout Windows; output harus di luar repository:

```powershell
python -B .\build_windows_configured_release_tooling.py `
  --output C:\AI_SCALPER_RELEASES\configured-release-tooling-v1.zip
```

Bangun dua kali pada environment independen dan bandingkan SHA-256 serta
release identity melalui reproducibility process yang sama dengan release
lain. Bundle ini hanya untuk release operator, bukan service account.

## Build configured release

Ekstrak tooling bundle ke operator-only directory. Untuk setiap process,
gunakan base release dan overlay yang berbeda:

```powershell
python -I -S -B .\build_windows_configured_service_release.py `
  --base-release C:\AI_SCALPER_RELEASES\decision-base.zip `
  --overlay-root C:\AI_SCALPER_PRIVATE\decision-overlay `
  --descriptor C:\AI_SCALPER_PRIVATE\decision-overlay.json `
  --output C:\AI_SCALPER_RELEASES\decision-configured.zip

python -I -S -B .\build_windows_configured_service_release.py `
  --base-release C:\AI_SCALPER_RELEASES\execution-base.zip `
  --overlay-root C:\AI_SCALPER_PRIVATE\execution-overlay `
  --descriptor C:\AI_SCALPER_PRIVATE\execution-overlay.json `
  --output C:\AI_SCALPER_RELEASES\execution-configured.zip

python -I -S -B .\build_windows_configured_service_release.py `
  --base-release C:\AI_SCALPER_RELEASES\status-monitor-base.zip `
  --overlay-root C:\AI_SCALPER_PRIVATE\status-monitor-overlay `
  --descriptor C:\AI_SCALPER_PRIVATE\status-monitor-overlay.json `
  --output C:\AI_SCALPER_RELEASES\status-monitor-configured.zip
```

Builder memverifikasi base manifest, byte-deterministic base ZIP, exact
overlay, factory contract, full inheritance, configured identity, dan archive
hasil sebelum menulis output create-exclusive.

## Independent verification

Pin identity dari reviewed off-host release receipt, bukan dari ZIP yang sedang
diverifikasi:

```powershell
python -I -S -B .\verify_windows_configured_service_release.py `
  --archive C:\AI_SCALPER_RELEASES\execution-configured.zip `
  --expected-release-identity-sha256 <REVIEWED_CONFIGURED_IDENTITY> `
  --expected-base-release-identity-sha256 <REVIEWED_BASE_IDENTITY>
```

Ulangi untuk ketiga release. Verifier tidak mengimpor factory dan tidak
mematerialisasi provider.

## Deployment rule

- Ekstrak **configured ZIP**, bukan base ZIP, ke read-only service root.
- Factory manifest yang diberikan ke launcher harus merupakan member exact di
  dalam configured release root.
- Launcher policy/attestation dan operations review v2 harus mengikat
  configured identity. Base identity tetap disimpan sebagai provenance tetapi
  tidak boleh dipakai sebagai identity proses akhir.
- Decision, execution, dan status-monitor release harus memiliki root, service
  identity, state directory, factory, provider set, dan launcher attestation
  terpisah.
- Current decision runner masih validate-only; configured decision packaging
  tidak mengubahnya menjadi production launcher.
- Jangan mengubah ZIP, manifest, overlay, atau factory setelah build. Perubahan
  apa pun memerlukan descriptor, configured identity, review, dan attestation
  baru.

## Batas yang tetap eksternal

Configured packaging tidak menyediakan provider implementation yang telah
diterima, Credential Manager custody, trusted clock, signed news, IPC/CAS,
WORM, heartbeat, Task Scheduler ACL, offline RSA issuer, Windows acceptance,
manual-demo evidence, policy unlock, atau soak evidence. Seluruhnya tetap
merupakan gate terpisah.
