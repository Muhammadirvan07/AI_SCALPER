# AI_SCALPER Progress — 2026-07-28

Status: **LOCAL RELEASE CANDIDATE VERIFIED / WINDOWS EVIDENCE PENDING /
DEMO-AUTO BLOCKED / LIVE DO NOT SHIP**

## Outcome

Source dashboard operasional dan boundary custody V6 kini dilacak, diuji, dan
dipublikasikan pada branch `agent/live-grade-phase3`. Commit implementasi yang
menjadi baseline audit incremental ini adalah:

- `22e2616a16666ee9caef3e2f5d8172ba194051f1` — landing operasional
  executive yang fail-closed;
- `d5495260d3a47a4ce7759f044ff7299a79c1970a` — validasi evidence runtime
  dan klasifikasi status negatif yang diperketat;
- `0c5e2ad83b89b48d1b25a31f636c69487357586b` — signed V6 WORM custody
  request/receipt boundary;
- `e367d5e35b9cb84ff87be1d43390b98bad15c2a1` — create-exclusive output
  preservation awal terhadap dangling symlink dan cleanup race;
- `c10d4740ded8d798567a2e27404bfffb6e3fce42` — baseline bersih sebelum
  hardening create-exclusive diperluas ke seluruh publisher release,
  evidence, provider, dan atomic-suite yang relevan.

Remediation lintas publisher yang dicatat pada laporan ini turun langsung
dari baseline `c10d474`. Exact commit dan tree final adalah identitas Git dari
commit yang memuat laporan ini; keduanya harus selalu dipin dari checkout atau
build manifest, bukan ditulis secara self-referential ke source sebelum
commit dibuat.

## Perbaikan yang selesai

- Landing page membedakan readiness operasional, konektivitas, data,
  keputusan, dan trading safety tanpa menyamakan status `NOT_READY` atau
  `INACTIVE` dengan status sehat.
- Guard runtime memvalidasi struktur summary, performance, serta paper-order
  secara lengkap sebelum data dipakai UI.
- Route dashboard tetap GET-only dan loopback-first. Tidak ada credential,
  permit, arm, mutasi Task Scheduler, broker mutation, atau order submission.
- Dokumentasi status utama diperbarui agar tidak lagi menyatakan dashboard
  untracked dan tidak lagi memakai angka regresi 1.575 yang sudah usang.
- Boundary penerimaan pasca-run V6.3 kini tersedia sebagai satu deterministic
  toolkit ZIP. Wrapper menjalankan exact health checker terpin tanpa memulai
  task, lalu membuat satu acceptance ZIP create-exclusive yang mengikat
  scheduler snapshot, health transcript, signed checkpoint terbaru, exact
  audit pair, installation receipt, dan installed task XML.
- Verifier toolkit/acceptance menolak outer-hash atau Git ancestry drift,
  metadata/trailer/inventory ZIP yang tidak kanonis, checkpoint yang belum
  maju, waktu sebelum boundary, task result yang tidak sehat, transcript yang
  tidak sama dengan checkpoint, source/audit mutation, dan custody overclaim.
- Toolkit yang sama kini membuat custody-request ZIP deterministik berisi
  exact acceptance bytes dan canonical request manifest. Boundary receipt
  memerlukan policy hash terpin, RSA 3072–8192 bit, exact destination/provider,
  remote object version, Object Lock `COMPLIANCE`, versioning, content hash,
  serta minimum retention sebelum menerbitkan assessment deny-only.
- Assessment membedakan signed custodian attestation yang tervalidasi dari
  inspeksi API storage langsung. Tidak ada private key, credential, MT5,
  Task Scheduler mutation, order, promotion, atau live authority di toolkit.
- Seluruh output toolkit/custody sekarang diperiksa dengan `lstat` no-follow.
  File, folder, symlink valid, dan dangling symlink yang sudah ada ditolak
  tanpa mutasi; cleanup hanya boleh menghapus regular file exact yang dibuat
  oleh invocation berjalan.
- Kontrak yang sama kini diterapkan ke shared release writer, kelima Windows
  release/sidecar path, configured overlay, secure/evidence/feed publisher,
  provider conformance, provider-pack generator, vulnerability receipt,
  atomic-suite publication lock/staging root, serta Execution/Status Monitor
  configured-candidate cleanup. Identity yang tidak diketahui atau berubah
  berarti preserve-and-fail, bukan unlink. Spesifikasi kanonisnya berada di
  `specs/create_exclusive_output_custody_v1.md`.
- Fresh registry audit menemukan environment development masih membawa
  GitPython 3.1.51 dan manifest dashboard menarik FastAPI/Starlette, pytest,
  serta python-dotenv yang sudah memiliki advisory 2026. Environment
  development dinaikkan ke GitPython 3.1.55. Manifest dashboard sekarang
  mem-pin FastAPI 0.140.7, Starlette 1.3.1, pytest 9.0.3,
  python-dotenv 1.2.2, dan httpx2 2.9.1. Audit ulang environment development,
  exact dashboard requirements, dan npm masing-masing melaporkan nol
  vulnerability yang diketahui.
- Audit lanjutan menemukan builder preparation XM/FINEX masih memakai
  `exists()` diikuti recursive unconditional cleanup. Builder sekarang
  mensyaratkan clean checkout, menolak dangling output symlink dan parent
  indirection, membuat root/leaf secara exclusive, mengikat identitas setiap
  objek yang dibuat, dan hanya membersihkan identity yang tetap sama. Helper
  Windows mengekstrak ke sibling staging root, memverifikasi inventory sebelum
  dan setelah no-replace directory move, serta mempertahankan staging gagal
  untuk forensic review. XM tetap legal-hold dan FINEX tetap preparation-only.
- Audit network boundary menemukan CORS REST tidak melindungi route WebSocket.
  Backend sekarang menolak bind host non-loopback sebelum `uvicorn.run`,
  menormalisasi dan membatasi origin HTTP(S) ke loopback tanpa wildcard, serta
  menolak WebSocket tanpa `Origin` atau dengan origin di luar allowlist sebelum
  `accept()`. Public dashboard tetap tidak didukung tanpa review deployment
  terpisah.
- Audit publisher evidence inti menemukan `os.rename` dapat mengganti target
  direktori kosong pada POSIX dan cleanup staging lama tidak terikat identitas
  pembuatan. Frozen snapshot dan forward-contract registration sekarang
  memublikasikan direktori dengan native atomic no-replace pada
  Windows/macOS/Linux, mem-pin parent/staging identity, dan mempertahankan
  target race atau staging pengganti untuk forensic review. Temporary file
  cleanup dan clear marker `paired_pending` sekarang juga memerlukan exact
  creation identity sehingga file pengganti dipertahankan.
- Audit ship-gate menemukan runtime model hash belum memiliki portable frozen
  artifact. Shared rule-core digest kini menjadi satu source of truth untuk
  runner, builder, dan verifier. Artifact deterministik mengikat delapan source
  files, tracked Phillip Commodity config, exact XAUUSD M15 snapshot, cutoff,
  commit/tree, serta canonical `ModelArtifactManifest`. Verifier Windows
  membutuhkan archive/model/snapshot/config/commit/tree pin dan tidak dapat
  mengklaim quality, promotion, order, atau live readiness.
- Gap berikutnya pada lineage adalah handoff registry yang sebelumnya hanya
  berupa aksi eksternal tanpa format request/receipt lokal. Tooling operator
  kini membuat deterministic two-member champion-custody request, memverifikasi
  request terhadap tujuh pin independen, serta memverifikasi canonical
  policy-pinned RSA custodian receipt menjadi assessment deny-only. Tooling
  tidak mengunggah, membaca credential/private key, menginspeksi storage API,
  mengakses MT5, atau memberikan quality/promotion/order/live authority.

## Bukti otomatis

| Gate | Result |
|---|---|
| Full Python regression | 1.762 PASS, 3 skip, exit 0 |
| Full Python regression with optimization enabled | 1.762 PASS, 3 skip, exit 0 |
| Rule-core artifact + registry/custody + configured-tooling focused cluster | 36 PASS per normal/optimized mode |
| Create-exclusive publisher focused cluster | 238 PASS per normal/optimized mode |
| Atomic-suite + one-ZIP transfer feature cluster | 52 PASS per normal/optimized mode |
| Atomic-suite verifier consumer cluster | 62 PASS per normal/optimized mode |
| V6 packaging + post-run/custody focused cluster | 35 PASS per normal/optimized mode |
| Phillip V5/V6 scheduler + post-run/custody cluster | 67 PASS, 2 skip per normal/optimized mode |
| XM/FINEX preparation create-exclusive cluster | 15 PASS per normal/optimized mode |
| Frontend unit tests | 21 PASS |
| Dashboard backend tests | 45 PASS |
| Browser E2E | 14 PASS |
| Frontend lint, TypeScript, production build, bundle verification | PASS |
| npm dependency audit | 0 known vulnerabilities |
| Windows CPython 3.12 dependency lock | PASS |
| Git checkout before release build | CLEAN |

Pesan `REJECTED` yang tampil selama regression berasal dari fixture negatif
yang membuktikan fail-closed behavior; kedua proses regresi berakhir dengan
kode 0.

## Atomic five-role baseline

Dua build independen dari source commit `d5495260d3a47a4ce7759f044ff7299a79c1970a`
menghasilkan seluruh file yang byte-identical.

| Artifact | SHA-256 |
|---|---|
| Suite identity | `fb50dab2079793dd780de6885f51471c17ca0aaeb3efd62aace09d4e7f414f71` |
| Suite manifest file | `e2f47ff45fca67ca29f66bf7fa44bf748cdb0cc9e8de19849613afc33cb53956` |
| Decision | `a97abc08054d97bd812ac06bc0818876eb3741412864859055a6680281caeec8` |
| Execution | `b1f95819f4c6352f1a84e590aa9184f2ff351f8df94d9f0e8d27269b9a2ab9d7` |
| Status Monitor | `eab3399be6f68b19f6f8e60333ad20ca83eef795b4bc45b5f5e0b345e6284c37` |
| Read-only Shadow | `15cc446315b97986bd8266230ae0b32f59eb1f31ae15b12b3647657c52f86ddb` |
| Configured Release Tooling | `1e49da63e4f7cf66978d090eb55f4d35ac1e5731fdf59874e6635dfed32b22b2` |

Suite tetap menyatakan `DISABLED_AT_SUITE_BOUNDARY` dan
`production_execution_ready=false`. Build lokal ini membuktikan
reproducibility source; ia tidak menggantikan exact Windows build atau
external provider acceptance.

## Atomic-suite dan satu-ZIP transfer verification

`verify_windows_base_release_suite.py` menyediakan public read-only boundary
untuk direktori sebelas-file. Success memerlukan exact suite identity, full
Git commit, dan full Git tree yang dipin dari channel independen. CLI
merekonstruksi kelima ZIP, kelima sidecar, embedded manifest, source inventory,
ZIP determinism, safety, dan source identity.

Lapisan baru `build_windows_base_release_suite_transfer.py` membungkus exact
direktori tersebut menjadi satu deterministic ZIP. ZIP memuat canonical
transfer manifest, exact suite di `base-release-suite-v1/`, dan helper
PowerShell 5.1. Tidak ada manifest atau helper kedua yang harus disalin secara
terpisah. `verify_windows_base_release_suite_transfer.py` memerlukan empat pin
independen: outer archive SHA-256, suite identity, full commit, dan full tree.
Verifier itu kini menjadi bagian configured-release operator tooling dan
bootstrap di bawah `python -I -S -B`.

Builder melakukan self-verification sebelum no-replace publication. Verifier
menolak pin salah, file ekstra/hilang, duplicate/case-fold/path traversal,
ZIP metadata nondeterministik, non-canonical manifest, payload drift,
symlink/reparse, dan nested-suite drift. Helper Windows mengulang outer hash,
exact extracted inventory, size/hash, reparse, dan safety checks sebelum
menjalankan bundled verifier. Temporary extraction hanya digunakan untuk
verifikasi dan tidak memasang task/service atau mengakses MT5/broker.

Karena perubahan ini menambah source dan mengubah configured tooling
allowlist, exact Windows suite dan transfer ZIP untuk tahap berikutnya wajib
dibangun ulang dua kali dari commit final. Seluruh suite identity dan hash
lama tetap historical evidence dan tidak boleh dipakai sebagai pin build
baru.

## Safety state

```text
live_allowed = false
safe_to_demo_auto_order = false
promotion_eligible = false
max_lot = 0.01
```

Tidak ada perubahan yang membuka order. Execution capability tetap dormant
dan berlapis gate.

## Rule-core champion lineage

Source contract berada di `specs/rule_core_champion_artifact_v1.md`; operator
runbook berada di `docs/RULE_CORE_CHAMPION_ARTIFACT.md`. Builder hanya menerima
clean tracked checkout, exact source bytes dari `HEAD`, stable regular snapshot,
explicit post-cutoff UTC registration time, reviewed output name, dan output
baru di luar repository. Independent verifier tersedia di configured-release
operator tooling dan bootstrap di bawah `python -I -S -B`.

Kontrak custody lanjutan berada di
`specs/rule_core_champion_registry_custody_v1.md` dengan runbook
`docs/RULE_CORE_CHAMPION_REGISTRY_CUSTODY.md`. CLI portable
`manage_rule_core_champion_registry.py` berada hanya di configured-release
operator tooling. Request deterministik mengikat exact champion dan seluruh
pin; receipt verifier mengikat independently pinned RSA policy, immutable
destination/version/retention, dan signature custodian. Assessment success
tetap menyatakan direct storage API inspection tidak dilakukan dan seluruh
trading lock false.

Ini menutup format dan verifier handoff lineage lokal, bukan aksi custody atau
quality gate. Exact artifact untuk commit final harus dibangun dua kali setelah
commit, diverifikasi terhadap enam pin, lalu request diserahkan ke custodian
eksternal yang benar-benar independen. Policy pin, upload/version immutable,
signed receipt, restore proof, offline champion/challenger evaluation, OOS dan
broker-forward thresholds, risk feasibility, manual demo, demo-auto soak, serta
live approval tetap pending.

## Phillip Commodity V6.3 post-run handoff

Source lokal sekarang memiliki:

- `build_phillip_commodity_v6_postrun_acceptance_package.py` untuk membangun
  satu toolkit ZIP deterministik dari exact clean Git commit/tree;
- `Invoke-PhillipCommodityV6PostRunAcceptance.ps1` untuk menjalankan health
  checker V6.3 yang hash-pinned, mengumpulkan raw XML Task Scheduler events,
  dan menolak run tanpa korelasi event 107/100 atau dengan event 110/manual;
- `Test-PhillipCommodityV6TriggerAuditReadiness.ps1` untuk memastikan log
  Operational sudah aktif dan exact task/next-run tetap benar sebelum
  boundary, tanpa mengubah log atau task;
- `phillip_commodity_v6_postrun_acceptance.py` untuk verifikasi toolkit,
  collection, re-verification acceptance ZIP, deterministic custody request,
  serta RSA receipt verification di bawah `-I -S -B`;
- `New-PhillipCommodityV6CustodyRequest.ps1` untuk satu request ZIP yang
  mengikat exact acceptance bytes, tujuan, dan retention minimum;
- `Test-PhillipCommodityV6CustodyReceipt.ps1` untuk policy-pinned receipt dan
  assessment tanpa private key atau direct cloud API access;
- acceptance bundle exact delapan-member, termasuk
  `task-scheduler-events.json`, dan runbook custody terpisah.

Toolkit sengaja mencatat trigger provenance sebagai
`LOCAL_HOST_EVENT_LOG`, mengikat correlated `InstanceId` serta record ID
107/100, dan tetap mencatat
`independent_hmac_reverification_performed=false`,
`offhost_custody_performed=false`, dan
`worm_retention_verified=false`. Nilai itu tidak boleh berubah hanya karena
bundle atau custody request lokal berhasil. Source verifier untuk signed
custodian receipt sudah lengkap, tetapi scheduled proof pertama, policy pin
independen, upload WORM aktual, dan receipt eksternal tetap belum ada.

## Posisi roadmap

Phillip Commodity V6.3 sudah dilaporkan terpasang dan sehat pada Windows dalam
fase `PRE_START`. Exact first scheduled boundary tetap
`2026-07-30T06:45:00+09:00`. Sistem harus menunggu pemicu Task Scheduler
otomatis tersebut; manual start tidak boleh dipakai sebagai pengganti bukti.

Urutan berikutnya tetap:

1. setelah boundary, verifikasi toolkit terhadap archive/commit/tree pins,
   jalankan wrapper satu kali, lalu re-verify exact acceptance ZIP;
2. buat custody-request ZIP, kirim exact embedded acceptance bytes ke storage
   immutable di luar VPS, lalu verifikasi canonical policy/receipt RSA dan
   simpan assessment terpisah;
3. bangun ulang atomic five-role suite dua kali pada exact Windows source,
   cocokkan semua hash, lalu buat satu transfer ZIP dan verifikasi empat pin
   independennya sebelum dipindahkan;
4. siapkan, generate, dan validasi Decision, Execution, serta Status Monitor
   provider pack dan configured candidate dari custody Windows yang direview;
5. kumpulkan operations review, provider conformance, independent validation
   receipt, dan sembilan signed pre-manual observations;
6. jalankan sepuluh controlled manual-demo lifecycle dengan review manusia;
7. lakukan demo-auto activation review terpisah;
8. baru mulai soak minimal 30 hari, 50 broker-reconciled closed fills, dan 20
   XAUUSD closed fills;
9. selesaikan statistical/OOS gates, failure drills, legal/operational
   approval, lalu mulai live XAUUSD canary yang dibatasi.

Detail ship-gate dan blocker eksternal terdapat di
[SHIP_GATE_AUDIT_2026-07-28.md](SHIP_GATE_AUDIT_2026-07-28.md).
