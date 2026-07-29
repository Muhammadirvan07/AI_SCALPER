# AI_SCALPER Live-Grade v1 — Implementation Status

Status: **FOUNDATION IMPLEMENTED / DO NOT SHIP / NOT_READY**

Validasi lokal terakhir pada 2026-07-29 menjalankan **2.001 test** tanpa
kegagalan dalam mode normal dan optimized pada development Mac; tiga test
platform-dependent dilewati pada mode normal dan tiga belas pada mode
optimized.
Baseline dashboard read-only yang sudah dilacak sebelumnya lulus 21 unit test
frontend, 50 test backend, 14 browser E2E, lint, TypeScript, production build,
dan bundle verification. Refactor dashboard lokal yang masih uncommitted tidak
termasuk milestone ini, tetapi audit terbarunya lulus 16 unit test, lint,
TypeScript production build, bundle budget, npm audit dengan nol vulnerability,
dan 24 browser E2E desktop/mobile terhadap backend granular. Itu adalah
software regression evidence pada Mac, bukan Windows host acceptance,
broker-forward evidence, atau izin trading.

Audit aktif dan baseline release-candidate dicatat di
[SHIP_GATE_AUDIT_2026-07-29.md](SHIP_GATE_AUDIT_2026-07-29.md) serta
[PROJECT_PROGRESS_2026-07-29.md](PROJECT_PROGRESS_2026-07-29.md). Audit
historis tetap immutable sebagai catatan keputusan pada tanggalnya.

Dependency lock/install manifest/SBOM lokal juga tervalidasi dan
`pip-audit 2.10.1` melaporkan nol kerentanan yang diketahui pada environment
development. Pemeriksaan tersebut tidak menggantikan fresh signed OSV receipt
dari exact Windows release.

Fresh audit 2026-07-28 juga menutup drift dependency dashboard: manifest kini
mem-pin FastAPI 0.140.7, Starlette 1.3.1, pytest 9.0.3,
python-dotenv 1.2.2, dan httpx2 2.9.1. Exact requirements audit serta npm audit
melaporkan nol vulnerability yang diketahui; `pip check`, 50 backend tests,
dan 14 browser E2E lulus. Ini tetap bukti source/development, bukan approval
deployment publik atau trading.

Dokumen ini membedakan implementasi software lokal dari bukti operasi. Test
hijau tidak menggantikan broker-forward evidence, legal review, Windows VPS
hardening, demo soak, atau approval manusia. Tidak ada bagian dokumen ini yang
membuka demo-auto maupun live.

Windows decision-provider pack v1 kini lengkap secara source lokal. Base
decision release memiliki read-only exact Credential Manager lookup, signed
trusted-clock attestation, external directory CAS untuk IPC/cursor, strict
external checkpoint parsers, dan brokerless service composition. Tooling
operator terpisah menghasilkan serta memvalidasi exact four-file secret-free
overlay dari atomic-suite decision base. Generator tidak membaca credential,
tidak mengimpor generated factory, tidak membuka state, dan tidak memiliki
broker/order authority. Status output tetap
`EXTERNAL_PROVIDER_ACCEPTANCE_REQUIRED`; exact Windows build, provider custody,
ACL, clock, CAS, launcher, task, dan independent conformance belum diterima.

Provider-bound WORM handoff v1 kini juga lengkap secara source lokal dan masuk
ke configured-release operator tooling. Request builder membuat exact ZIP
empat member dari admission, custody policy, provider policy, serta manifest
yang mengikat delapan pin independen. Verifier receipt menerima hanya schema
v2, domain-separated RSA signature, retention/chronology yang valid, dan
exported readback yang byte-identical serta dipin independen. Assessment tetap
offline dan deny-only: tidak ada storage API inspection, runtime seal, CAS,
nonce, central unlock, process, MT5, atau broker effect. WORM upload/readback
aktual dan signed external CAS/checkpoint/nonce masih wajib sebelum
launch-session v2 dapat dibentuk pada runtime.

External CAS handoff v1 kini juga lengkap secara source lokal dan masuk ke
configured-release operator tooling. Request ZIP tiga member mengikat exact
canonical launch proposal serta public custody policy ke lima belas pin
independen. Response verifier menerima hanya signed checkpoint, separately
signed acknowledgement, byte-identical head readback, dan signed nonce
readback pada domain ketiga. Assessment tetap evidence-only: runtime callback
belum dijalankan, nonce tidak dikonsumsi oleh tool, module-sealed capability
tidak dibuat, dan central unlock/process/MT5/broker tetap tidak dilakukan.
Karena proposal berlaku maksimal 60 detik, actual integration harus memakai
adapter provider sinkron yang direview; workflow manual atau file lokal tidak
dapat menggantikan atomic external CAS.

Windows LIVE-canary external CAS directory adapter v1 kini mengisi callback
sinkron tersebut secara source lokal. Adapter menerima exact canonical public
custody-policy bytes dengan independent SHA-256 pin, memverifikasi proposal,
checkpoint, acknowledgement, dan nonce response secara mandiri, lalu memakai
stable immediate-child reads serta staged+synced atomic no-replace request
publication sehingga watcher tidak dapat membaca final JSON parsial. Deadline
tetap dua detik; stale staging, cleanup failure, timeout, dan hasil ambigu
tetap terminal tanpa overwrite atau retry. Adapter masuk ke Execution
allowlist dan isolated probe tanpa mengimpor custody/admission/acceptance/
launch-session producer graph atau private-key tooling. Ini masih client
primitive, bukan bukti external atomic service: actual mount/ACL/durability,
signed Windows responses, target-host acceptance, dan external custodian tetap
wajib.

Decision configured-candidate assembler v1 juga lengkap secara source lokal.
Ia menjaga original four-file pack immutable, membuat working overlay
terpisah, menurunkan producer bootstrap hash, membangun exact suite-bound
configured Decision ZIP, dan menghasilkan seven-provider factory template
serta closed receipt. Loader Decision dan Status Monitor sekarang
membandingkan descriptor terhadap exact factory-template member dari verified
nested base inventory. Candidate tetap
`EXTERNAL_PROVIDER_CONFORMANCE_REQUIRED`; tidak ada provider acceptance,
credential access, task installation, broker mutation, demo-auto, atau live
authority.

Primitive Windows lintas service kini juga memiliki satu source of truth.
Exact read-only Credential Manager lookup dan signed monotonic trusted UTC
dipindahkan ke modul standard-library-only yang dibundel hanya pada
`DECISION`, `EXECUTION`, dan `STATUS_MONITOR`. Decision tetap source-compatible melalui
exact re-export. Provider implementation hash v2 mengikat byte Decision
foundation dan shared primitive secara transitif; member hilang atau duplikat
gagal sebelum output. Tahap ekstraksi primitive tidak membaca credential saat
build atau validation.

Status Monitor provider pack dan configured-candidate v1 sekarang juga lengkap
secara source lokal. Dua belas provider role terikat ke exact foundation
bytes, tujuh key/fingerprint terpisah, signed snapshot/checkpoint/incident
protocol, preprovisioned strict SQLite outbox, dan create-existing-only
transport. Offline tooling menghasilkan exact four-file pack, lalu assembler
menjaga pack asli immutable sambil membuat exact suite-bound 15-file candidate.
Tooling operator tidak mengimpor factory, membaca credential, membuka SQLite,
mengirim request, memasang task, memulai process, mengakses MT5, atau menyentuh
broker. Status tetap `EXTERNAL_PROVIDER_CONFORMANCE_REQUIRED`.

Execution provider pack dan configured-candidate v1 kini juga lengkap secara
source lokal. Foundation mengikat tepat 46 port, 37 port wajib DEMO, sembilan
port opsional, dua belas referensi Credential Manager yang purpose-bound, dan
satu signed-clock trust domain independen. Materializer memverifikasi service
config, production-config source, bootstrap binding, runtime mode, seluruh
provider value, heartbeat custody, serta policy lock sebelum mengembalikan
`WindowsServiceFactoryResult` tersegel dengan `mt5_module=None`. Generated
factory tanpa runtime Windows yang direview menolak stabil dengan
`EXECUTION_PROVIDER_RUNTIME_NOT_CONFIGURED`; pack/candidate offline tidak
membaca credential, membuka SQLite, mengimpor MT5, mengirim jaringan,
memasang task, atau menyentuh broker. Status lokal adalah
`PASS_LOCALLY_EXTERNAL_RUNTIME_REQUIRED`, bukan provider acceptance atau
order authority.

Execution source-bound candidate v1 kini menutup source/provider/bootstrap
handoff secara lokal. Satu deterministic ZIP membawa exact tujuh-pin source
archive dan seluruh 15 file configured candidate; verifier membutuhkan
sembilan pin independen dan merekonstruksi candidate di temporary private root
untuk menjalankan validator authoritative terhadap exact atomic suite dan
Execution role. Provider source hash, bootstrap binding, suite identity,
commit, dan tree harus identik. Tooling ini hanya berada di configured-release
operator bundle, tidak di empat service release, dan seluruh hasil tetap
`provider_accepted=false`, `production_execution_ready=false`, serta
`order_capability=DISABLED`. Provider-conformance v3 kini lengkap secara
lokal: input dan review wajib memakai hasil verifier source-bound tersegel,
mengikat 26 lineage field, merekonstruksi 65 provider, dan mencocokkan exact
canonical `DEMO` Execution template/source/bootstrap/suite/role/commit/tree.
V1/v2 tetap byte-compatible. Exact v3 artifacts dan bukti Windows aktual
belum dikumpulkan.

LIVE Execution source-bound candidate v1 kini juga menutup ancestry handoff
secara lokal. Satu deterministic 17-member ZIP mengemas exact DEMO
source-bound archive yang sudah diverifikasi serta seluruh 15 file LIVE
configured candidate. Public verifier memerlukan sepuluh pin independen,
merekonstruksi kedua input dari packaged bytes, dan mencocokkan production
source, bootstrap, suite/Execution role, commit/tree, base/configured release,
49 provider, serta 12 credential reference. Tooling hanya ada di configured
operator bundle dan tetap menolak provider acceptance, credential access,
MT5, task/service, central unlock, broker mutation, dan order. Exact
target-Windows artifact serta external acceptance belum ada.

Provider-conformance v4 kini mengonsumsi hanya hasil verifier LIVE
source-bound sepuluh-pin yang tersegel. Input dan review merekonstruksi tiga
factory template, mengikat exact `LIVE` Execution template, dan memerlukan
tepat 68 fresh provider record: tujuh Decision, 49 Execution, serta dua belas
Status Monitor. Hash binding setiap provider LIVE diturunkan dari seluruh
tujuh field canonical, termasuk provider ID dan purpose-bound credential
reference. V1-v3 tetap kompatibel. Tooling ini tetap deny-only dan tidak
mengimpor provider, membaca credential, membuka central lock, menginisialisasi
MT5, atau memberi order authority. Exact packet, signature owner, runtime
attestation, dan acceptance dari target Windows belum dikumpulkan.

External acceptance v1 untuk packet tersebut kini juga lengkap secara source
lokal. Boundary operator-offline memverifikasi ulang exact sealed v4 review
dan ten-pin LIVE source closure, mewajibkan pin policy dan target-host dari
kanal independen, dua RSA authority 3072-bit-or-stronger yang benar-benar
berbeda, serta exact bytes tiga external evidence file. Runtime attestation
harus lebih baru daripada seluruh 68 provider observation. Hasil tersegel
dapat menyatakan `provider_accepted=true`, tetapi selalu menetapkan
`prebootstrap_binding_required=true`, `execution_enabled=false`,
`live_allowed=false`, dan `order_capability=DISABLED`. Tidak ada private-key,
credential, provider import, process/task, MT5, network, broker, atau order
surface. Policy/signature/evidence target Windows yang nyata belum tersedia;
fixture RSA lokal bukan external acceptance.

Execution launcher kini juga mempunyai boundary
`--materialize-only`. Boundary ini memerlukan external RSA launcher
attestation yang secara eksplisit dipin ke profile Execution, memanggil exact
reviewed factory, lalu berhenti sebelum production bootstrap, runner, signal
handler, MT5 import/initialize, authorization consumption, atau broker
mutation. Boundary bootstrap memeriksa ulang exact config/ports, semua
execution lock, dan `mt5_module=None`; mutasi pascakonstruksi ditolak dengan
`SERVICE_FACTORY_MT5_INJECTION_FORBIDDEN`. Test lokal membuktikan semantiknya,
tetapi receipt Windows aktual
belum ada. Statusnya
`PASS_LOCALLY_EXTERNAL_WINDOWS_EVIDENCE_REQUIRED`; default generated factory
tetap fail-closed tanpa reviewed external runtime.

Live-canary runtime launch-session v1 kini juga tersedia sebagai boundary
source lokal yang tersegel. Boundary ini hanya dapat dibentuk dari exact
`LiveCanaryRuntimeCandidate`, prebootstrap admission, one-use portable launch
capability, launcher policy, serta seluruh pin independen yang cocok. Ia
membaca ulang checkpoint dan durable nonce dua kali, menolak reuse capability
secara atomik di dalam process, dan memeriksa central `LIVE` policy pada awal
serta akhir aktivasi. Pada source yang dicheck-in, `LIVE_ALLOWED=false`, jadi
session tidak dapat dibentuk. Bahkan setelah central policy dibuka melalui
ceremony terpisah, hasilnya hanya memberi `bootstrap_authorized=true` dan
`process_launch_authorized=true`; `execution_authorized` serta
`broker_mutation_authorized` tetap false dan setiap order masih wajib melewati
permit, promotion, risk/news, journal lease, dan final MT5 guard. Boundary ini
tidak memulai process, mengakses credential, menginisialisasi MT5, atau
mengirim order.

Launch-session tersebut kini menjadi input wajib pada jalur `LIVE/LIVE`
`ProductionRuntimeBootstrap`, `ProductionRuntimeComposition`, dan
`RuntimeSupervisor`. Seluruh binding candidate/config/session diverifikasi
secara exact, currentness diperiksa ulang sebelum effect boundary, dan LIVE
tidak lagi dipetakan ke stage authorization DEMO. Supervisor LIVE dapat
memproses `NO_ACTION` atau satu action khusus `LIVE_CANARY_EXECUTE` saja.

Jalur execute baru memerlukan exact `LiveCanaryPreparedOrder` dan satu
`LiveCanaryOrderAuthorization` tersegel yang berlaku maksimal satu detik,
mengikat candidate/session/intent XAUUSD 0.01, account hash, server, journal,
model/champion, permit, promotion, arm, checkpoint, risk, reconciliation,
signed news, dan runtime facts. Supervisor, coordinator, runtime
authorization, durable submission lease, service, dan MT5 adapter semuanya
memeriksa hash authority yang sama hingga tepat sebelum `order_send`. Test
end-to-end memakai fake MT5 dan membuktikan satu send serta penolakan replay;
tidak ada MT5 nyata atau broker yang disentuh. Central lock tetap false, jadi
session dan per-order authority tidak dapat diterbitkan dari source
checked-in. Windows factory-template v1 juga tetap DEMO-only dan belum
menyediakan tiga callback LIVE; exact Windows LIVE factory/provider release
masih wajib direview dan dibuktikan eksternal.

Boundary materialisasi Windows LIVE yang terpisah kini tersedia secara source
lokal tanpa mengubah kontrak Execution v1. Ia mengikat tepat 49 port: 40
provider LIVE wajib dan sembilan port lintas-mode yang harus tetap kosong,
serta 12 referensi Credential Manager purpose-bound dengan
`MT5_LIVE_SESSION`. Materializer hanya menerima exact sealed candidate dan
launch session, memeriksa central policy sebelum/sesudah setiap callback,
menyusun provider secara terurut, memvalidasi heartbeat, dan mengembalikan
`WindowsServiceFactoryResult` tersegel dengan `mt5_module=None`. Ia tidak
mengimpor/menginisialisasi MT5, tidak memasang task, tidak mengirim jaringan,
dan tidak menyentuh broker. Dengan central lock checked-in tetap false,
materialisasi production juga tetap tertolak. Tooling deterministic provider
pack kini menghasilkan dan memvalidasi tepat empat file secret-free yang
terikat exact atomic-suite/Execution-base, 49 provider, 12 credential
reference, implementation hash, dan configuration hash. Tooling tidak
mengimpor provider, membaca credential, membuka SQLite, memulai process,
menginisialisasi MT5, mengakses network, memasang task, atau menyentuh broker.
Tooling suite-bound configured candidate kini juga tersedia: legacy overlay
API tetap menolak LIVE, sedangkan additive LIVE API menurunkan exact reviewed
materializer hash dari Execution base dan membentuk tepat 15 deterministic
files. Validator merekonstruksi configured ZIP/sidecar, pack/overlay, 49-port
contract set, 12 non-secret credential references, task, template, suite,
commit, tree, serta seluruh hash tanpa provider/credential/MT5/broker effect.
Actual target-host pack dan candidate belum dibangun dari commit Windows yang
diterima; concrete Windows providers, source-bound release, dan external
conformance receipt masih belum ada.

Dashboard operasional sekarang merupakan source yang dilacak dan telah
dipublikasikan sebagai boundary read-only terpisah. FastAPI hanya menyediakan
route GET. Startup menolak bind host non-loopback sebelum `uvicorn.run`; CORS
dan WebSocket memakai canonical origin allowlist HTTP(S) loopback tanpa
wildcard, dan handshake WebSocket tanpa origin tepercaya ditutup sebelum
`accept()`. Seluruh respons HTTP, termasuk CORS preflight dan negative route,
sekarang membawa CSP tanpa wildcard, `nosniff`, anti-frame, no-referrer,
permissions policy, dan `Cache-Control: no-store`; respons dokumentasi HTML
memakai allowlist CDN sempit agar `/docs` dan `/redoc` tetap berfungsi.
Frontend menolak payload runtime yang tidak lengkap, dan token
status negatif seperti `NOT_READY` atau `INACTIVE` tidak dapat dipetakan
sebagai status positif. Dashboard tidak memiliki credential, permit, arm,
task mutation, broker mutation, maupun order authority. Penggunaan di luar
loopback tetap memerlukan deployment review, TLS, authentication, dan
security-header policy terpisah.

Create-exclusive output custody kini konsisten pada shared Windows release
writer, role release/sidecar builder, configured overlay, evidence/feed dan
provider publisher, provider-pack generator, atomic-suite lock/staging,
configured-candidate cleanup, builder preparation XM/FINEX, serta publisher
frozen snapshot dan forward contract. Publikasi direktori evidence terakhir
itu kini memakai native atomic no-replace pada Windows/macOS/Linux, mem-pin
identitas parent dan staging, dan hanya membersihkan exact staging root yang
dibuat invocation berjalan. Identitas hilang, berubah, symlink/reparse, target
race, atau object pengganti selalu dipertahankan dan proses gagal tertutup.
File sementara exclusive-write/replace serta marker transaksi
`paired_pending` juga membawa identity token hingga cleanup atau clear; path
pengganti tidak pernah dihapus.
Helper extraction XM/FINEX juga memakai sibling staging dan no-replace
directory move sebelum verifikasi ulang destination. Full regression normal
dan optimized sama-sama lulus 1.790 test dengan tiga platform skip. Kontrak ini
hanya memperkuat artifact custody dan tidak mengubah `order_capability`,
`live_allowed`, demo-auto, promotion, atau broker authority.

## Status roadmap

| Tahap | Status | Bukti saat ini |
|---|---|---|
| 1. Baseline terkunci | Selesai secara lokal | Seluruh safety lock terjaga; mutable CSV market cache dan legacy JSON runtime sudah dikeluarkan dari release source. Atomic five-role builder sekarang mengikat decision, execution, status monitor, read-only shadow, dan configured-release tooling dari satu clean commit/tree. Ia juga mengharuskan serta menghitung ulang exact six-file deny-only Execution provider-bound runtime closure terhadap source inventory. Real clean-repository build lokal dan independent byte-for-byte rebuild lulus. Public read-only verifier merekonstruksi seluruh suite dan memerlukan external suite-identity/commit/tree pins. Satu deterministic transfer ZIP kini mengikat seluruh sebelas-file suite, canonical transfer manifest, dan helper PowerShell 5.1; verifikasinya menambah independent outer archive SHA-256 sebagai pin keempat. Exact Windows candidate dan transfer ZIP baru masih wajib dibangun setelah commit. |
| 2. Evidence infrastructure | Implemented locally | Frozen snapshot, HMAC-signed forward contract v4, v3 compatibility, byte-derived regulatory review package with two independent HMAC approvals, byte-derived pre-window base-calendar review with a separate human HMAC approval, prospective closure-only amendment chain, final completeness attestation, append chains/heads, seal, blinded receipt, strict UTC/build/source/spec/grid verification, broker-neutral profile/plan/contract binding, dan generic one-shot collector dengan mandatory exact-terminal binding tersedia. |
| 3. Broker read-only shadow | Phillip Commodity V6.3 installed and healthy on Windows; awaiting first automatic scheduled run | FBS forex/metal/crypto diagnostic domains dan Phillip FX/commodity dual-terminal lanes memiliki journal/report terpisah. Phillip Commodity sanitized discovery-v3, signed regulatory/calendar reviews, dan registration gate telah disetujui. Contract v1 tetap immutable/kosong setelah legacy expert-flag HOLD. Contract v2 membuktikan HMAC source chain tetapi startup melebihi append grace; v3 mempertahankan repeated-activation failure. V4 membuktikan 13 authenticated children tetapi task gagal tertutup pada optional `RunLevel`. V5 membuktikan 12 authenticated children dan one dependency session; task V5 kemudian disabled ketika Windows menghilangkan XSD-default `StartWhenAvailable=false` dan validator StrictMode lama membacanya secara dinamis. V6 mempertahankan frozen worker/contract/journal/proof V5 dan membuat task/evidence scheduler baru dengan shared XSD+CIM validator. Helper transfer V6 pertama gagal sebelum instalasi karena bentuk array top-level `ConvertFrom-Json` pada Windows PowerShell 5.1. V6.1 memperbaiki inventaris tetapi first boundary kedaluwarsa sebelum transfer. V6.2 berhasil diekstrak, lalu berhenti sebelum registrasi ketika XML adapter PowerShell 5.1 mengubah empty `Principal` self-test menjadi string. V6.3 memakai exact XPath `XmlElement`, mempertahankan jadwal `2026-07-30T06:45:00+09:00`, memakai root commit baru, dan memperlakukan root/transfer lama sebagai `PRESERVE_IF_PRESENT`. Windows kemudian melaporkan transfer verified, installation verified, dan health `PRE_START` sehat dengan task `Ready`, exact `NextRunTime=2026-07-30T06:45:00+09:00`, serta tanpa manual start atau broker mutation. Deterministic post-run toolkit lokal kini menyiapkan exact health/checkpoint/audit/task-XML acceptance ZIP tanpa manual task start, membuat deterministic custody-request ZIP, dan memverifikasi policy-pinned RSA custodian receipt menjadi assessment deny-only. Keberadaannya bukan scheduled proof atau custody aktual; policy pin, upload WORM, receipt eksternal, first automatic-run acceptance, dan observation window masih wajib. V4/V5 tetap disabled dan immutable. Phillip FX tetap registration-disabled. |
| 4. Manual demo | Component foundation ready, readiness locked, orders not run | Journal-bound signed permit, one-second process environment arm, signed per-intent operator approval, champion-model binding, signed news guard, broker-native sizing, account-currency-normalized USD risk cap, account-wide fence, risk governor, fenced journal, bounded Windows composition, MT5 preflight/executor/reconciliation, dual-control kill-switch reset, non-mutating readiness report, deny-only pre-manual entry verifier, dan exact configured-release admission tersedia. Sembilan signed gate pra-run, review aktivasi manual-demo, serta sepuluh order demo belum selesai. |
| 5. Demo-auto soak | Local three-service activation foundation and source-bound provider-conformance v3 complete but locked; soak not started | Decision IPC, one-use risk/intent, renewable session CAS, journal-bound dispatch settlement/restart recovery, authenticated soak projection, account-level 30-day/50-fill/20-XAU cohort, mode-aware Windows factory contract, separate decision/execution/status-monitor releases, read-only shadow publisher release, deny-only gate catalog, dan atomic five-role base-suite manifest tersedia. Decision, Execution, dan Status Monitor kini memiliki exact provider foundation, deterministic four-file pack generator/validator, shared read-only Credential Manager/trusted-clock primitive, dan immutable suite-bound configured candidate tanpa build-time provider effect. Status Monitor menerbitkan checkpoint/incident request melalui private staging, fsync, stable readback, dan atomic no-replace final visibility sehingga watcher tidak dapat membaca partial JSON. Execution mengikat 46 port; exact `--materialize-only` probe kini tersedia dan berhenti sebelum bootstrap/MT5/runner, tetapi runtime Windows eksternal serta receipt aktual belum ada dan default generated factory tetap fail-closed. Production-bootstrap schema v2 memerlukan lima pin champion eksplisit di konfigurasi Windows dan mencocokkannya dengan `StageBinding` v3 sebelum effect. Deterministic production-config source v1 mengikat canonical config, stage, dan champion dengan tujuh pin; downstream source-bound candidate v1 mengemas exact source plus 15-file candidate dan memverifikasi closure sembilan-pin tanpa provider effect. Direct runtime-source/result construction ditolak. Provider-conformance v3 sekarang mengharuskan sealed nine-pin result, exact 26-field Execution lineage, canonical `DEMO` template, dan 65 fresh provider records; v1/v2 tetap byte-compatible. Configured build wajib mengikat exact role di satu five-role suite; admission memverifikasi ulang kelima ZIP/sidecar dan menolak configured release legacy atau mixed-suite. Provider packet hanya dapat menjadi `source_evidence_sha256` dengan independent `validation_receipt_sha256`, dan tetap `provider_accepted=false`. Exact Windows builds/candidates/source-bound/v3 artifacts, externally reviewed Execution runtime hooks and provider state, external key/CAS/latch/WORM/MT5 custody, signed acceptance observations, launcher issuance, exact Windows task/ACL activation, policy approval/unlock, sepuluh manual-demo lifecycle, serta actual soak evidence belum ada. |
| 6. XAUUSD live canary | Provider-bound activation, custody, launch composition, and synchronous external-CAS client implemented locally and locked; canary not started | Exact broker/demo/live/release/champion binding, policy-pinned promotion/gate/human/deployment authorities, three distinct approvals, five-minute trusted-clock window, atomic one-use SQLite registry, exact DDL/trigger verification, dan signed off-host rollback checkpoint tersedia secara source. Prebootstrap v1 menambah complete non-secret LIVE runtime candidate dan exact sealed DEMO Execution source-bound ancestry. Provider-bound prebootstrap v1 selalu mengulang verifikasi acceptance dari raw evidence pada trusted clock, mengikat exact consumed activation ke DEMO/LIVE ancestry, host, installed environment, configured Execution release/task, serta menetapkan expiry paling awal dari owner/runtime/request; hasilnya tetap deny-only. Provider-bound custody v2 kini mewajibkan domain-separated RSA receipt dan byte-identical WORM readback atas exact provider-bound admission, mengikat provider acceptance/policy/review, kedua source projection, host/environment/release/task, launcher policy, service account, activation, provider expiry, serta custody authority yang berbeda dari kedua provider authority. Provider-bound launch-session v2 mengomposisikan custody tersebut dengan protokol signed CAS/checkpoint/nonce v1 tanpa mengubah canonical v1, lalu membatasi expiry ke minimum capability/provider/custody. Production bootstrap, supervisor, per-order authorization, dan Windows LIVE materializer hanya menerima exact registered v2; session v1, subclass, forged object, dan duck type ditolak. Session v2 tetap launch-only, dengan execution dan broker mutation false serta seluruh per-order guard tetap wajib. Deterministic Execution base sekarang membawa minimal six-file v2 consumer closure, isolated probe, dan independent directory-CAS callback client dalam allowlist 56 file. Adapter memverifikasi canonical public protocol tanpa producer import; producer dan consumer tetap memakai exact class/seal yang sama, sedangkan assembler candidate/source-bound, conformance, acceptance, admission/custody, dan activation tetap operator-only. Per-order v1 menambah `LIVE_CANARY_EXECUTE`, exact prepared order, sealed authority maksimal satu detik, durable pre-dispatch/reservation binding, dan revalidation hingga tepat sebelum MT5 `order_send`; fake-MT5 integration membuktikan satu send dan replay denial. Additive Windows LIVE materializer mengikat 49 port dan 12 purpose-bound credential references tanpa MT5/broker effect; Execution V1 tetap byte-compatible. Deterministic four-file pack, exact 15-file configured candidate, dan 17-member ten-pin source-bound archive tersedia secara source. Provider-conformance v4 mengikat sealed LIVE closure tersebut ke tepat 68 fresh provider record dan tetap `provider_accepted=false`. Additive external acceptance v1 memerlukan dua authority RSA berbeda, independently pinned policy/host, serta tiga exact evidence file; hanya hasil tersegel itu yang boleh menjadi `provider_accepted=true`, dan hasilnya tetap non-executable. Checked-in central policy tetap false, sehingga real authority tidak dapat diterbitkan. Canonical Windows factory v1 tetap DEMO-only. Actual independently eligible selected-broker demo-auto cohort 30 hari/50 fill/20 XAU (current JP lane: `phillip-commodity`), target-host LIVE provider ZIP/configured/source-bound/v4 artifacts, signature owner/runtime serta exact evidence acceptance, real provider-bound result, independent provider-bound WORM/CAS service/mount/receipt evidence, promotion/gate/approval evidence, central unlock ceremony, first real canary, broker acknowledgement, dan reconciliation evidence belum ada. XM tetap diagnostic/paper-only selama operating jurisdiction adalah JP. Lima puluh closed live trades adalah bukti pascacanary untuk ekspansi, bukan syarat membuat order canary pertama. |
| 7. Pair expansion | Not started | EURUSD, USDJPY, dan AUDUSD harus mengulang seluruh gate per lane; hasil lane lain tidak boleh menutup kegagalan sebuah pair. |
| 8. Scaling | Out of v1 | Tidak ada auto-scaling lot maupun risk cap. |

Catatan roadmap tahap 6: deterministic provider-bound WORM dan external CAS
handoff serta synchronous Windows directory client sekarang termasuk dalam
foundation lokal. Semuanya belum mengubah status canary karena WORM
upload/readback, runtime-sealed custody, actual external atomic service dan
mount/ACL, signed checkpoint/acknowledgement/head/nonce readback pada Windows,
dan external acceptance aktual tetap belum tersedia.

## Kontrol yang sudah diimplementasikan lokal

### Evidence dan kalender sesi

- Forward contract menyimpan kalender UTC per simbol yang berisi market-open
  intervals, closure eksplisit, dan metadata broker. Canonical SHA-256 kalender
  harus sama dengan `instrument_spec.session_calendar_sha256` dan seluruh
  payload terikat HMAC kontrak.
- Expected M15 grid dihitung dari signed calendar. Weekend/holiday yang sudah
  didaftarkan sebelum observasi boleh menjadi gap; bar/tick di luar sesi atau
  gap intraday yang tidak terdaftar ditolak fail-closed.
- `session_calendar_verified=true` hanya jika kalender seluruh simbol lolos
  schema, UTC, window, broker-source, hash, dan signature binding.
- Snapshot, source, instrument spec, build identity, append order, logical-row
  hash, blinded period, high-water head, seal, dan receipt diverifikasi ulang.
  Yahoo FX serta `GC=F` tetap development-only dan tidak dapat menjadi live
  evidence.
- Kontrak baru memakai `forward-contract-v4` dengan sequence-zero calendar
  genesis. Notice resmi yang terbit kemudian hanya dapat menutup bucket M15
  yang masih future/open melalui history HMAC append-only, minimum lead 900
  detik, exact source-document SHA-256, dan optimistic head binding. Replay
  chain menghasilkan satu effective calendar untuk append, reconciliation,
  coverage, evidence root, shadow planning, dan receipt. Kontrak v3 tetap
  readable tetapi immutable.
- Setelah blind window, signed completeness attestation mengikat final calendar
  head dan inventaris source resmi sebelum seal. Chain yang autentik tetapi
  belum memiliki completeness tetap `valid` secara mekanis namun tidak dapat
  membuat complete coverage atau promotion readiness menjadi true.
- Raw-tick partition dan finalized M15 segment kini ditulis melalui satu API
  berpasangan di bawah contract-wide OS lock. HMAC-signed paired commit chain
  mengikat kedua payload hash, exporter identity hash, coverage metadata hash,
  build, waktu, dan urutan. Reader juga mengambil lock yang sama sehingga tidak
  melihat keadaan setengah jadi; crash di tengah append membuat kontrak invalid
  dan recovery marker memblokir append berikutnya.
- MT5 login hanya digunakan di memori sebagai input HMAC domain-separated.
  Discovery, contract, broker binding, dan paired commit mengikat exact account
  identity/key/currency tanpa menyimpan login mentah. Identity diverifikasi
  sebelum dan sesudah tick collection.
- Discovery v3 dan setiap capture juga mewajibkan investor/read-only account
  serta terminal-native order lock: `account.trade_allowed=false`,
  `terminal.trade_allowed=false`, dan `terminal.tradeapi_disabled=true`.
  `account.trade_expert` wajib berupa boolean dan dicatat apa adanya karena
  sebagian investor session melaporkan `true` walaupun account trading tetap
  unavailable. Runtime shadow mengimpor package secara lazy dan facade tidak
  menyimpan raw MT5 module atau mengekspor execution stack.
- Shadow collector memegang persistent OS singleton fence untuk seluruh siklus
  verify, plan, collect, append, dan SQLite receipt. Optimistic paired sequence
  fence menolak stale writer, sedangkan timestamp append baru dicetak setelah
  tick collection selesai.
- Artifact JSON discovery/calendar/preflight/plan memakai create-exclusive
  writer bersama yang serializes-before-create, menolak symlink/overwrite,
  melakukan file fsync dan POSIX directory fsync, serta menghapus partial file
  saat write gagal. Build identity path generik dibatasi ke regular tracked
  repository path dan menolak absolute/traversal/symlink escape.
- Gate broker generik tidak circular: setup key, discovery, plan, dan calendar
  tunduk pada gate sumber masing-masing; hanya contract registration dan
  evidence collector yang mensyaratkan profile `registration_enabled=true`.
- Contract bootstrap mengikat Git provenance ke exact absolute repository
  root, clean worktree, serta commit/tree object ID yang valid dan stabil.
  Seluruh pre-window, ruleset, source, spec, dan identity gate yang tersedia
  dijalankan sebelum frozen snapshot dibuat; wrong-repo, malformed identity,
  drift, atau late registration gagal tanpa memublikasikan contract.
- Registration-review tooling menghitung hash dari byte dokumen authority
  lokal, mengikat satu candidate/template/symbol lane, dan membutuhkan tepat
  dua approval HMAC dengan role, approver, key ID, serta secret fingerprint
  berbeda. Reviewer key hanya dimuat dari Windows Credential Manager. Final
  assembly tidak mengubah tracked config. Setelah proposal exact
  `597b4c5a1c20c836c468652019bc1e50d4545912c4b96920494fef62805421e4`
  disetujui manual, hanya profile `phillip-commodity` yang diaktifkan untuk
  registrasi evidence diagnostic; `phillip-fx` tetap disabled. Plan dan
  contract tetap mengulang verifier dengan vault key provider.
- Activation-review pack non-mutating kini mengikat discovery-v3, dua approval
  regulasi, satu signed pre-window calendar review, serta clean Git commit/tree
  dalam satu proposal immutable. Pack membawa base dan after-image lengkap
  untuk tepat tiga tracked file sehingga bounded diff dapat diverifikasi tanpa
  secret. Tool tidak memiliki apply entrypoint; penerapan proposal dilakukan
  sebagai bounded manual patch yang terpisah. Registrasi evidence Commodity
  sekarang aktif, sedangkan order, execution, promotion, demo-auto, dan live
  tetap false.

### Runtime trust boundary

- Replay dan future shadow/demo/live adapter memanggil pure decision core yang
  sama. Golden fixtures empat lane mengikat finalized M15, structured score,
  first eligible bid/ask tick, entry reference, SL, dan TP. Legacy proxy data
  tanpa first-tick broker evidence ditolak sebagai runtime-parity proof.
- Runner real-time diagnostic terpisah membaca bar M15 closed dari posisi MT5
  `1`, mencari first eligible tick maksimum 10 detik sesudah close, dan
  mencatat decision serta paper outcome berbasis tick ke SQLite WAL
  hash-chained append-only. BUY dievaluasi pada bid dan SELL pada ask. Satu
  paper position per lane mencegah overlap, tetapi output selalu
  `validation_evidence=false`, `promotion_eligible=false`, dan
  `legal_gate_bypassed=false`.
- Lane weekend crypto terisolasi memakai Binance spot public sebagai primary
  `BTCUSDT`/`ETHUSDT` dan Coinbase public `BTC-USD`/`ETH-USD` sebagai validator.
  Ia menerima finalized UTC M15 serta sampled bid/ask melalui allowlisted GET
  tanpa credential/order capability, memakai shared decision core, lalu menulis
  journal dan report crypto terpisah. Feed stale, crossed, gap, clock drift,
  spread, atau deviasi cross-feed menghasilkan fail-closed `HOLD`. BTCUSD dan
  ETHUSD tetap shadow-only dan output ini bukan parity atau broker-forward
  evidence.
- M5 crypto challenger berjalan sebagai domain terpisah dari champion M15:
  config, profile, schema, source binding, decision key, SQLite journal,
  summary, dan report tidak dapat dicampur. M5 mempertahankan horizon enam jam
  melalui 72 bar, tetapi memakai indikator M5 dan tetap uncalibrated
  diagnostic-only. Snapshot M5 ditolak oleh `TradeIntent`, sehingga perluasan
  pure decision core tidak membuka jalur execution baru.
- Executor dan MT5 adapter membaca waktu dari injected trusted-clock provider;
  timestamp caller hanya assertion dan mismatch ditolak. Runtime facts/model
  binding harus berumur paling lama satu detik, sedangkan health gate menolak
  measured clock drift di atas satu detik.
- News feed v2 mengikat provider metadata, coverage, event list, key ID, dan
  HMAC signature. Missing key, signature invalid, stale/empty feed, coverage
  tidak cukup, atau high-impact blackout membuat keputusan fail-closed.
- Model artifact manifest immutable mengikat role, model version, artifact,
  training snapshot, commit, config, training cutoff, dan registration time.
  Hanya `CHAMPION` yang dapat lolos binding; challenger tetap shadow-only,
  tanpa credential, online learning, atau self-promotion. Promotion permit juga
  terikat pada exact model-artifact hash.
- Builder dan verifier artifact rule-core Phillip Commodity kini memakai satu
  inventori/digest source bersama dengan runner diagnostic. ZIP deterministik
  mengikat exact delapan source, tracked candidate config, snapshot XAUUSD M15,
  cutoff, commit, tree, serta canonical runtime binding. Verifier memerlukan
  enam external pin dan tetap menyatakan quality/promotion/live false. Builder
  dan training data tidak masuk configured-release operator tooling.
- Configured-release operator tooling kini juga membawa CLI registry/custody
  stdlib-only. CLI membangun deterministic two-member champion request,
  memverifikasi tujuh pin independen, serta memverifikasi canonical
  policy-pinned RSA custodian receipt menjadi assessment deny-only. Ia tidak
  melakukan upload, credential/private-key access, direct storage API
  inspection, MT5 initialization, Task Scheduler mutation, atau broker effect;
  custody eksternal aktual dan model-quality evidence tetap belum ada.
- Kill switch tetap latched setelah restart. Reset membutuhkan tepat dua
  approver berbeda, dua key ID serta secret berbeda, dua signature HMAC, exact
  journal identity, exact latch timestamp, reviewed-reason hash, expiry, dan
  sealed one-use authorization dari trusted clock; reset stale, backdated,
  mismatch, atau replay ditolak.
- SQLite WAL journal menerapkan unique intent, executor fencing, durable state
  transitions, unique decision-to-intent binding, random persistent journal
  incarnation identity, durable one-use authorization consumption, submission
  guard, global/daily entry limits, receipts, dan reconciliation-required
  states. Retry dengan control observation baru tetap idempotent dan satu
  decision tidak dapat membuat intent baru sesudah reject. Unknown broker
  result tetap `UNCERTAIN`; restart atau adapter baru tidak boleh memakai ulang
  otorisasi maupun mengirim ulang sebelum reconciliation.
- `PromotionPermit` mengikat exact journal identity. OS/process account fence
  memakai exact MT5 login + server + environment sehingga dua journal atau dua
  executor tidak dapat menguasai account yang sama secara bersamaan. Pergantian
  journal setelah restart juga ditolak oleh permit lama.
- Execution-symbol policy sekarang mode-aware. Legacy, dry-run, dan paper
  tetap EURUSD-only; controlled manual-demo menerima EURUSD dan XAUUSD agar
  exact XAU account/adapter dapat diuji sebelum aktivasi; dormant `DEMO_AUTO`
  serta future `LIVE` canary hanya menerima XAUUSD. Pure risk, one-shot service, coordinator,
  MT5 preflight/submit, production bootstrap, dan final supervisor dispatch
  semuanya wajib membawa exact mode. Symbol scope ini tidak dapat membuka
  `SAFE_TO_DEMO_AUTO_ORDER=false` atau `LIVE_ALLOWED=false`, dan manual
  `XAUUSD_EXECUTION_POLICY_APPROVAL_REQUIRED` tetap pending.
- Environment arm dibaca langsung dari process environment, terikat pada exact
  account/server/mode/journal, dan berlaku paling lama satu detik. Manual demo
  tidak menerima boolean approval; setiap intent membutuhkan artefak HMAC yang
  terikat intent/account/server/journal/approver/key dan berlaku maksimal lima
  menit. Kedua kontrol diverifikasi ulang tepat sebelum reservation.
- Demo-auto/live kelak membutuhkan signed `PromotionEvidenceReceipt` yang
  mengikat exact lane, strategy, config, commit, model, broker server, journal,
  readiness, evidence-store receipt, parity receipt, dan build manifest.
  Receipt dan permit saling mengikat hash; keduanya tetap tidak dapat mengubah
  hard lock.
- `LiveRuntimeService` hanya menyusun satu siklus: sealed decision, broker-native
  sizing, immutable intent, signed controls, coordinator, atau reconciliation.
  Ia tidak memiliki loop produksi, bootstrap credential, atau auto-start.
- Batas absolut `$0.20` XAU dan `$0.25` FX tetap berdenominasi USD. Untuk akun
  non-USD, adapter hanya menerima sealed quote yang terikat exact account,
  server, conversion symbol, broker currency metadata, bid/ask, dan timestamp.
  Direct `USD/ACCOUNT` memakai bid; inverse `ACCOUNT/USD` memakai `1/ask`.
  Quote hilang, mismatch, stale, atau future menghentikan komposisi sebelum
  sizing dan menghasilkan lot nol di pure risk governor. Akun USD memakai
  identity rate `1.0`; tidak ada risk cap yang dinaikkan.
- `run_manual_demo_readiness.py` hanya membaca tracked policy/candidate/profile
  dan melaporkan blocker. Tool ini tidak menginisialisasi MT5, tidak membaca
  secret, tidak membuat permit/approval, dan tidak memiliki jalur preflight
  maupun order. Current policy sengaja memaksa `ready=false`.
- Preflight mengikat timestamp dan bid/ask side dari first eligible broker tick
  persis ke `DecisionSnapshot.entry_reference`; drift sebelum `order_send`
  ditolak. Filled volume tertinggi disimpan durable sehingga partial fill yang
  sah direconcile/ditutup terhadap volume yang benar-benar terisi, bukan volume
  request awal.

### Windows service, release trust, dan decision IPC

- Operator release memiliki strict
  `prepare_windows_demo_soak_operations.py` yang membaca satu dokumen non-secret
  dengan schema tertutup dan membuat bundle review create-exclusive. Verifier
  membangun ulang typed operations plan, failure-drill manifest, tiga
  Task Scheduler XML, tiga skrip PowerShell read-only, readiness, effects, dan
  seluruh safety lock. CLI tidak mengakses credential, menginstal task,
  menjalankan proses, membuka jaringan/MT5, atau mengirim order; file tersebut
  tidak masuk shadow/decision/execution service release.
- Operator-only `verify_windows_three_service_external_acceptance.py`
  merekonstruksi review v3 dan memverifikasi RSA-3072–8192 public policy yang
  hash-nya dipin dari channel independen, exact tiga configured identity,
  fixed gate-owner inventory, source/validation evidence hash yang berbeda,
  freshness, dan satu signature per gate. Complete dossier tetap menghasilkan
  `EXTERNAL_ACCEPTANCE_COMPLETE_ACTIVATION_REVIEW_REQUIRED`; ia tidak dapat
  menerbitkan signature, memasang task, memuat provider, membuka policy, atau
  memberi order authority.
- Operator-only `verify_windows_manual_demo_entry_review.py` memakai exact
  review v3, pinned public RSA policy, dan owner map yang sama, tetapi
  mengklasifikasikan batas pra-run secara terpisah. Ia hanya meminta review
  aktivasi manusia bila seluruh sembilan gate pra-manual accepted dan
  `MANUAL_DEMO_10_CONTROLLED_ORDERS_REQUIRED` belum memiliki observation.
  Observation hasil yang muncul terlalu awal ditolak. Output selalu
  `manual_demo_authorized=false`, `execution_enabled=false`,
  `safe_to_demo_auto_order=false`, `live_allowed=false`, dan
  `order_capability=DISABLED`.
- Operator-only
  `verify_windows_pre_manual_configured_release_admission.py` membaca ketiga
  configured ZIP satu kali dengan stable regular-file fence, memverifikasi
  byte yang sama, lalu mengikat archive/manifest hash, base/configured
  identity, role/profile, Git commit/tree, factory contract/manifest, service
  config, serta Task Scheduler definition ke exact review v3 sebelum
  menjalankan pre-manual assessment. Paket valid tetapi tertukar atau berasal
  dari build lain ditolak. Tool tidak memiliki provider import, credential,
  process/task, MT5, broker, issuer, atau activation surface.
- Stage-readiness v2 mengikat SHA-256, status lengkap, dan trusted UTC check
  dari exact pre-manual entry review ke signed readiness, request, sealed
  validation, serta supervisor startup receipt v3. Substitusi hash, review
  stale, validation drift, atau stage fields parsial gagal sebelum `READY`;
  receipt divalidasi sebelum SQLite append sehingga row parsial tidak durable.
- `WindowsGatedServiceRunner` menyediakan bounded cadence, interruptible wait,
  off-host heartbeat, serta pre/post external-evidence attestation. Exact
  release root menolak member yang tidak ada di manifest, symlink/reparse
  point, case-collision, hash/size drift, dan factory/import origin di luar
  release atau stdlib yang direview. Dynamic loader shapes ditolak pada seluruh
  source release kecuali bentuk loader/validator yang direview; factory load
  dan invocation membandingkan registry modul dan mereattest seluruh origin.
- Heartbeat head dibangun ulang dari durable acknowledged outbox. Successor
  tidak dibuat sampai predecessor memiliki acknowledgement valid; retry
  transient tidak boleh membuat fork atau sequence gap.
- Broker cycle berjalan pada bounded daemon worker agar service tetap mengirim
  heartbeat. Jika deadline hilang atau heartbeat gagal saat worker aktif,
  composition melakukan best-effort exact-once fail-closed abort dan proses
  wajib berhenti dengan `os._exit(70)`. Python thread tidak dianggap dapat
  dibatalkan dengan aman; startup berikutnya harus reconcile state broker yang
  mungkin `UNCERTAIN`. Semantik ini belum menjalani exact Windows reboot/MT5/
  network-partition failure drills.
- `ProductionRuntimeComposition.abort_fail_closed()` mencegah double abort,
  sedangkan supervisor mempertahankan `STOPPED_CRITICAL` dan tidak menimpanya
  menjadi clean stop saat shutdown.
- `signed_release_trust.py` mengikat release identity, full Git commit/tree,
  profile, host/service-account alias hash, TTL, external sequence/predecessor,
  historical nonce custody, dan post-CAS clock. Namun implementasi HMAC adalah
  **local/test-only**: host yang memegang verification secret juga dapat
  memalsukan receipt. Karena itu `SIGNED_RELEASE_TRUST_ENABLED=false` dan
  `HMAC_RELEASE_TRUST_PRODUCTION_READY=false`; production membutuhkan
  asymmetric public-key verification atau external trusted-launcher
  attestation dengan policy yang dipin di luar release.
- `asymmetric_release_trust.py` sekarang menyediakan verifier RSA-3072
  public-key-only untuk short-lived external launcher attestation. Policy hash
  dipin oleh launcher, private key tetap di luar VPS/repository, dan attestation
  mengikat exact release/host/service-account/Task Scheduler. Runner
  memverifikasi sebelum factory import dan mengecek freshness kembali sesudah
  materialization. Receipt ini deny-only dan tidak menggantikan stage, permit,
  arm, risk, atau approval.
- Configured decision release sekarang memiliki production loader dan bounded
  runner yang memverifikasi exact extracted inventory, nested base provenance,
  overlay descriptor, factory/config/provider hash, import origin, module
  registry, serta RSA decision-profile attestation sebelum factory
  dimaterialisasi. Validate-only tidak mengimpor factory, membaca provider,
  mengambil market data, atau menulis IPC.
- Profile ketiga `WINDOWS_EXTERNAL_STATUS_MONITOR_V1` kini tersedia sebagai
  deterministic stdlib-only base release yang terpisah dari decision dan
  execution. Configured loader-nya mewajibkan exact release-local factory,
  provider template, runtime config, service/task/account/release/IPC binding,
  serta RSA monitor-profile attestation. Runtime status-only mengevaluasi
  service/process freshness, restart reconciliation, clock, disk, MT5, news,
  IPC, audit, backup, dan off-host health; critical state harus dilatch dan
  alert/heartbeat wajib memperoleh signed acknowledgement sebelum checkpoint
  CAS maju. Ia tidak mengimpor broker/risk/permit/executor/reconciliation dan
  tidak memiliki order authority.
- `DemoAutoDecisionIPCConsumer` terikat `decision-ipc-binding-v2`, exact permit
  key/fingerprint, supervisor/journal/lane, fresh stage request, promotion
  permit, serta real environment arm yang dibaca ulang sesudah queue CAS. Stage
  expiry dan arm replacement setelah consume ditolak sebagai safe-loss: queue
  head tetap habis dan tidak dapat direplay, tanpa dispatch. Output sukses
  hanya sealed `DemoAutoIPCRiskIntentInput` atau deny-only no-action. Consumer
  menerima sealed consume-only port tanpa `publish`, signing provider,
  database, exporter, atau raw queue. Modul ini tidak mengimpor MT5, tidak
  mempunyai executor callback, dan tidak membuka hard lock; production
  composition serta durable one-decision-to-one-intent integration masih harus
  direview terpisah.
- Untuk manual-demo, supervisor mencatat signed `PRE_DISPATCH` news head lalu,
  setelah callback approval/policy, memverifikasi ulang decision, approval,
  journal, risk, facts, account snapshot, lease, dan signed successor news.
  Stale/blackout/fork/expiry sebelum dispatch melatch fail-closed.

### Feasibility risk cap pada minimum lot

- Pure governor tetap memakai `order_calc_profit()`/broker spec dan conversion
  receipt. Untuk pair USD-quoted, contract 100.000, dan `0.01` lot, cap FX
  `$0.25` kira-kira hanya memberi 2,5 pip sebelum biaya. Untuk XAU contract 100,
  `0.01` lot adalah kira-kira satu ounce sehingga cap `$0.20` kira-kira hanya
  memberi `$0.20` jarak harga sebelum biaya.
- Ini bukan alasan menaikkan batas. Jika spread, komisi, slippage, stop level,
  atau minimum volume melampaui risk budget, hasil wajib `WAIT`. Feasibility
  harus diukur pada exact broker/account/symbol dan menjadi bagian manual-demo
  serta soak acceptance.

## Lock dan acceptance lokal

```text
live_allowed = false
safe_to_demo_auto_order = false
max_lot = 0.01
GBPUSD = blocked
BTCUSD = shadow-only
```

- Safety decisions, permit validation, health decision, receipt, dan model
  binding semuanya deny-only; tidak ada satu artefak yang dapat membuka
  execution dengan sendirinya.
- Orphan position, missing/mismatched server-side protection, risk stop, atau
  critical reconciliation condition melatch kill switch.
- File bridge/MQL5 lama tetap legacy demo-only. Runtime entrypoint decision,
  execution, dan status monitor tersedia, tetapi tidak ada entrypoint yang
  dapat membuka central lock atau mengaktifkan demo-auto/live coordinator
  tanpa seluruh external authority dan release acceptance.
- Hashed transitive `pylock.windows-cp312.toml` mengikat 14 dependency runtime
  minimal untuk
  CPython 3.12 `win_amd64`, exact MetaTrader5 wheel, dan reproducible vendored
  `ta` wheel. Exact pip vendored menjalankan bootstrap dari wheelhouse flat yang
  diverifikasi tanpa mempercayai pip lama; validator lalu menolak target,
  version, artifact, hash, selected-wheel, installed tree, bytecode, wrapper,
  source-manifest, package-set, atau wheel-availability drift. `yfinance` dan
  dependency Yahoo tidak boleh masuk runtime live. Ruleset contract mengikat
  lock, wheel-tree manifest, hashed requirements, guard, bootstrap, dan
  verification scripts.
- CycloneDX 1.6 SBOM deterministik mengikat tepat 14 dependency runtime dan
  satu wheel bootstrap `pip`, termasuk exact purl, role, filename, ukuran, dan
  SHA-256 wheel. Validator membangun ulang expected SBOM dari lock serta install
  manifest dan menolak semantic rewrite, package drift, encoding noncanonical,
  atau hash mismatch. Writer wheel/install manifest dan hashed requirements
  menetapkan LF secara eksplisit, sementara `.gitattributes` memaksa `eol=lf`
  pada seluruh dependency artifact yang terikat hash. Ini menutup drift CRLF
  Git-for-Windows yang sempat menghasilkan manifest 9.398 byte alih-alih
  canonical 9.197 byte.
- Gate vulnerability OSV terpisah mengikat exact lock/SBOM/package inventory,
  seluruh raw query/response dan pagination, freshness maksimum 24 jam, key ID,
  payload hash, serta HMAC. Provider unavailable/incomplete/unknown, receipt
  stale/future/tampered, atau satu known vulnerability selalu memblokir.
  Signing key file wajib berada di luar repository. Belum ada receipt OSV nyata
  yang diklaim sebagai bukti release.
- Builder release Windows memakai exact allowlist dari clean Git commit,
  output deterministik create-exclusive di luar repository, local-import
  closure, secret/state/history exclusion, dan immutable safety/usage policy.
  Modul executor/MT5 adapter/reconciliation/MQL5 serta primitive
  `order_send`, `order_check`, action/order constants, dan `CTrade` ditolak
  struktural dari profile read-only. Profile operator tooling tetap terpisah;
  minimal read-only shadow service memiliki allowlist dan policy exact sendiri.

## Batas bukti yang masih fail-closed

1. Signed local head/HMAC mendeteksi mutation, truncation, dan ordinary local
   tampering, tetapi tidak dapat membuktikan coordinated rollback seluruh
   directory. Random journal incarnation mendeteksi fresh database replacement
   di path sama, namun restore snapshot lama dari incarnation yang sama juga
   baru dapat dideteksi bila high-water anchor dibandingkan dengan copy off-host.
   `off_host_object_lock_verified` tetap `false`.
2. Evidence, permit, news, dan reset keys belum memiliki production custody
   terpisah/HSM-backed. Local signature bukan bukti independen dari host yang
   menghasilkan data. `external_key_custody_verified` tetap `false`.
3. Python MT5 tidak menyediakan broker-authenticated monotonic tick sequence.
   Local `source_sequence` hanya dapat dipakai bila benar-benar tersedia dan
   contiguous, sehingga `external_tick_sequence_authenticity_verified` tetap
   `false`. Tanpa sequence, tick berbeda pada millisecond yang sama
   mempertahankan urutan yang dikembalikan broker; sistem tidak lagi membuat
   urutan lexicographic sintetis. Record yang benar-benar identik ditolak
   fail-closed karena urutan aslinya tidak dapat dibedakan.
4. Byte-derived regulatory review, signed base calendar, dan prospective
   amendment chain membuktikan integrity,
   urutan, no-hindsight closure, serta final source-inventory binding. Kontrol
   ini belum membuktikan bahwa reviewer manusia independen/berkualifikasi atau
   interpretasi setiap dokumen resmi benar, dan exact broker calendar/export
   provenance belum dijalankan sebagai evidence window nyata. Tidak ada
   compliance/legal approval aktual yang diklaim; Phillip profile registration
   tetap false.
5. Trusted-clock interface dan drift gate sudah ada, tetapi Windows time source,
   independent clock monitoring, dan off-host time attestation belum dipasang.
6. Signed-news verifier sudah ada, tetapi production provider, independent key
   custody, feed SLA, replay archive, dan failure evidence belum tersedia.
7. Model-binding code, portable frozen artifact, dan local registry
   request/receipt verifier tidak membuktikan kualitas model. Exact-HEAD
   champion ZIP harus dibangun dari snapshot yang direview; independently
   pinned policy, external immutable upload/version, signed custodian receipt,
   restore proof, dan offline validation receipt masih harus dibuat dan
   diaudit.
8. Logical paired commit dan fail-closed crash state sudah diterapkan lokal,
   tetapi ini bukan satu atomic filesystem transaction lintas seluruh file.
   Repeated paired-export, forced-crash recovery, NTFS durability, dan lock
   behavior pada exact Windows/MT5 stack masih harus dibuktikan lewat soak.
9. `RuntimeFactCollector` dan factory yang mengubah signed fact receipt menjadi
   risk context sudah tersedia serta memeriksa account, tick, broker spec,
   disk/clock/news/journal dan exact binding/freshness. Namun exact Windows/MT5
   provider integration, independent key custody, off-host high-water, dan
   broker rollover/news production source belum dipasang. Karena itu receipt
   lokal belum menjadi trust root live.
10. Independent promotion issuer kini menerima raw immutable observations,
    menghitung ulang trade count/duration/PF/drawdown/cost stress/seeded
    bootstrap, memverifikasi tepat lima fold dan parity corpus, serta hanya
    menerima validation binding dari verifier adapter yang sealed. Exact
    champion ZIP diverifikasi langsung terhadap enam pin menjadi sealed
    observation; seluruh trade/fold/parity wajib membawa lane/config/model yang
    sama dan complete raw corpus memiliki canonical SHA-256. Signed
    `promotion-evidence-v2` menurunkan commit/model dari champion dan mengikat
    archive/package/snapshot/tree/runtime/corpus/bootstrap identities. Receipt
    tetap memerlukan independent production key custody dan corpus broker/OOS
    nyata; data sintetis dalam test bukan promotion evidence.
11. Champion lineage kini mencapai stage dan runtime boundary. `StageBinding`
    v3 mewajibkan exact archive, package, training snapshot, Git tree, dan
    runtime-binding identities selain commit/config/model. Signed promotion
    evidence dibandingkan dengan pin stage independen saat authorization,
    standalone validation, supervisor verification, reservation refresh, dan
    immediate pre-send. Cross-champion atau pin hilang ditolak sebelum adapter
    preflight/submission. Windows production-bootstrap schema v2 juga membawa
    kelima pin sebagai field konfigurasi yang direview dan membandingkannya
    dengan exact stage sebelum provider, SQLite, credential, MT5, network, atau
    adapter effect; aggregate stage hash tetap wajib. Kontrak dan bukti lokal
    ada di `docs/RUNTIME_STAGE_CHAMPION_BINDING.md` dan
    `docs/WINDOWS_RUNTIME_STAGE_CHAMPION_CONFIGURATION.md`; ini bukan activation
    approval.
12. Broker-neutral one-shot evidence shadow runner kini memiliki durable per-stage receipt,
    hash-chained operational journal, singleton fence, disk floor, heartbeat
    projection, status-only watchdog, verified create-exclusive audit export,
    serta mandatory exact absolute `terminal64.exe` binding untuk seluruh
    kandidat non-XM. Missing/relative/directory/symlink/wrong-name paths ditolak
    sebelum journal/runtime effect; receipt hanya menyimpan normalized-path
    SHA-256. Exact Windows/Phillip v1 invocation sudah membuktikan dependency
    guard, startup receipt, exact terminal initialization, fail-closed HOLD,
    audit export, dan runtime-status projection. Ia belum mencapai contract
    verification karena collector memakai legacy XM expert-flag rule.
    Remediation v2 mempertahankan XM strict default tetapi mengizinkan flag
    informational `account.trade_expert=true` untuk kandidat broker-neutral
    hanya ketika account/terminal trading tetap false dan trade API disabled.
    Status/audit v2 juga memakai validated candidate runtime key serta
    candidate-prefixed invocation filename dan menolak journal dengan runtime
    namespace berbeda; XM legacy tetap backward-compatible. Exact Windows v2
    proof sudah berhasil dengan authenticated chain from genesis, runtime
    `HEALTHY`, dan cycle `IDLE`; belum ada broker evidence append karena masih
    pre-window. Proof timestamp mengungkap startup-to-cycle sekitar 202,635
    detik, sementara append grace hanya 60 detik. Immutable v3 remediation
    menambahkan bounded persistent worker: full environment di-hash sekali per
    proses, child berikutnya memvalidasi ulang lock/install-manifest dan
    membawa compact HMAC-bound session reference, cycle dicoba setiap menit
    detik `02`, worker/process fence terpisah mencegah overlap, dan setiap
    child nonzero menghentikan worker fail-closed. Exact V3 proof mempertahankan
    kegagalan first-child akibat aktivasi site-packages berulang. V4
    memperbaikinya dengan aktivasi satu kali plus validasi path/precedence per
    child dan exact Windows proof lulus untuk 13 children. Task V4 kemudian
    dinonaktifkan fail-closed ketika exported XML menghilangkan optional
    `RunLevel`. Worker proof V5 kemudian lulus untuk 12 authenticated
    children. Task V5 kembali dinonaktifkan fail-closed ketika exported XML
    menghilangkan XSD-default `StartWhenAvailable=false`. V6 scheduler-only
    memakai satu validator bersama untuk installer/health, menerapkan default
    XSD secara eksplisit, memeriksa semua effective CIM settings, serta
    mempertahankan V4/V5 disabled tanpa mengubah worker contract V5. V6
    register-disabled-first, mensyaratkan lead 900 detik, memverifikasi exact
    first `NextRunTime`, memakai fail-closed stop+disable rollback, dan menilai
    freshness hanya dari heartbeat HMAC monotonic—not file mtimes. Exact proof
    children dan predecessor sequence/hash/HMAC kini diikat ke append-only
    signed checkpoint; health memverifikasi suffix baru saja, toleran terhadap
    audit publication yang belum memiliki manifest, dan mengikat exact head ke
    HMAC-authenticated live SQLite journal agar tail rollback ditolak. Named
    mutex mencegah checkpoint fork; installer dan opsi `-FullArchiveAudit`
    memeriksa ulang seluruh byte arsip historis, dengan mode eksplisit hanya
    saat task `Ready`, di luar active interval, dan memiliki lead sedikitnya
    3600 detik. Checkpoint diflush ke temporary non-chain lalu dipindah atomik
    ke nama final create-exclusive. Health menghitung ulang fase
    scheduler setelah verifikasi, menerima `Queued` hanya sebelum startup
    attempt, serta menolak early worker exit.
    Transport V6 pertama berhenti sebelum instalasi ketika Windows PowerShell
    5.1 mempertahankan array JSON top-level sebagai satu pipeline object.
    V6.1 mere-enumerasi hasil parse secara eksplisit, mengikat expected count
    ke manifest, dan menolak file/direktori ekstra secara rekursif, tetapi
    first boundary-nya lewat sebelum transfer. V6.2 mempertahankan extraction
    fix dan berhasil diekstrak, tetapi pre-registration self-test gagal ketika
    XML adapter PowerShell 5.1 mengubah empty `Principal` menjadi string.
    V6.3 memilih parent fixture melalui exact XPath `XmlElement`, mempertahankan
    first boundary `2026-07-30T06:45:00+09:00`, mengikat schedule identity yang
    sama pada manifest/installer/health/contract, dan memakai root operator
    baru yang terikat commit. Root/transfer V6, V6.1, dan V6.2 wajib tidak
    diubah bila ada; ketiadaan path yang belum pernah dibuat bukan blocker.
    Satu deterministic post-run toolkit kini memverifikasi outer ZIP dan exact
    source commit/tree, menjalankan hash-pinned health checker tanpa memulai
    task, lalu mengikat health snapshot, signed checkpoint terbaru, exact audit
    pair, installation receipt, installed task XML, dan raw XML Task Scheduler
    Operational events ke acceptance ZIP create-exclusive. Toolkit v2 juga
    menyediakan pre-boundary readiness checker. Verifier memerlukan correlated
    event 107/100 pada `InstanceId` yang sama, menolak event 110/manual pada
    launch yang sama, dan menolak pre-boundary/non-advanced evidence,
    transcript drift, scheduler failure, archive drift, atau custody overclaim.
    Create-exclusive publication memakai no-follow `lstat`; output regular,
    directory, valid symlink, atau dangling symlink yang sudah ada ditolak
    tanpa mutasi, dan cleanup dibatasi ke exact file identity yang dibuat oleh
    invocation berjalan.
    Actual scheduled proof serta off-host Object Lock/WORM acknowledgement
    tetap belum ada.
    Loop broker-tick diagnostic non-promotional juga sudah tersedia.
    Periodic broker reconciliation supervisor lokal kini memiliki durable
    lease/fence, startup reconciliation, hash-chain receipt, dan fail-closed
    latch. Provider-neutral off-host signed envelope/outbox/ack port serta
    directory-drop adapter juga tersedia. Durable soak/demotion reset tracker,
    actual remote WORM/alert provider, supervisor composition, dan restore drill
    belum dipasang atau diuji pada Windows VPS.
13. Supply-chain workflow, SBOM, OSV receipt verifier, deterministic release
    builder, exact minimal read-only service allowlist, serta signed two-build
    reproducibility receipt sudah tersedia lokal, tetapi actual OSV collection,
    independent signing-key custody, clean committed release identity, dan
    clean-checkout build pada exact Windows host belum dilakukan. CSV market
    cache di `data/` dan seluruh legacy runtime JSON di repository root sudah
    dikeluarkan dari Git serta tetap bukan release input; immutable JSON
    configuration hanya boleh berada di `config/`. Karena itu ZIP hanya boleh
    dibuat dari clean checkout commit yang sudah direview.
14. Bounded Windows service sudah menutup release-root, import-origin,
    heartbeat-chain, lost-deadline, dan exact-once abort gap secara lokal.
    Static reviewed factory template sekarang juga mengikat exact provider
    contract, implementation/config hash, purpose-matched Windows Credential
    Manager references, dan Task Scheduler host/release/service-account/ACL
    identity tanpa mengimpor provider atau materialize broker component.
    HMAC trust tetap local/test. Public RSA verifier kini tersedia, tetapi
    externally issued launcher policy/attestation, offline private-key custody,
    external factory/provider configuration, Task Scheduler registration,
    Credential Manager custody, dan restart/failure behavior tiga service
    belum dipasang serta diterima pada target Windows.
    Base decision/execution release kini dapat digabung dengan exact
    secret-free overlay melalui configured-service builder yang
    byte-deterministic, create-exclusive, self-verifying, dan mempertahankan
    nested base manifest/identity. Verifier offline memerlukan pin configured
    serta base identity dan tidak mengimpor factory. Tooling tersebut berada
    dalam profile operator stdlib-only terpisah; keberadaannya tidak
    mematerialisasi provider atau menggantikan external provider acceptance,
    launcher attestation, maupun Task Scheduler review. Production decision
    loader sekarang memverifikasi exact configured release, RSA launcher
    attestation, import origin, sealed factory result, dan bounded runtime.
    Operator tooling kini juga memiliki candidate preparer yang menurunkan
    exact profile-template hash dari base ZIP, stable-read Task Scheduler
    definition, membuat canonical factory manifest/descriptor, memverifikasi
    exact local import closure, lalu menulis keduanya secara create-exclusive.
    Statusnya tetap `CANDIDATE_PREPARED_EXTERNAL_REVIEW_REQUIRED`; tool tidak
    menulis provider, credential, task, configured ZIP, atau authority.
    Operator tooling juga dapat membentuk provider conformance packet yang
    merekonstruksi tiga factory template. V1-v3 mempertahankan 65 binding;
    additive v4 memerlukan sealed LIVE source-bound result dan mencocokkan
    tepat 68 binding, termasuk 49 provider Execution LIVE, dengan fresh
    external suite/artifact hashes. Kontrak v2 menurunkan
    configured-release set dari tiga exact identity dan tidak lagi meminta
    future pre-manual admission hash. Packet tetap `provider_accepted=false`;
    content hash hanya boleh menjadi `source_evidence_sha256` setelah objek
    validasi independen yang berbeda menghasilkan
    `validation_receipt_sha256`.
    Deterministic external status-monitor release, configured-release loader,
    serta bounded runner juga sudah tersedia sebagai service ketiga tanpa
    broker/order authority. Provider nyata, key/CAS/latch custody, dan
    off-host delivery acceptance tetap eksternal.
15. Demo-auto decision IPC consumer sudah ada tetapi sengaja locked. Outputnya
    dapat diproses oleh risk/intent boundary dan dispatch seam yang memerlukan
    seluruh sealed authority. Session reservation terikat journal, crash
    sebelum send hanya boleh ditutup dengan unused-lease proof, sedangkan
    possible send tetap reconciliation-required lintas restart. Account cohort
    memverifikasi projection chain dan broker-closed-deal evidence untuk ambang
    30 hari/50 fill/20 XAU tanpa memberi authority. Dormant renewable session
    capability dan deny-by-default gate catalog tetap false/disabled.
    Brokerless M15 decision producer sekarang memiliki
    deterministic Windows profile tersendiri dengan exact allowlist, pinned
    dependency closure, static factory contract, serta runtime runner dengan
    validasi side-effect-free dan jalur operasional ber-attestation. Profile itu
    dipisahkan dari executor bundle. Signed append-only decision-feed handoff
    sekarang menyediakan implementation option untuk role
    `FINALIZED_M15_DATA`: exact broker/account/lane binding, canonical
    HMAC-authenticated packet, per-lane sequence/predecessor, create-exclusive
    persistence, strict stable read, fork/rollback/tamper rejection, dan
    reconstruction ke exact `FinalizedM15DecisionInput`. Handoff itu tetap
    runtime transport, bukan validation/promotion evidence, dan tidak
    mengandung MT5 maupun order capability. Reference broker-side publisher
    sekarang tersedia di profile read-only shadow terpisah: ia mengikat exact
    demo account/server/lane, re-attest sebelum dan sesudah market read,
    menegakkan current finalized M15, first eligible tick, publish-lag budget,
    independent session-gap receipt, serta signed-feed conflict semantics.
    Jalur operasional masih membutuhkan reviewed
    trusted-clock/key/account-identity/calendar/provider configuration,
    external provider conformance, configured identity, dan external RSA
    launcher attestation.
    Operations review v2 kini mengikat exact decision dan execution release,
    Python runtime serta service identity yang terpisah, IPC v2, dan external
    status-monitor reference. Implementasi monitor lokal tidak mengubah bundle
    v2 menjadi installer: configured monitor release, third service task, dan
    provider acceptance harus direview terpisah. Schema v1 tetap readable untuk
    histori tetapi tidak lagi menjadi kontrak host karena memakai satu release
    serta placeholder entrypoint yang tidak ada di release aktual.
    Independent session/projection custody, exact Windows queue/provider wiring,
    externally signed launcher attestation, sembilan observation pra-manual,
    review manusia untuk stage evidence, 10 manual-demo lifecycle, observation
    hasil ke-10, dan approval DEMO_AUTO tetap harus diselesaikan sebelum soak
    boleh dimulai.

Karena batas di atas, kalender yang valid dapat membuat
`session_calendar_verified=true` dan data grid dapat lengkap secara lokal,
tetapi `coverage_complete` serta `promotion_eligible` tetap `false` selama gate
eksternal belum terpenuhi.

## Blocker eksternal sebelum tahap berikutnya

1. FBS exact demo binding, read-only preflight, dan diagnostic shadow telah
   berhasil diamati, tetapi official Japan FSA unregistered-operator warning
   membuatnya project-blocked untuk discovery evidence, order, promotion, dan
   live selama lokasi operasi masih Jepang. Diagnostic paper boleh berlanjut.
   FINEX adalah future-Indonesia preparation path karena registrasi Bappebti
   telah diverifikasi, tetapi personal/account eligibility setelah kembali dan
   current-Japan eligibility tetap belum disetujui.
   Phillip Securities Japan adalah candidate path untuk operasi saat ini:
   exact demo lanes, signed regulatory/calendar review, dan manual activation
   profile `phillip-commodity` sudah terikat. Immutable Commodity v1 tetap
   kosong. Namespace v2 sudah diregistrasikan dan pre-window proof-nya
   terverifikasi, tetapi tidak dipakai untuk scheduled append karena latency
   full-environment verification melebihi deadline. Namespace v3/v4/v5 adalah
   bukti historis immutable. Remediasi scheduler V6.3 sudah terpasang dan
   health `PRE_START` Windows sudah sehat; tahap berikutnya wajib menunggu
   pemicu otomatis pertama pada `2026-07-30T06:45:00+09:00`, lalu menjalankan
   menjalankan trigger-audit readiness sebelum boundary, lalu acceptance
   post-run tanpa manual start. `phillip-fx` tetap menunggu review
   dan activation lane-nya sendiri. XM Window 02 tetap tidak boleh dijalankan.
   Setiap kandidat
   tetap membutuhkan minimal 20 sesi terpisah.
2. Jalankan broker read-only shadow pada exact symbols; ekspor signed session
   calendars, finalized M15 bid/ask bars, raw ticks, spread/fill distributions,
   dan bukti minimal delapan minggu per lane.
3. Ekspor chain head/receipt ke Object Lock/WORM di luar VPS, gunakan key
   custody terpisah, dan uji restore serta coordinated-rollback detection.
4. Provision Windows VPS dengan tiga least-privilege service identity dan tiga
   exact Task Scheduler definitions untuk decision, execution, serta external
   status monitor; gunakan Credential Manager, VPN/MFA, offline-issued RSA
   launcher policy/attestation yang SHA-256-nya dipin di setiap task
   definition, trusted time source, off-host heartbeat/alert acknowledgement,
   immutable audit export, disk alarm, dan daily backup/restore drill.
5. Pilih production news provider; provision signing-key custody, coverage/SLA
   monitoring, replay archive, stale-feed drill, dan documented failover yang
   tetap fail-closed.
6. Bangun dan verifikasi exact-HEAD frozen champion ZIP dengan enam pin
   independen; buat serta verifikasi deterministic registry request dengan pin
   ketujuh; register exact bytes di custody eksternal; verifikasi receipt
   custodian terhadap policy RSA yang dipin independen; buktikan restore serta
   offline champion/challenger evaluation; dan pastikan challenger tidak
   memiliki credential maupun execution path.
7. Provision dua identitas approver reset yang benar-benar independen beserta
   secret custody; lakukan drill latch/restart/stale/mismatch/replay dan simpan
   audit receipt.
8. Install dan verifikasi hashed Windows lock pada exact VPS menggunakan pip
   26.1.2 serta binary-only mode, lalu ulangi import, vulnerability, rollback,
   clean-checkout, dan reproducibility checks pada host target.
9. Setelah perubahan direview, buat clean commit baru, bangun bundle dengan
   exact allowlist dari clean checkout, collect receipt OSV nyata dengan key di
   luar repository, dan arsipkan manifest/receipt melalui channel off-host.
   Deterministic decision, execution, status-monitor, dan configured-tooling
   archive untuk commit `d153361` sudah lulus reproduksibilitas lintas-host;
   receipt-nya tercatat di
   `docs/WINDOWS_BASE_RELEASE_REPRODUCIBILITY_2026-07-24.md`. Receipt tersebut
   sekarang merupakan baseline historis karena decision allowlist mendapat
   signed-feed module; seluruh role harus dibangun ulang dari clean commit yang
   sama sebelum configured-release review. Receipt lama belum menggantikan OSV
   receipt atau configured-provider acceptance.
10. Bangun profile `WINDOWS_READ_ONLY_SHADOW_SERVICE_V1` dari clean checkout
    pada exact Windows host, lakukan dua build independen, verifikasi signed
    reproducibility receipt, lalu jalankan hanya bundle service tersebut melalui
    Task Scheduler. Bundle operator tetap tidak boleh dijalankan oleh service
    account.
11. Selesaikan failure drills serta repeated paired bar/raw ingestion. Sesudah
   sembilan signed gate pra-run diterima, jalankan pre-manual entry verifier
   dan review stage evidence secara terpisah; kemudian jalankan 10 manual-demo
   order. Observation hasil ke-10 dan full external dossier baru boleh dibuat
   setelah run, sebelum 30-day demo-auto soak direview. Reporter
   `run_manual_demo_readiness.py` dan pre-manual verifier tidak merupakan izin
   order.
12. Penuhi gate statistik per lane: OOS/forward trade minimum, purged folds,
    PF, bootstrap expectancy lower bound, drawdown, cost stress, dan 100%
    deterministic replay/runtime parity.

Sampai seluruh blocker relevan ditutup dan manual ship approval diberikan,
sistem harus tetap **NOT_READY / DO NOT SHIP**. Tidak ada config, permit,
receipt, model, test, atau restart yang boleh menampilkan
`safe_to_demo_auto_order=true` maupun `live_allowed=true`.
