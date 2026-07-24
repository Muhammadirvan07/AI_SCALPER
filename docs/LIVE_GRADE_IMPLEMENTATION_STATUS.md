# AI_SCALPER Live-Grade v1 — Implementation Status

Status: **FOUNDATION IMPLEMENTED / DO NOT SHIP / NOT_READY**

Validasi lokal terakhir pada 2026-07-24 menjalankan **1.387 test** tanpa
kegagalan dalam mode normal maupun optimized pada development Mac. Itu adalah
software regression evidence, bukan Windows host acceptance, broker-forward
evidence, atau izin trading.

Dependency lock/install manifest/SBOM lokal juga tervalidasi dan
`pip-audit 2.10.1` melaporkan nol kerentanan yang diketahui pada environment
development. Pemeriksaan tersebut tidak menggantikan fresh signed OSV receipt
dari exact Windows release.

Dokumen ini membedakan implementasi software lokal dari bukti operasi. Test
hijau tidak menggantikan broker-forward evidence, legal review, Windows VPS
hardening, demo soak, atau approval manusia. Tidak ada bagian dokumen ini yang
membuka demo-auto maupun live.

## Status roadmap

| Tahap | Status | Bukti saat ini |
|---|---|---|
| 1. Baseline terkunci | Selesai secara lokal | Seluruh safety lock terjaga; mutable CSV market cache dan legacy JSON runtime sudah dikeluarkan dari release source. Exact committed source lulus full regression dan empat clean-checkout Windows release build tanpa membawa artefak runtime lokal. |
| 2. Evidence infrastructure | Implemented locally | Frozen snapshot, HMAC-signed forward contract v4, v3 compatibility, byte-derived regulatory review package with two independent HMAC approvals, byte-derived pre-window base-calendar review with a separate human HMAC approval, prospective closure-only amendment chain, final completeness attestation, append chains/heads, seal, blinded receipt, strict UTC/build/source/spec/grid verification, broker-neutral profile/plan/contract binding, dan generic one-shot collector tersedia. |
| 3. Broker read-only shadow | FBS and Phillip diagnostic bindings observed; evidence not started | FBS forex/metal/crypto diagnostic domains dan Phillip FX/commodity dual-terminal lanes memiliki journal/report terpisah. Phillip sanitized discovery-v3 inputs berhasil dibuat dan reviewed regular M15 base schedules tersedia, tetapi profile registration, regulatory approval, 20-session benchmark, broker-forward contract, dan promotion evidence tetap disabled/pending. FINEX tidak dipakai untuk observasi baru. |
| 4. Manual demo | Component foundation ready, readiness locked, orders not run | Journal-bound signed permit, one-second process environment arm, signed per-intent operator approval, champion-model binding, signed news guard, broker-native sizing, account-currency-normalized USD risk cap, account-wide fence, risk governor, fenced journal, bounded Windows composition, MT5 preflight/executor/reconciliation, dual-control kill-switch reset, non-mutating readiness report, deny-only pre-manual entry verifier, dan exact configured-release admission tersedia. Sembilan signed gate pra-run, review aktivasi manual-demo, serta sepuluh order demo belum selesai. |
| 5. Demo-auto soak | Local three-service activation foundation complete but locked; soak not started | Decision IPC, one-use risk/intent, renewable session CAS, journal-bound dispatch settlement/restart recovery, authenticated soak projection, account-level 30-day/50-fill/20-XAU cohort, mode-aware Windows factory contract, separate decision/execution/status-monitor releases, deny-only gate catalog, immutable operator-only three-service v3 operations review bundle, public-key external-acceptance verifier, deterministic configured-release builder/verifier, exact three-ZIP admission, production decision loader, external status-monitor loader/runner, deny-only 65-binding provider conformance packet, serta offline evidence-input assembler tersedia. Assembler menurunkan binding truth dari tiga exact factory template dan menolak transkripsi manual, tetapi tidak membuat evidence/acceptance. V3 mengikat ketiga configured identity, runtime, IPC, monitor custody, failure manifest, dan tepat tiga validation-only scheduler review; admission membaca byte ZIP secara stabil lalu mengikat archive/manifest/Git/factory/config/task ke signed dossier sebelum pre-manual assessment. Provider packet memberi target detail hash per role/port tetapi tetap `provider_accepted=false`. Semua verifier hanya dapat meminta activation review. Historical v1/v2 tetap readable dan deny-only. External provider/key/CAS/latch custody dan actual signed acceptance observations, launcher issuance, exact Windows task/ACL activation, policy approval/unlock, sepuluh manual-demo lifecycle, serta actual soak evidence belum ada. |
| 6. XAUUSD live canary | Not started | Dormant XAUUSD-only symbol scope sudah tersedia, tetapi central live lock, execution-policy approval, promotion evidence/permit/soak, dan 50 closed live trades belum ada. |
| 7. Pair expansion | Not started | EURUSD, USDJPY, dan AUDUSD harus mengulang seluruh gate per lane; hasil lane lain tidak boleh menutup kegagalan sebuah pair. |
| 8. Scaling | Out of v1 | Tidak ada auto-scaling lot maupun risk cap. |

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
- Registration-review tooling menghitung hash dari byte dokumen authority
  lokal, mengikat satu candidate/template/symbol lane, dan membutuhkan tepat
  dua approval HMAC dengan role, approver, key ID, serta secret fingerprint
  berbeda. Reviewer key hanya dimuat dari Windows Credential Manager. Final
  assembly tidak mengubah tracked config dan profile Phillip tetap disabled;
  plan/contract kelak juga mengulang verifier dengan vault key provider.
- Activation-review pack non-mutating kini mengikat discovery-v3, dua approval
  regulasi, satu signed pre-window calendar review, serta clean Git commit/tree
  dalam satu proposal immutable. Pack membawa base dan after-image lengkap
  untuk tepat tiga tracked file sehingga bounded diff dapat diverifikasi tanpa
  secret. Tool tidak memiliki apply entrypoint; actual registration, order,
  promotion, demo-auto, dan live tetap false.

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
  atau hash mismatch.
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
7. Model-binding code tidak membuktikan kualitas model. Frozen champion
   artifact, training snapshot, offline validation receipt, dan production
   registry masih harus dibuat dan diaudit.
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
    menerima validation binding dari verifier adapter yang sealed. Signed
    receipt tetap memerlukan independent production key custody dan corpus
    broker/OOS nyata; data sintetis dalam test bukan promotion evidence.
11. Broker-neutral one-shot evidence shadow runner kini memiliki durable per-stage receipt,
    hash-chained operational journal, singleton fence, disk floor, heartbeat
    projection, status-only watchdog, dan verified create-exclusive audit
    export. Loop broker-tick diagnostic non-promotional juga sudah tersedia,
    tetapi generic collector belum dibuktikan pada exact Windows/FBS host.
    Periodic broker reconciliation supervisor lokal kini memiliki durable
    lease/fence, startup reconciliation, hash-chain receipt, dan fail-closed
    latch. Provider-neutral off-host signed envelope/outbox/ack port serta
    directory-drop adapter juga tersedia. Durable soak/demotion reset tracker,
    actual remote WORM/alert provider, supervisor composition, dan restore drill
    belum dipasang atau diuji pada Windows VPS.
12. Supply-chain workflow, SBOM, OSV receipt verifier, deterministic release
    builder, exact minimal read-only service allowlist, serta signed two-build
    reproducibility receipt sudah tersedia lokal, tetapi actual OSV collection,
    independent signing-key custody, clean committed release identity, dan
    clean-checkout build pada exact Windows host belum dilakukan. CSV market
    cache di `data/` dan seluruh legacy runtime JSON di repository root sudah
    dikeluarkan dari Git serta tetap bukan release input; immutable JSON
    configuration hanya boleh berada di `config/`. Karena itu ZIP hanya boleh
    dibuat dari clean checkout commit yang sudah direview.
13. Bounded Windows service sudah menutup release-root, import-origin,
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
    merekonstruksi tiga factory template dan mencocokkan seluruh 65 binding
    dengan fresh external suite/artifact hashes. Packet tetap
    `provider_accepted=false` sampai hash-nya ditandatangani owner independen.
    Deterministic external status-monitor release, configured-release loader,
    serta bounded runner juga sudah tersedia sebagai service ketiga tanpa
    broker/order authority. Provider nyata, key/CAS/latch custody, dan
    off-host delivery acceptance tetap eksternal.
14. Demo-auto decision IPC consumer sudah ada tetapi sengaja locked. Outputnya
    dapat diproses oleh risk/intent boundary dan dispatch seam yang memerlukan
    seluruh sealed authority. Session reservation terikat journal, crash
    sebelum send hanya boleh ditutup dengan unused-lease proof, sedangkan
    possible send tetap reconciliation-required lintas restart. Account cohort
    memverifikasi projection chain dan broker-closed-deal evidence untuk ambang
    30 hari/50 fill/20 XAU tanpa memberi authority. Dormant renewable session
    capability dan deny-by-default gate catalog tetap false/disabled.
    Brokerless M15 decision producer sekarang memiliki
    deterministic Windows profile tersendiri dengan exact allowlist, pinned
    dependency closure, static factory contract, dan validate-only runner.
    Profile itu dipisahkan dari executor bundle dan masih membutuhkan reviewed
    finalized-data/trusted-clock/key/CAS/provider configuration.
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
   exact demo lanes dan regular schedule sudah terikat, namun signed regulatory
   approval aktual, human acceptance atas profile-registration review pack,
   dan contract registration belum selesai. XM Window 02 tetap tidak boleh
   dijalankan. Setiap kandidat
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
6. Freeze champion model serta training snapshot; register artifact/hash,
   buktikan offline champion/challenger evaluation, dan pastikan challenger
   tidak memiliki credential maupun execution path.
7. Provision dua identitas approver reset yang benar-benar independen beserta
   secret custody; lakukan drill latch/restart/stale/mismatch/replay dan simpan
   audit receipt.
8. Install dan verifikasi hashed Windows lock pada exact VPS menggunakan pip
   26.1.2 serta binary-only mode, lalu ulangi import, vulnerability, rollback,
   clean-checkout, dan reproducibility checks pada host target.
9. Setelah perubahan direview, buat clean commit baru, bangun bundle dengan
   exact allowlist dari clean checkout, collect receipt OSV nyata dengan key di
   luar repository, dan arsipkan manifest/receipt melalui channel off-host.
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
