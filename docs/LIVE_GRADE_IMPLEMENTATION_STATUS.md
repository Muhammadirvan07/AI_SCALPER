# AI_SCALPER Live-Grade v1 — Implementation Status

Status: **FOUNDATION IMPLEMENTED / DO NOT SHIP / NOT_READY**

Dokumen ini membedakan implementasi software lokal dari bukti operasi. Test
hijau tidak menggantikan broker-forward evidence, legal review, Windows VPS
hardening, demo soak, atau approval manusia. Tidak ada bagian dokumen ini yang
membuka demo-auto maupun live.

## Status roadmap

| Tahap | Status | Bukti saat ini |
|---|---|---|
| 1. Baseline terkunci | Sebagian | Seluruh safety lock terjaga, tetapi worktree telah berisi perubahan user/runtime sebelum implementasi sehingga clean baseline commit terisolasi belum dibuat. |
| 2. Evidence infrastructure | Implemented locally | Frozen snapshot, HMAC-signed forward contract v3, signed session calendar per simbol, append chains/heads, seal, blinded receipt, dan strict UTC/build/source/spec/grid verification tersedia. |
| 3. Broker read-only shadow | FINEX demo preflight passed; diagnostic observation ready; evidence not started | Runner `BROKER_REALTIME_DIAGNOSTIC_ONLY` dapat membaca finalized M15 dan broker tick, menjalankan shared decision core, serta mencatat paper outcome append-only. Exact demo server `FinexBisnisSolusi-Demo`, akun USD 500:1, dan mapping XAUUSD/EURUSD/USDJPY/AUDUSD telah lolos read-only preflight. Artefak FINEX dipisahkan dari XM dan journal lintas broker ditolak. Eligibility operasi dari Jepang, 20-session benchmark, serta promotion evidence tetap pending. XM/Tradexfin tetap blocked dan discovery lamanya hanya historical diagnostic. |
| 4. Manual demo | Component foundation ready, orders not run | Journal-bound signed permit, one-second process environment arm, signed per-intent operator approval, champion-model binding, signed news guard, broker-native sizing, account-wide fence, risk governor, fenced journal, one-shot runtime composition, MT5 preflight/executor/reconciliation, dan dual-control kill-switch reset tersedia. Sepuluh order demo belum dilakukan. |
| 5. Demo-auto soak | Not started | Policy tetap locked; belum ada 30 hari, 50 fill, minimal 20 XAU, atau clean incident record. |
| 6. XAUUSD live canary | Not started | XAUUSD belum execution-approved dan belum memiliki promotion evidence/permit/soak maupun 50 closed live trades. |
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
  `account.trade_expert=false`, `terminal.trade_allowed=false`, dan
  `terminal.tradeapi_disabled=true`. Runtime shadow mengimpor package secara
  lazy dan facade tidak menyimpan raw MT5 module atau mengekspor execution
  stack.
- Shadow collector memegang persistent OS singleton fence untuk seluruh siklus
  verify, plan, collect, append, dan SQLite receipt. Optimistic paired sequence
  fence menolak stale writer, sedangkan timestamp append baru dicetak setelah
  tick collection selesai.

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
- Preflight mengikat timestamp dan bid/ask side dari first eligible broker tick
  persis ke `DecisionSnapshot.entry_reference`; drift sebelum `order_send`
  ditolak. Filled volume tertinggi disimpan durable sehingga partial fill yang
  sah direconcile/ditutup terhadap volume yang benar-benar terisi, bukan volume
  request awal.

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
- File bridge/MQL5 lama tetap legacy demo-only. Tidak ada entrypoint produksi
  saat ini yang mengaktifkan demo-auto atau live coordinator.
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
  struktural dari profile read-only. Bundle saat ini tetap operator tooling,
  bukan service runtime.

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
4. Signed session calendar membuktikan kalender tidak berubah setelah kontrak
   dibuat, bukan bahwa jadwal awalnya diterbitkan dan di-attest oleh broker.
   Exact broker calendar exporter serta provenance eksternalnya belum dijalankan.
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
9. `RiskContext`, `RuntimeHealthFacts`, decision data provenance, dan broker
   rollover input masih merupakan domain contract dari caller. Executor
   memeriksa tipe, exact binding, freshness, serta konsistensi, tetapi collector
   production yang membaca state broker/OS dan menerbitkan receipt durable
   belum tersedia. Karena itu komponen ini belum menjadi trust root live.
10. `LaneEvidence` dan golden parity saat ini adalah calculator/fixture lokal.
    Signed promotion receipt menyediakan independent-key boundary, tetapi
    issuer production yang membuka, menghitung ulang, dan memverifikasi trade
    ledger, bootstrap, fold, evidence-store receipt, serta parity corpus belum
    tersedia.
11. One-shot evidence shadow runner kini memiliki durable per-stage receipt,
    hash-chained operational journal, singleton fence, disk floor, heartbeat
    projection, status-only watchdog, dan verified create-exclusive audit
    export. Loop broker-tick diagnostic non-promotional juga sudah tersedia,
    tetapi belum dibuktikan pada exact Windows/XM host dan bukan collector
    evidence. Periodic broker reconciliation supervisor, durable soak/demotion
    reset tracker, actual off-host alert/WORM delivery, serta restore drill
    belum dipasang atau diuji pada Windows VPS.
12. Supply-chain workflow, SBOM, OSV receipt verifier, dan deterministic
    release builder sudah tersedia lokal, tetapi actual OSV collection,
    independent signing-key custody, clean committed release identity, dan
    clean-checkout build pada exact Windows host belum dilakukan. Worktree saat
    ini juga masih dirty; branch remote belum memuat seluruh hardening terbaru.
    Karena itu source/ZIP dari remote saat ini tidak boleh dipakai sebagai
    release.

Karena batas di atas, kalender yang valid dapat membuat
`session_calendar_verified=true` dan data grid dapat lengkap secara lokal,
tetapi `coverage_complete` serta `promotion_eligible` tetap `false` selama gate
eksternal belum terpenuhi.

## Blocker eksternal sebelum tahap berikutnya

1. FINEX telah dipilih sebagai target dan exact demo binding sudah lolos
   read-only preflight. Selama operating jurisdiction masih Jepang, batasi ke
   diagnostic read-only/paper sampai eligibility lintas yurisdiksi dikonfirmasi.
   Lengkapi discovery v3 dan evidence contract secara terpisah. XM Window 02 tetap tidak boleh dijalankan. Setiap
   kandidat tetap membutuhkan minimal 20 sesi terpisah.
2. Jalankan broker read-only shadow pada exact symbols; ekspor signed session
   calendars, finalized M15 bid/ask bars, raw ticks, spread/fill distributions,
   dan bukti minimal delapan minggu per lane.
3. Ekspor chain head/receipt ke Object Lock/WORM di luar VPS, gunakan key
   custody terpisah, dan uji restore serta coordinated-rollback detection.
4. Provision Windows VPS dengan Credential Manager, least privilege, VPN/MFA,
   Task Scheduler watchdog, trusted time source, off-host heartbeat, alerting,
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
10. Pisahkan service-runtime minimal dari deployment-tooling bundle dengan
    menghapus coupling build identity terhadap generator/network tooling.
    Jangan menjalankan bundle operator melalui Task Scheduler/service account.
11. Selesaikan failure drills serta repeated paired bar/raw ingestion, lalu
   jalankan 10 manual-demo order dan 30-day demo-auto soak hanya setelah policy
   review terpisah.
12. Penuhi gate statistik per lane: OOS/forward trade minimum, purged folds,
    PF, bootstrap expectancy lower bound, drawdown, cost stress, dan 100%
    deterministic replay/runtime parity.

Sampai seluruh blocker relevan ditutup dan manual ship approval diberikan,
sistem harus tetap **NOT_READY / DO NOT SHIP**. Tidak ada config, permit,
receipt, model, test, atau restart yang boleh menampilkan
`safe_to_demo_auto_order=true` maupun `live_allowed=true`.
