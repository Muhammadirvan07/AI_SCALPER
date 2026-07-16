# AI_SCALPER Live-Grade v1 Architecture

Status implementasi: fondasi tersedia, tetapi sistem tetap `NOT_READY`. Dokumen
ini bukan izin trading dan tidak mengubah lock eksekusi.

## Boundary produksi

```text
Broker MT5 tick
  -> read-only broker exporter
  -> data QC + immutable evidence
  -> pure decision core
  -> independent risk governor
  -> fenced execution coordinator
  -> official MetaTrader5 adapter
  -> reconciliation
  -> SQLite WAL journal + off-host audit export
```

Modul utama:

- `validation_evidence/`: snapshot development frozen, HMAC-signed forward
  contract, finalized M15 bid/ask bars, raw tick partitions, signed high-water
  chain/anchor, one-lock paired append, signed paired commit/pending chain,
  contract seal, dan blinded receipt yang mengikat chain head.
  Yahoo/`GC=F` selalu development-only. External WORM/Object Lock tetap wajib
  karena local anchor tidak dapat membuktikan rollback seluruh directory.
- `live_runtime/broker_exporter.py`: read-only exact account/server/symbol/spec
  binding, boundary and continuity proof, raw/finalized split, serta paired
  recovery marker. Bridge dari `BrokerSpec` memakai validator evidence yang
  sama agar schema broker tidak bercabang diam-diam.
- `live_runtime/contracts.py`: broker, decision, intent, dan receipt contracts
  dengan UTC-aware validation serta canonical SHA-256.
- `live_runtime/decision_core.py`: pure, mode-agnostic decision core yang
  mempertahankan semantics selector/supervisor/profile saat ini. Replay,
  future shadow, demo, dan live memakai builder snapshot deterministik yang
  sama; finalized M15 proof dan first eligible bid/ask tick wajib tersedia.
- `live_runtime/parity.py`: exact replay/runtime comparison untuk seluruh field
  deterministik. Fill, ticket, dan realized slippage bukan field parity.
- `live_runtime/risk.py`: risk governor pure/fail-closed. Lot yang belum sesuai
  hasil sizing ditolak; caller harus membuat intent immutable baru.
- `live_runtime/permit.py`: HMAC permit yang terikat account/server/symbol,
  journal identity, promotion-evidence hash, commit, config, exact champion
  artifact, mode, dan expiry. Permit tidak dapat membuka lock sendiri;
  kill-switch reset memakai dua approval HMAC independen.
- `live_runtime/controls.py`: process environment arm berumur satu detik dan
  signed manual-demo approval per intent. Tidak ada caller boolean yang dapat
  menggantikan kedua capability tersegel ini.
- `live_runtime/account_fence.py`: OS/process mutex account-wide yang terikat
  exact MT5 login, server, dan environment untuk mencegah split-brain lintas
  journal atau proses.
- `live_runtime/promotion_evidence.py`: independent HMAC receipt yang mengikat
  exact lane/build/broker/journal/readiness/evidence/parity. Receipt ini wajib
  untuk demo-auto/live, tetapi tidak dapat membuka policy lock.
- `live_runtime/market_guard.py`: signed news payload, coverage/freshness,
  high-impact blackout, dan broker rollover blackout dalam sealed deny-only
  decision.
- `live_runtime/model_governance.py`: immutable offline champion/challenger
  manifest; hanya exact champion binding yang dapat mencapai execution gate.
- `live_runtime/journal.py`: SQLite WAL, unique intent ID, state transitions,
  unique decision-to-intent binding, random persistent journal incarnation,
  executor fencing, durable filled volume, one-use authorization consumption,
  append-only receipts, dan latched kill switch.
- `live_runtime/mt5_adapter.py`: official Python integration boundary, exact
  account/server/environment/symbol binding, first eligible tick,
  `order_check`, broker-native sizing via `order_calc_profit`, bounded filling
  policy/slippage, journal-minted one-use submission lease, `order_send`, dan
  broker reads.
- `live_runtime/executor.py`: orchestration at-most-once. Setelah state
  `SUBMITTING`, hasil yang tidak pasti selalu menjadi `UNCERTAIN` dan tidak
  pernah dikirim ulang sebelum reconciliation.
- `live_runtime/runtime_service.py`: composition root one-shot untuk shared
  decision, broker sizing, immutable intent, signed controls, coordinator, dan
  reconciliation. Production tick loop/watchdog sengaja belum tersedia.
- `live_runtime/reconciliation.py`: active order/position/deal matching, orphan
  detection, external-close handling, serta server-side SL/TP confirmation.
- `live_runtime/health.py`: clock, heartbeat, disk, database, feed, audit,
  backup, broker, dan kill-switch deny gates.
- `live_runtime/readiness.py`: gate per lane; tidak melakukan agregasi lintas
  pair untuk menutupi lane yang gagal.

## Invariant eksekusi

- Timeframe eksekusi M15.
- Keputusan hanya sesudah bar final; entry memakai tick broker pertama yang
  eligible sesudah close dan wajib berada dalam window 10 detik.
- BUY memakai ask untuk masuk dan bid untuk keluar; SELL sebaliknya.
- Replay ambiguous candle memakai stop-first.
- Risk final dihitung ulang dari harga request menggunakan broker
  `order_calc_profit()` dan margin menggunakan `order_calc_margin()`.
- Intent immutable dan idempotent. Lot tidak pernah diubah diam-diam setelah
  intent dibuat. Satu sealed decision hanya boleh menghasilkan satu durable
  intent, termasuk setelah definitive broker reject.
- First eligible tick time serta side-correct bid/ask price harus sama persis
  dengan snapshot entry reference sebelum preflight; broker fill sesudah send
  boleh berbeda dan dicatat sebagai slippage.
- Adapter hanya menerima short-lived capability yang terikat signed permit,
  approved risk decision, sealed health/news/rollover guard, exact champion,
  broker spec, preflight, dan durable `SUBMITTING` reservation. Request dibangun
  ulang tepat sebelum network call.
- Receipt `FILLED` belum dianggap aman sampai reconciliation membuktikan posisi
  serta SL/TP server-side.
- Broker object tanpa intent melatch kill switch dan memerlukan review manual.
- Champion adalah satu-satunya kandidat yang kelak boleh punya execution path;
  challenger tetap offline/shadow dan tanpa credentials.

### Shared decision-core adapters

`strategy.replay_validator.build_replay_decision_snapshot()` dan
`live_runtime.decision_core.build_runtime_decision_snapshot()` adalah thin
adapters yang sama-sama memanggil `build_decision_snapshot()`. Input wajib
berupa OHLC M15 yang telah distandardisasi Data QC, bukti setiap bar final,
timestamp UTC, serta tick broker pertama setelah close. Tick harus tiba paling
lambat 10 detik; BUY memakai ask dan SELL memakai bid. Replay CSV proxy atau
midpoint-only tidak dapat menghasilkan snapshot parity broker-grade.

Core hanya menghasilkan keputusan deterministik. Ia tidak membaca mode,
permit, environment arm, credential, broker API, clock, atau execution policy, dan
tidak dapat memberi izin order; risk governor serta seluruh hard lock tetap
berada di downstream trust boundary.

## Lock yang berlaku

```text
live_allowed = false
safe_to_demo_auto_order = false
max_lot = 0.01
GBPUSD = blocked
BTCUSD = shadow-only
```

Manual demo adalah lane terpisah: hanya mungkin dengan permit journal-bound,
exact process environment arm yang fresh, signed approval per intent,
health/risk/preflight lulus, journal fence dan account-wide fence aktif. Tidak
ada entrypoint produksi saat ini yang memanggil coordinator untuk mengirim
order. Policy source-of-truth saat ini masih execution-approved untuk EURUSD
saja; karena itu XAUUSD juga belum dapat mencapai adapter order sampai shadow
dan promotion gate XAU selesai serta perubahan policy disetujui terpisah.

`RiskContext`, `RuntimeHealthFacts`, decision data provenance, dan rollover
input masih harus diganti oleh collector production yang membaca broker/OS dan
menerbitkan receipt durable. Demikian juga issuer promotion production harus
menghitung ulang lane metrics dari trade ledger dan memverifikasi corpus parity,
bukan menerima angka caller. Selama trust roots ini belum tersedia, arsitektur
tetap foundation dan bukan runtime live-grade yang siap dipakai.

## Promotion gates

Gate dihitung per kombinasi symbol + strategy + config:

- sekurangnya 100 closed OOS trades;
- sekurangnya 50 broker-forward trades dan 8 minggu;
- 3 dari 5 purged rolling folds positif;
- OOS PF minimal 1.20 dan broker-forward PF minimal 1.15;
- lower 95% bootstrap confidence bound expectancy setelah cost di atas nol;
- maximum validation drawdown maksimal 8%;
- expectancy tetap positif pada 1.5 kali measured cost;
- exact deterministic parity 100%;
- snapshot, source, contract, broker spec, dan ruleset tidak drift;
- manual ship approval tetap wajib.

Incident critical pada integrity, reconciliation, risk, atau security memaksa
demotion ke shadow dan mengulang soak period dari nol.
