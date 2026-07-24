# Durable Risk Ledger v1

## Status dan batas keamanan

Komponen ini adalah trust-building persistence primitive untuk future risk-state
collector. Ia tidak membuat `RiskContext`, tidak membaca atau menulis order MT5,
tidak menerbitkan permit, serta tidak dapat membuka manual-demo, demo-auto, atau
live trading.

Implementasi: `live_runtime/risk_ledger.py`.

## Tujuan

Ledger menyimpan fakta broker yang dibutuhkan agar daily/weekly stop, global
entry count, high-water drawdown, dan consecutive-loss latch tidak dapat hilang
hanya karena proses restart. Seluruh perubahan state harus dapat dihitung ulang
dari event immutable.

## Exact binding

Satu file database terikat secara immutable ke tepat satu:

- `account_id_sha256`; raw login/alias broker dilarang disimpan;
- exact broker `server`;
- exact `environment` (`DEMO` atau `LIVE`);
- execution `journal_sha256`;
- exact `broker_spec_sha256`;
- tiga huruf `account_currency`;
- HMAC `key_id` dan fingerprint key.

Binding yang berbeda pada reopen atau pada event baru ditolak. Secret tidak
disimpan di SQLite dan hanya diperoleh melalui injected `key_provider(key_id)`.
Key harus minimal 32 byte. Trust set source issuer/key ikut di-hash ke immutable
identity dan key source wajib terpisah dari key internal ledger.

## Production source provenance

Public production append tidak menerima event mentah sendirian. Setiap event
wajib disertai sealed `RiskSourceReceipt`, exact upstream receipt object, dan
injected strict verifier yang mengembalikan objek sealed yang sama (`is`, bukan
boolean atau object pengganti).

Mapping upstream wajib: account snapshot → `RUNTIME_FACT_RECEIPT`; entry →
`EXECUTION_RECEIPT`; closed trade → `BROKER_DEAL_RECEIPT` atau
`BROKER_RECONCILIATION_RECEIPT`.

Source receipt mengikat source ID/kind, issuer/key, seluruh exact ledger binding,
event content hash, upstream type/hash, observed/expiry UTC, dan HMAC. Lifetime
maksimum lima detik. Forged, stale, future, noncanonical, detached-time,
cross-account/server/environment/journal/spec/currency, wrong upstream, dan
source maupun upstream receipt replay ditolak. Composition root hanya boleh menandatangani envelope
setelah exact receipt upstream benar-benar diverifikasi. Tidak ada raw fallback
pada ledger execution-trusted ini.

## Storage

SQLite harus berjalan dengan:

- `journal_mode=WAL`;
- `synchronous=FULL`;
- foreign keys aktif;
- `busy_timeout=10000`;
- setiap append memakai `BEGIN IMMEDIATE` dan menulis event serta materialized
  state dalam transaksi yang sama.

Tabel:

1. `risk_ledger_identity` — singleton immutable untuk schema, ledger ID, hashed
   account identity, exact binding, key ID/fingerprint, source trust hash,
   timestamp, dan identity HMAC.
2. `risk_events` — event append-only dengan sequence contiguous, event ID unik,
   canonical event/source JSON, unique source ID/hash, issuer/key/upstream
   identity, predecessor HMAC, dan event HMAC.
3. `risk_state` — singleton materialized projection yang selalu diverifikasi
   ulang terhadap full event replay dan state HMAC.

Trigger menolak `UPDATE` dan `DELETE` pada identity dan event. Tamper pada
materialized state dideteksi oleh HMAC dan replay comparison.

## Immutable event contracts

### `AccountRiskSnapshot`

Fakta snapshot:

- unique `snapshot_id`;
- exact binding;
- aware UTC `observed_at_utc`;
- caller-supplied exact `daily_baseline_id` dan `weekly_baseline_id`;
- positive finite account equity.

Snapshot pertama wajib menjadi event pertama. Ia menetapkan baseline daily,
weekly, current equity, dan high-water awal.

### `EntryRiskEvent`

Fakta entry:

- unique `entry_id`;
- exact binding dan aware UTC timestamp;
- exact current daily/weekly baseline IDs;
- canonical symbol.

Entry menambah `entries_today`. Event dengan session ID yang tidak sama dengan
current state ditolak; caller harus lebih dahulu menulis account snapshot untuk
session baru.

### `ClosedTradeRiskEvent`

Fakta close:

- unique `trade_id` dan referensi ke satu known `entry_id`;
- exact binding/current session IDs/symbol;
- outcome `WIN`, `LOSS`, atau `BREAKEVEN`;
- finite realized PnL dalam account currency dengan sign yang konsisten.

Satu entry hanya boleh memiliki satu final closed-trade event. `LOSS` menambah
consecutive losses. Loss kedua melatch stop. `WIN` atau `BREAKEVEN` mereset
counter consecutive loss, tetapi latch yang sudah aktif tidak dibuka otomatis.
Reset latch kelak memerlukan workflow manual terpisah dan bukan bagian v1 ini.

## Session roll dan high-water

Daily dan weekly baseline IDs adalah identifier exact dari upstream trusted
session-calendar collector; ledger tidak menurunkannya dari local clock.

- ID yang sama mempertahankan baseline dan entry count.
- Daily ID baru menetapkan daily baseline ke equity snapshot dan mereset
  `entries_today` ke nol.
- Weekly ID baru menetapkan weekly baseline ke equity snapshot.
- Penggunaan ulang ID historis setelah berganti dianggap rollback dan ditolak.
- High-water hanya `max(previous_high_water, snapshot_equity)` dan tidak pernah
  berkurang.
- Consecutive-loss counter dan loss latch bertahan melewati session roll dan
  restart.

## HMAC chain

Setiap event HMAC mengikat:

- schema dan ledger ID;
- binding SHA-256;
- exact sequence, event type/ID, related entry;
- canonical aware UTC timestamp dan session IDs;
- canonical event payload;
- canonical signed source payload dan upstream receipt identity;
- previous event HMAC.

Domain separation berbeda digunakan untuk identity, event, materialized state,
dan receipt. Verifikasi full chain serta semantic replay dilakukan pada open,
sebelum append, sesudah append, sebelum receipt, dan saat explicit integrity
check.

## Rollback checkpoint

Local database saja tidak dapat membedakan restore byte-identik dari backup lama.
Karena itu `RiskStateReceipt` berfungsi sebagai externally retained checkpoint.
Saat `expected_receipt` diberikan pada reopen/integrity check:

- receipt HMAC, key ID, ledger ID, dan exact binding wajib valid;
- local event sequence tidak boleh lebih kecil;
- HMAC pada exact checkpoint sequence wajib sama.

Database yang lebih lama atau forked ditolak. Production composition harus
menyimpan receipt di off-host append-only/WORM custody sebelum menggunakannya
sebagai startup checkpoint.

## Sealed receipt

`RiskStateReceipt` adalah frozen/sealed contract dan hanya dapat dibuat oleh
`DurableRiskLedger`. Receipt memuat:

- ledger/binding/key identity;
- issue/latest event timestamps;
- sequence dan chain head;
- current daily/weekly baseline IDs dan equity;
- current/high-water equity;
- entries today;
- consecutive losses dan latched state;
- `source_verified=true`, evidence count yang sama dengan event sequence, latest
  source receipt/issuer/key, dan cumulative source receipt chain;
- domain-separated receipt HMAC.

Receipt adalah evidence input untuk future trusted collector. Ia bukan
`RiskContext`, risk approval, promotion evidence, atau execution authorization.

## Fail-closed rules

Ledger menolak:

- naive atau non-UTC timestamps;
- event yang lebih dari satu detik di depan trusted UTC;
- timestamp atau historical session ID regression;
- duplicate event ID atau duplicate closed entry;
- unknown entry references dan symbol mismatch;
- outcome/PnL inconsistency;
- exact binding or key mismatch;
- event tanpa sealed signed source dan exact verified upstream receipt;
- forged/stale/future/noncanonical source, untrusted issuer/key, source replay,
  cross-account/server/environment/journal/spec/currency source;
- boolean/replacement dari upstream verifier atau wrong upstream type/hash;
- non-contiguous sequence, invalid predecessor, HMAC mismatch;
- non-canonical payload/timestamp, SQLite integrity failure;
- materialized projection yang berbeda dari full replay;
- database yang lebih tua/forked dari expected receipt.

## Acceptance tests

Focused tests harus membuktikan:

1. WAL/FULL dan state persistence setelah restart.
2. Dua loss melatch dan tetap latched setelah restart.
3. Daily/weekly roll, entry reset, baseline, serta monotonic high-water.
4. Duplicate event/closed entry ditolak tanpa mengubah head.
5. SQL event mutation ditolak dan state tamper terdeteksi.
6. HMAC key mismatch ditolak.
7. Naive/future/regressed UTC ditolak.
8. External receipt mendeteksi restored older database.
9. Account/server/journal/currency binding mismatch ditolak.
10. Raw ingestion ditolak dan receipt selalu `source_verified=true`.
11. Forged/stale/future/cross-binding source dan wrong upstream ditolak.
12. Source one-time consumption dan tidak adanya raw login di SQLite/receipt.

## Non-goals v1

- Tidak ada automatic latch reset.
- Tidak ada broker/OS/news collector.
- Tidak ada `RiskContext` construction.
- Tidak ada order, credential bootstrap, permit, execution flag, atau release
  profile changes.
- Tidak ada klaim bahwa local SQLite merupakan off-host immutable custody.
