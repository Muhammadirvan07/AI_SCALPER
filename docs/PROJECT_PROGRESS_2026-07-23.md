# AI_SCALPER Progress — 2026-07-23

Status: **LOCAL DEMO_AUTO ACTIVATION FOUNDATION COMPLETE / OPERATIONAL
ACTIVATION BLOCKED / LIVE NOT READY**

Full regression pada development Mac menyelesaikan **1.168 test** tanpa
kegagalan. `compileall`, dependency check, release-port validator, safety-lock
scan, dan diff check juga lulus. Pesan penolakan yang tampil dari negative-path
tests adalah perilaku fail-closed yang diharapkan. Tidak ada order broker,
credential provisioning, Task Scheduler installation, policy unlock, atau
deployment yang dilakukan.

## Fondasi yang selesai secara lokal

- brokerless M15 decision producer dan deterministic Windows decision-only
  release terpisah dari executor;
- signed one-use decision IPC dengan cursor/checkpoint CAS dan continuity
  calendar yang fail-closed;
- locked decision-to-risk-to-intent pipeline, renewable DEMO_AUTO session
  capability, journal-bound submission settlement, dan restart recovery;
- kemungkinan submit yang tidak dapat dibuktikan tetap
  `RECONCILIATION_REQUIRED` dan tidak boleh dikirim ulang;
- authenticated soak projection dan account-level cohort untuk ambang 30 hari,
  50 closed fill, serta minimal 20 XAUUSD closed fill;
- mode-aware Windows factory contract untuk `DEMO` dan `DEMO_AUTO`;
- verifier RSA-3072 public-key-only untuk external launcher attestation sebelum
  provider factory diimpor;
- deny-by-default live-grade gate catalog dan activation runbook; dan
- immutable manual-demo activation kit yang merangkum blocker kandidat,
  37 required external provider contracts, urutan operator, dan target 10
  controlled order lifecycles tanpa memperoleh execution authority;
- perbaikan race pada soak projection: verifikasi custody kini dilakukan di
  bawah SQLite writer fence dan operasi tracker+projection diserialkan dalam
  satu runtime instance; uji konkurensi identik lulus 30 pengulangan; dan
- exact-type hardening pada risk governor dan evidence boundaries.

Semua komponen di atas tetap mempertahankan:

```text
live_allowed = false
safe_to_demo_auto_order = false
max_lot = 0.01
promotion_eligible = false
```

## Gate menuju DEMO_AUTO yang tidak dapat diselesaikan dari Mac

1. Build bersih dan acceptance pada exact Windows 64-bit, Python 3.12,
   `MetaTrader5==5.0.5735`, NTFS, terminal, account, server, dan symbol spec.
2. Reviewed external provider factory, Windows Credential Manager, service
   identities, Task Scheduler ACL, trusted clock, signed news, off-host CAS,
   WORM audit, heartbeat, backup/restore, dan offline RSA-key custody.
3. Exact XAUUSD minimum-lot risk feasibility memakai broker-native
   `order_calc_profit()`, spread, commission, slippage, dan stop level.
4. Sepuluh controlled manual-demo lifecycles tanpa duplicate, orphan,
   unresolved `UNCERTAIN`, missing SL/TP, atau critical alert failure.
5. Manual review atas activation release yang hanya membuka XAUUSD pada satu
   exact demo account. FX tetap shadow pada tahap pertama.

Setelah kelima gate tersebut terbukti, DEMO_AUTO soak baru boleh dimulai. Soak
harus berjalan minimal 30 hari dan menutup minimal 50 trade, termasuk 20
XAUUSD, tanpa critical incident. Insiden critical mereset periode soak.

## Gate live setelah soak

Hasil soak tidak otomatis membuka live. Setiap lane masih memerlukan 100 OOS
closed trades, 50 broker-forward closed trades dan delapan minggu observasi,
purged folds, PF/expectancy/bootstrap/drawdown/cost-stress gates, full parity,
broker/legal/security acceptance, serta manual ship approval. Live pertama
tetap XAUUSD canary `0.01` lot dengan satu posisi global. Concurrent
multi-account expansion memerlukan external atomic portfolio-exposure custody.

Runbook operasional terdapat di
`docs/DEMO_AUTO_ACTIVATION_RUNBOOK.md`. Repository kini menyediakan fondasi
source untuk tahap tersebut, tetapi tidak boleh menyatakan soak berjalan atau
live ready sebelum bukti eksternal dan temporal benar-benar tersedia.
