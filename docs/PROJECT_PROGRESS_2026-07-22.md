# AI_SCALPER Progress — 2026-07-22

Status: **LOCAL DEMO-SOAK FOUNDATION UNDER FINAL VALIDATION / OPERATIONAL
READINESS BLOCKED / DO NOT SHIP**

Pembaruan validasi: **2026-07-22**. Full local regression pada development
Mac menyelesaikan **1.033 test** tanpa kegagalan. Pesan penolakan dependency
bootstrap/CLI yang muncul selama run berasal dari negative-path tests yang
memang mengharapkan fail-closed. Hasil ini belum menggantikan acceptance test
pada exact Windows/Python/MT5/VPS target.

Dokumen ini memisahkan kelengkapan software dari izin operasional. Unit test,
receipt lokal, atau hasil shadow tidak dapat menggantikan waktu observasi,
transaksi broker nyata, legal review, keamanan VPS, maupun approval manusia.

## Hasil audit terbaru

Audit jalur broker menemukan dan menutup beberapa trust-boundary gap:

- journal sekarang mengonsumsi otorisasi sekali pakai secara durable sebelum
  broker I/O, melakukan final fence/risk/kill-switch check dalam transaksi
  pendek, dan tidak menahan SQLite lock selama `order_send`;
- timestamp journal berasal dari trusted journal clock. Timestamp caller hanya
  assertion; timestamp masa depan ditolak ketat dan keterlambatan pencatatan
  broker hanya diterima dalam window sempit;
- preflight, submission guard, dan execution receipt memakai waktu setelah
  broker call selesai, bukan timestamp sebelum call;
- stop risk dan margin dihitung ulang tepat sebelum `order_send` memakai harga
  adverse BUY/SELL, deviation, broker contract specification, dan
  `order_calc_profit`/`order_calc_margin`;
- evidence broker yang tidak valid tidak lagi dapat mengubah ticket, volume,
  protection, state, atau close result di journal reconciliation;
- `PromotionPermit` dibatasi maksimum lima menit;
- manual-demo readiness memakai exact allowlist status binding dan kalender;
- risk ledger, journal checkpoint, runtime fact collector, supervisor,
  manual-demo tracker, stage authorization, serta demo-auto soak tracker dibuat
  durable dan fail-closed. Seluruh output tetap deny-only;
- Windows operations plan mengikat clean release, Python/MT5/account/spec,
  credential references, isolated state databases, two-process layout,
  watchdog, hardening, off-host destinations, dan delapan failure drills tanpa
  memasang task atau mengirim order;
- bounded Windows service sekarang memverifikasi exact release inventory,
  menolak extra member, symlink/reparse point, case-collision, serta import
  origin di luar release/stdlib. Dynamic import/file-loader API ditolak pada
  seluruh source release kecuali dua bentuk loader/validator yang direview;
  `sys.modules` dan origin direattest setelah factory load serta invocation.
  Heartbeat memakai durable acknowledged outbox tanpa membuat successor ketika
  predecessor belum terselesaikan;
- cycle worker tetap mengirim heartbeat saat broker cycle tertahan. Deadline
  atau heartbeat failure memicu exact-once fail-closed abort lalu mandatory
  process termination dengan exit code `70`; proses pengganti wajib melakukan
  startup reconciliation sebelum melanjutkan;
- decision IPC consumer untuk future demo-auto tersedia sebagai boundary
  inert melalui sealed consume-only port tanpa `publish`, signing provider,
  database, atau raw queue. Ia mengonsumsi satu signed decision secara one-use,
  memverifikasi stage, permit, environment arm sebelum/sesudah queue CAS, lalu
  hanya menghasilkan sealed risk/intent input atau no-action. Ia tidak
  mempunyai adapter, callback, atau primitive pengiriman order;
- manual-demo supervisor kini membuat signed `PRE_DISPATCH` news checkpoint.
  Setelah callback approval/policy, decision, approval, journal, risk, facts,
  account snapshot, lease, dan signed successor news diperiksa ulang tepat
  sebelum execution service; expiry, blackout, stale feed, atau fork melatch
  fail-closed tanpa dispatch;
- signed release-trust HMAC tersedia hanya sebagai fondasi local/test.
  `SIGNED_RELEASE_TRUST_ENABLED=false` dan
  `HMAC_RELEASE_TRUST_PRODUCTION_READY=false`; production tetap membutuhkan
  asymmetric public-key verification atau external trusted launcher.

## Bukti shadow yang tersedia

Observasi Phillip pada 2026-07-21 menghasilkan masing-masing empat closed paper
trades pada lane FX dan XAUUSD. Angka itu tetap berstatus
`VERY_LOW_SAMPLE`, diagnostic-only, dan bukan promotion evidence:

- Phillip FX: 4 closed, 3 win, 1 loss, PF 5.648132, net +5.006610 R;
- Phillip XAUUSD: 4 closed, 2 win, 2 loss, PF 2.039345, net +2.105670 R.

Delapan trade tidak cukup untuk menyimpulkan win rate, expectancy, atau
robustness. Minimum roadmap tetap 50 broker-forward closed trades dan delapan
minggu per lane, ditambah 100 OOS closed trades serta seluruh quality gate.

## Posisi roadmap sebenarnya

| Tahap | Software lokal | Bukti operasional |
|---|---|---|
| Baseline dan safety locks | Tersedia | Clean reviewed release baru belum dibangun pada Windows target |
| Evidence infrastructure | Tersedia | Phillip profile registration, exact prospective contract, 20 sessions, dan 8-week window belum selesai |
| Read-only shadow | Berjalan diagnostic | Bukan broker-forward promotion evidence |
| Manual demo | Komponen, tracker, risk, journal, reconciliation, dan supervisor tersedia | Global readiness receipt, keys, VPS controls, lalu 10 controlled orders belum selesai |
| Demo-auto soak | Tracker, stage-control, rollback detection, operations plan, failure-drill model, dan inert decision-IPC consumer tersedia | Belum terhubung ke executor dan tetap policy-locked; 30 hari/50 fill/minimal 20 XAU belum dimulai |
| Live canary | Arsitektur executor/risk/reconciliation tersedia dan terkunci | Seluruh lane gate, soak, security/legal, dan manual ship approval belum selesai |

## Kelayakan risk cap pada lot minimum

Risk governor tetap menghitung kerugian stop dengan broker-native
`order_calc_profit()` dan conversion receipt, bukan asumsi pip value tetap.
Sebagai sanity check, untuk pair USD-quoted dengan contract size 100.000,
`0.01` lot dan cap FX `$0.25` hanya menyediakan sekitar **2,5 pip** jarak stop
sebelum spread, komisi, dan slippage. Untuk XAU dengan contract size 100,
`0.01` lot berarti exposure sekitar satu ounce; cap `$0.20` hanya menyediakan
sekitar **$0.20** jarak harga sebelum biaya.

Karena itu minimum lot, spread, stop level, dan biaya broker sering membuat
trade tidak feasible. Hasil yang benar dalam keadaan tersebut adalah `WAIT`,
bukan memperlebar cap atau menaikkan lot. Feasibility harus dibuktikan ulang
per exact symbol/account/broker sebelum manual demo dan demo-auto.

## Gate yang tidak boleh disimulasikan

1. Signed regulatory/legal activation review untuk exact broker, account type,
   jurisdiction, dan operating location.
2. Signed calendar/spec review dan prospective forward contract sebelum window
   dimulai.
3. Minimal 20 broker sessions, delapan minggu, 50 broker-forward trades, dan
   100 OOS trades per lane.
4. Exact Windows clean build, vulnerability receipt, reproducibility receipt,
   asymmetric release verification atau external trusted launcher, Credential
   Manager custody, VPN/MFA/least privilege, clock/disk/watchdog,
   backup/restore, WORM/off-host acknowledgements, dan production news feed.
5. Delapan failure drills dan zero unresolved critical/high finding.
6. Sepuluh controlled manual-demo lifecycles dengan preflight, execution,
   SL/TP, close, dan reconciliation yang lengkap.
7. Reviewed demo-auto activation, lalu masa soak baru minimal 30 hari, 50 fill,
   minimal 20 XAU, tanpa critical incident. Insiden mereset masa soak.
8. XAUUSD live canary 0.01 lot hanya sesudah semua gate di atas serta manual
   approval; FX ditambahkan satu lane per tahap.

## Lock yang tetap berlaku

```text
live_allowed = false
safe_to_demo_auto_order = false
max_lot = 0.01
promotion_eligible = false
order_capability = DISABLED
```

Tidak ada broker order, credential provisioning, Task Scheduler installation,
policy unlock, demo-auto start, live deployment, atau kenaikan lot yang
dilakukan oleh audit lokal ini.
