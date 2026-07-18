# Windows Release Packaging

Status saat ini tetap **READ-ONLY SHADOW / NOT_READY**. Artefak yang dibuat
builder ini adalah **deployment/tooling bundle untuk release operator**, bukan
service-runtime bundle. Builder tidak membuka manual-demo, demo-auto, atau
live.

## Mengapa repository tidak boleh langsung diarsipkan

Repository development masih memiliki data cache CSV, status JSON, histori
paper/demo, backup, snapshot runtime, evidence store, dan ZIP lama. Sebagian
bahkan masih tracked karena berasal dari fase proyek sebelumnya. `git archive`,
`Compress-Archive *`, atau builder migration/context tidak boleh digunakan
sebagai release Windows.

Deployment/tooling bundle Windows hanya boleh dibuat oleh
`build_windows_release.py` berdasarkan daftar exact di
`config/windows_release_allowlist.v1.json`. Tidak ada glob, scan extension,
atau fallback yang otomatis menambahkan file baru.

Bundle ini memiliki generator, bootstrapper, setup credential, registration
tool, dan network-capable vulnerability collector karena current build identity
masih mengikat source tooling tersebut. Karena itu:

- bundle hanya boleh dipegang/dijalankan release operator;
- production service account tidak boleh menjalankan bundle ini;
- source tree tidak boleh langsung dijadikan Task Scheduler working directory;
- materialisasi service-runtime minimal membutuhkan profile/allowlist terpisah.

Profile tooling juga membawa runner crypto weekend read-only. Runner tersebut
hanya memakai allowlisted public GET Binance/Coinbase, tanpa credential maupun
order API, dan tetap bukan service-runtime production.
M15 champion dan M5 challenger dibundel sebagai entrypoint diagnostic berbeda;
keduanya memiliki config serta journal domain terpisah dan tidak memiliki
primitive execution.

Pemisahan runtime minimal belum boleh diklaim: current shadow identity masih
memverifikasi beberapa generator source. Refactor identity input harus selesai
dan diuji dahulu sebelum profile service-runtime dibuat.

## Gate builder

Builder menolak release bila:

- Git worktree tidak bersih atau ada file untracked;
- file allowlist tidak tracked, hilang, berubah selama build, terlalu besar,
  bukan regular file, atau melalui symlink;
- path absolut, traversal, collision case-insensitive, runtime/evidence/data
  directory, backup, history, CSV, ZIP, database, log, bytecode, credential,
  private key, atau JSON sensitif ditemukan;
- modul/cabang legacy yang memiliki execution capability, termasuk executor,
  MT5 adapter, reconciliation runtime, MQL5, VPS package, dan paper executor;
- primitive order ditemukan dalam source profile read-only, termasuk
  `order_send`, `order_check`, `TRADE_ACTION_*`, `ORDER_TYPE_BUY/SELL`,
  `CTrade`, atau pemanggilan `Buy`/`Sell`;
- root field allowlist bertambah, berkurang, atau berubah dari schema exact;
- import Python lokal tidak ikut dalam allowlist;
- safety lock bukan persis `live_allowed=false`,
  `safe_to_demo_auto_order=false`, `max_lot=0.01`, dan
  `order_capability=DISABLED`;
- usage policy bukan persis `DEPLOYMENT_TOOLING`,
  `RELEASE_OPERATOR_ONLY`, dan service execution disabled;
- output ditempatkan di dalam repository atau destination sudah ada.

ZIP dan `RELEASE_MANIFEST.json` dibuat deterministik. Manifest mengikat exact
Git commit/tree, hash raw allowlist, hash dan ukuran setiap source file, safety
policy, serta `release_identity_sha256`. Manifest sidecar sama persis dengan
manifest di dalam ZIP.

## Build

Jalankan dari clean checkout. Tulis output di luar repository:

```powershell
python -I -S -B .\build_windows_release.py `
  --output C:\AI_SCALPER_RELEASES\ai-scalper-deployment-tooling-v1.zip
```

Simpan SHA-256 ZIP dan release identity ke release receipt/off-host audit.
Jangan menjalankan ZIP ini sebagai service runtime. Wheelhouse lengkap, broker
discovery/calendar, forward contract, journal, credential, dan validation
evidence adalah artefak terpisah. Jangan menyalin `data/`, `runtime_state/`,
`runtime_snapshots/`, atau `validation_artifacts/` ke release source.

## Perubahan allowlist

Penambahan file adalah perubahan security-sensitive:

1. Tambahkan path exact; jangan menambah prefix atau wildcard.
2. Pastikan local-import closure dan seluruh test lulus.
3. Review bahwa file bukan state, history, backup, credential, atau evidence.
   Builder tetap akan menolak execution path dan order primitive walaupun path
   tersebut sengaja dimasukkan ke allowlist.
4. Buat clean commit baru; release lama tidak boleh ditimpa.
5. Buat service-runtime profile terpisah setelah coupling build identity
   dibuang; generator/network collector tidak boleh diwariskan ke profile itu.
6. Untuk fase manual-demo atau live, buat versi/profile baru dan approval
   terpisah. Jangan menambahkan executor ke deployment profile ini.
