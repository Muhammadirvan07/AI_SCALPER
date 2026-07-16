# Real-Time Diagnostic Shadow

Runner ini dipakai untuk melihat perilaku AI_SCALPER terhadap bar dan tick XM
yang benar-benar sedang diterima MT5. Runner tidak mengirim transaksi, tidak
mengubah posisi broker, tidak menghasilkan validation evidence, dan tidak
membuka gate demo-auto atau live.

Status permanen output:

```text
profile = BROKER_REALTIME_DIAGNOSTIC_ONLY
live_allowed = false
safe_to_demo_auto_order = false
promotion_eligible = false
validation_evidence = false
legal_gate_bypassed = false
order_capability = DISABLED
max_lot = 0.01
```

Jalur ini tidak mengubah keputusan legal XM untuk operasi dari Jepang. Data
boleh dipakai untuk diagnosis teknis dan observasi strategi, tetapi tidak boleh
dimasukkan ke gate promosi broker-forward.

## Prasyarat MT5

- Windows, Python 3.12, dan virtual environment proyek aktif.
- MT5 sedang terbuka dan login ke akun demo `XMTrading-MT5 3`.
- Gunakan investor/read-only password.
- Algo Trading/AutoTrading tetap OFF.
- External Python trading API dinonaktifkan.
- Empat simbol tersedia: `GOLD.`, `EURUSD.`, `USDJPY.`, `AUDUSD.`.

Runtime memeriksa ulang bahwa account dan terminal tidak memiliki kemampuan
trading. Pada investor authorization, MT5 dapat melaporkan
`account.trade_expert=true` karena Expert Advisor masih boleh dipakai untuk
analisis. Diagnostic runner tetap mensyaratkan `account.trade_allowed=false`,
`terminal.trade_allowed=false`, dan `terminal.tradeapi_disabled=true`. Jika
salah satu gate transaksi tersebut hilang atau aktif, proses berhenti.

## Sinkronisasi source

Jalankan di PowerShell:

```powershell
cd C:\AI_SCALPER
git pull origin agent/live-grade-phase3
.\.venv\Scripts\Activate.ps1
python --version
```

Python harus menunjukkan versi 3.12.x.

## Uji satu cycle

```powershell
python -B .\run_realtime_diagnostic_shadow.py `
  --acknowledge-diagnostic-only `
  --cycles 1
```

Satu cycle akan:

1. menguji read-only account dan terminal;
2. membaca minimal 250 finalized M15 bars per simbol;
3. mencari first eligible broker tick dalam 10 detik sesudah candle selesai;
4. menjalankan pure decision core yang sama dengan replay;
5. mencatat BUY, SELL, atau WAIT;
6. membuka posisi paper virtual bila ada sinyal dan lane belum memiliki posisi;
7. mengevaluasi SL/TP virtual memakai bid untuk BUY dan ask untuk SELL.

Tidak ada transaksi broker yang dibuat.

## Jalankan loop terus-menerus

```powershell
python -B .\run_realtime_diagnostic_shadow.py `
  --acknowledge-diagnostic-only `
  --continuous `
  --poll-seconds 5
```

Hentikan dengan `Ctrl+C`. Jangan membuka instance kedua pada akun/server yang
sama; account-wide singleton fence akan menolak split-brain.

## Output

Journal append-only:

```text
runtime_state\diagnostic\xm-real-market.sqlite3
```

Ringkasan yang mudah dibaca:

```text
runtime_state\diagnostic\xm-real-market-summary.json
```

Ringkasan berisi:

- jumlah keputusan BUY/SELL/WAIT;
- paper position terbuka dan tertutup;
- win/loss, win rate, net R, serta profit factor berbasis R;
- metrik terpisah per XAUUSD, EURUSD, USDJPY, dan AUDUSD;
- hasil cycle terakhir;
- status integritas hash chain.

Win rate awal dengan sampel kecil hanya diagnostic. Jangan menyimpulkan
kelayakan strategi sebelum jumlah trade dan durasi observasi memenuhi gate
roadmap.

## Status normal

- `PAPER_OPENED`: sinyal virtual dibuka.
- `WAIT`: decision core tidak menyetujui entry.
- `ALREADY_PROCESSED`: candle itu sudah dicatat, sehingga tidak diduplikasi.
- `WAITING_ENTRY_TICK`: candle baru selesai dan runtime masih menunggu tick
  pertama dalam entry window.
- `ENTRY_WINDOW_MISSED`: tidak ada tick valid dalam 10 detik.
- `STALE_BAR`: market tutup atau finalized bar terlalu lama.
- `HOLD:<Error>`: data atau runtime gagal divalidasi; jangan menghapus journal
  untuk memaksa proses lolos.

## Batas simulasi

- Ini adalah paper lane per simbol, bukan akun demo broker.
- PnL uang dan margin tidak dihitung; outcome dicatat dalam R-multiple.
- Komisi, swap, dan conversion account JPY belum dimasukkan ke metrik ini.
- Output tidak menggantikan broker-forward evidence, manual demo order,
  reconciliation test, atau demo-auto soak.
