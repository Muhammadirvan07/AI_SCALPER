# AI_SCALPER Frontend Dashboard

Dashboard React/Vite/TypeScript untuk observasi data AI_SCALPER. Satu
`DashboardRealtimeProvider` menangani REST initial load, WebSocket, reconnect,
fallback REST polling, stale state, dan mock fallback development yang berlabel.

```bash
cp .env.example .env.local
npm install
npm run dev
```

Development: <http://localhost:5173/overview>

```bash
npm run lint
npm run build
npm run check:bundle
npm run preview
npm run test:unit
npm run test:e2e:list
npm run test:e2e
```

Kontrak backend, endpoint, source mapping, safety, dan troubleshooting dijelaskan
di [dashboard_api/README.md](../dashboard_api/README.md).

Frontend tidak memiliki kontrol Buy/Sell/order/live enable. Tombol “Jeda
pembaruan tampilan” hanya menahan penerapan snapshot pada UI; backend watcher dan
engine proyek tidak dihentikan atau diubah.

Halaman News menggunakan `snapshot.news` dari backend. Bila provider belum
dikonfigurasi, halaman menampilkan `UNAVAILABLE`. Mock hanya dapat diaktifkan
secara eksplisit saat Vite berjalan dalam mode development dan badge global
menunjukkan `MOCK FALLBACK`; build production selalu fail-closed tanpa data
simulasi. Kontrak
`decision_readiness` ditampilkan eksplisit dan bersifat fail-closed.

Snapshot REST dan WebSocket melewati validasi runtime serta gate versi monotonik.
Snapshot yang mundur, payload yang tidak memenuhi kontrak keselamatan, sumber
berwaktu tidak valid, dan heartbeat yang kedaluwarsa tidak boleh ditampilkan
sebagai data sehat.
