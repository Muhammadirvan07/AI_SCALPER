# Kontrak Data Dashboard AI_SCALPER

Kontrak ini adalah target producer untuk mengurangi mapping format legacy. Adapter
dashboard tetap menerima format lama dan tidak pernah menulis ulang sumber.

## Envelope minimum

Setiap producer JSON baru sebaiknya menyediakan:

```json
{
  "schema_version": "1.0",
  "updated_at": "2026-07-25T00:00:00Z",
  "source": "nama_producer",
  "event_id": "idempotent-event-id",
  "data_status": "fresh",
  "data": {}
}
```

Schema machine-readable:

- `contracts/source-envelope.schema.json`
- `contracts/market-news.schema.json`
- `contracts/decision-readiness.schema.json`

## Penulisan atomic oleh producer

Perubahan atomic harus diterapkan di producer pada pekerjaan terpisah dan setelah
review engine. Pola yang disarankan adalah menulis ke temporary file pada
filesystem yang sama, melakukan flush dan `fsync`, kemudian `os.replace` ke
target. Adapter dashboard tidak menyediakan helper penulis agar boundary
read-only tetap dapat diaudit.

## Decision readiness

`decision_ready=true` hanya berarti semua gate observasi paper lolos. Field ini
tidak boleh mengubah `live_allowed`, membuat order, atau menjadi izin eksekusi.
Adapter menggunakan kebijakan fail-closed: field hilang, sumber stale, news tidak
tersedia, spread guard tidak tersedia, atau score kurang akan menghasilkan
`decision_ready=false` beserta daftar `blockers`.

## News

News dapat berasal dari `market_news.json`, `economic_calendar.json`,
`news_feed.json`, atau provider HTTP read-only. Arah tidak diturunkan bila
provider tidak memberikan `direction_bias`. Mapping pair dari currency ditandai
sebagai interpretasi turunan, bukan signal trading.

## Snapshot dashboard 1.2

Snapshot dashboard read-only versi `1.2` menambahkan kontrak landing operasional:

- `project_progress`: tahap, evidence gate, observation window, blind-until date,
  dan promotion eligibility;
- `broker_readiness`: kandidat dinamis, server/environment, discovery, evidence
  regulasi, calendar review, contract registration, runtime shadow, dan eligibility;
- `safety.order_capability`: kemampuan order yang dibaca dari kebijakan readiness,
  nullable bila sumber tidak tersedia.

Nilai nullable tidak boleh diganti asumsi oleh frontend. Runtime validator menolak
snapshot yang mengendurkan `live_allowed=false`, `live_trading=LOCKED`,
`safe_to_demo_auto_order=false`, atau `max_lot=0.01`.
