# FBS Broker-Forward Evidence Pipeline

Status: **IMPLEMENTED LOCALLY / EXTERNAL GATES BLOCKED / NO ORDER CAPABILITY**

Dokumen ini mengatur evidence broker-forward FBS. Ia bukan diagnostic paper
shadow, bukan izin demo order, dan bukan promotion evidence sampai seluruh
verification receipt valid. Lock permanen selama fase ini:

```text
live_allowed = false
safe_to_demo_auto_order = false
promotion_eligible = false
max_lot = 0.01
```

## Gate saat ini

Profile `fbs` ada di `config/broker_evidence_profiles.v1.json`, tetapi
`registration_enabled=false`. Template sesi ada di
`config/fbs_calendar_window_01.template.json`, tetapi
`special_hours_review.attested=false`. Candidate juga masih
`read_only_discovery_allowed=false` dan regulatory eligibility belum mendapat
dual independent approval. Karena itu discovery, plan, contract, dan collector
akan berhenti fail-closed pada gate masing-masing.

Weekly session yang ada sekarang hanya scaffold konservatif dari screenshot.
Ia tidak boleh diubah menjadi attested tanpa sumber resmi FBS yang mencakup
exact account/server, timezone, regular hours, holiday, early close, dan
maintenance untuk seluruh observation window.

## Urutan setelah review eksternal selesai

1. Selesaikan legal/regulatory eligibility untuk operasi dari Jepang dan masa
   depan di Indonesia. Rekam approval independen sesuai schema candidate.
2. Review exact FBS symbol specification melalui discovery API dan set
   `read_only_discovery_allowed=true` melalui clean reviewed commit.
3. Attest template session/special-hours terhadap sumber HTTPS resmi. Daftarkan
   closure dengan exact symbols dan UTC interval; jangan memakai wildcard.
4. Provision candidate-namespaced HMAC key di Windows Credential Manager:

   ```powershell
   python -B .\setup_broker_evidence_key.py --candidate fbs
   ```

5. Buat immutable signed discovery receipt. Langkah ini tidak memerlukan
   contract registration enablement:

   ```powershell
   python -B .\mt5_readonly_discovery.py `
     --candidate fbs `
     --output .\runtime_state\broker_discovery\fbs-window-01-v1.json
   ```

6. Prepare future-window plan lalu calendar bundle:

   ```powershell
   python -B .\prepare_broker_window.py `
     --candidate fbs `
     --discovery .\runtime_state\broker_discovery\fbs-window-01-v1.json `
     --output .\runtime_state\broker_discovery\fbs-window-01-plan-v1.json

   python -B .\build_broker_calendar.py `
     --candidate fbs `
     --plan .\runtime_state\broker_discovery\fbs-window-01-plan-v1.json `
     --output .\runtime_state\broker_discovery\fbs-window-01-calendar-v1.json
   ```

7. Review seluruh hash/binding. Hanya setelah itu, ubah
   `registration_enabled=true` dalam clean reviewed commit. Perubahan ini
   mengaktifkan registrasi evidence saja; order tetap mustahil.
8. Register immutable DIAGNOSTIC contract:

   ```powershell
   python -B .\register_broker_forward_contract.py `
     --candidate fbs `
     --discovery .\runtime_state\broker_discovery\fbs-window-01-v1.json `
     --plan .\runtime_state\broker_discovery\fbs-window-01-plan-v1.json `
     --calendar .\runtime_state\broker_discovery\fbs-window-01-calendar-v1.json `
     --artifact-root .\validation_artifacts
   ```

9. Jalankan one-shot collector melalui Task Scheduler pada eligible M15
   boundaries:

   ```powershell
   python -I -S -B .\run_broker_shadow_once.py `
     --candidate fbs `
     --artifact-root .\validation_artifacts
   ```

Setiap invocation membuat durable startup/operational receipt dan verified
audit export. Export tetap harus dipindahkan ke WORM/off-host store. Local
SQLite dan local HMAC tidak dapat membuktikan bahwa seluruh host tidak pernah
di-rollback.
