# Windows Status Monitor Provider Pack v1

Status: **IMPLEMENTED LOCALLY / EXTERNAL ACCEPTANCE REQUIRED / DENY-ONLY**

Provider pack ini mengisi dua belas port Status Monitor tanpa memberi
authority trading:

1. alert outbox dan transport;
2. checkpoint CAS dan acknowledgement verifier;
3. heartbeat outbox dan transport;
4. incident latch dan acknowledgement verifier;
5. remote-ack dan sender-key custody;
6. signed status-snapshot source; dan
7. signed monotonic trusted clock.

Runtime foundation memakai exact read-only Windows Credential Manager,
preprovisioned SQLite/outbox, serta directory protocol yang dikendalikan
eksternal. Tidak ada fallback file/environment untuk secret, auto-provisioning
state, network client, MT5, task installer, broker adapter, atau order
primitive.

## Batas release

- `live_runtime/windows_status_monitor_provider_pack.py` hanya masuk base
  release `STATUS_MONITOR`.
- Shared credential/clock primitive masuk `DECISION`, `EXECUTION`, dan
  `STATUS_MONITOR` dengan exact type identity.
- Generator dan CLI hanya masuk
  `WINDOWS_CONFIGURED_RELEASE_OPERATOR_TOOLING_V1`.
- Provider pack yang dihasilkan berisi tepat empat file:

```text
config/windows_service_config.json
configured_providers/__init__.py
configured_providers/status_monitor_provider.py
reviewed_windows_factory.py
```

Semua dua belas implementation hash mengikat exact path dan SHA-256 dari
`offhost_delivery.py`, `windows_provider_primitives.py`, dan
`windows_status_monitor_provider_pack.py` di verified Status Monitor base ZIP.

## Generate dan validate di Windows

Siapkan canonical secret-free input sesuai
`specs/windows_status_monitor_provider_pack_v1.md`. Input hanya berisi ID,
fingerprint, absolute reviewed path, timeout, serta exact release/task/IPC
hash; tidak boleh memuat credential value, password, token, URL, permit, arm,
atau approval.

```powershell
$suiteRoot = "C:\AI_SCALPER_RELEASES\<COMMIT>\base-release-suite-v1"
$statusBase = "$suiteRoot\status-monitor-base-v1.zip"
$packInput = "C:\AI_SCALPER_PRIVATE\status-monitor-provider-input.json"
$packRoot = "C:\AI_SCALPER_PRIVATE\status-monitor-provider-pack-v1"

python -I -S -B .\prepare_windows_status_monitor_provider_pack.py `
  --base-suite-root $suiteRoot `
  --status-monitor-base-release $statusBase `
  --pack-input $packInput `
  --output-root $packRoot

python -I -S -B .\validate_windows_status_monitor_provider_pack.py `
  --base-suite-root $suiteRoot `
  --status-monitor-base-release $statusBase `
  --pack-root $packRoot
```

Output baru selalu create-exclusive. Generator dan validator tidak membaca
Credential Manager, membuka SQLite, membuat directory, mengimpor generated
factory, mengirim request, memasang task, memulai proses, atau mengakses
broker.

## Acceptance eksternal yang masih wajib

Pack lokal belum membuktikan:

- Credential Manager ACL dan service identity;
- issuer/custody signed clock;
- independently controlled snapshot/checkpoint/incident directories;
- off-host acknowledgement dan WORM custody;
- preprovisioned SQLite schema, ACL, backup, serta recovery;
- Task Scheduler ACL dan launcher attestation;
- exact Windows configured-release reproducibility.

Seluruh hasil tetap:

```text
status_only = true
order_capability = DISABLED
live_allowed = false
safe_to_demo_auto_order = false
max_lot = 0.01
promotion_eligible = false
provider_accepted = false
production_execution_ready = false
```
