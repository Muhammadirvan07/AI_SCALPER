# Windows LIVE Canary External CAS Directory Adapter v1

Status: **IMPLEMENTED LOCALLY / CENTRALLY LOCKED / EXTERNAL SERVICE REQUIRED**

Adapter ini adalah client sinkron untuk tiga callback otoritatif yang sudah
digunakan custody core:

```text
checkpoint_provider() -> bytes | None
checkpoint_cas(expected_predecessor_sha256, proposal_payload) -> (bytes, bytes)
nonce_seen_provider(launcher_nonce_sha256) -> bool
```

Ia tidak membuat launch capability, tidak menyimpan private key, tidak membuka
central LIVE lock, tidak menjalankan MT5, dan tidak mengirim order. Hanya
`consume_live_canary_launch_reservation(...)` yang tetap dapat memverifikasi
readback lalu membuat module-sealed one-use launch capability.

## Isolasi release

Adapter masuk ke Windows Execution base release dan isolated closure probe.
Import-nya dibatasi ke:

- Python standard library;
- `execution_policy`;
- canonical JSON contracts;
- RSA public-verification primitives.

Adapter tidak mengimpor custody/admission producer, acceptance tooling,
WORM-handoff tooling, launch-session producer, credential provider, atau
private-key code. Canonical public custody-policy bytes diparsing ulang secara
mandiri dan dipin dengan SHA-256 yang diterima lewat channel independen.

## Directory protocol

Konstruksi membutuhkan dua directory absolut, existing, real, dan berbeda:

- request directory: hanya ditulis client dengan create-exclusive publication;
- response directory: hanya dibaca client untuk signed provider responses.

Semua file harus immediate child, regular file, maksimal 1 MiB, canonical
UTF-8 JSON, dan stabil sebelum/sesudah read. Symlink, reparse point, path
indirection, duplicate JSON key, non-finite value, unknown field, atau file
yang berubah selama read ditolak.

Protocol files:

```text
current.checkpoint.json
<request-id>.nonce-request.json
<request-id>.nonce-response.json
<request-id>.cas-request.json
<request-id>.cas-response.json
```

Nonce response, checkpoint, dan acknowledgement wajib memakai RSA signature
domain yang terpisah. Setiap response mengikat provider, custody policy,
repository, request hash, current head, proposal, nonce, waktu, authority, dan
locked safety fields.

## Batas ambiguity

Timeout maksimum adalah dua detik dan polling berhenti pada trusted UTC expiry
atau monotonic deadline. Setelah request CAS mungkin terpublikasi, timeout atau
response invalid adalah terminal ambiguity: adapter tidak membuat request
kedua dan tidak retry otomatis. Race create-exclusive hanya dapat dilanjutkan
jika file yang sudah ada byte-identical.

## Wiring pre-launch

Contoh berikut hanya menunjukkan composition. Directory dan public policy
harus berasal dari deployment Windows yang sudah direview dan dipin:

```python
from pathlib import Path

from live_runtime.windows_live_canary_external_cas_directory_adapter import (
    WindowsLiveCanaryExternalCasDirectoryAdapter,
)

adapter = WindowsLiveCanaryExternalCasDirectoryAdapter(
    provider_id="<reviewed-provider-id>",
    custody_policy_payload=Path(
        r"C:\AI_SCALPER_PRIVATE\live-canary\portable-custody-policy.json"
    ).read_bytes(),
    expected_custody_policy_sha256="<independently-pinned-sha256>",
    request_directory=r"<absolute-independent-request-directory>",
    response_directory=r"<absolute-independent-response-directory>",
    clock_provider=trusted_utc_now,
    timeout_seconds=2.0,
)

# Pass these exact bound methods to the existing custody core:
external_checkpoint_provider = adapter.checkpoint_provider
external_checkpoint_cas = adapter.checkpoint_cas
external_nonce_seen_provider = adapter.nonce_seen_provider
```

Ini bukan perintah aktivasi. Checked-in `execution_policy.LIVE_ALLOWED` tetap
`False`, dan adapter sengaja menolak operasi jika central policy tidak persis
`false/(LIVE_MODE_LOCKED)`.

## Bukti yang masih wajib

Status tidak dapat dinaikkan hanya karena test directory fixture lulus. Masih
wajib tersedia dan diterima secara independen:

- layanan CAS atomik eksternal yang nyata;
- mount, ownership, ACL, durability, backup/restore, dan failover evidence;
- custody policy serta public-key pin dari channel independen;
- actual signed checkpoint/acknowledgement/nonce responses pada Windows;
- provider-bound admission, WORM receipt/readback, dan launcher attestation;
- exact committed Execution release dan target-host acceptance;
- central unlock ceremony yang terpisah;
- first 0.01-lot canary, broker acknowledgement, dan reconciliation.

Sampai bukti tersebut lengkap, verdict tetap **DO NOT SHIP LIVE TRADING**.
