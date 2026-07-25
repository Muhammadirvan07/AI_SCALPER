# Windows Shared Provider Primitives v1

## Status

```text
SOURCE_IMPLEMENTATION = COMPLETE_LOCALLY
WINDOWS_EXACT_BUILD = PENDING
EXTERNAL_PROVIDER_ACCEPTANCE = REQUIRED
ORDER_CAPABILITY = DISABLED
PRODUCTION_EXECUTION_READY = false
```

Modul `live_runtime/windows_provider_primitives.py` adalah satu-satunya
implementasi primitive Windows yang dipakai lintas service untuk:

- membaca exact allowlisted HMAC key secara read-only dari Windows Credential
  Manager; dan
- menghasilkan trusted UTC monotonik dari signed external clock attestation.

Ekstraksi ini menghilangkan kebutuhan menyalin logika credential dan clock
antara Decision, Status Monitor, serta provider foundation berikutnya. Modul
ini bukan service, tidak membuat provider pack, dan tidak memiliki broker,
MT5, risk, intent, permit, task, process, network, atau order authority.

## Boundary release

- Base release `DECISION` memuat primitive bersama karena Decision provider
  foundation mengimpornya.
- Base release `STATUS_MONITOR` memuat primitive bersama sebagai dependency
  foundation untuk slice provider Status Monitor berikutnya.
- Base release `EXECUTION`, `READ_ONLY_SHADOW`, dan
  `CONFIGURED_RELEASE_TOOLING` tidak memuat primitive ini.
- Status Monitor builder hanya mengizinkan import `ctypes` pada exact file
  primitive tersebut. `ctypes`, `subprocess`, dynamic loading, atau capability
  terlarang pada file lain tetap ditolak.

## Kompatibilitas Decision

`live_runtime/windows_decision_provider_pack.py` tetap mengekspor nama publik
lama:

```text
CredentialReference
WindowsCredentialManagerKeyProvider
WindowsClockBinding
WindowsClockAttestation
AttestedTrustedUTCProvider
issue_windows_clock_attestation
WindowsDecisionProviderError
```

Import lama dan import baru menunjuk objek Python yang identik. Schema clock
v1, canonical payload, HMAC domain, reason code, decoding key, freshness,
drift, serta monotonic rule tetap sama. Satu hardening tambahan disengaja:
credential key ID atau target yang bertabrakan hanya karena perbedaan huruf
besar/kecil sekarang ditolak sebelum backend dibaca.

## Binding implementation hash

Decision provider-pack generator membaca tepat dua regular member dari exact
verified Decision base release:

```text
live_runtime/windows_decision_provider_pack.py
live_runtime/windows_provider_primitives.py
```

Setiap `implementation_sha256` memakai domain
`windows-decision-provider-implementation-v2` dan mengikat:

- role serta provider contract hash;
- daftar path+SHA-256 kedua foundation file yang tersortir; dan
- path+SHA-256 generated provider module.

Member hilang, kosong, terlalu besar, tidak terbaca, atau duplikat ditolak
sebelum output provider pack dibuat. Perubahan byte pada salah satu primitive
selalu menghasilkan implementation identity baru.

## Efek dan secret

Import, release build, validation, serta contract construction:

```text
credential_access = false
credential_mutation = false
filesystem_write = false
network_access = false
process_launch = false
task_installation = false
mt5_initialization = false
broker_mutation = false
```

Credential value tidak boleh berada di repository, konfigurasi, manifest,
error, `repr`, output overlay, atau log. Native Credential Manager hanya
dibaca ketika exact configured service kelak dimaterialisasi pada Windows
setelah external provider acceptance.

## Safety lock

```text
live_allowed = false
safe_to_demo_auto_order = false
max_lot = 0.01
promotion_eligible = false
production_execution_ready = false
```

Langkah berikutnya adalah membangun Status Monitor provider pack di atas
primitive ini, tetap tanpa membuka order authority. Exact Windows release,
Credential Manager ACL, signed clock issuer, external custody, launcher,
Task Scheduler identity, dan independent conformance masih harus dibuktikan
di luar development Mac.
