# Phillip Securities Japan Read-Only Preparation

Status: **REGULATED JAPAN CANDIDATE / DEMO BINDING ONLY / ORDERS DISABLED**

Phillip Securities Japan uses separate MT5 accounts for FX and commodity CFD.
AI_SCALPER therefore prepares two isolated bindings:

- `phillip-fx`: EURUSD, USDJPY, and AUDUSD;
- `phillip-commodity`: Gold/XAUUSD.

The stock/index account is outside the current v1 symbol lanes. Do not place
an account number, password, name, balance, or other credential in repository
configuration or CLI arguments.

## Terminal safety

Before either probe:

1. Log in to the intended Phillip **demo** account using read-only/investor
   authorization where available.
2. Turn Algo Trading off.
3. Enable MT5's option to disable automated trading through the external
   Python API.
4. Keep only the intended Phillip terminal instance active.

The probe fails closed for a live account or any enabled mutation capability.

## FX account

```powershell
cd C:\AI_SCALPER
git pull origin agent/live-grade-phase3
.\.venv\Scripts\Activate.ps1

python -B .\run_mt5_binding_probe.py `
  --candidate phillip-fx `
  --scope fx `
  --terminal-path "C:\path\to\Phillip MT5\terminal64.exe"
```

## Commodity account

After switching to the separate commodity CFD demo account:

```powershell
python -B .\run_mt5_binding_probe.py `
  --candidate phillip-commodity `
  --scope commodity `
  --terminal-path "C:\path\to\Phillip MT5\terminal64.exe"
```

`--candidate` is a reviewed identity label; it does not switch MT5 accounts.
The explicit terminal path prevents Python from attaching to a different
installed broker terminal. Known candidate families also fail closed when the
connected MT5 company does not match the requested label.

The probe may use MT5's read-only symbol catalog when direct common aliases are
not visible. Only symbol name, description, and path are retained. A successful
binding probe still has `discovery_evidence=false`,
`promotion_evidence=false`, `live_allowed=false`, and
`order_capability=DISABLED`.

## Reviewed bindings

The two sanitized probes are now reviewed and bound without storing account
identifiers:

- FX demo: `PhillipSecuritiesJP-PROD`, JPY, 1:25, with
  `AUDUSD.ps01`, `EURUSD.ps01`, and `USDJPY.ps01`;
- commodity CFD demo: `PhillipSecuritiesJP-PROD`, JPY, 1:20, with
  `XAUUSD.ps01`.

Karena kedua akun memakai JPY, nilai stop-loss dari `order_calc_profit()` dan
equity broker juga berdenominasi JPY. Runtime foundation kini mempertahankan
hard cap dalam USD lalu mengubahnya melalui sealed fresh broker quote. FX lane
dapat memakai exact `USDJPY.ps01` direct bid. Commodity lane tetap membutuhkan
attestation bahwa exact USDJPY conversion symbol tersedia pada akun/terminal
commodity; jangan menyalin quote dari terminal FX. Tanpa binding account,
server, symbol metadata, dan tick segar tersebut, sizing harus WAIT.

Run the scoped preflight after logging in to the matching demo account:

```powershell
$phillipTerminal = "C:\Program Files\Phillip Securities Japan MT5 Terminal\terminal64.exe"

python -B .\run_mt5_readonly_preflight.py `
  --candidate phillip-fx `
  --terminal-path $phillipTerminal
```

Switch to the commodity demo account before running the corresponding command:

```powershell
python -B .\run_mt5_readonly_preflight.py `
  --candidate phillip-commodity `
  --terminal-path $phillipTerminal
```

Only after the matching preflight passes, the isolated diagnostic launchers
are:

```powershell
python -B .\run_phillip_fx_shadow.py `
  --candidate phillip-fx `
  --terminal-path $phillipTerminal `
  --acknowledge-diagnostic-only `
  --continuous `
  --poll-seconds 5
```

```powershell
python -B .\run_phillip_commodity_shadow.py `
  --candidate phillip-commodity `
  --terminal-path $phillipTerminal `
  --acknowledge-diagnostic-only `
  --continuous `
  --poll-seconds 5
```

One MT5 terminal executable has only one active account context. Run these
lanes sequentially unless two separately installed Phillip terminal instances
with distinct executable paths are available. Each launcher writes a separate
SQLite journal and summary. Both account lanes have independently observed
fixed `UTC+09:00` server offsets: the FX observation is bound to
`AUDUSD.ps01`, `EURUSD.ps01`, and `USDJPY.ps01`; the commodity observation is
bound to `XAUUSD.ps01`. The reviewed regular DST schedules are now encoded as
conservative full-M15 base calendars. Later official holiday or special-hours
notices must use the signed prospective amendment chain described in
[`PROSPECTIVE_CALENDAR_AMENDMENTS.md`](PROSPECTIVE_CALENDAR_AMENDMENTS.md);
they must never be guessed or applied retroactively.

Preflight and shadow remain diagnostic-only. Promotion, demo auto-order, and
live trading remain disabled. A sanitized discovery-v3 receipt may now be
captured for each exact lane, but it is only an input to later evidence review
and does not make shadow results promotional evidence.

Generate the corresponding non-promotional reports with:

```powershell
python -B .\generate_realtime_diagnostic_report.py `
  --candidate phillip-fx `
  --artifact-tag fx-real-market `
  --acknowledge-diagnostic-only

python -B .\generate_realtime_diagnostic_report.py `
  --candidate phillip-commodity `
  --artifact-tag commodity-real-market `
  --acknowledge-diagnostic-only
```

Current manual-demo blocker inventory dapat dilihat tanpa membuka MT5:

```powershell
python -B .\run_manual_demo_readiness.py --candidate phillip-fx
python -B .\run_manual_demo_readiness.py --candidate phillip-commodity
```

Output tersebut bukan permit atau approval dan tidak dapat mengirim order.

## Dual-terminal concurrent shadow

MetaTrader 5 does not permit two running copies from one installation
directory. Install the second Phillip terminal into a different directory;
each installation path receives its own MT5 data-directory identity. Keep the
existing installation for FX and use a clearly named second directory for the
commodity account. Do not copy credentials or account identifiers into this
repository.

Suggested layout:

```text
C:\Program Files\Phillip Securities Japan MT5 Terminal FX\terminal64.exe
C:\Program Files\Phillip Securities Japan MT5 Terminal Commodity\terminal64.exe
```

In the FX terminal, login to the FX demo account. In the commodity terminal,
login to the commodity CFD demo account. On both terminals, turn Algo Trading
off and enable the option that disables automated trading through the external
Python API. Close the original single installation after the two new paths are
confirmed, so Python cannot attach to the wrong account context.

Validate the topology without starting either shadow:

```powershell
$fxTerminal = "C:\Program Files\Phillip Securities Japan MT5 Terminal FX\terminal64.exe"
$commodityTerminal = "C:\Program Files\Phillip Securities Japan MT5 Terminal Commodity\terminal64.exe"

python -B .\run_phillip_dual_shadow.py `
  --fx-terminal-path $fxTerminal `
  --commodity-terminal-path $commodityTerminal `
  --acknowledge-diagnostic-only `
  --validate-only
```

After both individual preflights pass against their exact paths, start the two
isolated child processes:

```powershell
python -B .\run_phillip_dual_shadow.py `
  --fx-terminal-path $fxTerminal `
  --commodity-terminal-path $commodityTerminal `
  --acknowledge-diagnostic-only `
  --poll-seconds 5
```

The supervisor passes no login or password. Each child repeats its read-only
attestation and account fence. If one child exits, the supervisor terminates
the other rather than leaving a partial topology running. `Ctrl+C` stops both.

## Lane-isolated discovery-v3 preparation

Set up a different Windows Credential Manager signing key for each lane. The
secret is generated locally and is never printed or stored in the repository:

```powershell
python -B .\setup_broker_evidence_key.py --candidate phillip-fx
python -B .\setup_broker_evidence_key.py --candidate phillip-commodity
```

While the matching demo account is active in each exact terminal, capture one
immutable sanitized discovery receipt. Use a new output filename if a prior
receipt already exists; evidence files are intentionally never overwritten.

```powershell
python -B .\mt5_readonly_discovery.py `
  --candidate phillip-fx `
  --terminal-path $fxTerminal `
  --output .\runtime_state\broker_discovery\phillip-fx-window-01-v3.json

python -B .\mt5_readonly_discovery.py `
  --candidate phillip-commodity `
  --terminal-path $commodityTerminal `
  --output .\runtime_state\broker_discovery\phillip-commodity-window-01-v3.json
```

Discovery requires the stricter evidence attestation, including investor or
read-only account authorization, Algo Trading off, and external Python API
trading disabled. FX receipts contain only AUDUSD/EURUSD/USDJPY facts;
commodity receipts contain only XAUUSD facts. Cross-lane symbol mixing,
candidate drift, terminal-path drift, raw account identifiers, or enabled
mutation capability fail closed.

Phillip investor sessions may report `account.trade_expert=true` even though
`account.trade_allowed=false`. The receipt records that broker flag exactly;
it is not treated as order capability. Discovery still fails unless account
trading is unavailable, terminal Algo Trading is off, and external Python API
trading is disabled. The read-only facade exposes no order API.

The `phillip-commodity` profile has now passed its separate signed
regulatory/calendar review and exact manual activation proposal. It may run
`prepare_broker_window.py`, `build_broker_calendar.py`, and
`register_broker_forward_contract.py` solely to register diagnostic evidence.
The `phillip-fx` profile remains disabled and must not run contract
registration. The signed review tooling and exact operator workflow are
documented in
[`BROKER_REGISTRATION_REVIEW.md`](BROKER_REGISTRATION_REVIEW.md). Tooling
availability alone does not count as approval. A valid base calendar or
discovery receipt does not open a lane whose profile remains disabled.

Reviewed schedule basis:

- [Phillip FX service hours](https://www.phillip.co.jp/fx/servicelist.php)
  publish the DST weekly span and daily maintenance interval;
- [Phillip's 2026 DST notice](https://www.phillip.co.jp/information/info/10999)
  identifies the applicable seasonal transition; and
- [Phillip commodity-CFD important notes](https://www.phillip.co.jp/fx/pdf/C-CFD_important_notes.pdf)
  publish the XAU trading hours.

The templates include only buckets that can complete before a published close.
Future exceptional closures require an official HTTPS document hash, at least
900 seconds of lead time, an authenticated current head, and a final
post-window completeness attestation. This feature remains evidence-only and
cannot enable orders.

The immutable human-review workflow for those base calendars is documented in
[`PREWINDOW_CALENDAR_REVIEW.md`](PREWINDOW_CALENDAR_REVIEW.md). It hashes the
exact operator-supplied source bytes and creates a separate Credential
Manager-backed calendar-review approval. The current tracked templates are not
automatically patched or activated by that workflow.

After both regulatory approvals and the pre-window calendar review have been
assembled, use the non-mutating review pack documented in
[`BROKER_REGISTRATION_ACTIVATION_REVIEW.md`](BROKER_REGISTRATION_ACTIVATION_REVIEW.md).
It verifies the discovery, approvals, clean Git identity, and exact three-file
proposal together. It has no apply path. The exact Commodity proposal was
applied only after explicit approval; FX remains false until it completes the
same independent lane workflow.

After pulling the reviewed activation commit on Windows, create new immutable
filenames and run from a clean checkout. The currently signed Commodity window
starts at `2026-07-26T16:00:00Z` (`2026-07-27 01:00:00 JST`), so contract
registration must finish before that instant. If the deadline is missed, do
not backdate or bypass the gate; create a new pre-window calendar review and
activation proposal for a future observation window.

```powershell
python -B .\prepare_broker_window.py `
  --candidate phillip-commodity `
  --discovery .\runtime_state\broker_discovery\phillip-commodity-window-01-v3.json `
  --output .\runtime_state\broker_discovery\phillip-commodity-window-01-plan-v1.json

python -B .\build_broker_calendar.py `
  --candidate phillip-commodity `
  --plan .\runtime_state\broker_discovery\phillip-commodity-window-01-plan-v1.json `
  --output .\runtime_state\broker_discovery\phillip-commodity-window-01-calendar-v1.json

python -B .\register_broker_forward_contract.py `
  --candidate phillip-commodity `
  --discovery .\runtime_state\broker_discovery\phillip-commodity-window-01-v3.json `
  --plan .\runtime_state\broker_discovery\phillip-commodity-window-01-plan-v1.json `
  --calendar .\runtime_state\broker_discovery\phillip-commodity-window-01-calendar-v1.json `
  --artifact-root .\validation_artifacts
```

All three commands remain evidence-only. Any key, discovery, template,
calendar, approval, clock, clean-build, or lane-binding mismatch must fail
closed before contract publication. Git provenance is bound to the exact
AI_SCALPER repository rather than the shell's current Git repository, and a
late or malformed registration is rejected before a new frozen snapshot is
created.

### Commodity contract revision after the first Windows probe

The first immutable Commodity contract,
`phillip-commodity-window-01-diagnostic-v1`, was registered successfully on
the clean `ebd449f` Windows checkout. Its contract payload SHA-256 is
`c459a89a48db2cdc00d2df5f70fc2bd604b08ce69d41e20f465e493ce24cb94a`.
No market evidence was appended to it. The first collector invocation stopped
at `MT5_READ_ONLY_ATTESTATION_FAILED` because the compatibility runner applied
the legacy XM rule `account.trade_expert=false` to a Phillip investor session
whose effective mutation locks were all safe:

```text
account.trade_allowed = false
account.trade_expert = true
terminal.trade_allowed = false
terminal.tradeapi_disabled = true
```

That HOLD submitted no broker order and produced a durable audit export. The
fix keeps the XM legacy policy unchanged and applies the already reviewed
investor-login policy only to broker-neutral candidates. Account trading,
terminal trading, and the external trade API must still remain disabled, and
the facade still exposes no order API. The v2 operational store also binds
`runtime_key=phillip-commodity-broker-shadow-v1` and uses
`phillip-commodity-shadow-invocation-*` audit filenames. It rejects an
existing journal created for another runtime namespace, while XM retains its
historical runtime key and filenames.

Because the contract binds the exact Git commit/tree, v1 must not be patched,
overwritten, renamed, or reused after this source correction. The tracked
Commodity profile therefore advances only its immutable contract namespace to
`phillip-commodity-window-01-diagnostic-v2`. The discovery, signed plan,
calendar, evidence key, frozen development snapshot, observation window, and
all safety flags remain unchanged. Register v2 into the same artifact root;
the valid frozen snapshot may be reused, while the new forward-contract
directory and operational journal must be new.

The Windows wheel-manifest probe also exposed host newline translation:
generated JSON was 9,398 bytes with CRLF instead of the canonical 9,197-byte
LF object. Generated lock artifacts now write explicit LF, and
`.gitattributes` pins the exact lock/manifest files to `eol=lf`.

Setelah contract Commodity berhasil didaftarkan dan window sudah eligible,
jalankan satu cycle evidence dengan terminal yang sama:

```powershell
& "$releaseVenv\Scripts\python.exe" -I -S -B `
  .\run_broker_shadow_once.py `
  --candidate phillip-commodity `
  --terminal-path $commodityTerminal `
  --artifact-root .\validation_artifacts `
  --journal .\runtime_state\shadow\phillip-commodity-shadow-cycles-v2.sqlite3 `
  --audit-export-dir C:\AI_SCALPER_PRIVATE\phillip-commodity-v2-audit-exports
```

Runner broker-neutral menolak kandidat non-XM tanpa exact absolute
`terminal64.exe`. Operational journal hanya menyimpan mode binding dan SHA-256
path ternormalisasi; raw local path tidak dimasukkan ke receipt. Sebelum
observation start, cycle v2 yang sehat harus berhenti sebagai `IDLE/NOT_DUE`
atau status non-append ekuivalen; ia tidak boleh membuat bar evidence lebih
awal.

Official MT5 documentation states that simultaneous copies require different
installation directories:
https://www.metatrader5.com/en/terminal/help/start_advanced/start. Python binds
each child to the exact executable path using the documented `initialize(path)`
interface: https://www.mql5.com/en/docs/python_metatrader5/mt5initialize_py.

### Commodity v2 proof and bounded-worker v3

The immutable v2 remediation was registered and proved successfully on the
exact Windows release:

```text
contract_id = phillip-commodity-window-01-diagnostic-v2
runtime_key = phillip-commodity-broker-shadow-v1
runtime_state = HEALTHY
cycle_status = IDLE
source_chain_from_genesis = true
authenticity = HMAC_SHA256
order_capability = DISABLED
live_allowed = false
```

That proof also exposed an operational deadline defect before any market
evidence existed. The invocation began at
`2026-07-25T14:19:15.605479Z`, while its successful cycle receipt was created
at `2026-07-25T14:22:38.240694Z`: approximately 202.635 seconds later. The
one-shot runner was hashing thousands of installed-environment files on every
launch. A Task Scheduler invocation once per minute therefore could not
reliably meet the contract's 60-second append grace.

Contract v2 remains immutable and valid, but it must not receive evidence from
a source revision made after registration. The bounded-worker remediation
therefore advances Commodity to
`phillip-commodity-window-01-diagnostic-v3`. It does not modify the discovery,
signed plan/calendar, observation window, evidence key, symbol scope, or any
safety flag.

The v3 worker:

- acquires a process-lifetime kernel fence distinct from the per-cycle fence;
- fully verifies and hashes the installed environment once per bounded
  process;
- records the full dependency receipt in its first child invocation;
- revalidates the exact dependency lock and install-manifest identity before
  every later child invocation;
- records an HMAC-bound compact same-process reference to the full receipt;
- invokes the existing one-shot boundary every UTC minute at second `02`;
- stops nonzero on any child `HOLD` or `BUSY`; and
- accepts an explicit lifetime from 900 through 86,400 seconds only.

The cache cannot survive a process restart. No worker path adds an order API,
changes broker state, or relaxes `live_allowed=false`.

After the v3 source commit is pulled into a clean Windows checkout, register
the new immutable contract before the signed observation start. Use a new
journal and audit directory. A bounded pre-window proof may then be run with:

```powershell
$releasePython = "C:\AI_SCALPER_PRIVATE\phillip-commodity-v3-venv\Scripts\python.exe"
$commodityTerminal = "C:\Program Files\Phillip Securities Japan MT5 Terminal Commodity\terminal64.exe"
$v3AuditRoot = "C:\AI_SCALPER_PRIVATE\phillip-commodity-v3-audit-exports"

& $releasePython -I -S -B `
  .\run_broker_shadow_once.py `
  --candidate phillip-commodity `
  --terminal-path $commodityTerminal `
  --artifact-root .\validation_artifacts `
  --journal .\runtime_state\shadow\phillip-commodity-shadow-cycles-v3.sqlite3 `
  --audit-export-dir $v3AuditRoot `
  --worker `
  --worker-duration-seconds 900
```

The proof is acceptable only if at least two consecutive child invocations
verify successfully, the first contains
`broker-shadow-dependency-session-v1`, the next contains
`broker-shadow-dependency-session-reference-v1`, the measured later-child
latency remains below the append grace, the source chain verifies from
genesis, and every receipt still reports order capability disabled.

Only after that proof may the same command be installed as a read-only
scheduled task. The reviewed task shape is:

- run as the same logged-in Windows identity that owns the evidence key and
  exact Phillip terminal;
- start Monday through Friday at `06:45 JST`;
- use `--worker-duration-seconds 84300`;
- use Task Scheduler `IgnoreNew`;
- disable catch-up and forced termination; and
- export every invocation pair to off-host immutable storage.

The Friday worker covers the final Saturday-morning XAU session. Monday starts
before the published `07:00 JST` commodity open. Scheduled-task installation
and off-host/WORM acknowledgement remain external operator actions and are not
evidence until their exact receipts are reviewed.
