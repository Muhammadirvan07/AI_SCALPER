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
SQLite journal and summary. Broker UTC offset and exact session calendars are
still pending runtime observation and must not be guessed.

Preflight and shadow remain diagnostic-only. Discovery evidence, promotion,
demo auto-order, and live trading remain disabled.

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
