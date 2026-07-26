# Windows XM and FINEX Preparation Packages

Status: `PREPARATION_ONLY / ORDER_DISABLED / NOT_ACTIVATION`

The builder creates two source-bound Windows handoff packages:

- XM Japan legal-hold preparation: validates the exact source and current
  legal block without importing MetaTrader5 or touching a terminal.
- FINEX read-only preparation: validates the exact source and dependency lock,
  then runs only the existing sanitized FINEX preflight against an explicit
  `terminal64.exe` path.

Neither package creates an evidence key, discovery receipt, calendar, forward
contract, journal, scheduled task, paper order, demo order, or live order.

## Build

Run only from the committed source branch:

```powershell
python -B .\build_windows_xm_finex_preparation_packages.py `
  --output-root C:\AI_SCALPER_RELEASES\xm-finex-preparation-v1
```

Copy each ZIP together with its `.manifest.json` and matching `Expand-*.ps1`
helper to Windows. Extraction is create-exclusive and verifies archive/member
hashes before writing the destination.

## XM

```powershell
& .\Expand-XMJapanLegalHoldPreparationPackage.ps1
& C:\AI_SCALPER_PRIVATE\xm-japan-legal-hold-preparation-v1\Test-XMPreparationGate.ps1
```

Expected outcome: `XM_PREPARATION_GATE_VERIFIED` with eligibility
`LEGAL_BLOCKED_CURRENT_JAPAN`. This is not permission to initialize XM MT5 or
collect XM evidence. Public crypto marketing is not an account symbol binding.

## FINEX

```powershell
& .\Expand-FINEXReadOnlyPreparationPackage.ps1

$finexTerminal = "C:\Program Files\FINEX MetaTrader 5\terminal64.exe"

& C:\AI_SCALPER_PRIVATE\finex-read-only-preparation-v1\Test-FINEXReadOnlyPreflight.ps1 `
  -TerminalPath $finexTerminal
```

Use the actual exact terminal path; do not copy the example if FINEX is
installed elsewhere. A passing result remains preparation-only. FINEX
discovery and contract registration stay disabled until operating eligibility
and a separate source/config review are complete.

The reviewed official FINEX inventory contains Forex, metals/energy, indices,
and stocks. It does not currently list cryptocurrency instruments; do not add
BTC or ETH mappings by assumption.
