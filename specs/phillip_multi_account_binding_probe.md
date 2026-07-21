# Phillip Multi-Account Binding Probe

## Purpose

Phillip Securities Japan separates FX and commodity CFD accounts. The
preparation-only MT5 binding probe must therefore evaluate one account lane at
a time without weakening the read-only boundary.

## Contract

- `--scope fx` requires only `EURUSD`, `USDJPY`, and `AUDUSD`.
- `--scope commodity` requires only canonical `XAUUSD`.
- `--scope all` preserves the legacy four-symbol behavior.
- `--terminal-path` pins the exact MT5 executable when several broker
  terminals are installed.
- A known `phillip-*` candidate must attest a Phillip Securities Japan company
  identity; a mislabeled FBS or other terminal is rejected.
- The optional MT5 symbol catalog capability is read-only.
- Catalog output is reduced to symbol `name`, `description`, and `path`.
- Unique delimiter-qualified broker names may be selected; ambiguous matches
  remain unselected.
- Login, account name, balance, equity, credentials, and arbitrary symbol
  metadata must never be emitted.
- Every result remains demo-only, non-evidentiary, non-promotional, and unable
  to submit broker orders.

## Operational sequence

1. Probe the Phillip FX demo login with `--scope fx`.
2. Probe the separate Phillip commodity CFD demo login with
   `--scope commodity`.
3. Review and bind the exact server and symbol names in configuration.
4. Keep both account adapters isolated while a future global risk governor
   coordinates exposure across lanes.
