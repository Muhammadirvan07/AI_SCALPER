# Phillip Dual-Terminal Read-Only Shadow

## Purpose

Run the Phillip FX and commodity M15 diagnostic lanes concurrently without
sharing an MT5 account context. This topology remains diagnostic-only and has
no broker mutation capability.

## Acceptance criteria

1. The FX and commodity `terminal64.exe` paths must be absolute Windows paths,
   must exist, and must resolve to different installation directories.
2. The launcher must use two independent Python child processes with
   `shell=False`; each child receives only its fixed candidate, terminal path,
   diagnostic acknowledgement, continuous mode, and polling interval.
3. Account number, password, server credential, and order arguments are not
   accepted or persisted.
4. Each child retains its existing read-only MT5 attestation, account fence,
   domain-specific SQLite journal, profile, symbol map, and server-time model.
5. A child startup/exit failure terminates its peer and returns a failure. An
   operator interrupt terminates both children.
6. `--validate-only` verifies topology without starting MT5 or child processes.
7. The launcher must run only on Windows and remain explicitly
   non-promotional with order capability disabled.

## Deployment topology

```text
dual-shadow supervisor
  |-- FX child -------- exact FX terminal64.exe -------- phillip-fx journal
  `-- commodity child - exact commodity terminal64.exe - phillip-commodity journal
```

MetaTrader 5 requires separate installation directories for simultaneous
copies. Each terminal must be logged in to its matching demo account before
the supervisor starts.
