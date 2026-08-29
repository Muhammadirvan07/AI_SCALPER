FINEX READ-ONLY PRECOLLECTION V1

This pack captures signed MT5 discovery receipts every 15 minutes while the
interactive operator session and FINEX terminal are available.

It does not create or renew a terminal fence, attest UI settings, register a
broker-forward contract, generate promotion evidence, enable execution, or
submit an order. Receipts created before the reviewed forward window remain
diagnostic-only and cannot be credited retroactively.

Install from the AI_SCALPER project account:

  powershell.exe -ExecutionPolicy Bypass -File `
    .\operator_packs\finex_readonly_precollection_v1\INSTALL_FINEX_READONLY_DISCOVERY_TASK.ps1

Run one bounded capture manually:

  powershell.exe -ExecutionPolicy Bypass -File `
    .\operator_packs\finex_readonly_precollection_v1\RUN_FINEX_READONLY_DISCOVERY.ps1

Safety invariants:

  AUTHORIZATION_GRANTED=false
  BROKER_FORWARD_CREDIT=false
  ORDER_CAPABILITY=DISABLED
