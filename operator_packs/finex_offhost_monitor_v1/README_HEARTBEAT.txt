FINEX off-host connectivity heartbeat v1
=========================================

This service proves continuous Tailscale reachability and off-host Ed25519 key
custody. It does not claim decision/execution runtime health and cannot grant
trading authorization.

Install on desktop-8cc1fnj
--------------------------
1. Open PowerShell with Run as administrator.
2. Open this extracted package directory.
3. Run:

   powershell.exe -ExecutionPolicy Bypass -File .\INSTALL_FINEX_OFFHOST_HEARTBEAT.ps1

The scheduled task runs only while Putra has an interactive Windows session.
Keep Tailscale connected and keep Putra logged in.

Verify from the AI Scalper host
-------------------------------
Run:

   powershell.exe -ExecutionPolicy Bypass -File .\VERIFY_FINEX_OFFHOST_HEARTBEAT_REMOTE.ps1 -PublicKey <PUBLIC_KEY_PATH>

Network boundary
----------------
Listener: 100.121.177.7:43129
Allowed remote IP: 100.80.180.13 only
Public internet listener: none

Safety
------
RUNTIME_HEALTH_VERIFIED=false
AUTHORIZATION_GRANTED=false
LIVE_ALLOWED=false
SAFE_TO_DEMO_AUTO_ORDER=false
ORDER_CAPABILITY=DISABLED
