FINEX off-host monitor acceptance v1
====================================

Purpose
-------
Prove that the Putra physical device owns the reviewed Ed25519 key, is running
Tailscale at 100.121.177.7, and can reach the AI Scalper host at 100.80.180.13.
This package is status-only. It cannot grant authorization or submit orders.

Run on the Putra physical device
--------------------------------
1. Keep the private key at:
   %USERPROFILE%\.ssh\finex_runtime_health_offhost_v1
2. Open PowerShell in this extracted package directory.
3. Run:

   powershell.exe -ExecutionPolicy Bypass -File .\CREATE_FINEX_OFFHOST_ACCEPTANCE.ps1

4. Return only the two paths printed as RECEIPT and SIGNATURE.
5. Never return the private key, the .ssh directory, or a credential export.

Verify on the AI Scalper host
-----------------------------
Run VERIFY_FINEX_OFFHOST_ACCEPTANCE.ps1 with the returned receipt, signature,
and runtime_evidence\finex_runtime_health_offhost_v1.pub.

Fixed bindings
--------------
Putra device: desktop-8cc1fnj / 100.121.177.7
AI Scalper host: 100.80.180.13
Trust policy SHA-256:
f957e29a0b5456e7b7936baf37ce65c601ce0ac3ca97a0fcd85ce6b1a0eb9747
Public-key fingerprint:
SHA256:t9QelAsZpP4wo0J9MyiYyB3kU/RF+xTBWSixLl60yXs

Safety
------
AUTHORIZATION_GRANTED=false
LIVE_ALLOWED=false
SAFE_TO_DEMO_AUTO_ORDER=false
ORDER_CAPABILITY=DISABLED
