FINEX OFF-HOST RUNTIME HEALTH KEY SETUP V1
==========================================

Purpose
-------
Create the Ed25519 signing identity for the FINEX runtime-health monitor on a
physical Windows device separate from the FINEX trading computer.

Mandatory custody rules
-----------------------
1. Run this package only on the separate off-host monitor device.
2. Never run CREATE_FINEX_OFFHOST_MONITOR_KEY.ps1 on the FINEX trading device.
3. Never upload, email, copy, or back up the private key outside the approved
   off-host encrypted key custody.
4. Return only public_output\finex_runtime_health_offhost_v1.pub to the FINEX
   host operator.
5. This package does not authorize trading and contains no broker capability.

Run in PowerShell on the off-host device
----------------------------------------
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\CREATE_FINEX_OFFHOST_MONITOR_KEY.ps1
.\VERIFY_FINEX_OFFHOST_MONITOR_KEY.ps1

Expected private-key location
-----------------------------
%USERPROFILE%\.ssh\finex_runtime_health_offhost_v1

File to return
--------------
public_output\finex_runtime_health_offhost_v1.pub

Do not return the file without the .pub extension.
