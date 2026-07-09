AI_SCALPER DEMO MT5 SETUP

STATUS:
- Demo-only bridge package.
- Do not use on live account.
- live_allowed must stay false.
- max_lot must stay 0.01.

FILES:
1. AI_SCALPER_DemoBridgeReader.mq5
   Copy to:
   MT5 Data Folder/MQL5/Experts/

2. mt5_demo_bridge_outbox.json
   Copy to:
   MT5 Common Files folder

3. bridge_status.json
   Optional diagnostic file.

4. bridge_rejected_signals.json
   Optional diagnostic file.

MT5 SETUP:
1. Open MT5 on Windows VPS.
2. Login to DEMO account only.
3. Click File > Open Data Folder.
4. Open MQL5 > Experts.
5. Copy AI_SCALPER_DemoBridgeReader.mq5 into Experts.
6. Open MetaEditor.
7. Compile AI_SCALPER_DemoBridgeReader.mq5.
8. Attach EA to any chart.
9. Enable Algo Trading.
10. Confirm account is DEMO.

IMPORTANT SAFETY:
- EA refuses execution if account is not DEMO.
- EA refuses execution if outbox demo_only is not true.
- EA refuses execution if live_allowed is true.
- EA caps lot at 0.01.
- EA skips duplicate signal_id.
- EA uses magic number 260615.

CURRENT EXPECTED STATE:
- order_count may be 0.
- This is normal if AI_SCALPER has no valid signal.
- When AI_SCALPER later exports a valid demo order, order_count can become 1.

COMMON FILES:
The EA reads mt5_demo_bridge_outbox.json from MT5 FILE_COMMON folder.
In MT5/MQL5, this usually maps to:
C:\Users\<WindowsUser>\AppData\Roaming\MetaQuotes\Terminal\Common\Files

Do not copy JSON only to MQL5/Experts.
The EA file goes to Experts, but JSON outbox goes to Common Files.
