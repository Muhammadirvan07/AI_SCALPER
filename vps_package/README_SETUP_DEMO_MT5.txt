AI_SCALPER LEGACY MT5 DIAGNOSTIC READER

STATUS:
- Legacy file bridge execution is decommissioned.
- The MQ5 source is an inert diagnostic reader only.
- It contains no broker-order capability and never transmits an order.
- Do not use this package as the AI_SCALPER executor.
- live_allowed must stay false.
- safe_to_demo_auto_order must stay false.
- max_lot must stay 0.01.
- order_count must stay 0.

FILES:
1. AI_SCALPER_DemoBridgeReader.mq5
   Optional inert diagnostic source.
   Copy to:
   MT5 Data Folder/MQL5/Experts/

No runtime JSON, signal history, rejected-order history, account data, or
broker evidence is distributed in this package. Diagnostic JSON must be
generated locally by the current locked runtime and must never be committed.

SHADOW SETUP:
1. Open MT5 on Windows VPS.
2. Login to DEMO account with the investor/read-only password only.
3. Keep Algo Trading OFF.
4. Enable the MT5 option that disables automated trading through the external
   Python API.
5. Confirm the Python discovery reports account trade_allowed=false,
   trade_expert=false, terminal trade_allowed=false, and
   tradeapi_disabled=true.
6. Do not attach this legacy reader during broker read-only shadow.
7. Run the official Python read-only discovery/exporter workflow instead.

OPTIONAL DIAGNOSTIC INSPECTION:
1. Click File > Open Data Folder.
2. Open MQL5 > Experts.
3. Remove every older compiled AI_SCALPER_DemoBridgeReader.ex5.
4. Copy and compile the current AI_SCALPER_DemoBridgeReader.mq5.
5. Keep Algo Trading OFF.
6. Attach only if local outbox lock diagnostics are explicitly needed.

IMPORTANT SAFETY:
- The current source has no Trade library, CTrade object, or order primitive.
- The reader accepts only the locked diagnostic state:
  demo_only=true, paper_only=true, live_allowed=false,
  safe_to_demo_auto_order=false, max_lot=0.01, order_count=0.
- A malformed or unlocked outbox is rejected and only logged.
- An older compiled EX5 may still contain obsolete execution code. Remove it.
- The official Python MT5 adapter is the only planned execution path, and it
  remains disabled until its separate manual-demo and promotion gates pass.

CURRENT EXPECTED STATE:
- order_count must be exactly 0.
- safe_to_demo_auto_order must be exactly false.
- No transition to order_count=1 is supported by this legacy reader.

If optional diagnostic inspection is explicitly authorized, the reader looks
for mt5_demo_bridge_outbox.json in MT5 FILE_COMMON. The file must be generated
locally from the current locked runtime; it is deliberately absent from this
source package. This legacy path must never be used for execution.
