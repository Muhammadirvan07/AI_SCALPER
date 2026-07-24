//+------------------------------------------------------------------+
//| AI_SCALPER_DemoBridgeReader.mq5                                  |
//| Inert diagnostic reader for mt5_demo_bridge_outbox.json          |
//+------------------------------------------------------------------+
#property strict

// This legacy adapter deliberately has no broker-order capability.
// Only file location and polling cadence are configurable.
input string InpOutboxFileName = "mt5_demo_bridge_outbox.json";
input int    InpCheckIntervalSeconds = 10;

const double EXPECTED_MAX_LOT = 0.01;

string ReadWholeFile(string file_name)
{
   ResetLastError();

   int handle = FileOpen(file_name, FILE_READ | FILE_TXT | FILE_ANSI | FILE_COMMON);
   if(handle == INVALID_HANDLE)
   {
      Print("Diagnostic reader cannot open COMMON file: ", file_name, " error=", GetLastError());
      return "";
   }

   string content = "";
   while(!FileIsEnding(handle))
      content += FileReadString(handle);

   FileClose(handle);
   return content;
}

int JsonValuePosition(string json, string key)
{
   string pattern = "\"" + key + "\"";
   int pos = StringFind(json, pattern);
   if(pos < 0)
      return -1;

   pos = StringFind(json, ":", pos + StringLen(pattern));
   if(pos < 0)
      return -1;

   pos++;
   while(pos < StringLen(json))
   {
      ushort ch = StringGetCharacter(json, pos);
      if(ch != ' ' && ch != '\t' && ch != '\r' && ch != '\n')
         break;
      pos++;
   }

   return pos;
}

bool TryJsonBool(string json, string key, bool &value)
{
   int pos = JsonValuePosition(json, key);
   if(pos < 0)
      return false;

   if(StringSubstr(json, pos, 4) == "true")
   {
      value = true;
      return true;
   }

   if(StringSubstr(json, pos, 5) == "false")
   {
      value = false;
      return true;
   }

   return false;
}

bool TryJsonInt(string json, string key, int &value)
{
   int pos = JsonValuePosition(json, key);
   if(pos < 0)
      return false;

   string text = "";
   while(pos < StringLen(json))
   {
      ushort ch = StringGetCharacter(json, pos);
      if((ch >= '0' && ch <= '9') || (ch == '-' && text == ""))
      {
         text += ShortToString(ch);
         pos++;
         continue;
      }
      break;
   }

   if(text == "" || text == "-")
      return false;

   value = (int)StringToInteger(text);
   return true;
}

bool TryJsonDouble(string json, string key, double &value)
{
   int pos = JsonValuePosition(json, key);
   if(pos < 0)
      return false;

   string text = "";
   while(pos < StringLen(json))
   {
      ushort ch = StringGetCharacter(json, pos);
      if((ch >= '0' && ch <= '9') || (ch == '-' && text == "") || ch == '.')
      {
         text += ShortToString(ch);
         pos++;
         continue;
      }
      break;
   }

   if(text == "" || text == "-" || text == ".")
      return false;

   value = StringToDouble(text);
   return true;
}

bool ValidateLockedDiagnosticState(string json)
{
   bool demo_only = false;
   bool paper_only = false;
   bool live_allowed = false;
   bool safe_to_demo_auto_order = false;
   int order_count = -1;
   double max_lot = -1.0;

   if(!TryJsonBool(json, "demo_only", demo_only) ||
      !TryJsonBool(json, "paper_only", paper_only) ||
      !TryJsonBool(json, "live_allowed", live_allowed) ||
      !TryJsonBool(json, "safe_to_demo_auto_order", safe_to_demo_auto_order) ||
      !TryJsonInt(json, "order_count", order_count) ||
      !TryJsonDouble(json, "max_lot", max_lot))
   {
      Print("Diagnostic safety rejection: required root lock field is missing or malformed.");
      return false;
   }

   if(!demo_only || !paper_only)
   {
      Print("Diagnostic safety rejection: demo_only and paper_only must both be true.");
      return false;
   }

   if(live_allowed)
   {
      Print("Diagnostic safety rejection: live_allowed must remain false.");
      return false;
   }

   if(safe_to_demo_auto_order)
   {
      Print("Diagnostic safety rejection: safe_to_demo_auto_order must remain false.");
      return false;
   }

   if(order_count != 0)
   {
      Print("Diagnostic safety rejection: order_count must remain zero.");
      return false;
   }

   if(MathAbs(max_lot - EXPECTED_MAX_LOT) > 0.0000001)
   {
      Print("Diagnostic safety rejection: max_lot must remain 0.01.");
      return false;
   }

   return true;
}

void InspectOutbox()
{
   string json = ReadWholeFile(InpOutboxFileName);
   if(json == "")
      return;

   if(!ValidateLockedDiagnosticState(json))
      return;

   Print(
      "AI_SCALPER legacy diagnostic state verified: ",
      "safe_to_demo_auto_order=false, live_allowed=false, order_count=0. ",
      "This reader cannot transmit orders."
   );
}

int OnInit()
{
   int interval = InpCheckIntervalSeconds;
   if(interval < 1)
      interval = 1;

   Print("AI_SCALPER inert legacy diagnostic reader initialized.");
   Print("Broker-order capability is not compiled into this source.");
   EventSetTimer(interval);
   return INIT_SUCCEEDED;
}

void OnDeinit(const int reason)
{
   EventKillTimer();
   Print("AI_SCALPER inert legacy diagnostic reader stopped.");
}

void OnTick()
{
   // Intentionally empty. Diagnostics are read by the timer only.
}

void OnTimer()
{
   InspectOutbox();
}
