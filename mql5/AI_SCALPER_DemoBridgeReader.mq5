//+------------------------------------------------------------------+
//| AI_SCALPER_DemoBridgeReader.mq5                                  |
//| Demo-only MT5 reader for AI_SCALPER mt5_demo_bridge_outbox.json   |
//+------------------------------------------------------------------+
#property strict

#include <Trade/Trade.mqh>

CTrade trade;

// =========================
// USER SETTINGS
// =========================
input string InpOutboxFileName = "mt5_demo_bridge_outbox.json";
input int    InpCheckIntervalSeconds = 10;
input double InpMaxLot = 0.01;
input int    InpMagicNumber = 260615;
input int    InpDeviationPoints = 30;
input bool   InpDemoOnly = true;
input bool   InpRequireDemoOnlyFlag = true;
input bool   InpRequireLiveAllowedFalse = true;
input bool   InpOnePositionPerSymbol = true;

// =========================
// STATE
// =========================
datetime last_check_time = 0;
string executed_signal_ids[];

//+------------------------------------------------------------------+
//| Utility                                                          |
//+------------------------------------------------------------------+
bool IsDemoAccount()
{
   ENUM_ACCOUNT_TRADE_MODE mode = (ENUM_ACCOUNT_TRADE_MODE)AccountInfoInteger(ACCOUNT_TRADE_MODE);
   return mode == ACCOUNT_TRADE_MODE_DEMO;
}

string ReadWholeFile(string file_name)
{
   ResetLastError();

   int handle = FileOpen(file_name, FILE_READ | FILE_TXT | FILE_ANSI | FILE_COMMON);
   if(handle == INVALID_HANDLE)
   {
      Print("Cannot open file from COMMON folder: ", file_name, " error=", GetLastError());
      return "";
   }

   string content = "";
   while(!FileIsEnding(handle))
   {
      content += FileReadString(handle);
   }

   FileClose(handle);
   return content;
}

bool JsonBool(string json, string key, bool default_value=false)
{
   string pattern_true = "\"" + key + "\": true";
   string pattern_false = "\"" + key + "\": false";

   if(StringFind(json, pattern_true) >= 0)
      return true;

   if(StringFind(json, pattern_false) >= 0)
      return false;

   return default_value;
}

int JsonInt(string json, string key, int default_value=0)
{
   string pattern = "\"" + key + "\":";
   int pos = StringFind(json, pattern);
   if(pos < 0)
      return default_value;

   pos += StringLen(pattern);

   while(pos < StringLen(json))
   {
      ushort ch = StringGetCharacter(json, pos);
      if(ch != ' ' && ch != '\t' && ch != '\r' && ch != '\n')
         break;
      pos++;
   }

   string value = "";
   while(pos < StringLen(json))
   {
      ushort ch = StringGetCharacter(json, pos);
      if((ch >= '0' && ch <= '9') || ch == '-')
      {
         value += ShortToString(ch);
         pos++;
      }
      else
      {
         break;
      }
   }

   if(value == "")
      return default_value;

   return (int)StringToInteger(value);
}

double JsonDouble(string json, string key, double default_value=0.0)
{
   string pattern = "\"" + key + "\":";
   int pos = StringFind(json, pattern);
   if(pos < 0)
      return default_value;

   pos += StringLen(pattern);

   while(pos < StringLen(json))
   {
      ushort ch = StringGetCharacter(json, pos);
      if(ch != ' ' && ch != '\t' && ch != '\r' && ch != '\n')
         break;
      pos++;
   }

   string value = "";
   while(pos < StringLen(json))
   {
      ushort ch = StringGetCharacter(json, pos);
      if((ch >= '0' && ch <= '9') || ch == '-' || ch == '.')
      {
         value += ShortToString(ch);
         pos++;
      }
      else
      {
         break;
      }
   }

   if(value == "")
      return default_value;

   return StringToDouble(value);
}

string JsonString(string json, string key, string default_value="")
{
   string pattern = "\"" + key + "\":";
   int pos = StringFind(json, pattern);
   if(pos < 0)
      return default_value;

   pos += StringLen(pattern);

   while(pos < StringLen(json))
   {
      ushort ch = StringGetCharacter(json, pos);
      if(ch != ' ' && ch != '\t' && ch != '\r' && ch != '\n')
         break;
      pos++;
   }

   if(pos >= StringLen(json) || StringGetCharacter(json, pos) != '"')
      return default_value;

   pos++;

   string value = "";
   while(pos < StringLen(json))
   {
      ushort ch = StringGetCharacter(json, pos);
      if(ch == '"')
         break;

      value += ShortToString(ch);
      pos++;
   }

   return value;
}

string ExtractArrayContent(string json, string key)
{
   string pattern = "\"" + key + "\":";
   int pos = StringFind(json, pattern);
   if(pos < 0)
      return "";

   int start = StringFind(json, "[", pos);
   if(start < 0)
      return "";

   int depth = 0;
   for(int i = start; i < StringLen(json); i++)
   {
      ushort ch = StringGetCharacter(json, i);

      if(ch == '[')
         depth++;

      if(ch == ']')
      {
         depth--;
         if(depth == 0)
            return StringSubstr(json, start + 1, i - start - 1);
      }
   }

   return "";
}

string ExtractNextObject(string array_content, int &pos)
{
   int start = -1;
   int depth = 0;

   for(int i = pos; i < StringLen(array_content); i++)
   {
      ushort ch = StringGetCharacter(array_content, i);

      if(ch == '{')
      {
         if(depth == 0)
            start = i;
         depth++;
      }

      if(ch == '}')
      {
         depth--;
         if(depth == 0 && start >= 0)
         {
            pos = i + 1;
            return StringSubstr(array_content, start, i - start + 1);
         }
      }
   }

   return "";
}

bool WasExecuted(string signal_id)
{
   for(int i = 0; i < ArraySize(executed_signal_ids); i++)
   {
      if(executed_signal_ids[i] == signal_id)
         return true;
   }

   return false;
}

void MarkExecuted(string signal_id)
{
   int size = ArraySize(executed_signal_ids);
   ArrayResize(executed_signal_ids, size + 1);
   executed_signal_ids[size] = signal_id;
}

bool HasOpenPositionForSymbol(string symbol)
{
   for(int i = PositionsTotal() - 1; i >= 0; i--)
   {
      ulong ticket = PositionGetTicket(i);
      if(ticket == 0)
         continue;

      if(!PositionSelectByTicket(ticket))
         continue;

      string pos_symbol = PositionGetString(POSITION_SYMBOL);
      long magic = PositionGetInteger(POSITION_MAGIC);

      if(pos_symbol == symbol && magic == InpMagicNumber)
         return true;
   }

   return false;
}

double NormalizeLot(string symbol, double requested_lot)
{
   double min_lot = SymbolInfoDouble(symbol, SYMBOL_VOLUME_MIN);
   double max_lot = SymbolInfoDouble(symbol, SYMBOL_VOLUME_MAX);
   double step = SymbolInfoDouble(symbol, SYMBOL_VOLUME_STEP);

   double capped = MathMin(requested_lot, InpMaxLot);
   capped = MathMin(capped, max_lot);

   if(capped < min_lot)
      return 0.0;

   if(step > 0)
      capped = MathFloor(capped / step) * step;

   return NormalizeDouble(capped, 2);
}

bool ValidateOutboxRoot(string json)
{
   bool demo_only = JsonBool(json, "demo_only", false);
   bool live_allowed = JsonBool(json, "live_allowed", true);
   int order_count = JsonInt(json, "order_count", 0);
   double max_lot = JsonDouble(json, "max_lot", 0.0);

   if(InpDemoOnly && !IsDemoAccount())
   {
      Print("Safety stop: this EA is demo-only, but account is not DEMO.");
      return false;
   }

   if(InpRequireDemoOnlyFlag && !demo_only)
   {
      Print("Safety stop: outbox demo_only flag is not true.");
      return false;
   }

   if(InpRequireLiveAllowedFalse && live_allowed)
   {
      Print("Safety stop: outbox live_allowed is true. Refusing.");
      return false;
   }

   if(max_lot > InpMaxLot)
   {
      Print("Safety stop: outbox max_lot exceeds EA max lot. outbox=", max_lot, " ea=", InpMaxLot);
      return false;
   }

   if(order_count <= 0)
   {
      Print("No demo order in outbox.");
      return false;
   }

   return true;
}

bool ExecuteDemoOrder(string order_json)
{
   string signal_id = JsonString(order_json, "signal_id", "");
   string symbol = JsonString(order_json, "symbol_mt5", "");
   if(symbol == "")
      symbol = JsonString(order_json, "symbol", "");

   string order_type = JsonString(order_json, "order_type", "");
   double lot = JsonDouble(order_json, "lot", 0.0);
   double sl = JsonDouble(order_json, "stop_loss", 0.0);
   double tp = JsonDouble(order_json, "take_profit", 0.0);

   bool order_demo_only = JsonBool(order_json, "demo_only", false);
   bool order_live_allowed = JsonBool(order_json, "live_allowed", true);

   if(signal_id == "")
   {
      Print("Skip order: signal_id missing.");
      return false;
   }

   if(WasExecuted(signal_id))
   {
      Print("Skip duplicate signal: ", signal_id);
      return false;
   }

   if(symbol == "" || !SymbolSelect(symbol, true))
   {
      Print("Skip order: symbol unavailable: ", symbol);
      return false;
   }

   if(order_demo_only != true)
   {
      Print("Skip order: order demo_only is not true. Signal=", signal_id);
      return false;
   }

   if(order_live_allowed == true)
   {
      Print("Skip order: order live_allowed is true. Signal=", signal_id);
      return false;
   }

   if(order_type != "BUY" && order_type != "SELL")
   {
      Print("Skip order: invalid order_type=", order_type, " signal=", signal_id);
      return false;
   }

   double safe_lot = NormalizeLot(symbol, lot);
   if(safe_lot <= 0.0)
   {
      Print("Skip order: invalid safe lot. requested=", lot, " signal=", signal_id);
      return false;
   }

   if(InpOnePositionPerSymbol && HasOpenPositionForSymbol(symbol))
   {
      Print("Skip order: existing position for symbol ", symbol, " signal=", signal_id);
      return false;
   }

   trade.SetExpertMagicNumber(InpMagicNumber);
   trade.SetDeviationInPoints(InpDeviationPoints);

   bool result = false;
   string comment = "AI_SCALPER_DEMO";

   if(order_type == "BUY")
      result = trade.Buy(safe_lot, symbol, 0.0, sl, tp, comment);

   if(order_type == "SELL")
      result = trade.Sell(safe_lot, symbol, 0.0, sl, tp, comment);

   if(result)
   {
      MarkExecuted(signal_id);
      Print("DEMO order executed: ", signal_id, " ", symbol, " ", order_type, " lot=", safe_lot);
      return true;
   }

   Print("OrderSend failed: signal=", signal_id, " retcode=", trade.ResultRetcode(), " desc=", trade.ResultRetcodeDescription());
   return false;
}

void ProcessOutbox()
{
   string json = ReadWholeFile(InpOutboxFileName);
   if(json == "")
      return;

   if(!ValidateOutboxRoot(json))
      return;

   string orders_content = ExtractArrayContent(json, "orders");
   if(orders_content == "")
   {
      Print("No orders array content.");
      return;
   }

   int pos = 0;
   while(pos < StringLen(orders_content))
   {
      string object_json = ExtractNextObject(orders_content, pos);
      if(object_json == "")
         break;

      ExecuteDemoOrder(object_json);
   }
}

//+------------------------------------------------------------------+
//| Expert lifecycle                                                 |
//+------------------------------------------------------------------+
int OnInit()
{
   Print("AI_SCALPER Demo Bridge Reader initialized.");
   Print("Demo only: ", InpDemoOnly, " | Max lot: ", InpMaxLot, " | File: ", InpOutboxFileName);

   if(InpDemoOnly && !IsDemoAccount())
   {
      Print("Safety warning: attached account is not DEMO. EA will refuse execution.");
   }

   trade.SetExpertMagicNumber(InpMagicNumber);
   EventSetTimer(InpCheckIntervalSeconds);
   return INIT_SUCCEEDED;
}

void OnDeinit(const int reason)
{
   EventKillTimer();
   Print("AI_SCALPER Demo Bridge Reader stopped.");
}

void OnTick()
{
   // Timer handles file polling.
}

void OnTimer()
{
   ProcessOutbox();
}
