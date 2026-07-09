import argparse
import importlib
import json
import os
import sys
from datetime import datetime, timezone
from types import ModuleType

try:
    yf: ModuleType | None = importlib.import_module("yfinance")
except ImportError:
    yf = None


# =========================
# SYMBOL MAP
# =========================

# Pair utama dan instrumen populer untuk scalping/backtest
SYMBOLS = {
    # Major forex pairs
    "EURUSD": "EURUSD=X",
    "GBPUSD": "GBPUSD=X",
    "USDJPY": "JPY=X",
    "USDCHF": "CHF=X",
    "AUDUSD": "AUDUSD=X",
    "NZDUSD": "NZDUSD=X",
    "USDCAD": "CAD=X",

    # Cross pairs populer
    "EURJPY": "EURJPY=X",
    "GBPJPY": "GBPJPY=X",
    "EURGBP": "EURGBP=X",
    "AUDJPY": "AUDJPY=X",
    "CADJPY": "CADJPY=X",
    "CHFJPY": "CHFJPY=X",

    # Instrumen tambahan yang sering dipakai trader scalping
    "XAUUSD": "GC=F",      # Gold futures proxy
    "XAGUSD": "SI=F",      # Silver futures proxy
    "USOIL": "CL=F",       # WTI crude oil futures proxy
    "BTCUSD": "BTC-USD",
}

# Fallback kalau active_pairs.json belum ada / kosong.
DEFAULT_FAST_SYMBOLS = ["EURUSD", "GBPUSD", "BTCUSD"]

# Commodity symbols are available for FULL/CUSTOM data repair mode,
# but are intentionally not added to DEFAULT_FAST_SYMBOLS to avoid
# accidentally expanding the live/paper decision universe.
COMMODITY_REPAIR_SYMBOLS = ["XAUUSD", "XAGUSD", "USOIL"]

PERIOD = "30d"
INTERVAL = "15m"
DATA_DIR = "data"
ACTIVE_PAIRS_FILE = "active_pairs.json"
PAPER_ORDERS_FILE = "paper_orders.json"
DATA_COLLECTOR_STATUS_FILE = "data_collector_status.json"

MODE_FAST = "fast"
MODE_FULL = "full"
MODE_CUSTOM = "custom"


# =========================
# BASIC HELPERS
# =========================


def utc_now_iso():
    return datetime.now(timezone.utc).isoformat()



def load_json(path, default):
    if not os.path.exists(path):
        return default

    try:
        with open(path, "r") as f:
            return json.load(f)
    except Exception:
        return default



def save_json(path, data):
    with open(path, "w") as f:
        json.dump(data, f, indent=4)


def get_yfinance_module():
    if yf is None:
        raise RuntimeError(
            "yfinance is not installed in this Python environment. "
            "Run: pip install yfinance"
        )

    return yf



def normalize_symbol(symbol):
    return str(symbol or "").strip().upper()



def unique_symbols(symbols):
    result = []
    seen = set()

    for symbol in symbols:
        normalized = normalize_symbol(symbol)
        if not normalized:
            continue
        if normalized not in SYMBOLS:
            print(f"⚠️  Skip unknown symbol: {normalized}")
            continue
        if normalized in seen:
            continue
        seen.add(normalized)
        result.append(normalized)

    return result


# =========================
# SYMBOL SELECTION
# =========================



def extract_active_pairs(data):
    symbols = []

    if isinstance(data, list):
        for item in data:
            if isinstance(item, str):
                symbols.append(item)
            elif isinstance(item, dict):
                symbols.append(item.get("symbol") or item.get("pair") or item.get("name"))

    elif isinstance(data, dict):
        for key in ["active_pairs", "symbols", "pairs", "approved_symbols"]:
            value = data.get(key)
            if isinstance(value, list):
                for item in value:
                    if isinstance(item, str):
                        symbols.append(item)
                    elif isinstance(item, dict):
                        symbols.append(item.get("symbol") or item.get("pair") or item.get("name"))

        # Support format seperti {"EURUSD": {...}, "GBPUSD": {...}}
        for key in data.keys():
            if normalize_symbol(key) in SYMBOLS:
                symbols.append(key)

    return unique_symbols(symbols)



def get_open_order_symbols():
    orders = load_json(PAPER_ORDERS_FILE, [])
    symbols = []

    if not isinstance(orders, list):
        return symbols

    for order in orders:
        if not isinstance(order, dict):
            continue
        if order.get("status") == "PAPER_OPEN":
            symbols.append(order.get("symbol"))

    return unique_symbols(symbols)



def get_fast_symbols():
    active_data = load_json(ACTIVE_PAIRS_FILE, [])
    active_symbols = extract_active_pairs(active_data)
    open_order_symbols = get_open_order_symbols()

    symbols = unique_symbols(active_symbols + open_order_symbols)

    if not symbols:
        symbols = unique_symbols(DEFAULT_FAST_SYMBOLS + open_order_symbols)

    if "BTCUSD" not in symbols:
        symbols = unique_symbols(symbols + ["BTCUSD"])

    return symbols



def parse_custom_symbols(raw_symbols):
    if not raw_symbols:
        return []

    symbols = []
    for chunk in raw_symbols:
        for item in str(chunk).split(","):
            symbols.append(item)

    return unique_symbols(symbols)



def resolve_symbols(mode, custom_symbols=None):
    if mode == MODE_FULL:
        return list(SYMBOLS.keys())

    if mode == MODE_CUSTOM:
        symbols = parse_custom_symbols(custom_symbols or [])
        if not symbols:
            print("⚠️  Custom mode selected but no valid symbol provided. Falling back to FAST mode.")
            return get_fast_symbols()
        return symbols

    return get_fast_symbols()


# =========================
# DATA PROCESSING
# =========================



def clean_columns(df):
    """Bersihkan format kolom yfinance agar menjadi Open, High, Low, Close, Volume."""

    if hasattr(df.columns, "droplevel"):
        try:
            df.columns = df.columns.droplevel(1)
        except Exception:
            pass

    return df



def validate_data(df, symbol_name):
    required_columns = ["Open", "High", "Low", "Close", "Volume"]

    if df.empty:
        print(f"❌ {symbol_name}: data kosong")
        return False

    missing_columns = [
        column for column in required_columns
        if column not in df.columns
    ]

    if missing_columns:
        print(f"❌ {symbol_name}: kolom hilang {missing_columns}")
        return False

    return True



def download_symbol(symbol_name, yahoo_ticker, verbose=True):
    print(f"\nDownloading {symbol_name} ({yahoo_ticker})...")

    yfinance = get_yfinance_module()
    df = yfinance.download(
        yahoo_ticker,
        period=PERIOD,
        interval=INTERVAL,
        auto_adjust=True,
        progress=False,
    )

    df = clean_columns(df)

    if not validate_data(df, symbol_name):
        return False, None

    os.makedirs(DATA_DIR, exist_ok=True)

    output_path = f"{DATA_DIR}/{symbol_name.lower()}.csv"
    df.to_csv(output_path)

    latest_index = str(df.index[-1]) if not df.empty else None
    latest_close = None
    try:
        latest_close = float(df["Close"].iloc[-1])
    except Exception:
        latest_close = None

    print(f"✅ Saved: {output_path}")
    print(f"Latest candle: {latest_index} | Close: {latest_close}")

    if verbose:
        print(df.tail(3))

    return True, {
        "symbol": symbol_name,
        "ticker": yahoo_ticker,
        "output_path": output_path,
        "rows": int(len(df)),
        "latest_candle": latest_index,
        "latest_close": latest_close,
    }


# =========================
# CLI / MAIN
# =========================



def parse_args():
    parser = argparse.ArgumentParser(description="AI_SCALPER market data collector")
    parser.add_argument(
        "--mode",
        choices=[MODE_FAST, MODE_FULL, MODE_CUSTOM],
        default=os.getenv("DATA_COLLECTOR_MODE", MODE_FAST),
        help="fast=active/open symbols only, full=all symbols, custom=use --symbols",
    )
    parser.add_argument(
        "--symbols",
        nargs="*",
        default=None,
        help="Custom symbols, e.g. --symbols EURUSD GBPUSD or --symbols EURUSD,GBPUSD",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Do not print dataframe tail rows.",
    )
    return parser.parse_args()



def main():
    args = parse_args()
    mode = args.mode
    selected_symbols = resolve_symbols(mode, args.symbols)

    success_count = 0
    failed_count = 0
    success_items = []
    failed_items = []

    print("\n=== AI_SCALPER DATA COLLECTOR ===")
    print(f"Mode      : {mode.upper()}")
    print(f"Period    : {PERIOD}")
    print(f"Interval  : {INTERVAL}")
    print(f"Symbols   : {', '.join(selected_symbols) if selected_symbols else 'none'}")
    print(f"Data dir  : {DATA_DIR}/")

    if not selected_symbols:
        print("No symbol selected. Nothing to download.")
        return 1

    for symbol_name in selected_symbols:
        yahoo_ticker = SYMBOLS.get(symbol_name)
        if not yahoo_ticker:
            failed_count += 1
            failed_items.append({"symbol": symbol_name, "reason": "Unknown symbol"})
            print(f"❌ Failed {symbol_name}: unknown symbol")
            continue

        try:
            success, info = download_symbol(symbol_name, yahoo_ticker, verbose=not args.quiet)

            if success:
                success_count += 1
                success_items.append(info)
            else:
                failed_count += 1
                failed_items.append({"symbol": symbol_name, "reason": "Validation failed or empty data"})

        except Exception as error:
            failed_count += 1
            failed_items.append({"symbol": symbol_name, "reason": str(error)})
            print(f"❌ Failed {symbol_name}: {error}")

    status = {
        "generated_at": utc_now_iso(),
        "mode": mode,
        "period": PERIOD,
        "interval": INTERVAL,
        "data_dir": DATA_DIR,
        "selected_symbols": selected_symbols,
        "success_count": success_count,
        "failed_count": failed_count,
        "success_items": success_items,
        "failed_items": failed_items,
    }
    save_json(DATA_COLLECTOR_STATUS_FILE, status)

    print("\n=== DATA COLLECTION SUMMARY ===")
    print(f"Mode: {mode.upper()}")
    print(f"Selected: {len(selected_symbols)}")
    print(f"Success: {success_count}")
    print(f"Failed : {failed_count}")
    print(f"Saved directory: {DATA_DIR}/")
    print(f"Status file: {DATA_COLLECTOR_STATUS_FILE}")

    return 0 if failed_count == 0 else 1


if __name__ == "__main__":
    sys.exit(main())