"""Market-data provenance policy used by collectors and validators."""

from __future__ import annotations


YFINANCE_TICKERS = {
    "EURUSD": "EURUSD=X",
    "GBPUSD": "GBPUSD=X",
    "USDJPY": "JPY=X",
    "USDCHF": "CHF=X",
    "AUDUSD": "AUDUSD=X",
    "NZDUSD": "NZDUSD=X",
    "USDCAD": "CAD=X",
    "EURJPY": "EURJPY=X",
    "GBPJPY": "GBPJPY=X",
    "EURGBP": "EURGBP=X",
    "AUDJPY": "AUDJPY=X",
    "CADJPY": "CADJPY=X",
    "CHFJPY": "CHFJPY=X",
    "XAUUSD": "GC=F",
    "XAGUSD": "SI=F",
    "USOIL": "CL=F",
    "BTCUSD": "BTC-USD",
}


PROXY_SYMBOLS = {
    "XAUUSD": "COMEX_GOLD_FUTURES_PROXY_FOR_XAUUSD",
    "XAGUSD": "COMEX_SILVER_FUTURES_PROXY_FOR_XAGUSD",
    "USOIL": "NYMEX_WTI_FUTURES_PROXY_FOR_USOIL",
}


def normalize_symbol(symbol: object) -> str:
    return str(symbol or "").strip().upper()


def get_data_source_metadata(symbol: object) -> dict:
    """Return fail-closed provenance metadata for the configured data feed."""

    normalized = normalize_symbol(symbol)
    ticker = YFINANCE_TICKERS.get(normalized)
    proxy_description = PROXY_SYMBOLS.get(normalized)

    return {
        "symbol": normalized,
        "provider": "YFINANCE",
        "provider_ticker": ticker,
        "source_type": "MARKET_PROXY" if proxy_description else "INDICATIVE_MARKET_DATA",
        "proxy_description": proxy_description,
        "is_proxy": bool(proxy_description),
        "broker_feed_aligned": False,
        "source_aligned_for_live_validation": False,
        "live_block_reason": (
            "Futures proxy is not the broker XAU/XAG/USOIL instrument feed."
            if proxy_description
            else "Indicative Yahoo data is not the target broker execution feed."
        ),
    }
