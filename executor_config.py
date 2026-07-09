# executor_config.py

# =========================
# EXECUTION SAFETY CONFIG
# =========================

EXECUTION_MODE = "DRY_RUN"
# Options:
# "DRY_RUN"    = hanya validasi, tidak order real
# "PAPER"      = catat sebagai simulasi order
# "LIVE_READY" = validasi final sebelum live
# "LIVE"       = real order, masih dikunci

ALLOW_LIVE_TRADING = False

# =========================
# RISK GUARD
# =========================

MAX_RISK_PER_TRADE_USD = 0.50
MAX_LOT = 0.01
MIN_SCORE_TO_EXECUTE = 3
MAX_ORDERS_PER_RUN = 1
MAX_OPEN_PAPER_ORDERS_GLOBAL = 1
MAX_OPEN_PAPER_ORDERS_PER_SYMBOL = 1

# =========================
# SYMBOL GUARD
# =========================

ALLOWED_SYMBOLS = [
    "EURUSD",
    "GBPUSD",
    "AUDUSD",
    "NZDUSD",
    "XAUUSD",
    "BTCUSD",
]

# =========================
# SYMBOL RISK PROFILE GUARD
# =========================

DEFAULT_SYMBOL_RISK_PROFILE = {
    "max_risk_usd": 0.25,
    "max_lot": 0.01,
    "min_score": 3,
}

SYMBOL_RISK_PROFILES = {
    "EURUSD": {
        "max_risk_usd": 0.25,
        "max_lot": 0.01,
        "min_score": 3,
    },
    "GBPUSD": {
        "max_risk_usd": 0.25,
        "max_lot": 0.01,
        "min_score": 3,
    },
    "AUDUSD": {
        "max_risk_usd": 0.25,
        "max_lot": 0.01,
        "min_score": 3,
    },
    "NZDUSD": {
        "max_risk_usd": 0.25,
        "max_lot": 0.01,
        "min_score": 3,
    },
    "XAUUSD": {
        "max_risk_usd": 0.20,
        "max_lot": 0.01,
        "min_score": 4,
    },
    "BTCUSD": {
        "max_risk_usd": 0.15,
        "max_lot": 0.01,
        "min_score": 4,
    },
}

# =========================
# SIGNAL GUARD
# =========================

BLOCK_IF_SIGNAL_EXPIRED = True
BLOCK_DUPLICATE_SIGNAL = True

# Signal expiry dibuat oleh decision_engine.
# Kalau sinyal sudah expired, paper_executor akan menolak.