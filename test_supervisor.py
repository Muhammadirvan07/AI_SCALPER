import pandas as pd

from strategy.trend_analyzer import analyze_trend
from agents.volatility_agent import get_atr
from agents.market_status import classify_market
from agents.risk_manager import RiskManager
from agents.supervisor_agent import SupervisorAgent

# Load data
df = pd.read_csv("data/btcusd.csv")

# Trend
signal = analyze_trend(df)

# Volatility
atr = get_atr(df)

# Market status
price = df["Close"].iloc[-1]
market_status = classify_market(atr, price)

# Risk
rm = RiskManager()

risk = rm.calculate_trade_parameters(
    balance=50,
    risk_percent=1,
    atr=atr
)

# Supervisor
supervisor = SupervisorAgent()

decision = supervisor.make_decision(
    signal,
    market_status
)

print("\n=== AI SCALPER REPORT ===")
print(f"Signal: {signal}")
print(f"ATR: {atr:.2f} | Market: {market_status}")
print(f"Risk Amount: ${risk['risk_amount']}")
print(f"SL: {risk['stop_loss']}")
print(f"TP: {risk['take_profit']}")
print(f"\nDecision: {decision}")
