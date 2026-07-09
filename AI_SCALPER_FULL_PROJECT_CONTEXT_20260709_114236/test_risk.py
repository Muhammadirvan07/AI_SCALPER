from agents.risk_manager import RiskManager

rm = RiskManager()

result = rm.calculate_trade_parameters(
    balance=50,
    risk_percent=1,
    atr=13.64
)

print(result)