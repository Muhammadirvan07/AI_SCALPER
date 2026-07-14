class RiskManager:

    def calculate_trade_parameters(
        self,
        balance,
        risk_percent,
        atr
    ):

        risk_amount = balance * (risk_percent / 100)

        stop_loss = atr * 2

        take_profit = atr * 3

        return {
            "risk_amount": round(risk_amount, 2),
            "stop_loss": round(stop_loss, 6),
            "take_profit": round(take_profit, 6)
        }
