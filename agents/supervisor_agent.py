class SupervisorAgent:

    def make_decision(
        self,
        signal,
        market_status
    ):

        if signal == "BUY" and market_status != "HIGH":
            return "BUY"

        if signal == "SELL" and market_status != "HIGH":
            return "SELL"

        return "WAIT"