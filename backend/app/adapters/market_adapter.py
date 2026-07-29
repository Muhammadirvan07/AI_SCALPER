from __future__ import annotations

import pandas as pd

from app.schemas.market import MarketIndicators


class MarketAdapter:
    def indicators(self, symbol: str, timeframe: str, candles: list[dict]) -> MarketIndicators:
        if not candles:
            return MarketIndicators(symbol=symbol, timeframe=timeframe)
        frame = pd.DataFrame(candles)
        close = pd.to_numeric(frame["close"], errors="coerce")
        high = pd.to_numeric(frame["high"], errors="coerce")
        low = pd.to_numeric(frame["low"], errors="coerce")
        ema20 = close.ewm(span=20, adjust=False).mean()
        ema50 = close.ewm(span=50, adjust=False).mean()
        previous = close.shift(1)
        true_range = pd.concat([(high - low).abs(), (high - previous).abs(), (low - previous).abs()], axis=1).max(
            axis=1
        )
        atr = true_range.rolling(14, min_periods=1).mean()
        up_move = high.diff()
        down_move = -low.diff()
        plus_dm = up_move.where((up_move > down_move) & (up_move > 0), 0.0)  # type: ignore[operator]
        minus_dm = down_move.where((down_move > up_move) & (down_move > 0), 0.0)  # type: ignore[operator]
        atr_safe = atr.replace(0, float("nan"))
        plus_di = 100 * plus_dm.rolling(14, min_periods=1).mean() / atr_safe
        minus_di = 100 * minus_dm.rolling(14, min_periods=1).mean() / atr_safe
        dx = 100 * (plus_di - minus_di).abs() / (plus_di + minus_di).replace(0, float("nan"))
        adx = dx.rolling(14, min_periods=1).mean()
        last_close = float(close.iloc[-1])
        e20 = float(ema20.iloc[-1])
        e50 = float(ema50.iloc[-1])
        atr14 = float(atr.iloc[-1])
        adx14 = None if pd.isna(adx.iloc[-1]) else float(adx.iloc[-1])
        volatility = atr14 / last_close * 100 if last_close else None
        trend = "BULLISH" if last_close > e20 > e50 else "BEARISH" if last_close < e20 < e50 else "SIDEWAYS"
        regime = "TRENDING" if adx14 is not None and adx14 >= 25 else "RANGING"
        return MarketIndicators(
            symbol=symbol,
            timeframe=timeframe,
            ema20=e20,
            ema50=e50,
            atr14=atr14,
            adx14=adx14,
            volatility=volatility,
            trend=trend,
            market_regime=regime,
        )
