"""Read-only, cross-validated public crypto market data for weekend shadowing.

The capability boundary in this module is intentionally narrow: HTTPS GETs to
two allow-listed public market-data hosts.  It has no credential, account,
order, wallet, or execution surface.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import json
import math
import socket
import ssl
from types import MappingProxyType
from typing import Callable, Mapping, Protocol
from urllib import error as urllib_error
from urllib import parse as urllib_parse
from urllib import request as urllib_request

import pandas as pd

from strategy.strategy_selector import MIN_REQUIRED_ROWS


UTC = timezone.utc
M15_SECONDS = 15 * 60
DEFAULT_MAX_CROSS_FEED_DEVIATION_BPS = 50.0
DEFAULT_MAX_TICKER_AGE_SECONDS = 30.0
DEFAULT_MAX_SPREAD_BPS = 25.0
DEFAULT_MAX_CLOCK_DRIFT_SECONDS = 1.0
_ALLOWED_HOSTS = frozenset(
    {"data-api.binance.vision", "api.exchange.coinbase.com"}
)
_BINANCE_ALLOWED_PATHS = frozenset(
    {"/api/v3/time", "/api/v3/klines", "/api/v3/ticker/bookTicker"}
)


class CryptoMarketDataError(RuntimeError):
    """Raised when public crypto market data cannot be trusted fail-closed."""


def _network_failure_reason_code(exc: Exception) -> str:
    """Return a bounded reason code without reflecting endpoint/error text."""

    if isinstance(exc, urllib_error.HTTPError):
        code = int(exc.code) if isinstance(exc.code, int) else 0
        return f"HTTP_STATUS_{code}" if 100 <= code <= 599 else "HTTP_ERROR"
    reason: object = exc.reason if isinstance(exc, urllib_error.URLError) else exc
    if isinstance(reason, ssl.SSLCertVerificationError):
        return "TLS_CERTIFICATE_VERIFY_FAILED"
    if isinstance(reason, ssl.SSLError):
        return "TLS_ERROR"
    if isinstance(reason, (TimeoutError, socket.timeout)):
        return "TIMEOUT"
    if isinstance(reason, socket.gaierror):
        return "DNS_RESOLUTION_FAILED"
    if isinstance(reason, ConnectionRefusedError):
        return "CONNECTION_REFUSED"
    if isinstance(reason, ConnectionResetError):
        return "CONNECTION_RESET"
    if isinstance(reason, OSError):
        error_number = reason.errno
        if isinstance(error_number, int) and 0 < error_number <= 9999:
            return f"NETWORK_OS_ERROR_{error_number}"
        return "NETWORK_OS_ERROR"
    if isinstance(exc, urllib_error.URLError):
        return "URL_ERROR"
    return "TRANSPORT_ERROR"


@dataclass(frozen=True)
class CryptoInstrument:
    canonical_symbol: str
    primary_symbol: str
    validator_symbol: str


CRYPTO_SYMBOLS: Mapping[str, CryptoInstrument] = MappingProxyType(
    {
        "BTCUSD": CryptoInstrument("BTCUSD", "BTCUSDT", "BTC-USD"),
        "ETHUSD": CryptoInstrument("ETHUSD", "ETHUSDT", "ETH-USD"),
    }
)


@dataclass(frozen=True)
class CryptoQuote:
    bid: float
    ask: float
    observed_at: datetime

    @property
    def midpoint(self) -> float:
        return (self.bid + self.ask) / 2.0


@dataclass(frozen=True)
class CryptoMarketSnapshot:
    canonical_symbol: str
    primary_symbol: str
    validator_symbol: str
    frame: pd.DataFrame
    bar_closed_at: datetime
    primary_quote: CryptoQuote
    validator_quote: CryptoQuote
    cross_feed_deviation_bps: float
    primary_spread_bps: float
    validator_spread_bps: float
    primary_server_time: datetime


class JSONTransport(Protocol):
    def get_json(self, url: str) -> object: ...


def _utc(value: datetime, field: str) -> datetime:
    if not isinstance(value, datetime):
        raise CryptoMarketDataError(f"{field} must be a datetime")
    if value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise CryptoMarketDataError(f"{field} must be timezone-aware UTC")
    return value.astimezone(UTC)


def _finite_positive(value: object, field: str) -> float:
    if isinstance(value, bool):
        raise CryptoMarketDataError(f"{field} must be finite and positive")
    try:
        parsed = float(value)
    except (TypeError, ValueError) as exc:
        raise CryptoMarketDataError(f"{field} must be finite and positive") from exc
    if not math.isfinite(parsed) or parsed <= 0.0:
        raise CryptoMarketDataError(f"{field} must be finite and positive")
    return parsed


def _utc_from_milliseconds(value: object, field: str) -> datetime:
    milliseconds = _finite_positive(value, field)
    try:
        return datetime.fromtimestamp(milliseconds / 1000.0, tz=UTC)
    except (OverflowError, OSError, ValueError) as exc:
        raise CryptoMarketDataError(f"{field} is outside the UTC range") from exc


def _utc_from_text(value: object, field: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError) as exc:
        raise CryptoMarketDataError(f"{field} is not valid UTC") from exc
    return _utc(parsed, field)


def _spread_bps(quote: CryptoQuote) -> float:
    return (quote.ask - quote.bid) / quote.midpoint * 10_000.0


def _instrument(symbol: object) -> CryptoInstrument:
    canonical = str(symbol or "").strip().upper()
    try:
        return CRYPTO_SYMBOLS[canonical]
    except KeyError as exc:
        raise CryptoMarketDataError(f"unsupported crypto symbol: {canonical}") from exc


class PublicJSONTransport:
    """Small GET-only transport restricted to public market-data hosts."""

    def __init__(self, *, timeout_seconds: float = 5.0):
        if not 1.0 <= float(timeout_seconds) <= 30.0:
            raise ValueError("timeout_seconds must be between 1 and 30")
        self.timeout_seconds = float(timeout_seconds)

    def get_json(self, url: str) -> object:
        parsed = urllib_parse.urlsplit(url)
        if (
            parsed.scheme != "https"
            or parsed.hostname not in _ALLOWED_HOSTS
            or parsed.username is not None
            or parsed.password is not None
        ):
            raise CryptoMarketDataError("public market-data URL is not allow-listed")
        if parsed.hostname == "data-api.binance.vision":
            path_allowed = parsed.path in _BINANCE_ALLOWED_PATHS
        else:
            segments = parsed.path.strip("/").split("/")
            path_allowed = (
                len(segments) == 3
                and segments[0] == "products"
                and segments[1] in {"BTC-USD", "ETH-USD"}
                and segments[2] == "ticker"
                and not parsed.query
            )
        if not path_allowed:
            raise CryptoMarketDataError("public market-data path is not allow-listed")
        request = urllib_request.Request(
            url,
            method="GET",
            headers={
                "Accept": "application/json",
                "User-Agent": "AI_SCALPER-crypto-shadow/1",
            },
        )
        try:
            with urllib_request.urlopen(
                request,
                timeout=self.timeout_seconds,
            ) as response:
                if getattr(response, "status", 200) != 200:
                    raise CryptoMarketDataError("public market-data HTTP status is not 200")
                if response.geturl() != url:
                    raise CryptoMarketDataError(
                        "public market-data redirects are forbidden"
                    )
                content_type = str(response.headers.get("Content-Type", "")).lower()
                if not content_type.startswith("application/json"):
                    raise CryptoMarketDataError(
                        "public market-data content type is invalid"
                    )
                raw = response.read(8 * 1024 * 1024 + 1)
        except CryptoMarketDataError:
            raise
        except Exception as exc:
            reason_code = _network_failure_reason_code(exc)
            raise CryptoMarketDataError(
                f"public market-data request failed [{reason_code}]"
            ) from exc
        if len(raw) > 8 * 1024 * 1024:
            raise CryptoMarketDataError("public market-data response is too large")
        try:
            return json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise CryptoMarketDataError("public market-data response is invalid JSON") from exc


class CryptoPublicMarketClient:
    """Read-only Binance primary and Coinbase validation adapter."""

    BINANCE_BASE = "https://data-api.binance.vision"
    COINBASE_BASE = "https://api.exchange.coinbase.com"

    def __init__(
        self,
        *,
        transport: JSONTransport | None = None,
        clock_provider: Callable[[], datetime] | None = None,
    ):
        self._transport = transport or PublicJSONTransport()
        self._clock_provider = clock_provider or (lambda: datetime.now(UTC))

    def trusted_now(self) -> datetime:
        return _utc(self._clock_provider(), "client clock")

    def _binance(
        self,
        path: str,
        parameters: Mapping[str, object] | None = None,
    ) -> object:
        query = urllib_parse.urlencode(parameters or {})
        url = f"{self.BINANCE_BASE}{path}" + (f"?{query}" if query else "")
        return self._transport.get_json(url)

    def _coinbase(self, path: str) -> object:
        return self._transport.get_json(f"{self.COINBASE_BASE}{path}")

    def server_time(self) -> datetime:
        payload = self._binance("/api/v3/time")
        if not isinstance(payload, Mapping):
            raise CryptoMarketDataError("Binance server-time payload is invalid")
        return _utc_from_milliseconds(payload.get("serverTime"), "Binance serverTime")

    def klines(self, primary_symbol: str, *, limit: int) -> object:
        return self._binance(
            "/api/v3/klines",
            {"symbol": primary_symbol, "interval": "15m", "limit": limit},
        )

    def primary_quote(self, primary_symbol: str) -> CryptoQuote:
        payload = self._binance(
            "/api/v3/ticker/bookTicker",
            {"symbol": primary_symbol},
        )
        if not isinstance(payload, Mapping) or payload.get("symbol") != primary_symbol:
            raise CryptoMarketDataError("Binance book ticker payload is invalid")
        return CryptoQuote(
            bid=_finite_positive(payload.get("bidPrice"), "Binance bid"),
            ask=_finite_positive(payload.get("askPrice"), "Binance ask"),
            observed_at=self.trusted_now(),
        )

    def validator_quote(self, validator_symbol: str) -> CryptoQuote:
        encoded = urllib_parse.quote(validator_symbol, safe="-")
        payload = self._coinbase(f"/products/{encoded}/ticker")
        if not isinstance(payload, Mapping):
            raise CryptoMarketDataError("Coinbase ticker payload is invalid")
        return CryptoQuote(
            bid=_finite_positive(payload.get("bid"), "Coinbase bid"),
            ask=_finite_positive(payload.get("ask"), "Coinbase ask"),
            observed_at=_utc_from_text(payload.get("time"), "Coinbase ticker time"),
        )


def crypto_weekend_focus_active(observed_at: datetime) -> bool:
    """Return the explicit forex-weekend focus window in UTC.

    Friday 21:00 UTC through Sunday 22:00 UTC covers the common DST/non-DST
    forex closure conservatively.  This controls diagnostics only.
    """

    current = _utc(observed_at, "observed_at")
    weekday = current.weekday()
    if weekday == 4:
        return current.hour >= 21
    if weekday == 5:
        return True
    if weekday == 6:
        return current.hour < 22
    return False


def _normalized_finalized_bars(
    raw: object,
    *,
    observed_at: datetime,
    count: int,
) -> tuple[pd.DataFrame, datetime]:
    if not isinstance(raw, list):
        raise CryptoMarketDataError("Binance kline payload must be a list")
    normalized: list[dict[str, object]] = []
    for item in raw:
        if not isinstance(item, (list, tuple)) or len(item) < 7:
            raise CryptoMarketDataError("Binance kline row is invalid")
        opened_at = _utc_from_milliseconds(item[0], "Binance kline open time")
        closed_at = _utc_from_milliseconds(item[6], "Binance kline close time")
        if int(opened_at.timestamp()) % M15_SECONDS:
            raise CryptoMarketDataError("Binance M15 bar is not UTC aligned")
        if closed_at > observed_at:
            continue
        normalized.append(
            {
                "open_time_utc": opened_at,
                "Open": _finite_positive(item[1], "Binance open"),
                "High": _finite_positive(item[2], "Binance high"),
                "Low": _finite_positive(item[3], "Binance low"),
                "Close": _finite_positive(item[4], "Binance close"),
                "is_final": True,
            }
        )
    if len(normalized) < count:
        raise CryptoMarketDataError(
            f"not enough finalized Binance M15 bars: {len(normalized)}/{count}"
        )
    frame = pd.DataFrame(normalized).sort_values("open_time_utc").reset_index(drop=True)
    if frame["open_time_utc"].duplicated(keep=False).any():
        raise CryptoMarketDataError("duplicate Binance M15 bars are forbidden")
    frame = frame.iloc[-count:].reset_index(drop=True)
    gaps = frame["open_time_utc"].diff().dropna().dt.total_seconds()
    if not gaps.eq(M15_SECONDS).all():
        raise CryptoMarketDataError("Binance M15 bars must be contiguous")
    if not (
        (frame["Low"] <= frame[["Open", "Close"]].min(axis=1))
        & (frame["High"] >= frame[["Open", "Close"]].max(axis=1))
        & (frame["Low"] <= frame["High"])
    ).all():
        raise CryptoMarketDataError("Binance M15 OHLC integrity failed")
    bar_closed_at = (
        pd.Timestamp(frame.iloc[-1]["open_time_utc"]).to_pydatetime()
        + timedelta(seconds=M15_SECONDS)
    )
    return frame, bar_closed_at


def build_crypto_market_snapshot(
    client: CryptoPublicMarketClient,
    *,
    symbol: str,
    observed_at: datetime,
    bar_count: int = 300,
    max_cross_feed_deviation_bps: float = DEFAULT_MAX_CROSS_FEED_DEVIATION_BPS,
    max_ticker_age_seconds: float = DEFAULT_MAX_TICKER_AGE_SECONDS,
    max_spread_bps: float = DEFAULT_MAX_SPREAD_BPS,
    max_clock_drift_seconds: float = DEFAULT_MAX_CLOCK_DRIFT_SECONDS,
) -> CryptoMarketSnapshot:
    """Build one fail-closed, cross-feed-validated finalized M15 snapshot."""

    if type(client) is not CryptoPublicMarketClient:
        raise TypeError("client must be CryptoPublicMarketClient")
    observed = _utc(observed_at, "observed_at")
    if isinstance(bar_count, bool) or not MIN_REQUIRED_ROWS <= bar_count <= 1000:
        raise CryptoMarketDataError(
            f"bar_count must be between {MIN_REQUIRED_ROWS} and 1000"
        )
    instrument = _instrument(symbol)
    server_time = client.server_time()
    raw = client.klines(instrument.primary_symbol, limit=min(bar_count + 2, 1000))
    primary = client.primary_quote(instrument.primary_symbol)
    validator = client.validator_quote(instrument.validator_symbol)
    if primary.observed_at < observed:
        raise CryptoMarketDataError("client clock moved backwards during capture")
    drift = float(max_clock_drift_seconds)
    if not (
        observed - timedelta(seconds=drift)
        <= server_time
        <= primary.observed_at + timedelta(seconds=drift)
    ):
        raise CryptoMarketDataError("Binance server clock drift exceeds limit")
    frame, bar_closed_at = _normalized_finalized_bars(
        raw,
        observed_at=primary.observed_at,
        count=bar_count,
    )
    if primary.ask < primary.bid:
        raise CryptoMarketDataError("Binance book ticker is crossed")
    if validator.ask < validator.bid:
        raise CryptoMarketDataError("Coinbase ticker is crossed")
    validator_age = (primary.observed_at - validator.observed_at).total_seconds()
    if validator_age < -float(max_clock_drift_seconds):
        raise CryptoMarketDataError("Coinbase ticker time is ahead of trusted UTC")
    if validator_age > float(max_ticker_age_seconds):
        raise CryptoMarketDataError("Coinbase ticker is stale")
    primary_spread = _spread_bps(primary)
    validator_spread = _spread_bps(validator)
    if primary_spread > float(max_spread_bps):
        raise CryptoMarketDataError("Binance spread exceeds diagnostic limit")
    if validator_spread > float(max_spread_bps):
        raise CryptoMarketDataError("Coinbase spread exceeds diagnostic limit")
    deviation = abs(primary.midpoint - validator.midpoint) / primary.midpoint * 10_000.0
    if deviation > float(max_cross_feed_deviation_bps):
        raise CryptoMarketDataError("cross-feed deviation exceeds diagnostic limit")
    return CryptoMarketSnapshot(
        canonical_symbol=instrument.canonical_symbol,
        primary_symbol=instrument.primary_symbol,
        validator_symbol=instrument.validator_symbol,
        frame=frame,
        bar_closed_at=bar_closed_at,
        primary_quote=primary,
        validator_quote=validator,
        cross_feed_deviation_bps=deviation,
        primary_spread_bps=primary_spread,
        validator_spread_bps=validator_spread,
        primary_server_time=server_time,
    )


__all__ = [
    "CRYPTO_SYMBOLS",
    "CryptoInstrument",
    "CryptoMarketDataError",
    "CryptoMarketSnapshot",
    "CryptoPublicMarketClient",
    "CryptoQuote",
    "PublicJSONTransport",
    "build_crypto_market_snapshot",
    "crypto_weekend_focus_active",
]
