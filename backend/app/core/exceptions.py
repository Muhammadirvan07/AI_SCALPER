from __future__ import annotations

from typing import Any


class AppError(Exception):
    code = "APPLICATION_ERROR"
    status_code = 500

    def __init__(self, message: str, *, details: Any = None) -> None:
        super().__init__(message)
        self.message = message
        self.details = details


class DataSourceUnavailableError(AppError):
    code = "DATA_SOURCE_UNAVAILABLE"
    status_code = 503


class InvalidDataFormatError(AppError):
    code = "INVALID_DATA_FORMAT"
    status_code = 422


class ResourceNotFoundError(AppError):
    code = "RESOURCE_NOT_FOUND"
    status_code = 404


class StaleDataError(AppError):
    code = "STALE_DATA"
    status_code = 409


class SafetyLockError(AppError):
    code = "LIVE_TRADING_LOCKED"
    status_code = 403


class MarketDataUnavailableError(DataSourceUnavailableError):
    code = "MARKET_DATA_UNAVAILABLE"


class FileTooLargeError(InvalidDataFormatError):
    code = "DATA_SOURCE_TOO_LARGE"
