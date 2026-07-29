from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from app.core.exceptions import AppError
from app.repositories.json_repository import JsonRepository, RepositoryResult
from app.schemas.common import ApiMeta


@dataclass(slots=True)
class ServicePayload:
    data: Any
    meta: ApiMeta


class BaseService:
    def __init__(self, json_repository: JsonRepository) -> None:
        self.json = json_repository

    async def optional_source(self, key: str) -> tuple[RepositoryResult | None, str | None]:
        try:
            return await self.json.read(key), None
        except AppError as exc:
            return None, f"{key}: {exc.message}"

    @staticmethod
    def meta(
        results: list[RepositoryResult | None], *, source: str, threshold: float, warnings: list[str] | None = None
    ) -> ApiMeta:
        now = datetime.now(UTC)
        available = [item for item in results if item is not None]
        timestamps = [item.source_updated_at for item in available if item.source_updated_at]
        updated = max(timestamps) if timestamps else None
        age = max(0.0, (now - updated).total_seconds()) if updated else None
        stale = not available or any(item.stale for item in available) or age is None or age > threshold
        status = "unavailable" if not available else "stale" if stale else "live"
        return ApiMeta(
            source=source,
            source_updated_at=updated,
            server_timestamp=now,
            age_seconds=age,
            stale=stale,
            source_available=bool(available),
            data_status=status,
            warnings=warnings or [],
        )
