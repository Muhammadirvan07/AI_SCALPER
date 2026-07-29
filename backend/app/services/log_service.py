from __future__ import annotations

from datetime import datetime

from app.repositories.log_repository import LogRepository
from app.schemas.common import ApiMeta, Page
from app.utils.datetime import utc_now

from .base import ServicePayload


class LogService:
    def __init__(self, repository: LogRepository) -> None:
        self.repository = repository

    async def list(
        self,
        *,
        level: str | None,
        component: str | None,
        search: str | None,
        start_time: datetime | None,
        end_time: datetime | None,
        limit: int,
        offset: int,
    ) -> ServicePayload:
        rows = await self.repository.query(level=level, component=component, search=search, limit=limit, offset=offset)
        if start_time:
            rows = [row for row in rows if row["timestamp"] >= start_time]
        if end_time:
            rows = [row for row in rows if row["timestamp"] <= end_time]
        now = utc_now()
        return ServicePayload(
            Page(items=rows, total=offset + len(rows), limit=limit, offset=offset),
            ApiMeta(
                source="*.log",
                server_timestamp=now,
                source_updated_at=rows[0]["timestamp"] if rows else None,
                age_seconds=None,
                stale=False,
                source_available=True,
                data_status="historical",
            ),
        )
