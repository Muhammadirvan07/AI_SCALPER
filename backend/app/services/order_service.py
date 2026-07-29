from __future__ import annotations

from datetime import datetime

from app.adapters.order_adapter import OrderAdapter
from app.core.exceptions import ResourceNotFoundError
from app.repositories.json_repository import RepositoryResult
from app.schemas.common import Page
from app.schemas.orders import PaperOrder

from .base import BaseService, ServicePayload


class OrderService(BaseService):
    def __init__(self, json_repository, adapter: OrderAdapter) -> None:
        super().__init__(json_repository)
        self.adapter = adapter

    async def all_orders(self) -> tuple[list[PaperOrder], RepositoryResult]:
        result = await self.json.read("paper_orders")
        orders = self.adapter.normalize_source(result.value)
        return orders, result

    async def list(
        self,
        *,
        symbol: str | None = None,
        status: str | None = None,
        side: str | None = None,
        strategy: str | None = None,
        start_date: datetime | None = None,
        end_date: datetime | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> ServicePayload:
        orders, result = await self.all_orders()
        filtered = [
            item
            for item in orders
            if (not symbol or item.symbol == symbol)
            and (not status or item.status == status)
            and (not side or item.side == side)
            and (not strategy or item.strategy == strategy)
            and (not start_date or (item.open_time and item.open_time >= start_date))
            and (not end_date or (item.open_time and item.open_time <= end_date))
        ]
        filtered.sort(
            key=lambda item: item.open_time or datetime.min.replace(tzinfo=start_date.tzinfo if start_date else None),
            reverse=True,
        )
        return ServicePayload(
            Page(items=filtered[offset : offset + limit], total=len(filtered), limit=limit, offset=offset),
            self.meta([result], source="paper_orders.json", threshold=1800),
        )

    async def by_state(self, state: str, limit: int, offset: int) -> ServicePayload:
        return await self.list(status=state, limit=limit, offset=offset)

    async def get(self, order_id: str) -> ServicePayload:
        orders, result = await self.all_orders()
        item = next((row for row in orders if row.order_id == order_id), None)
        if item is None:
            raise ResourceNotFoundError(f"Paper order {order_id} was not found")
        return ServicePayload(item, self.meta([result], source="paper_orders.json", threshold=1800))
