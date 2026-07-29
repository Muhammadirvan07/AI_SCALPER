from __future__ import annotations

from fastapi import Request

from app.schemas.common import SuccessResponse
from app.services.base import ServicePayload


def success(payload: ServicePayload, request: Request) -> SuccessResponse:
    payload.meta.request_id = getattr(request.state, "request_id", None)
    return SuccessResponse(data=payload.data, meta=payload.meta)
