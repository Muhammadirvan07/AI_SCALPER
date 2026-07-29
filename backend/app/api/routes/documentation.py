from __future__ import annotations

import asyncio
from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.responses import PlainTextResponse

from app.api.dependencies import Container
from app.api.responses import success
from app.core.exceptions import ResourceNotFoundError

router = APIRouter(prefix="/documentation", tags=["Documentation"])

DOCUMENTS: dict[str, tuple[str, str]] = {
    "architecture": ("Arsitektur live-grade", "docs/LIVE_GRADE_ARCHITECTURE.md"),
    "operator-runbook": ("Runbook operator read-only shadow", "docs/BROKER_READ_ONLY_SHADOW_RUNBOOK.md"),
    "release-history": ("Riwayat penyelesaian fondasi", "docs/ARCHITECTURE_FOUNDATION_COMPLETION_2026-07-21.md"),
    "safety-audit": ("Audit ship gate dan keselamatan", "docs/SHIP_GATE_AUDIT_2026-07-25.md"),
    "api-contract": ("Kontrak Dashboard API", "dashboard_api/CONTRACTS.md"),
}


def document_path(root: Path, slug: str) -> tuple[str, Path]:
    document = DOCUMENTS.get(slug)
    if document is None:
        raise ResourceNotFoundError("Documentation is not registered")
    title, relative_path = document
    target = (root / relative_path).resolve()
    try:
        target.relative_to(root.resolve())
    except ValueError as exc:
        raise ResourceNotFoundError("Documentation path is outside AI_SCALPER_ROOT") from exc
    if not target.is_file():
        raise ResourceNotFoundError("Documentation is currently unavailable")
    return title, target


@router.get("", summary="List allowlisted project documentation")
async def documentation(request: Request, container: Container):
    rows = []
    for slug in DOCUMENTS:
        try:
            title, _ = document_path(container.settings.ai_scalper_root, slug)
        except ResourceNotFoundError:
            continue
        rows.append({"slug": slug, "title": title, "href": f"/api/v1/documentation/{slug}"})
    return success(container.system.payload({"documents": rows}, "documentation_registry"), request)


@router.get("/{slug}", response_class=PlainTextResponse, summary="Read one allowlisted Markdown document")
async def get_documentation(slug: str, request: Request, container: Container) -> PlainTextResponse:
    _, target = document_path(container.settings.ai_scalper_root, slug)
    content = await asyncio.to_thread(target.read_text, encoding="utf-8")
    return PlainTextResponse(
        content,
        media_type="text/markdown; charset=utf-8",
        headers={"X-Request-ID": getattr(request.state, "request_id", "")},
    )
