from __future__ import annotations

import asyncio
from pathlib import Path

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import PlainTextResponse

router = APIRouter(prefix="/api/v1/documentation", tags=["documentation"])

DOCUMENTS: dict[str, tuple[str, str]] = {
    "architecture": (
        "Arsitektur live-grade",
        "docs/LIVE_GRADE_ARCHITECTURE.md",
    ),
    "operator-runbook": (
        "Runbook operator read-only shadow",
        "docs/BROKER_READ_ONLY_SHADOW_RUNBOOK.md",
    ),
    "release-history": (
        "Riwayat penyelesaian fondasi",
        "docs/ARCHITECTURE_FOUNDATION_COMPLETION_2026-07-21.md",
    ),
    "safety-audit": (
        "Audit ship gate dan keselamatan",
        "docs/SHIP_GATE_AUDIT_2026-07-25.md",
    ),
    "api-contract": (
        "Kontrak Dashboard API",
        "dashboard_api/CONTRACTS.md",
    ),
}


def _document_path(request: Request, slug: str) -> tuple[str, Path]:
    document = DOCUMENTS.get(slug)
    if document is None:
        raise HTTPException(status_code=404, detail="Dokumentasi tidak terdaftar")
    title, relative_path = document
    root = request.app.state.runtime.settings.root.resolve()
    target = (root / relative_path).resolve()
    if root not in target.parents or not target.is_file():
        raise HTTPException(status_code=404, detail="Dokumentasi belum tersedia")
    return title, target


@router.get("")
async def list_documentation(request: Request) -> dict[str, object]:
    available: list[dict[str, str]] = []
    for slug in DOCUMENTS:
        try:
            title, _ = _document_path(request, slug)
        except HTTPException:
            continue
        available.append(
            {
                "slug": slug,
                "title": title,
                "href": f"/api/v1/documentation/{slug}",
            }
        )
    return {"documents": available}


@router.get("/{slug}", response_class=PlainTextResponse)
async def get_documentation(request: Request, slug: str) -> PlainTextResponse:
    _, target = _document_path(request, slug)
    content = await asyncio.to_thread(target.read_text, encoding="utf-8")
    return PlainTextResponse(content, media_type="text/markdown; charset=utf-8")
