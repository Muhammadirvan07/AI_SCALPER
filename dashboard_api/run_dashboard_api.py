from __future__ import annotations

import sys
from pathlib import Path


if __package__ in {None, ""}:
    project_root = str(Path(__file__).resolve().parent.parent)
    if project_root not in sys.path:
        sys.path.insert(0, project_root)

import uvicorn

from dashboard_api.app.config import (
    settings,
    validate_loopback_dashboard_boundary,
)


def main() -> None:
    validate_loopback_dashboard_boundary(settings)
    uvicorn.run(
        "dashboard_api.app.main:app",
        host=settings.host,
        port=settings.port,
        reload=False,
    )


if __name__ == "__main__":
    main()
