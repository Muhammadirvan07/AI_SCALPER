from __future__ import annotations

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
