from __future__ import annotations

import uvicorn

from dashboard_api.app.config import settings


if __name__ == "__main__":
    uvicorn.run(
        "dashboard_api.app.main:app",
        host=settings.host,
        port=settings.port,
        reload=False,
    )
