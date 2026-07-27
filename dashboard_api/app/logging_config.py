from __future__ import annotations

import logging
import os
from logging.handlers import RotatingFileHandler
from pathlib import Path

from .config import Settings


def configure_logging(settings: Settings) -> None:
    level_name = os.getenv("AI_SCALPER_DASHBOARD_LOG_LEVEL", "INFO").upper()
    level = getattr(logging, level_name, logging.INFO)
    handlers: list[logging.Handler] = [logging.StreamHandler()]
    if settings.dashboard_log_file:
        log_path = Path(settings.dashboard_log_file).expanduser().resolve()
        log_path.parent.mkdir(parents=True, exist_ok=True)
        handlers.append(
            RotatingFileHandler(
                log_path,
                maxBytes=settings.dashboard_log_max_bytes,
                backupCount=settings.dashboard_log_backup_count,
                encoding="utf-8",
            )
        )
    logging.basicConfig(
        level=level,
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
        handlers=handlers,
        force=True,
    )
    logging.getLogger("uvicorn.access").setLevel(max(level, logging.WARNING))
