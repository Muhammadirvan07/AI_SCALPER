"""Broker-neutral compatibility entry point for one evidence shadow cycle."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import sys


def _load_main():
    path = Path(__file__).resolve().with_name("run_xm_shadow_once.py")
    spec = importlib.util.spec_from_file_location("_ai_scalper_broker_shadow", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("broker shadow runtime entry point is unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    except Exception:
        sys.modules.pop(spec.name, None)
        raise
    return module.main


main = _load_main()


if __name__ == "__main__":
    raise SystemExit(main())
