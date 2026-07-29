from __future__ import annotations

from typing import Any

from app.utils.serialization import as_dict, safe_float


class BridgeAdapter:
    def safety(self, raw: Any, backend_limit: float) -> dict[str, Any]:
        bridge = as_dict(raw)
        engine_max = safe_float(bridge.get("max_allowed_lot") or bridge.get("max_lot"))
        effective = min(
            value for value in (backend_limit, 0.01, engine_max if engine_max is not None else 0.01) if value >= 0
        )
        warnings: list[str] = []
        if bridge.get("live_allowed") is not False:
            warnings.append("Engine source requested live permission; backend safety lock overrode it.")
        if engine_max is not None and engine_max > backend_limit:
            warnings.append(f"Engine max lot {engine_max} exceeds backend safety limit {backend_limit}.")
        return {
            "engine_live_allowed": bridge.get("live_allowed"),
            "live_allowed": False,
            "engine_max_lot": engine_max,
            "backend_safety_max_lot": min(backend_limit, 0.01),
            "effective_max_lot": effective,
            "guard_applied": bool(warnings),
            "warnings": warnings,
            "mode": str(bridge.get("mode") or "DRY_RUN"),
            "guard_enabled": bridge.get("guard_enabled"),
            "guard_status": str(bridge.get("guard_global_status") or "LOCKED"),
        }
