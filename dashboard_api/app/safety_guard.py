from __future__ import annotations

import logging
from collections.abc import Mapping, Sequence
from typing import Any

from .models import SafetyState

logger = logging.getLogger(__name__)


def _walk(value: Any, path: str = "") -> list[tuple[str, Any]]:
    found: list[tuple[str, Any]] = []
    if isinstance(value, Mapping):
        for key, child in value.items():
            child_path = f"{path}.{key}" if path else str(key)
            found.append((child_path, child))
            found.extend(_walk(child, child_path))
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for index, child in enumerate(value):
            found.extend(_walk(child, f"{path}[{index}]"))
    return found


class DashboardSafetyGuard:
    """Enforces immutable display safety without mutating project sources."""

    def __init__(self) -> None:
        self._last_violation_signature: tuple[str, ...] = ()

    def enforce(self, raw_sources: Mapping[str, Any]) -> SafetyState:
        violations: list[str] = []
        bridge_mode: str | None = None
        guard_enabled: bool | None = None

        bridge_status = raw_sources.get("bridge_status")
        if isinstance(bridge_status, Mapping):
            mode = bridge_status.get("mode")
            bridge_mode = str(mode) if mode is not None else None
            raw_guard = bridge_status.get("guard_enabled")
            guard_enabled = raw_guard if isinstance(raw_guard, bool) else None

        for source_key, source_value in raw_sources.items():
            if source_value is None:
                continue
            for field_path, value in _walk(source_value):
                leaf = field_path.rsplit(".", 1)[-1].split("[", 1)[0].lower()
                location = f"{source_key}.{field_path}"
                if leaf == "live_allowed" and value is not None and value is not False:
                    violations.append(
                        f"{location} meminta live_allowed={value!r}; dashboard memaksa false."
                    )
                elif leaf in {"max_lot", "max_allowed_lot"}:
                    if value is None:
                        continue
                    try:
                        if float(value) > 0.01:
                            violations.append(
                                f"{location} bernilai {value!r}; batas tampilan dipaksa 0.01."
                            )
                    except (TypeError, ValueError):
                        violations.append(
                            f"{location} memiliki tipe tidak valid; batas tampilan dipaksa 0.01."
                        )
                elif (
                    leaf == "safe_to_demo_auto_order"
                    and value is not None
                    and value is not False
                ):
                    violations.append(
                        f"{location} meminta demo auto-order; dashboard memaksa false."
                    )

        violations = sorted(set(violations))
        signature = tuple(violations)
        if signature and signature != self._last_violation_signature:
            logger.warning(
                "Kontradiksi keselamatan terdeteksi (%d). Sumber tidak diubah; "
                "status dashboard tetap LOCKED.",
                len(violations),
            )
        elif self._last_violation_signature and not signature:
            logger.info("Kontradiksi keselamatan sumber sudah tidak terdeteksi.")
        self._last_violation_signature = signature

        return SafetyState(
            display_status=(
                "LOCKED_BY_DASHBOARD_SAFETY_GUARD" if violations else "LOCKED"
            ),
            bridge_mode=bridge_mode,
            guard_enabled=guard_enabled,
            safety_violation=bool(violations),
            violations=violations,
        )
