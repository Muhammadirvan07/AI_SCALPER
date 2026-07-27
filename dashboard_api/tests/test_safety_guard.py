from dashboard_api.app.safety_guard import DashboardSafetyGuard


def test_safe_sources_remain_locked_without_violation() -> None:
    safety = DashboardSafetyGuard().enforce(
        {
            "bridge_status": {
                "mode": "DRY_RUN_SIMULATOR",
                "live_allowed": False,
                "max_allowed_lot": 0.01,
                "guard_enabled": True,
            },
            "manual_demo_readiness": {"order_capability": "DISABLED"},
        }
    )
    assert safety.live_allowed is False
    assert safety.live_trading == "LOCKED"
    assert safety.max_lot == 0.01
    assert safety.safety_violation is False
    assert safety.order_capability == "DISABLED"


def test_conflicting_live_and_lot_are_overridden() -> None:
    safety = DashboardSafetyGuard().enforce(
        {
            "unsafe_source": {
                "live_allowed": True,
                "max_lot": 1.0,
                "safe_to_demo_auto_order": True,
                "order_capability": "ENABLED",
            }
        }
    )
    assert safety.live_allowed is False
    assert safety.max_lot == 0.01
    assert safety.safe_to_demo_auto_order is False
    assert safety.safety_violation is True
    assert safety.display_status == "LOCKED_BY_DASHBOARD_SAFETY_GUARD"
    assert safety.order_capability == "DISABLED_BY_DASHBOARD_SAFETY_GUARD"
    assert len(safety.violations) == 4
