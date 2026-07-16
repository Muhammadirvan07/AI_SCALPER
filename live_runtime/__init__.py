"""AI_SCALPER runtime package.

The package initializer intentionally performs no eager imports.  In
particular, importing a read-only shadow component must not also load the
executor, broker order adapter, promotion permits, or kill-switch reset code.
Callers import the exact submodule they need.
"""

__all__: list[str] = []
