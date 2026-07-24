"""Account-wide single-runtime fence independent from the SQLite journal path.

The SQLite fence prevents two executors sharing one journal.  This fence closes
the split-brain boundary where two misconfigured runtimes point at different
journal files for the same broker account/server.  It is acquired once and held
for the lifetime of the execution coordinator.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import tempfile
import threading


class AccountRuntimeFenceError(RuntimeError):
    """Raised when another runtime already owns the broker account boundary."""


_PROCESS_LOCK = threading.Lock()
_PROCESS_OWNERS: dict[str, object] = {}


def account_runtime_identity(
    broker_login: int | str,
    server: str,
    environment: str,
) -> str:
    account = str(broker_login or "").strip()
    broker_server = str(server or "").strip()
    broker_environment = str(environment or "").strip().upper()
    if not account or not broker_server or broker_environment not in {
        "DEMO",
        "LIVE",
        "LIVE_READ_ONLY",
    }:
        raise ValueError("broker login, server, and environment are required")
    return hashlib.sha256(
        f"{account}\x00{broker_server}\x00{broker_environment}".encode("utf-8")
    ).hexdigest()


class AccountRuntimeFence:
    """Non-reentrant OS/process singleton for one account/server identity."""

    def __init__(self, identity_sha256: str) -> None:
        normalized = str(identity_sha256 or "").strip().lower()
        if len(normalized) != 64 or any(
            character not in "0123456789abcdef" for character in normalized
        ):
            raise ValueError("account runtime identity must be SHA-256")
        self.identity_sha256 = normalized
        self._owner_token = object()
        self._file = None
        self._windows_handle = None
        self._acquired = False

    def acquire(self) -> None:
        if self._acquired:
            return
        with _PROCESS_LOCK:
            if self.identity_sha256 in _PROCESS_OWNERS:
                raise AccountRuntimeFenceError(
                    "another runtime owns this broker account/server"
                )
            self._acquire_os_lock()
            _PROCESS_OWNERS[self.identity_sha256] = self._owner_token
            self._acquired = True

    def _acquire_os_lock(self) -> None:
        if os.name == "nt":
            import ctypes

            name = "Global\\AI_SCALPER_ACCOUNT_" + self.identity_sha256.upper()
            kernel32 = ctypes.windll.kernel32
            handle = kernel32.CreateMutexW(None, False, name)
            if not handle:
                raise AccountRuntimeFenceError("cannot create Windows account mutex")
            if int(kernel32.GetLastError()) == 183:  # ERROR_ALREADY_EXISTS
                kernel32.CloseHandle(handle)
                raise AccountRuntimeFenceError(
                    "another Windows runtime owns this broker account/server"
                )
            self._windows_handle = handle
            return

        import fcntl

        lock_root = Path(tempfile.gettempdir()) / "ai_scalper_account_runtime_locks"
        lock_root.mkdir(mode=0o700, parents=True, exist_ok=True)
        path = lock_root / f"{self.identity_sha256}.lock"
        handle = path.open("a+b")
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except (BlockingIOError, OSError) as exc:
            handle.close()
            raise AccountRuntimeFenceError(
                "another runtime owns this broker account/server"
            ) from exc
        self._file = handle

    def close(self) -> None:
        if not self._acquired:
            return
        with _PROCESS_LOCK:
            owner = _PROCESS_OWNERS.get(self.identity_sha256)
            if owner is self._owner_token:
                _PROCESS_OWNERS.pop(self.identity_sha256, None)
            if self._windows_handle is not None:
                import ctypes

                ctypes.windll.kernel32.CloseHandle(self._windows_handle)
                self._windows_handle = None
            if self._file is not None:
                try:
                    import fcntl

                    fcntl.flock(self._file.fileno(), fcntl.LOCK_UN)
                finally:
                    self._file.close()
                    self._file = None
            self._acquired = False

    def __enter__(self) -> AccountRuntimeFence:
        self.acquire()
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        self.close()

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            # Destructors must never mask interpreter shutdown or test errors.
            pass


__all__ = [
    "AccountRuntimeFence",
    "AccountRuntimeFenceError",
    "account_runtime_identity",
]
