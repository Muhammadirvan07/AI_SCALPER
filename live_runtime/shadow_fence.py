"""Crash-safe, nonblocking singleton fence for one shadow evidence contract."""

from __future__ import annotations

import os
from pathlib import Path
import threading


class ShadowCycleAlreadyRunning(RuntimeError):
    """Raised when another process or thread owns the shadow contract cycle."""


_PROCESS_GUARD = threading.Lock()
_PROCESS_OWNERS: dict[str, object] = {}


class ShadowCycleFence:
    """Hold one persistent kernel lock for the full read-only shadow cycle.

    The lock file is never deleted.  Ownership is represented only by the
    kernel lock, so an interpreter or host crash releases it automatically.
    """

    def __init__(self, artifact_root: str | Path, contract_id: str) -> None:
        root = Path(artifact_root)
        contract_directory = root / "forward" / str(contract_id)
        if contract_directory.is_symlink():
            raise ShadowCycleAlreadyRunning("shadow contract path cannot be a symlink")
        if not contract_directory.is_dir():
            raise ShadowCycleAlreadyRunning("shadow contract directory is unavailable")
        self.path = (contract_directory / ".shadow-cycle.lock").resolve()
        try:
            self.path.relative_to(contract_directory.resolve())
        except ValueError as exc:
            raise ShadowCycleAlreadyRunning("shadow lock escaped contract directory") from exc
        self._identity = str(self.path)
        self._owner_token = object()
        self._descriptor: int | None = None
        self._acquired = False

    def acquire(self) -> None:
        if self._acquired:
            return
        with _PROCESS_GUARD:
            if self._identity in _PROCESS_OWNERS:
                raise ShadowCycleAlreadyRunning(
                    "another shadow cycle already owns this evidence contract"
                )
            self._acquire_os_lock()
            _PROCESS_OWNERS[self._identity] = self._owner_token
            self._acquired = True

    def _acquire_os_lock(self) -> None:
        if self.path.is_symlink():
            raise ShadowCycleAlreadyRunning("shadow lock file cannot be a symlink")
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_BINARY", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(self.path, flags, 0o600)
        except OSError as exc:
            raise ShadowCycleAlreadyRunning("shadow cycle lock is unavailable") from exc
        try:
            if os.fstat(descriptor).st_size == 0:
                os.write(descriptor, b"\0")
                os.fsync(descriptor)
            os.lseek(descriptor, 0, os.SEEK_SET)
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except (BlockingIOError, OSError) as exc:
            os.close(descriptor)
            raise ShadowCycleAlreadyRunning(
                "another shadow cycle already owns this evidence contract"
            ) from exc
        self._descriptor = descriptor

    def close(self) -> None:
        if not self._acquired:
            return
        with _PROCESS_GUARD:
            owner = _PROCESS_OWNERS.get(self._identity)
            if owner is self._owner_token:
                _PROCESS_OWNERS.pop(self._identity, None)
            descriptor = self._descriptor
            self._descriptor = None
            if descriptor is not None:
                try:
                    os.lseek(descriptor, 0, os.SEEK_SET)
                    if os.name == "nt":
                        import msvcrt

                        msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
                    else:
                        import fcntl

                        fcntl.flock(descriptor, fcntl.LOCK_UN)
                finally:
                    os.close(descriptor)
            self._acquired = False

    def __enter__(self) -> ShadowCycleFence:
        self.acquire()
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        self.close()

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass


__all__ = ["ShadowCycleAlreadyRunning", "ShadowCycleFence"]
