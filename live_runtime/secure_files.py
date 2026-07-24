"""Small fail-closed helpers for immutable local JSON artifacts.

These helpers provide local durability and exclusive creation.  They do not
turn a local file into independent/off-host evidence.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Mapping


class SecureFileError(RuntimeError):
    """Raised when an immutable artifact cannot be written safely."""


def _json_bytes(payload: Mapping[str, object]) -> bytes:
    if not isinstance(payload, Mapping):
        raise TypeError("JSON artifact payload must be a mapping")
    try:
        rendered = json.dumps(
            payload,
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise SecureFileError("JSON artifact payload is not canonicalizable") from exc
    return (rendered + "\n").encode("utf-8")


def _sync_directory(directory: Path) -> None:
    """Persist the directory entry where the platform supports directory fsync."""

    if os.name == "nt":
        return
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    descriptor = os.open(directory, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def write_json_exclusive(
    path: str | Path,
    payload: Mapping[str, object],
    *,
    mode: int = 0o600,
) -> Path:
    """Create one immutable JSON file and remove any incomplete write.

    Serialization completes before the destination is created.  ``O_EXCL``
    prevents overwrite races, and ``O_NOFOLLOW`` is used where available so a
    symlink cannot be substituted between the pre-check and ``os.open``.
    """

    data = _json_bytes(payload)
    destination = Path(path)
    if destination.exists() or destination.is_symlink():
        raise FileExistsError("artifact already exists or is a symlink")
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.parent.is_symlink() or not destination.parent.is_dir():
        raise SecureFileError("artifact parent must be a real directory")

    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor: int | None = None
    try:
        descriptor = os.open(destination, flags, mode)
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = None  # ownership moved to the file object
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        _sync_directory(destination.parent)
    except Exception:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
        try:
            destination.unlink()
        except OSError:
            pass
        raise
    return destination


__all__ = ["SecureFileError", "write_json_exclusive"]
