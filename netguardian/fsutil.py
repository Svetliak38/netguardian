"""Filesystem helpers shared by the config, cache and hosts layers."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path
from typing import Iterable, Optional


def atomic_write_bytes(path: Path, data: bytes, *, mode: Optional[int] = None) -> None:
    """Write *data* to *path* atomically (same-directory temp file + replace)."""
    directory = path.parent
    directory.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(directory))
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        if mode is not None:
            try:
                os.chmod(tmp, mode)
            except OSError:
                pass
        os.replace(tmp, path)
    except BaseException:
        try:
            tmp.unlink()
        except OSError:
            pass
        raise


def atomic_write_text(path: Path, text: str, encoding: str = "utf-8") -> None:
    """Encode *text* with *encoding* and write it atomically."""
    atomic_write_bytes(path, text.encode(encoding))


def rotate_files(directory: Path, pattern: str, keep: int) -> Iterable[Path]:
    """Delete all but the newest *keep* files matching *pattern*."""
    if keep <= 0:
        return []
    try:
        files = sorted(
            (p for p in directory.glob(pattern) if p.is_file()),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )
    except OSError:
        return []
    removed = []
    for stale in files[keep:]:
        try:
            stale.unlink()
            removed.append(stale)
        except OSError:
            pass
    return removed


__all__ = ["atomic_write_bytes", "atomic_write_text", "rotate_files"]
