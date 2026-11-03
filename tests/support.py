"""Shared test helpers.

``tempfile.mkdtemp`` creates directories that the DSH file sandbox cannot
write into on this machine, so the suite uses plain ``os.makedirs`` under a
workspace-local base directory instead.
"""

from __future__ import annotations

import os
import shutil
import uuid
from pathlib import Path

_BASE = Path(os.environ.get("NETGUARDIAN_TEST_TMP") or (Path.cwd() / ".testtmp"))


class TempDir:
    """Minimal ``TemporaryDirectory`` replacement that works under the sandbox."""

    def __init__(self) -> None:
        _BASE.mkdir(parents=True, exist_ok=True)
        self.name = str(_BASE / f"case-{uuid.uuid4().hex[:12]}")
        os.makedirs(self.name)

    def cleanup(self) -> None:
        shutil.rmtree(self.name, ignore_errors=True)

    def __enter__(self) -> "TempDir":
        return self

    def __exit__(self, *exc_info) -> None:
        self.cleanup()


__all__ = ["TempDir"]
