"""NetGuardian - adaptive route manager for Windows.

NetGuardian keeps a set of host names reachable by pinning them to IP
addresses that actually accept TCP connections, writing the result into the
system ``hosts`` file through clearly marked, reversible blocks.

The package is deliberately dependency free: it runs on a stock CPython 3.9+
installation and is packaged into a single ``NetGuardian.exe`` with
PyInstaller.
"""

from __future__ import annotations

__version__ = "3.1.3"
__version_info__ = (3, 1, 3)
__author__ = "Svetliak"
__license__ = "MIT"
__url__ = "https://github.com/netguardian/netguardian"

APP_NAME = "NetGuardian"
APP_SLUG = "netguardian"
