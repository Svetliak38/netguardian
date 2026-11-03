"""Filesystem layout and path resolution.

The layout is intentionally portable: when NetGuardian lives in a writable
directory (the usual "unpack and run" case) configuration, cache and logs
stay next to the executable.  When it is installed into a read-only location
such as ``C:\\Program Files`` the mutable data moves to
``%LOCALAPPDATA%\\NetGuardian`` so the program never crashes on start-up just
because it cannot create a log directory.
"""

from __future__ import annotations

import os
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from . import APP_SLUG

CONFIG_NAME = "routes.json"
CACHE_NAME = "cache_ips.json"
LOG_NAME = "netguardian.log"


def program_dir() -> Path:
    """Directory that contains the executable (or the package checkout)."""
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent.parent


def is_writable(directory: Path) -> bool:
    """Return True when *directory* can be created and written by us."""
    try:
        directory.mkdir(parents=True, exist_ok=True)
        fd, probe = tempfile.mkstemp(prefix=".ng-probe-", dir=str(directory))
        os.close(fd)
        os.unlink(probe)
        return True
    except OSError:
        return False


def local_appdata() -> Path:
    base = os.environ.get("LOCALAPPDATA") or os.environ.get("APPDATA")
    if base:
        return Path(base)
    return Path.home() / "AppData" / "Local"


def default_data_dir(program: Optional[Path] = None) -> Path:
    """Prefer the portable location, fall back to %LOCALAPPDATA%."""
    program = program or program_dir()
    if is_writable(program):
        return program
    target = local_appdata() / "NetGuardian"
    try:
        target.mkdir(parents=True, exist_ok=True)
    except OSError:
        target = Path(tempfile.gettempdir()) / "NetGuardian"
        target.mkdir(parents=True, exist_ok=True)
    return target


def default_hosts_path() -> Path:
    override = os.environ.get("NETGUARDIAN_HOSTS")
    if override:
        return Path(override)
    system_root = os.environ.get("SystemRoot") or os.environ.get("WINDIR") or r"C:\Windows"
    return Path(system_root) / "System32" / "drivers" / "etc" / "hosts"


def find_config(program: Optional[Path] = None, data_dir: Optional[Path] = None) -> Path:
    """Resolve the configuration file using the documented search order."""
    override = os.environ.get("NETGUARDIAN_CONFIG")
    if override:
        return Path(override)
    program = program or program_dir()
    data_dir = data_dir or default_data_dir(program)
    portable = program / CONFIG_NAME
    if portable.is_file():
        return portable
    return data_dir / CONFIG_NAME


@dataclass(frozen=True)
class AppPaths:
    """Every mutable location used by one NetGuardian run."""

    program_dir: Path
    data_dir: Path
    config_file: Path
    cache_file: Path
    log_dir: Path
    backup_dir: Path
    hosts_file: Path

    @classmethod
    def resolve(
        cls,
        config: Optional[str] = None,
        data_dir: Optional[str] = None,
        hosts: Optional[str] = None,
        program: Optional[Path] = None,
    ) -> "AppPaths":
        program = program or program_dir()
        data = Path(data_dir).expanduser() if data_dir else default_data_dir(program)
        data.mkdir(parents=True, exist_ok=True)
        config_path = Path(config).expanduser() if config else find_config(program, data)
        hosts_path = Path(hosts).expanduser() if hosts else default_hosts_path()
        return cls(
            program_dir=program,
            data_dir=data,
            config_file=config_path,
            cache_file=data / CACHE_NAME,
            log_dir=data / "logs",
            backup_dir=data / "backups",
            hosts_file=hosts_path,
        )

    def ensure_directories(self) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.backup_dir.mkdir(parents=True, exist_ok=True)


def appdata_dir() -> Path:
    """Legacy helper kept for third-party imports."""
    return local_appdata() / "NetGuardian"


__all__ = [
    "APP_SLUG",
    "AppPaths",
    "CONFIG_NAME",
    "CACHE_NAME",
    "LOG_NAME",
    "appdata_dir",
    "default_data_dir",
    "default_hosts_path",
    "find_config",
    "is_writable",
    "local_appdata",
    "program_dir",
]
