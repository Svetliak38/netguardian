"""Exception hierarchy used across NetGuardian."""

from __future__ import annotations

from typing import Optional


class NetGuardianError(Exception):
    """Base class for all expected, user-facing failures."""

    exit_code = 1

    def __init__(self, message: str, *, hint: Optional[str] = None) -> None:
        super().__init__(message)
        self.message = message
        self.hint = hint


class ConfigError(NetGuardianError):
    exit_code = 2


class AdminRequiredError(NetGuardianError):
    exit_code = 3


class HostsError(NetGuardianError):
    pass


class HostsPermissionError(HostsError):
    exit_code = 3


class HostsSyntaxError(HostsError):
    exit_code = 4


class ResolverError(NetGuardianError):
    pass


class UserAbort(NetGuardianError):
    exit_code = 0


__all__ = [
    "AdminRequiredError",
    "ConfigError",
    "HostsError",
    "HostsPermissionError",
    "HostsSyntaxError",
    "NetGuardianError",
    "ResolverError",
    "UserAbort",
]
