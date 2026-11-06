"""Parsing of the Windows connection table with no third-party modules."""

from __future__ import annotations

import csv
import ctypes
import io
import ipaddress
import os
import re
import subprocess
import time
from ctypes import wintypes
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

CREATE_NO_WINDOW = 0x08000000 if os.name == "nt" else 0

#: States that already mean "this connection is not moving on its own".
DEFAULT_STUCK_STATES = ("SYN_SENT", "CLOSE_WAIT", "FIN_WAIT_1", "LAST_ACK")

#: A connection in ESTABLISHED can still be dead inside.  This is the reason
#: used when the socket survives, but the owning process performs no I/O.
STALLED_REASON = "stalled"

#: Patch clients that are known to hang in ESTABLISHED without a profile.
#: They are never used for DNS/hosts changes; only for stall diagnostics.
DEFAULT_STALLED_HINTS = ("PathOfExile", "PoeLauncher")


@dataclass
class Connection:
    proto: str
    local_ip: str
    local_port: int
    remote_ip: str
    remote_port: int
    state: str
    pid: int
    process: str = ""

    @property
    def remote(self) -> str:
        return f"{self.remote_ip}:{self.remote_port}"

    @property
    def local(self) -> str:
        return f"{self.local_ip}:{self.local_port}"


@dataclass
class StuckConnection:
    """A connection worth showing to the user, with the reason why."""

    connection: Connection
    reason: str  # "persistent" | "pileup" | "state"
    seen_sec: float

    @property
    def pid(self) -> int:
        return self.connection.pid

    @property
    def process(self) -> str:
        return self.connection.process

    @property
    def state(self) -> str:
        return self.connection.state

    @property
    def local(self) -> str:
        return self.connection.local

    @property
    def remote(self) -> str:
        return self.connection.remote


def split_address(token: str) -> Tuple[str, int]:
    """Split ``1.2.3.4:443`` / ``[fe80::1%12]:443`` / ``*:*``."""
    token = token.strip()
    if token.startswith("["):
        closing = token.find("]")
        if closing == -1:
            return token, 0
        address = token[1:closing]
        port_text = token[closing + 1 :].lstrip(":")
    else:
        if ":" not in token:
            return token, 0
        address, port_text = token.rsplit(":", 1)
    try:
        port = int(port_text)
    except (TypeError, ValueError):
        port = 0
    return address, port


def parse_netstat(text: str) -> List[Connection]:
    """Parse ``netstat -ano`` output for TCP endpoints.

    Works with IPv4, IPv6 and with the extra header lines Windows prints.
    """
    connections: List[Connection] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) < 4:
            continue
        proto = parts[0].upper()
        if proto not in ("TCP", "TCPV6"):
            continue
        if len(parts) < 5:
            continue
        try:
            pid = int(parts[-1])
        except ValueError:
            continue
        state = parts[-2].upper()
        if not re.fullmatch(r"[A-Z][A-Z0-9_]*", state):
            continue
        local_ip, local_port = split_address(parts[1])
        remote_ip, remote_port = split_address(parts[2])
        connections.append(
            Connection(
                proto=proto,
                local_ip=local_ip,
                local_port=local_port,
                remote_ip=remote_ip,
                remote_port=remote_port,
                state=state,
                pid=pid,
            )
        )
    return connections


def parse_tasklist(text: str) -> Dict[int, str]:
    """Parse ``tasklist /FO CSV /NH`` output into ``pid -> image name``."""
    mapping: Dict[int, str] = {}
    reader = csv.reader(io.StringIO(text))
    for row in reader:
        if len(row) < 2:
            continue
        name = row[0].strip()
        pid_text = row[1].strip()
        if not pid_text.isdigit():
            continue
        mapping[int(pid_text)] = name
    return mapping


class _IoCounters(ctypes.Structure):
    _fields_ = [
        ("ReadOperationCount", ctypes.c_ulonglong),
        ("WriteOperationCount", ctypes.c_ulonglong),
        ("OtherOperationCount", ctypes.c_ulonglong),
        ("ReadTransferCount", ctypes.c_ulonglong),
        ("WriteTransferCount", ctypes.c_ulonglong),
        ("OtherTransferCount", ctypes.c_ulonglong),
    ]


_PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
if os.name == "nt":
    try:
        _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        _kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        _kernel32.OpenProcess.restype = wintypes.HANDLE
        _kernel32.GetProcessIoCounters.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(_IoCounters),
        ]
        _kernel32.GetProcessIoCounters.restype = wintypes.BOOL
        _kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        _kernel32.CloseHandle.restype = wintypes.BOOL
    except (AttributeError, OSError):
        _kernel32 = None
else:
    _kernel32 = None


def process_io(pid: int) -> Optional[Tuple[int, ...]]:
    """Return the process I/O counters, or None when they are unavailable.

    Network reads and writes usually show up in these counters.  A socket
    that stays ESTABLISHED while this tuple does not move is a much better
    "stalled" signal than the socket state alone.
    """
    if _kernel32 is None or not pid:
        return None
    handle = _kernel32.OpenProcess(_PROCESS_QUERY_LIMITED_INFORMATION, False, int(pid))
    if not handle:
        return None
    try:
        counters = _IoCounters()
        if not _kernel32.GetProcessIoCounters(handle, ctypes.byref(counters)):
            return None
        return (
            counters.ReadOperationCount,
            counters.WriteOperationCount,
            counters.OtherOperationCount,
            counters.ReadTransferCount,
            counters.WriteTransferCount,
            counters.OtherTransferCount,
        )
    finally:
        _kernel32.CloseHandle(handle)


def _run(command: Sequence[str], timeout: float = 20.0) -> str:
    try:
        completed = subprocess.run(
            list(command),
            capture_output=True,
            text=True,
            encoding="mbcs",
            errors="replace",
            timeout=timeout,
            creationflags=CREATE_NO_WINDOW,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise RuntimeError(str(exc)) from exc
    return completed.stdout or ""


def list_connections() -> List[Connection]:
    """Snapshot of current TCP endpoints enriched with process names."""
    connections = parse_netstat(_run(["netstat", "-ano"]))
    try:
        names = parse_tasklist(_run(["tasklist", "/FO", "CSV", "/NH"]))
    except RuntimeError:
        names = {}
    for connection in connections:
        connection.process = names.get(connection.pid, "")
    return connections


def _is_routable(address: str) -> bool:
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    return not (ip.is_loopback or ip.is_unspecified or ip.is_multicast)


def snapshot(interval_sec: float = 3.0) -> Tuple[List[Connection], List[Connection]]:
    """Two connection table snapshots with a pause in between."""
    first = list_connections()
    time.sleep(interval_sec)
    second = list_connections()
    return first, second


def find_stuck(
    first: Optional[Sequence[Connection]] = None,
    hints: Sequence[str] = (),
    states: Sequence[str] = DEFAULT_STUCK_STATES,
    *,
    interval_sec: float = 3.0,
    pileup_threshold: int = 6,
    second: Optional[Sequence[Connection]] = None,
    stalled_sec: float = 0.0,
    stalled_hints: Optional[Sequence[str]] = None,
    io_reader=process_io,
) -> List[StuckConnection]:
    """Find stuck connections by comparing two snapshots.

    A connection is reported once, with ``stalled`` winning over
    ``persistent``, ``persistent`` over ``pileup`` and ``pileup`` over
    ``state``.  A non-zero *stalled_sec* also looks for ESTABLISHED sockets
    whose owning process performed no I/O during the observation window.
    ``stalled_hints`` narrows that check to specific processes (by default
    the same hints as the ordinary scan).
    """
    wait_sec = stalled_sec if stalled_sec > 0 else interval_sec
    first_io: Dict[int, Optional[Tuple[int, ...]]] = {}
    if first is None:
        first = list_connections()
        if stalled_sec > 0:
            for connection in first:
                if connection.pid and connection.pid not in first_io:
                    first_io[connection.pid] = io_reader(connection.pid)
        time.sleep(wait_sec)
        second = list_connections()
    elif second is None:
        if stalled_sec > 0:
            for connection in first:
                if connection.pid and connection.pid not in first_io:
                    first_io[connection.pid] = io_reader(connection.pid)
        time.sleep(wait_sec)
        second = list_connections()
    elif stalled_sec > 0:
        for connection in first:
            if connection.pid and connection.pid not in first_io:
                first_io[connection.pid] = io_reader(connection.pid)

    wanted_states = {state.upper() for state in states}
    lowered_hints = [hint.lower() for hint in hints if hint]
    stalled_lowered = (
        lowered_hints
        if stalled_hints is None
        else [hint.lower() for hint in stalled_hints if hint]
    )

    def matches(connection: Connection) -> bool:
        # PID 0 rows are kernel placeholders: nothing for the user to fix.
        if connection.pid == 0:
            return False
        if not _is_routable(connection.remote_ip):
            return False
        if not lowered_hints:
            return True
        name = (connection.process or "").lower()
        return any(hint in name for hint in lowered_hints)

    def stalled_matches(connection: Connection) -> bool:
        if not stalled_lowered or connection.pid == 0:
            return False
        if not _is_routable(connection.remote_ip):
            return False
        name = (connection.process or "").lower()
        return any(hint in name for hint in stalled_lowered)

    def key_of(connection: Connection) -> Tuple[str, str, int, str, int]:
        return (
            connection.proto,
            connection.local_ip,
            connection.local_port,
            connection.remote_ip,
            connection.remote_port,
        )

    first_states = {key_of(connection): connection.state for connection in first}
    result: List[StuckConnection] = []
    seen: set = set()

    # ESTABLISHED is not a "stuck state"; it becomes suspicious only when
    # the same socket survives and the process I/O counters do not move.
    if stalled_sec > 0 and stalled_lowered:
        for connection in second:
            if connection.state != "ESTABLISHED" or not stalled_matches(connection):
                continue
            key = key_of(connection)
            if key in seen or first_states.get(key) != "ESTABLISHED":
                continue
            before = first_io.get(connection.pid)
            after = io_reader(connection.pid)
            if before is not None and after is not None and before == after:
                result.append(StuckConnection(connection, STALLED_REASON, stalled_sec))
                seen.add(key)

    for connection in second:
        if not matches(connection):
            continue
        key = key_of(connection)
        if key in seen:
            continue
        if connection.state not in wanted_states:
            # TIME_WAIT and friends are normal shutdown, not a stuck socket.
            continue
        if first_states.get(key) == connection.state:
            result.append(StuckConnection(connection, "persistent", wait_sec))
        else:
            result.append(StuckConnection(connection, "state", 0.0))
        seen.add(key)

    groups: Dict[Tuple[int, str], List[Connection]] = {}
    for connection in second:
        if connection.state != "ESTABLISHED" or connection.remote_port != 443:
            continue
        if not matches(connection):
            continue
        groups.setdefault((connection.pid, connection.remote_ip), []).append(connection)

    for connections in groups.values():
        if len(connections) < pileup_threshold:
            continue
        for connection in connections:
            key = key_of(connection)
            if key in seen:
                continue
            result.append(StuckConnection(connection, "pileup", 0.0))
            seen.add(key)

    result.sort(key=lambda item: (item.process.lower(), item.pid))
    return result


def match_profile(process_name: str, profiles: Dict[str, Sequence[str]]) -> Optional[str]:
    """Return the first profile whose hints match *process_name*."""
    name = (process_name or "").lower()
    for profile, hints in profiles.items():
        for hint in hints:
            if hint and hint.lower() in name:
                return profile
    return None


__all__ = [
    "Connection",
    "CREATE_NO_WINDOW",
    "DEFAULT_STALLED_HINTS",
    "DEFAULT_STUCK_STATES",
    "STALLED_REASON",
    "StuckConnection",
    "find_stuck",
    "list_connections",
    "match_profile",
    "parse_netstat",
    "parse_tasklist",
    "process_io",
    "snapshot",
    "split_address",
]
