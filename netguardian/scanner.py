"""Parsing of the Windows connection table with no third-party modules."""

from __future__ import annotations

import csv
import io
import ipaddress
import os
import re
import subprocess
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

CREATE_NO_WINDOW = 0x08000000 if os.name == "nt" else 0


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


def find_stuck(
    connections: Iterable[Connection],
    hints: Sequence[str] = (),
    states: Sequence[str] = ("SYN_SENT", "CLOSE_WAIT"),
) -> List[Connection]:
    wanted_states = {state.upper() for state in states}
    lowered_hints = [hint.lower() for hint in hints if hint]
    result: List[Connection] = []
    for connection in connections:
        if connection.state not in wanted_states:
            continue
        if not _is_routable(connection.remote_ip):
            continue
        if lowered_hints:
            name = (connection.process or "").lower()
            if not any(hint in name for hint in lowered_hints):
                continue
        result.append(connection)
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
    "find_stuck",
    "list_connections",
    "match_profile",
    "parse_netstat",
    "parse_tasklist",
    "split_address",
]
