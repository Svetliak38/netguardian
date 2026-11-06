"""Safe one-button repair for NetGuardian-managed hosts entries.

Only marked NetGuardian blocks are touched.  A dead or broken IP is replaced
only with an address that passes TCP *and* TLS for the same host name; if no
candidate works, the entry is left in place and reported as dead.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Sequence, Tuple

from .config import Config
from .errors import HostsError
from .fsutil import atomic_write_bytes
from .hosts import HostsFile, parse_blocks
from .resolver import Resolver, tcp_probe
from .sslcheck import inspect, issuer_matches


@dataclass
class RepairAction:
    profile: str
    domain: str
    old_ip: str
    new_ip: str = ""
    status: str = "kept"  # kept | replaced | dead | error
    reason: str = ""


@dataclass
class RepairReport:
    actions: List[RepairAction] = field(default_factory=list)
    replaced: int = 0
    dead: int = 0
    kept: int = 0
    unmanaged: int = 0
    changed: bool = False
    written: bool = False
    backup: Optional[Path] = None

    @property
    def ok(self) -> bool:
        return not any(action.status == "error" for action in self.actions)


def _entry_is_good(
    domain: str,
    ip: str,
    ports: Sequence[int],
    expected_issuers: Sequence[str],
    mode: str,
    timeout: float,
    *,
    probe=tcp_probe,
    tls_inspect=inspect,
) -> Tuple[bool, str]:
    if not probe(ip, ports, timeout):
        return False, "no TCP answer"
    info = tls_inspect(domain, ip=ip, port=ports[0] if ports else 443, timeout=timeout, mode=mode)
    if not info.acceptable:
        return False, info.error or "TLS not confirmed"
    if expected_issuers and not issuer_matches(info.issuer, expected_issuers):
        return False, f"issuer '{info.issuer}' does not match expected"
    return True, ""


def _replace_line(
    lines: List[str],
    block_start: int,
    block_end: int,
    domain: str,
    old_ip: str,
    new_ip: str,
) -> bool:
    for index in range(block_start + 1, block_end):
        line = lines[index]
        content = line.split("#", 1)[0].strip()
        if not content:
            continue
        parts = content.split()
        if len(parts) < 2:
            continue
        names = {part.strip().lower().rstrip(".") for part in parts[1:]}
        if domain.lower().rstrip(".") not in names:
            continue
        # The same line can carry several host names.  The first replacement
        # already fixed all of them; a later action for the same line must not
        # become a false "entry line not found".
        if parts[0] == new_ip:
            return True
        if parts[0] != old_ip:
            continue
        lines[index] = line.replace(old_ip, new_ip, 1)
        return True
    return False


def _unmanaged_count(lines: Sequence[str], blocks) -> int:
    inside = set()
    for block in blocks:
        inside.update(range(block.start, block.end + 1))
    count = 0
    for index, line in enumerate(lines):
        if index in inside:
            continue
        content = line.split("#", 1)[0].strip()
        if not content:
            continue
        parts = content.split()
        if len(parts) < 2:
            continue
        try:
            ipaddress.IPv4Address(parts[0])
        except ValueError:
            continue
        count += 1
    return count


def repair_hosts(
    hosts: HostsFile,
    config: Config,
    resolver: Optional[Resolver] = None,
    *,
    dry_run: bool = False,
    timeout: Optional[float] = None,
    probe=tcp_probe,
    tls_inspect=inspect,
) -> RepairReport:
    """Plan and optionally apply repairs for marked NetGuardian blocks."""
    document = hosts.read()
    blocks = parse_blocks(document.lines)
    report = RepairReport(unmanaged=_unmanaged_count(document.lines, blocks))
    new_lines = list(document.lines)
    if resolver is None:
        raise ValueError("resolver is required")
    timeout = float(timeout or max(3.0, config.settings.tcp_timeout_sec))
    seen: set[Tuple[str, str]] = set()

    for block in blocks:
        profile = config.profiles.get(block.profile)
        ports = tuple(profile.ports) if profile else (443,)
        expected = profile.expected_issuers if profile else []
        strategy = profile.strategy if profile else "dns_discovery_only"
        static_candidates = profile.static_candidates if profile else []
        domain_candidates = profile.domain_candidates if profile else {}

        for old_ip, domain in block.entries:
            key = (block.profile, domain)
            if key in seen:
                continue
            seen.add(key)
            action = RepairAction(profile=block.profile, domain=domain, old_ip=old_ip)
            good, reason = _entry_is_good(
                domain,
                old_ip,
                ports,
                expected,
                config.settings.pin_mode,
                timeout,
                probe=probe,
                tls_inspect=tls_inspect,
            )
            if good:
                action.status = "kept"
                report.kept += 1
                report.actions.append(action)
                continue

            replacement = None
            resolution = resolver.resolve(
                domain,
                strategy=strategy,
                static_candidates=static_candidates,
                domain_candidates=domain_candidates,
                ports=ports,
                use_cache=False,
            )
            if resolution is not None and resolution.ip != old_ip:
                candidate_ok, candidate_reason = _entry_is_good(
                    domain,
                    resolution.ip,
                    ports,
                    expected,
                    config.settings.pin_mode,
                    timeout,
                    probe=probe,
                    tls_inspect=tls_inspect,
                )
                if candidate_ok:
                    replacement = resolution.ip
                else:
                    reason = candidate_reason

            if replacement:
                if _replace_line(new_lines, block.start, block.end, domain, old_ip, replacement):
                    action.new_ip = replacement
                    action.status = "replaced"
                    report.replaced += 1
                else:
                    action.status = "error"
                    action.reason = "entry line not found"
            else:
                action.status = "dead"
                action.reason = reason or "no working candidate"
                report.dead += 1
            report.actions.append(action)

    report.changed = new_lines != document.lines
    if not report.changed or dry_run:
        return report

    hosts._require_admin()  # same admin gate as apply/remove
    original_bytes = hosts.path.read_bytes()
    report.backup = hosts.create_backup("repair")

    # Another tool changed hosts between our read and backup: do not race it.
    if hosts.path.read_bytes() != original_bytes:
        raise HostsError("hosts changed while repairing; nothing was written")

    newline = document.newline
    new_text = newline.join(new_lines)
    if document.trailing_newline:
        new_text += newline
    try:
        atomic_write_bytes(hosts.path, new_text.encode(document.encoding))
        parse_blocks(new_lines)
        report.written = True
    except Exception:
        try:
            atomic_write_bytes(hosts.path, original_bytes)
        except OSError:
            pass
        raise
    return report
