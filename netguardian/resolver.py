"""Address discovery: cache, static candidates, local DNS and TCP probing."""

from __future__ import annotations

import ipaddress
import json
import random
import socket
import struct
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from .config import Settings
from .fsutil import atomic_write_text
from .log import get_logger

CACHE_VERSION = 2
SOURCE_CACHE = "cache"
SOURCE_STATIC = "static"
SOURCE_SYSTEM = "system"


class DnsError(Exception):
    """Raised when a DNS query cannot be completed."""


@dataclass
class Resolution:
    domain: str
    ip: str
    source: str
    elapsed: float = 0.0
    candidates: List[str] = field(default_factory=list)
    rtt_ms: Optional[float] = None
    candidate_rtts: Dict[str, float] = field(default_factory=dict)


@dataclass
class CacheEntry:
    ip: str
    timestamp: float
    source: str = SOURCE_CACHE

    @property
    def age(self) -> float:
        return max(0.0, time.time() - self.timestamp)

    def age_text(self) -> str:
        seconds = int(self.age)
        if seconds < 120:
            return f"{seconds}s"
        if seconds < 7200:
            return f"{seconds // 60}m"
        if seconds < 172800:
            return f"{seconds // 3600}h"
        return f"{seconds // 86400}d"


class Cache:
    """JSON cache tolerant to both the 2.x and the 3.x layouts."""

    def __init__(self, path: Path, ttl_hours: float = 6.0) -> None:
        self.path = Path(path)
        self.ttl = max(0.0, float(ttl_hours)) * 3600.0
        self._entries: Dict[str, CacheEntry] = {}
        self._dirty = False
        self._load()

    # -- loading -----------------------------------------------------------
    def _load(self) -> None:
        if not self.path.is_file():
            return
        try:
            with open(self.path, "r", encoding="utf-8-sig") as handle:
                raw = json.load(handle)
        except (OSError, json.JSONDecodeError):
            return
        if not isinstance(raw, dict):
            return
        if raw.get("version") == CACHE_VERSION and isinstance(raw.get("entries"), dict):
            entries = raw["entries"]
        else:
            entries = {key: value for key, value in raw.items() if key not in ("version", "entries")}
        for domain, value in entries.items():
            if not isinstance(value, dict):
                continue
            ip = str(value.get("ip", ""))
            timestamp = value.get("timestamp")
            try:
                ipaddress.IPv4Address(ip)
                timestamp = float(timestamp)
            except (ValueError, TypeError):
                continue
            source = str(value.get("source", SOURCE_CACHE))
            self._entries[str(domain).lower()] = CacheEntry(ip=ip, timestamp=timestamp, source=source)

    # -- queries -----------------------------------------------------------
    def get(self, domain: str, *, verify_ttl: bool = True) -> Optional[CacheEntry]:
        if self.ttl <= 0:
            return None
        entry = self._entries.get(domain.lower())
        if entry is None:
            return None
        if verify_ttl and entry.age > self.ttl:
            return None
        return entry

    def put(self, domain: str, ip: str, source: str = "dns") -> Optional[CacheEntry]:
        if self.ttl <= 0:
            return None
        entry = CacheEntry(ip=ip, timestamp=time.time(), source=source)
        self._entries[domain.lower()] = entry
        self._dirty = True
        return entry

    def drop(self, domain: str) -> None:
        if self._entries.pop(domain.lower(), None) is not None:
            self._dirty = True

    def prune(self) -> int:
        if self.ttl <= 0:
            count = len(self._entries)
            if count:
                self._entries.clear()
                self._dirty = True
            return count
        stale = [domain for domain, entry in self._entries.items() if entry.age > self.ttl]
        for domain in stale:
            del self._entries[domain]
        if stale:
            self._dirty = True
        return len(stale)

    def items(self) -> List[Tuple[str, CacheEntry]]:
        return sorted(self._entries.items(), key=lambda item: item[1].timestamp, reverse=True)

    def __len__(self) -> int:
        return len(self._entries)

    # -- persistence -------------------------------------------------------
    def to_dict(self) -> Dict[str, object]:
        return {
            "version": CACHE_VERSION,
            "entries": {
                domain: {"ip": entry.ip, "timestamp": entry.timestamp, "source": entry.source}
                for domain, entry in self._entries.items()
            },
        }

    def flush(self) -> None:
        if not self._dirty:
            return
        text = json.dumps(self.to_dict(), ensure_ascii=False, indent=2) + "\n"
        try:
            atomic_write_text(self.path, text)
            self._dirty = False
        except OSError as exc:
            get_logger().warning("cannot save cache %s: %s", self.path, exc)


# --------------------------------------------------------------------------
# DNS wire protocol (A records only)
# --------------------------------------------------------------------------
class DnsClient:
    """Minimal DNS client so NetGuardian does not depend on ``nslookup``.

    Parsing the text output of ``nslookup`` was both locale dependent and
    wrong on multi-address answers; speaking the protocol removes that whole
    class of bugs.
    """

    def __init__(self, timeout: float = 3.0) -> None:
        self.timeout = float(timeout)

    def query(self, domain: str, server: str) -> List[str]:
        try:
            ipaddress.IPv4Address(server)
        except ValueError as exc:
            raise DnsError(f"invalid DNS server: {server!r}") from exc
        packet = _build_query(domain)
        expected_id = struct.unpack("!H", packet[:2])[0]
        try:
            data = self._udp(packet, server)
            if _is_truncated(data):
                data = self._tcp(packet, server)
            if len(data) < 2 or struct.unpack("!H", data[:2])[0] != expected_id:
                raise DnsError("mismatched DNS response id")
            return _parse_response(data, domain)
        except socket.timeout as exc:
            raise DnsError(f"{server}: timeout") from exc
        except OSError as exc:
            raise DnsError(f"{server}: {exc}") from exc

    def _udp(self, packet: bytes, server: str) -> bytes:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(self.timeout)
            sock.sendto(packet, (server, 53))
            data, address = sock.recvfrom(4096)
        if address[0] != server:
            raise DnsError(f"unexpected DNS responder: {address[0]}")
        return data

    def _tcp(self, packet: bytes, server: str) -> bytes:
        with socket.create_connection((server, 53), timeout=self.timeout) as sock:
            sock.sendall(struct.pack("!H", len(packet)) + packet)
            header = _recv_exact(sock, 2)
            length = struct.unpack("!H", header)[0]
            return _recv_exact(sock, length)


def _recv_exact(sock: socket.socket, count: int) -> bytes:
    buffer = b""
    while len(buffer) < count:
        chunk = sock.recv(count - len(buffer))
        if not chunk:
            raise DnsError("connection closed")
        buffer += chunk
    return buffer


def _build_query(domain: str) -> bytes:
    query_id = random.randint(0, 0xFFFF)
    header = struct.pack("!HHHHHH", query_id, 0x0100, 1, 0, 0, 0)
    qname = b""
    for label in domain.rstrip(".").split("."):
        encoded = label.encode("ascii")
        if not encoded or len(encoded) > 63:
            raise DnsError(f"invalid label in {domain!r}")
        qname += bytes([len(encoded)]) + encoded
    qname += b"\x00"
    return header + qname + struct.pack("!HH", 1, 1)


def _is_truncated(data: bytes) -> bool:
    if len(data) < 4:
        return False
    flags = struct.unpack("!H", data[2:4])[0]
    return bool(flags & 0x0200)


def _read_name(data: bytes, offset: int) -> Tuple[str, int]:
    labels: List[str] = []
    jumped = False
    resume = offset
    hops = 0
    while True:
        if offset >= len(data):
            raise DnsError("truncated name")
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(data):
                raise DnsError("truncated pointer")
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            if not jumped:
                resume = offset + 2
            jumped = True
            hops += 1
            if hops > 32:
                raise DnsError("compression loop")
            offset = pointer
            continue
        offset += 1
        if offset + length > len(data):
            raise DnsError("truncated label")
        labels.append(data[offset : offset + length].decode("ascii", "replace"))
        offset += length
    return ".".join(labels), (resume if jumped else offset)


def _parse_response(data: bytes, domain: str) -> List[str]:
    if len(data) < 12:
        raise DnsError("short response")
    _, flags, qdcount, ancount, _, _ = struct.unpack("!HHHHHH", data[:12])
    if flags & 0x000F:
        raise DnsError(f"server returned rcode {flags & 0x000F}")
    offset = 12
    for _ in range(qdcount):
        _, offset = _read_name(data, offset)
        offset += 4
    addresses: List[str] = []
    for _ in range(ancount):
        _, offset = _read_name(data, offset)
        if offset + 10 > len(data):
            raise DnsError("truncated answer")
        rtype, rclass, _ttl, rdlength = struct.unpack("!HHIH", data[offset : offset + 10])
        offset += 10
        rdata = data[offset : offset + rdlength]
        offset += rdlength
        if rtype == 1 and rclass == 1 and rdlength == 4:
            address = str(ipaddress.IPv4Address(rdata))
            if address not in addresses:
                addresses.append(address)
    return addresses


def system_lookup(domain: str, timeout: float = 5.0) -> List[str]:
    """Resolve through the OS resolver (honours the hosts file)."""
    previous = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        infos = socket.getaddrinfo(domain, 443, socket.AF_INET, socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise DnsError(str(exc)) from exc
    finally:
        socket.setdefaulttimeout(previous)
    addresses: List[str] = []
    for info in infos:
        address = info[4][0]
        if address not in addresses:
            addresses.append(address)
    return addresses


def tcp_probe(ip: str, ports: Sequence[int] = (443,), timeout: float = 3.0) -> bool:
    for port in ports:
        try:
            with socket.create_connection((ip, int(port)), timeout=timeout):
                return True
        except OSError:
            continue
    return False


def tcp_rtt_ms(
    ip: str,
    ports: Sequence[int] = (443,),
    timeout: float = 3.0,
    attempts: int = 2,
) -> Optional[float]:
    """Median TCP handshake time in milliseconds, or None if unreachable.

    TCP, not ICMP: the route is judged by the port NetGuardian will actually
    pin.  Two attempts suppress a single unlucky spike without making a whole
    strategy scan take forever.
    """
    samples: List[float] = []
    for _ in range(max(1, attempts)):
        for port in ports or (443,):
            started = time.perf_counter()
            try:
                with socket.create_connection((ip, int(port)), timeout=timeout):
                    samples.append((time.perf_counter() - started) * 1000.0)
                    break
            except OSError:
                continue
    if not samples:
        return None
    samples.sort()
    middle = len(samples) // 2
    if len(samples) % 2:
        value = samples[middle]
    else:
        value = (samples[middle - 1] + samples[middle]) / 2.0
    return round(value, 1)


class Resolver:
    """Turns a profile into one reachable IPv4 address."""

    def __init__(
        self,
        settings: Settings,
        cache: Cache,
        *,
        dns_client: Optional[DnsClient] = None,
        probe: Optional[Callable[[str, Sequence[int], float], bool]] = None,
        rtt: Optional[Callable[[str, Sequence[int], float], Optional[float]]] = None,
    ) -> None:
        self.settings = settings
        self.cache = cache
        self.dns = dns_client or DnsClient(settings.dns_timeout_sec)
        self._probe = probe or tcp_probe
        # Only the real TCP probe gets automatic RTT measurement.  Tests and
        # callers that inject a boolean probe keep the old first-reachable
        # behaviour unless they inject ``rtt`` explicitly.
        if rtt is not None:
            self._rtt = rtt
        elif probe is None:
            self._rtt = tcp_rtt_ms
        else:
            self._rtt = None

    # -- public ------------------------------------------------------------
    def resolve(
        self,
        domain: str,
        *,
        strategy: str = "dns_discovery_only",
        static_candidates: Sequence[str] = (),
        domain_candidates: Optional[Mapping[str, Sequence[str]]] = None,
        ports: Sequence[int] = (443,),
        use_cache: bool = True,
        prefer_fastest: bool = False,
    ) -> Optional[Resolution]:
        started = time.time()
        try:
            if use_cache and not prefer_fastest:
                cached = self._from_cache(domain, ports)
                if cached is not None:
                    cached.elapsed = time.time() - started
                    return cached

            # Fastest-route mode looks at every source at once: a static
            # address is not automatically better than a closer DNS edge.
            if prefer_fastest and self._rtt is not None:
                ranked = []
                seen_candidates = set()
                for source in self._strategy_order(strategy):
                    if source == "static":
                        per_domain = (domain_candidates or {}).get(domain)
                        candidates = list(per_domain) if per_domain else list(static_candidates)
                    elif source == "dns":
                        candidates = self._dns_candidates(domain)
                    else:
                        try:
                            candidates = system_lookup(domain)
                        except DnsError:
                            candidates = []
                    source_label = source
                    if source == "dns":
                        source_label = f"dns:{self.settings.local_dns or 'system'}"
                    for candidate in candidates:
                        if candidate in seen_candidates:
                            continue
                        seen_candidates.add(candidate)
                        measured = self._rtt(candidate, ports, self.settings.tcp_timeout_sec)
                        if measured is not None:
                            ranked.append((measured, candidate, source_label))
                if not ranked:
                    return None
                ranked.sort(key=lambda item: (item[0], item[1]))
                rtt_ms, chosen, source_label = ranked[0]
                candidate_rtts = {candidate: ms for ms, candidate, _ in ranked}
                self.cache.put(domain, chosen, source=source_label)
                return Resolution(
                    domain=domain,
                    ip=chosen,
                    source=source_label,
                    elapsed=time.time() - started,
                    candidates=list(seen_candidates),
                    rtt_ms=rtt_ms,
                    candidate_rtts=candidate_rtts,
                )

            for source in self._strategy_order(strategy):
                if source == "static":
                    per_domain = (domain_candidates or {}).get(domain)
                    candidates = list(per_domain) if per_domain else list(static_candidates)
                elif source == "dns":
                    candidates = self._dns_candidates(domain)
                else:
                    try:
                        candidates = system_lookup(domain)
                    except DnsError:
                        candidates = []
                if not candidates:
                    continue
                chosen = self._first_reachable(candidates, ports)
                if chosen:
                    source_label = source
                    if source == "dns":
                        source_label = f"dns:{self.settings.local_dns or 'system'}"
                    self.cache.put(domain, chosen, source=source_label)
                    return Resolution(
                        domain=domain,
                        ip=chosen,
                        source=source_label,
                        elapsed=time.time() - started,
                        candidates=list(candidates),
                    )
            return None
        finally:
            self.cache.flush()

    def lookup(self, domain: str) -> List[str]:
        """Return every address we can discover, without probing."""
        addresses: List[str] = []
        if self.settings.local_dns:
            try:
                addresses.extend(self.dns.query(domain, self.settings.local_dns))
            except DnsError:
                pass
        try:
            addresses.extend(system_lookup(domain))
        except DnsError:
            pass
        unique: List[str] = []
        for address in addresses:
            if address not in unique:
                unique.append(address)
        return unique

    # -- internals ---------------------------------------------------------
    def _from_cache(self, domain: str, ports: Sequence[int]) -> Optional[Resolution]:
        entry = self.cache.get(domain)
        if entry is None:
            return None
        if not self._probe(entry.ip, ports, self.settings.tcp_timeout_sec):
            get_logger().info("cached address for %s is dead: %s", domain, entry.ip)
            self.cache.drop(domain)
            return None
        return Resolution(
            domain=domain,
            ip=entry.ip,
            source=SOURCE_CACHE,
            candidates=[entry.ip],
        )

    def _strategy_order(self, strategy: str) -> List[str]:
        if strategy == "static_first":
            return ["static", "dns", "system"]
        if strategy == "static_only":
            return ["static"]
        if strategy == "system_dns":
            return ["system", "dns"]
        return ["dns", "system"]

    def _dns_candidates(self, domain: str) -> List[str]:
        if self.settings.local_dns:
            try:
                return self.dns.query(domain, self.settings.local_dns)
            except DnsError as exc:
                get_logger().warning("local DNS failed for %s: %s", domain, exc)
        return []

    def _first_reachable(self, candidates: Iterable[str], ports: Sequence[int]) -> Optional[str]:
        for ip in candidates:
            if self._probe(ip, ports, self.settings.tcp_timeout_sec):
                return ip
        return None


__all__ = [
    "CACHE_VERSION",
    "Cache",
    "CacheEntry",
    "DnsClient",
    "DnsError",
    "Resolution",
    "Resolver",
    "SOURCE_CACHE",
    "SOURCE_STATIC",
    "SOURCE_SYSTEM",
    "system_lookup",
    "tcp_probe",
    "tcp_rtt_ms",
]
